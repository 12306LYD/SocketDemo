
#include "SocketClient.h"
#include <iostream>

Client::Client()
    : m_socket(INVALID_SOCKET)
    , m_serverPort(0)
    , m_state(ClientState::Disconnected)
    , m_running(false)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

Client::~Client()
{
    Stop();
    WSACleanup();
}

void Client::SetToken(std::string Name, std::string PassWord, std::string DeviceId)
{
    m_username = Name;
    m_password = PassWord;
    m_deviceId = DeviceId;
    return;
}

void Client::Start(const std::string& ip, int port)
{
    if (m_running)
    {
        return;
    }
    m_serverIp = ip;
    m_serverPort = port;
    m_running = true;
    m_state = ClientState::Disconnected;

    m_recvBuffer.clear(); // 清空缓冲区
    {
        std::lock_guard<std::mutex> lock(m_sendBufferMutex);
        m_sendBuffer.clear();
    }

    m_thread = std::thread(&Client::NetworkThreadFunc, this);
    return;
}

void Client::Stop()
{
    m_running = false;
    if (m_thread.joinable())
    {
        m_thread.join();
    }
    CloseSocket();
    return;
}


bool Client::SendChatMessage(const std::string& msg)
{
    if (m_state != ClientState::Authenticated)
    {
        std::cout << "[Client] Cannot send message, not authenticated." << std::endl;
        return false;
    }

    return SendPacket(static_cast<uint16_t>(CommandType::MessageReq), msg.c_str(), static_cast<uint64_t>(msg.size()));
}


void Client::NetworkThreadFunc()
{
    while (m_running)
    {
        // ------------------------------------------------------------------
        // 1. 连接状态维护
        // ------------------------------------------------------------------
        // 如果当前未连接，尝试连接服务器
        if (m_socket == INVALID_SOCKET)
        {
            if (ConnectToServer())
            {
                // 连接成功，初始化心跳和时间戳
                m_state = ClientState::Connected;
                m_lastHeartbeatReqTime = GetTickCount64();
                m_lastPacketRecvTime = GetTickCount64();
                std::cout << "[Client] Connected to server " << m_serverIp << ":" << m_serverPort << std::endl;
            }
            else
            {
                // 连接失败，等待 3 秒后重试 (避免死循环占用 CPU)
                std::this_thread::sleep_for(std::chrono::seconds(3));
                continue;
            }
        }

        // ------------------------------------------------------------------
        // 2. 准备 IO 多路复用 (Select 模型)
        // ------------------------------------------------------------------
        // Select 模型需要两个集合：
        // readfds: 监听是否可读 (有数据到来)
        // writefds: 监听是否可写 (发送缓冲区有数据需要发出)

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(m_socket, &readfds); // 始终监听可读事件

        fd_set writefds;
        FD_ZERO(&writefds);

        bool hasDataToSend = false;
        {
            // 检查发送缓冲区是否有积压数据
            std::lock_guard<std::mutex> lock(m_sendBufferMutex);
            if (!m_sendBuffer.empty())
            {
                FD_SET(m_socket, &writefds); // 只有当有数据要发时，才监听可写事件
                hasDataToSend = true;
            }
        }

        // 设置超时时间 (10ms)
        // 这个时间决定了网络线程的响应频率，10ms 是个比较平衡的值
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000; // 10ms

        // ------------------------------------------------------------------
        // 3. 等待 IO 事件 (Select)
        // ------------------------------------------------------------------
        // select 会阻塞等待，直到：
        // a. 有数据可读 (Socket 接收缓冲区有数据)
        // b. 可写 (Socket 发送缓冲区有空位且我们在监听 writefds)
        // c. 超时 (10ms)
        // d. 出错
        int ret = select(0, &readfds, hasDataToSend ? &writefds : NULL, NULL, &tv);

        if (ret == SOCKET_ERROR)
        {
            // Select 出错通常意味着 Socket 异常，需要重连
            // 这里简化处理，直接关闭 Socket 触发重连流程
            CloseSocket();
            m_state = ClientState::Disconnected;
            continue;
        }

        // ------------------------------------------------------------------
        // 4. 处理 IO 事件
        // ------------------------------------------------------------------
        // ret > 0 表示有事件发生
        if (ret > 0)
        {
            // 4.1 处理读事件 (Recv)
            if (FD_ISSET(m_socket, &readfds))
            {
                RecvToBuffer();  // 从网卡搬运数据到内存缓冲区
                ProcessBuffer(); // 解析缓冲区，切包并处理业务
            }

            // 4.2 处理写事件 (Send)
            if (hasDataToSend && FD_ISSET(m_socket, &writefds))
            {
                SendFromBuffer(); // 将内存缓冲区的数据发送到网卡
            }
        }

        // ------------------------------------------------------------------
        // 5. 心跳与超时检测
        // ------------------------------------------------------------------
        // 即使没有 IO 事件 (ret == 0)，也需要定期检查心跳

        ULONGLONG now = GetTickCount64();

        // 5.1 发送心跳包 (每 5 秒一次)
        if (now - m_lastHeartbeatReqTime >= 5000)
        {
            if (m_state == ClientState::Authenticated)
            {
                // 发送心跳请求 (放入发送缓冲区)
                SendPacket(static_cast<uint16_t>(CommandType::HeartbeatReq), m_deviceId.c_str(), m_deviceId.size());
            }
            m_lastHeartbeatReqTime = now;
        }

        // 5.2 检测超时断线 (15 秒未收到任何包)
        if (now - m_lastPacketRecvTime >= 15000)
        {
            std::cout << "[Client] Timeout (no data from server), disconnecting..." << std::endl;
            CloseSocket();
            m_state = ClientState::Disconnected;
        }

        // ------------------------------------------------------------------
        // 6. 自动登录逻辑
        // ------------------------------------------------------------------
        // 如果连接成功但未登录，自动发起登录
        if (m_state == ClientState::Connected)
        {
            // Send Login Request
            std::string loginData = m_username + "|" + m_password;
            std::cout << "[Client] Sending LoginReq..." << std::endl;
            if (SendPacket(static_cast<uint16_t>(CommandType::LoginReq), loginData.c_str(), static_cast<uint64_t>(loginData.size())))
            {
                m_state = ClientState::Authenticating;
            }
        }
    }
}

bool Client::ConnectToServer()
{
    // Create socket
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(m_serverPort);
    inet_pton(AF_INET, m_serverIp.c_str(), &serverAddr.sin_addr);

    // Set a timeout for connect if needed, but blocking connect is okay for a separate thread
    if (connect(s, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        closesocket(s);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(m_socketMutex);
        m_socket = s;
    }

    // 连接成功后，设置为非阻塞模式
    if (!SetNonBlocking(true))
    {
        std::cout << "[Client] Failed to set non-blocking mode." << std::endl;
        CloseSocket();
        return false;
    }

    std::cout << "[Client] Connected to server " << m_serverIp << ":" << m_serverPort << std::endl;
    return true;
}

bool Client::SetNonBlocking(bool nonBlocking)
{
    u_long mode = nonBlocking ? 1 : 0;
    if (ioctlsocket(m_socket, FIONBIO, &mode) == SOCKET_ERROR)
    {
        return false;
    }
    return true;
}


void Client::CloseSocket()
{
    std::lock_guard<std::mutex> lock(m_socketMutex);
    if (m_socket != INVALID_SOCKET)
    {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    return;
}



bool Client::SendPacket(uint16_t cmd, const void* data, uint64_t len)
{
    // 这里不再直接 send，而是追加到 buffer
    // 注意：这里不需要锁 m_socketMutex，因为我们不操作 socket
    // 但我们需要锁 m_sendBufferMutex，因为 SendPacket 可能被业务线程调用，而 NetworkThread 也会访问 buffer

    if (m_state == ClientState::Disconnected)
    {
        return false;
    }

    std::vector<char> buffer(sizeof(PacketHeader) + len);
    PacketHeader* header = reinterpret_cast<PacketHeader*>(buffer.data());
    
    header->magic = htons(PACKET_MAGIC);
    header->version = htons(PACKET_VERSION);
    header->cmd = htons(cmd);
    header->seq = 0; // seq 也应该 htons(0)，虽然 0 是一样的
    header->body_len = HostToNetwork64(len);

    if (len > 0 && data != nullptr)
    {
        memcpy(buffer.data() + sizeof(PacketHeader), data, len);
    }

    {
        std::lock_guard<std::mutex> lock(m_sendBufferMutex);
        m_sendBuffer.insert(m_sendBuffer.end(), buffer.begin(), buffer.end());
    }

    return true;
}

void Client::SendFromBuffer()
{
    std::lock_guard<std::mutex> lock(m_sendBufferMutex);
    if (m_sendBuffer.empty())
    {
        return;
    }
    if (m_socket == INVALID_SOCKET)
    {
        return;
    }
    // 尝试发送整个缓冲区
    // 注意：send 在非阻塞模式下可能只发送一部分，或者返回 EWOULDBLOCK
    int ret = send(m_socket, m_sendBuffer.data(), static_cast<int>(m_sendBuffer.size()), 0);
    
    if (ret > 0)
    {
        // 发送成功了 ret 字节，从缓冲区移除
        m_sendBuffer.erase(m_sendBuffer.begin(), m_sendBuffer.begin() + ret);
    }
    else if (ret == 0)
    {
        // 对方关闭连接？通常 send 返回 0 比较少见，除非发 0 字节
    }
    else
    {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK)
        {
            std::cout << "[Client] Send failed error: " << err << std::endl;
            CloseSocket();
            m_state = ClientState::Disconnected;
        }
        // 如果是 WSAEWOULDBLOCK，说明内核缓冲区满了，什么都不做，下次再试
    }
}

void Client::RecvToBuffer()
{
    if (m_socket == INVALID_SOCKET) return;

    char tempBuf[4096];
    // 非阻塞模式下，recv 会立即返回
    int ret = recv(m_socket, tempBuf, sizeof(tempBuf), 0);
    
    if (ret > 0)
    {
        // 收到数据，追加到缓冲区
        m_recvBuffer.insert(m_recvBuffer.end(), tempBuf, tempBuf + ret);
        m_lastPacketRecvTime = GetTickCount64();
    }
    else if (ret == 0)
    {
        // 连接关闭
        std::cout << "[Client] Connection closed by server." << std::endl;
        CloseSocket();
        m_state = ClientState::Disconnected;
    }
    else
    {
        int err = WSAGetLastError();
        // 在非阻塞模式下，WSAEWOULDBLOCK 表示“现在没数据，稍后再试”，这不是错误
        if (err != WSAEWOULDBLOCK)
        {
            std::cout << "[Client] Recv failed error: " << err << std::endl;
            CloseSocket();
            m_state = ClientState::Disconnected;
        }
    }
}

void Client::ProcessBuffer()
{
    // 循环处理 buffer 中的数据包
    while (m_recvBuffer.size() >= sizeof(PacketHeader))
    {
        // 偷看头部
        // 注意：这里拿到的指针指向的数据是网络字节序，不能直接读值判断，必须先转换
        PacketHeader* rawHeader = reinterpret_cast<PacketHeader*>(m_recvBuffer.data());
        
        // 转换为主机字节序
        PacketHeader header;
        header.magic = ntohs(rawHeader->magic);
        header.version = ntohs(rawHeader->version);
        header.cmd = ntohs(rawHeader->cmd);
        header.seq = ntohs(rawHeader->seq);
        header.body_len = NetworkToHost64(rawHeader->body_len);

        // 校验魔数
        if (header.magic != PACKET_MAGIC)
        {
            std::cout << "[Client] Invalid magic in buffer, clearing buffer and disconnecting." << std::endl;
            m_recvBuffer.clear();
            CloseSocket();
            m_state = ClientState::Disconnected;
            return;
        }

        // 校验包体长度
        if (header.body_len > MAX_PACKET_BODY_SIZE)
        {
            std::cout << "[Client] Packet too large (" << header.body_len << " bytes), limit is " << MAX_PACKET_BODY_SIZE << ". Disconnecting." << std::endl;
            m_recvBuffer.clear();
            CloseSocket();
            m_state = ClientState::Disconnected;
            return;
        }

        // 检查包是否完整
        size_t totalPacketSize = sizeof(PacketHeader) + header.body_len;
        if (m_recvBuffer.size() >= totalPacketSize)
        {
            // 提取包体
            std::vector<char> body;
            if (header.body_len > 0)
            {
                body.assign(m_recvBuffer.begin() + sizeof(PacketHeader), m_recvBuffer.begin() + totalPacketSize);
            }

            // 处理包
            HandlePacket(header, body);

            // 从 buffer 中移除已处理的包
            m_recvBuffer.erase(m_recvBuffer.begin(), m_recvBuffer.begin() + totalPacketSize);
        }
        else
        {
            // 数据不够一个完整包，等待下次接收
            break; 
        }
    }
}



void Client::HandlePacket(const PacketHeader& header, const std::vector<char>& body)
{
    CommandType cmd = static_cast<CommandType>(header.cmd);
    switch (cmd)
    {
    case CommandType::LoginRes:
        OnLoginRes(body);
        break;
    case CommandType::HeartbeatRes:
        OnHeartbeatRes();
        break;
    case CommandType::MessageRes:
        OnMessageRes(body);
        break;
    default:
        std::cout << "[Client] Unknown command: " << header.cmd << std::endl;
        break;
    }
    return;
}

void Client::OnLoginRes(const std::vector<char>& body)
{
    // Assume body contains "OK" or "FAIL" or just empty for success?
    // User said: "服务器获取到登录请求后会校验是否是合法的登录 如果是合法的登录会给客户端回复登陆成功信息"
    
    std::string res(body.begin(), body.end());
    std::cout << "[Client] Received LoginRes: " << res << std::endl;

    // Simple logic: if response contains "success" or is empty (assuming 200 OK equivalent), we are good.
    // Let's assume any LoginRes means success for now unless it says "Fail".
    
    if (res.find("Fail") != std::string::npos)
    {
        std::cout << "[Client] Login Failed." << std::endl;
        // Maybe disconnect or retry?
        // CloseSocket();
        // m_state = ClientState::Disconnected; 
        // If we disconnect, it will retry connection loop.
    }
    else
    {
        std::cout << "[Client] Login Success!" << std::endl;
        m_state = ClientState::Authenticated;
    }
    return;
}

void Client::OnHeartbeatRes()
{
    // std::cout << "[Client] Received HeartbeatRes" << std::endl;
    return;
}

void Client::OnMessageRes(const std::vector<char>& body)
{
    std::string msg(body.begin(), body.end());
    std::cout << "[Client] Received Message: " << msg << std::endl;
    return;
}




