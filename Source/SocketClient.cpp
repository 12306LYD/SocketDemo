
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
    
    std::cout << "[Client] Connected to server " << m_serverIp << ":" << m_serverPort << std::endl;
    return true;
}

bool Client::SendPacket(uint16_t cmd, const void* data, uint32_t len)
{
    std::lock_guard<std::mutex> lock(m_socketMutex);
    if (m_socket == INVALID_SOCKET)
    {
        return false;
    }
    // Prepare packet
    // Total size = header + body
    // We send header first, then body, or combine them to avoid multiple syscalls
    // For small packets, combining is better.
    
    std::vector<char> buffer(sizeof(PacketHeader) + len);
    PacketHeader* header = reinterpret_cast<PacketHeader*>(buffer.data());
    
    header->magic = PACKET_MAGIC;
    header->version = PACKET_VERSION;
    header->cmd = cmd;
    header->seq = 0; // TODO: Increment seq
    header->body_len = len;

    if (len > 0 && data != nullptr)
    {
        memcpy(buffer.data() + sizeof(PacketHeader), data, len);
    }

    int totalSent = 0;
    int totalSize = static_cast<int>(buffer.size());
    const char* bufPtr = buffer.data();

    // 循环发送数据，确保所有数据都发送完毕
    // TCP 是流式协议，send 返回发送成功的字节数，可能小于我们请求发送的长度
    while (totalSent < totalSize)
    {
        // 发送剩余数据：bufPtr + totalSent 是当前偏移，totalSize - totalSent 是剩余大小
        int sent = send(m_socket, bufPtr + totalSent, totalSize - totalSent, 0);
        
        // 如果返回 SOCKET_ERROR，说明网络出错（如连接断开）
        if (sent == SOCKET_ERROR)
        {
            std::cout << "[Client] Send failed error: " << WSAGetLastError() << std::endl;
            return false;
        }
        
        // 累加已发送的字节数，继续下一轮循环发送剩余部分
        totalSent += sent;
    }

    return true;
}

bool Client::RecvFixedSize(void* buf, int len)
{
    // m_socketMutex is NOT locked here because this is called only by the network thread
    // and we assume only network thread reads. Send uses mutex because it can be called from main thread.
    // However, if CloseSocket is called from main thread, m_socket might become INVALID.
    // So we should check m_socket, but strictly locking reading might block sending.
    // Usually, we rely on the fact that if socket is closed, recv returns error.
    
    if (m_socket == INVALID_SOCKET)
    {
        return false;
    }

    int totalRecv = 0;
    char* bufPtr = (char*)buf;

    while (totalRecv < len)
    {
        int ret = recv(m_socket, bufPtr + totalRecv, len - totalRecv, 0);
        if (ret > 0)
        {
            totalRecv += ret;
        }
        else if (ret == 0)
        {
            // Connection closed
            return false;
        }
        else
        {
            // Error
            return false;
        }
    }
    return true;
}

void Client::ReceiveAndProcessPacket()
{
    PacketHeader header;
    if (!RecvFixedSize(&header, sizeof(header)))
    {
        std::cout << "[Client] Recv header failed, disconnecting." << std::endl;
        CloseSocket();
        m_state = ClientState::Disconnected;
        return;
    }

    if (header.magic != PACKET_MAGIC)
    {
        std::cout << "[Client] Invalid magic, disconnecting." << std::endl;
        CloseSocket();
        m_state = ClientState::Disconnected;
        return;
    }

    std::vector<char> body;
    if (header.body_len > 0)
    {
        body.resize(header.body_len);
        if (!RecvFixedSize(body.data(), header.body_len))
        {
            std::cout << "[Client] Recv body failed, disconnecting." << std::endl;
            CloseSocket();
            m_state = ClientState::Disconnected;
            return;
        }
    }

    m_lastPacketRecvTime = GetTickCount64();
    HandlePacket(header, body);
    return;
}

void Client::NetworkThreadFunc()
{
    while (m_running)
    {
        // 1. Connection Management
        if (m_state == ClientState::Disconnected)
        {
            if (ConnectToServer())
            {
                m_state = ClientState::Connected;
                m_lastPacketRecvTime = GetTickCount64();
                m_lastHeartbeatReqTime = GetTickCount64();
            }
            else
            {
                // Retry every 3 seconds
                std::this_thread::sleep_for(std::chrono::seconds(3));
                continue;
            }
        }

        if (m_socket == INVALID_SOCKET)
        {
            m_state = ClientState::Disconnected;
            continue;
        }

        // 2. Select (Multiplexing)
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(m_socket, &readfds);

        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000; // 100ms

        int ret = select(0, &readfds, NULL, NULL, &tv);

        // ret > 0: 表示有 Socket 就绪 (有数据可读)
        if (ret > 0)
        {
            if (FD_ISSET(m_socket, &readfds))
            {
                ReceiveAndProcessPacket();
            }
        }
        // ret == 0: 表示超时 (在 tv 指定的时间内没有事件发生)
        // 此时我们不处理任何数据，而是继续循环，以便执行下面的心跳检查等逻辑
        else if (ret == 0)
        {
            // Timeout, do nothing, just continue loop
        }
        // ret < 0: 表示 select 调用出错 (通常意味着 Socket 异常)
        else
        {
             std::cout << "[Client] Select error (ret=" << ret << "), disconnecting." << std::endl;
             CloseSocket();
             m_state = ClientState::Disconnected;
        }

        // 3. Logic Loop
        if (m_state == ClientState::Connected)
        {
            // Send Login Request
            std::string loginData = m_username + "|" + m_password;
            std::cout << "[Client] Sending LoginReq..." << std::endl;
            if (SendPacket(static_cast<uint16_t>(CommandType::LoginReq), loginData.c_str(), static_cast<uint32_t>(loginData.size())))
            {
                m_state = ClientState::Authenticating;
            }
            else
            {
                CloseSocket();
                m_state = ClientState::Disconnected;
            }
        }
        else if (m_state == ClientState::Authenticating)
        {
             // Wait for response, maybe check timeout here?
             auto now = std::chrono::steady_clock::now();
             // Simple timeout check: 10 seconds?
        }
        else if (m_state == ClientState::Authenticated)
        {
            // Heartbeat Logic
            ULONGLONG now = GetTickCount64();
            // GetTickCount64 返回的是毫秒，所以差值也是毫秒
            if (now - m_lastHeartbeatReqTime >= 5000) // Send heartbeat every 5 seconds (5000ms)
            {
                std::string Temp = m_deviceId;
                SendPacket(static_cast<uint16_t>(CommandType::HeartbeatReq), Temp.c_str(), Temp.size());
                m_lastHeartbeatReqTime = now;
                // std::cout << "[Client] Sent Heartbeat" << std::endl;
            }
        }
    }

    return;
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

bool Client::SendChatMessage(const std::string& msg)
{
    if (m_state != ClientState::Authenticated)
    {
        std::cout << "[Client] Cannot send message, not authenticated." << std::endl;
        return false;
    }
    
    return SendPacket(static_cast<uint16_t>(CommandType::MessageReq), msg.c_str(), static_cast<uint32_t>(msg.size()));
}


