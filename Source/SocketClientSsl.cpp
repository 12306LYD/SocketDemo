#include "SocketClientSsl.h"
#include <iostream>
#include <chrono>

ClientSsl::ClientSsl()
    : m_socket(INVALID_SOCKET)
    , m_serverPort(0)
    , m_ctx(nullptr)
    , m_ssl(nullptr)
    , m_isHandshakeComplete(false)
    , m_state(ClientState::Disconnected)
    , m_running(false)
    , m_lastHeartbeatReqTime(0)
    , m_lastPacketRecvTime(0)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    m_ctx = SSL_CTX_new(TLS_client_method());
    if (m_ctx == nullptr) {
        std::cout << "[ClientSsl] Failed to create SSL Context" << std::endl;
    } else {
        std::cout << "[ClientSsl] SSL Context created" << std::endl;
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_NONE, nullptr);
    }
}

ClientSsl::~ClientSsl()
{
    Stop();
    if (m_ctx) SSL_CTX_free(m_ctx);
    WSACleanup();
}

void ClientSsl::SetToken(std::string Name, std::string PassWord, std::string DeviceId)
{
      m_username = Name;
      m_password = PassWord;
      m_deviceId = DeviceId;
      return;
}

void ClientSsl::Start(const std::string& ip, int port)
{
    if (m_running)
    {
        return;
    }
    m_serverIp = ip;
    m_serverPort = port;
    m_running = true;
    m_thread = std::thread(&ClientSsl::NetworkThreadFunc, this);
}

void ClientSsl::Stop()
{
    m_running = false;
    if (m_thread.joinable())
    {
        m_thread.join();
    }
    CloseSocket();
    return;
}

bool ClientSsl::SendChatMessage(const std::string& msg)
{
    if (m_state != ClientState::Authenticated) return false;
    return SendPacket(static_cast<uint16_t>(CommandType::MessageReq), msg.c_str(), msg.size());
}

void ClientSsl::NetworkThreadFunc()
{
    std::cout << "[ClientSsl] NetworkThreadFunc started." << std::endl;
    int sslWant = 3; // Initial state: Want Write (Client Hello)

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
                // 连接成功，初始化状态
                m_state = ClientState::Connected;
                m_lastHeartbeatReqTime = GetTickCount64();
                m_lastPacketRecvTime = GetTickCount64();
                sslWant = 3; // 重置握手状态为 Want Write (开始发送 Client Hello)
            }
            else
            {
                // 连接失败，等待 3 秒后重试
                std::this_thread::sleep_for(std::chrono::seconds(3));
                continue;
            }
        }

        // ------------------------------------------------------------------
        // 2. 准备 IO 多路复用 (Select 模型)
        // ------------------------------------------------------------------

        fd_set readfds;
        FD_ZERO(&readfds);
        fd_set writefds;
        FD_ZERO(&writefds);

        // SSL 特有的逻辑：区分握手阶段和数据传输阶段
        if (!m_isHandshakeComplete)
        {
            // [握手阶段]
            // OpenSSL 的非阻塞握手需要根据返回值决定监听读还是写
            if (sslWant == 2) FD_SET(m_socket, &readfds); // Want Read: 需要读数据才能继续握手
            if (sslWant == 3) FD_SET(m_socket, &writefds); // Want Write: 需要写数据才能继续握手
        }
        else
        {
            // [数据传输阶段]
            // 始终监听可读事件
            FD_SET(m_socket, &readfds);

            // 检查发送缓冲区，如果有数据则监听可写事件
            std::lock_guard<std::mutex> lock(m_sendBufferMutex);
            if (!m_sendBuffer.empty())
            {
                FD_SET(m_socket, &writefds);
            }
        }

        // 设置超时时间 (10ms)
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000; // 10ms

        // ------------------------------------------------------------------
        // 3. 等待 IO 事件 (Select)
        // ------------------------------------------------------------------
        int ret = select(0, &readfds, &writefds, NULL, &tv);

        if (ret == SOCKET_ERROR)
        {
            std::cout << "[ClientSsl] Select error: " << WSAGetLastError() << std::endl;
            CloseSocket();
            m_state = ClientState::Disconnected;
            continue;
        }

        // ------------------------------------------------------------------
        // 4. 处理 IO 事件
        // ------------------------------------------------------------------
        if (ret > 0)
        {
            if (!m_isHandshakeComplete)
            {
                // 4.1 [握手阶段] 处理
                // 只有当 select 返回了我们期望的事件（读或写）时，才调用 DoSslHandshake
                if ((sslWant == 2 && FD_ISSET(m_socket, &readfds)) ||
                    (sslWant == 3 && FD_ISSET(m_socket, &writefds)))
                {
                    int res = DoSslHandshake();
                    if (res == -1)
                    {
                        // 握手失败
                        std::cout << "[ClientSsl] Handshake failed, closing socket." << std::endl;
                        CloseSocket();
                        m_state = ClientState::Disconnected;
                    }
                    else if (res == 0)
                    {
                        // 握手成功 (DoSslHandshake 内部会将 m_isHandshakeComplete 设为 true)
                    }
                    else
                    {
                        // 握手未完成，更新 sslWant (2=WantRead, 3=WantWrite) 以便下一次循环继续监听
                        sslWant = res;
                    }
                }
            }
            else
            {
                // 4.2 [数据传输阶段] 处理

                // 处理读事件
                if (FD_ISSET(m_socket, &readfds))
                {
                    RecvToBuffer();  // SSL_read
                    ProcessBuffer(); // 解包逻辑
                }

                // 处理写事件
                if (FD_ISSET(m_socket, &writefds))
                {
                    SendFromBuffer(); // SSL_write
                }
            }
        }

        // ------------------------------------------------------------------
        // 5. 心跳与超时检测 & 自动登录
        // ------------------------------------------------------------------

        // 5.1 自动登录 (握手完成后立即发送)
        if (m_state == ClientState::Connected && m_isHandshakeComplete)
        {
            std::string loginData = m_username + "|" + m_password;
            SendPacket(static_cast<uint16_t>(CommandType::LoginReq), loginData.c_str(), loginData.size());
            m_state = ClientState::Authenticating;
        }
        else if (m_state == ClientState::Authenticated)
        {
            ULONGLONG now = GetTickCount64();

            // 5.2 发送心跳包 (每 5 秒)
            if (now - m_lastHeartbeatReqTime > 5000)
            {
                SendPacket(static_cast<uint16_t>(CommandType::HeartbeatReq), nullptr, 0);
                m_lastHeartbeatReqTime = now;
            }

            // 5.3 检测超时断线 (15 秒未收到数据)
            if (now - m_lastPacketRecvTime > 15000)
            {
                std::cout << "[ClientSsl] Timeout (no data from server), disconnecting..." << std::endl;
                CloseSocket();
                m_state = ClientState::Disconnected;
            }
        }
    }
}



bool ClientSsl::ConnectToServer()
{
    std::cout << "[ClientSsl] ConnectToServer entered." << std::endl;
    // 1. 创建 TCP Socket
    m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_socket == INVALID_SOCKET) return false;

    // 2. 设置为非阻塞模式
    // 这是为了使用 select 实现可控的连接超时，避免 connect 阻塞过长时间
    SetNonBlocking(true);

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(m_serverPort);
    if (inet_pton(AF_INET, m_serverIp.c_str(), &serverAddr.sin_addr) <= 0)
    {
        std::cout << "[ClientSsl] inet_pton failed for IP: " << m_serverIp << std::endl;
        closesocket(m_socket);
        return false;
    }

    std::cout << "[ClientSsl] Connecting to " << m_serverIp << ":" << m_serverPort << "..." << std::endl;

    // 3. 发起连接请求
    // 因为是非阻塞模式，connect 通常会返回 SOCKET_ERROR 并且 WSAGetLastError() 为 WSAEWOULDBLOCK
    int res = connect(m_socket, (sockaddr*)&serverAddr, sizeof(serverAddr));

    if (res == SOCKET_ERROR)
    {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK)
        {
            // 如果是其他错误，说明连接立即失败
            std::cout << "[ClientSsl] Connect failed immediately error: " << err << std::endl;
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
            return false;
        }
        else
        {
            // 4. 连接正在进行中 (WSAEWOULDBLOCK)
            // 使用 select 等待 Socket 变为可写（表示连接成功）或发生异常（表示连接失败）
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(m_socket, &writefds);

            fd_set exceptfds;
            FD_ZERO(&exceptfds);
            FD_SET(m_socket, &exceptfds);

            timeval tv;
            tv.tv_sec = 5; // 设置 5 秒连接超时
            tv.tv_usec = 0;

            int selRes = select(0, NULL, &writefds, &exceptfds, &tv);
            if (selRes > 0)
            {
                // 检查是否有异常（连接失败）
                if (FD_ISSET(m_socket, &exceptfds))
                {
                    std::cout << "[ClientSsl] Connect failed (exception)." << std::endl;
                    closesocket(m_socket);
                    m_socket = INVALID_SOCKET;
                    return false;
                }
                // 检查是否可写（可能连接成功）
                if (FD_ISSET(m_socket, &writefds))
                {
                    // 再次确认 Socket 状态，确保没有底层错误
                    int so_error = 0;
                    int len = sizeof(so_error);
                    if (getsockopt(m_socket, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) == SOCKET_ERROR)
                    {
                        std::cout << "[ClientSsl] getsockopt failed" << std::endl;
                        closesocket(m_socket);
                        m_socket = INVALID_SOCKET;
                        return false;
                    }

                    if (so_error != 0)
                    {
                        std::cout << "[ClientSsl] Connect failed with error: " << so_error << std::endl;
                        closesocket(m_socket);
                        m_socket = INVALID_SOCKET;
                        return false;
                    }
                    // 连接成功！
                }
            }
            else if (selRes == 0)
            {
                // select 返回 0 表示超时
                std::cout << "[ClientSsl] Connect timeout." << std::endl;
                closesocket(m_socket);
                m_socket = INVALID_SOCKET;
                return false;
            }
            else
            {
                std::cout << "[ClientSsl] Select error during connect." << std::endl;
                closesocket(m_socket);
                m_socket = INVALID_SOCKET;
                return false;
            }
        }
    }

    std::cout << "[ClientSsl] TCP Connected to " << m_serverIp << ":" << m_serverPort << std::endl;

    // 5. TCP 连接成功后，初始化 SSL 对象并绑定 Socket
    // 注意：此时还未开始 SSL 握手，握手将在 NetworkThreadFunc 中由 DoSslHandshake 触发
    m_ssl = SSL_new(m_ctx);
    SSL_set_fd(m_ssl, (int)m_socket);
    SSL_set_connect_state(m_ssl); // 设置为客户端模式

    m_isHandshakeComplete = false;
    return true;
}


bool ClientSsl::SetNonBlocking(bool nonBlocking)
{
    u_long mode = nonBlocking ? 1 : 0;
    return ioctlsocket(m_socket, FIONBIO, &mode) != SOCKET_ERROR;
}

void ClientSsl::CloseSocket()
{
    if (m_ssl) {
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    m_isHandshakeComplete = false;
    m_recvBuffer.clear();
    {
        std::lock_guard<std::mutex> lock(m_sendBufferMutex);
        m_sendBuffer.clear();
    }
}




int ClientSsl::DoSslHandshake()
{
    if (m_isHandshakeComplete)
    {
        return 0;
    }
    // std::cout << "[ClientSsl] SSL_connect..." << std::endl;
    int ret = SSL_connect(m_ssl);
    if (ret == 1)
    {
        std::cout << "[ClientSsl] Handshake success" << std::endl;
        m_isHandshakeComplete = true;
        return 0;
    }

    int err = SSL_get_error(m_ssl, ret);
    if (err == SSL_ERROR_WANT_READ)
    {
         std::cout << "[ClientSsl] SSL_connect WANT_READ" << std::endl;
        return 2; // Want Read
    }
    else if (err == SSL_ERROR_WANT_WRITE)
    {
         std::cout << "[ClientSsl] SSL_connect WANT_WRITE" << std::endl;
        return 3; // Want Write
    }
    else
    {
        std::cout << "[ClientSsl] Handshake failed error: " << err << std::endl;
        unsigned long e;
        while ((e = ERR_get_error()) != 0) {
             char msg[256];
             ERR_error_string_n(e, msg, sizeof(msg));
             std::cout << "[ClientSsl] OpenSSL Error: " << msg << std::endl;
        }
        return -1;
    }
}

bool ClientSsl::SendPacket(uint16_t cmd, const void* data, uint64_t len)
{
    if (m_state == ClientState::Disconnected) return false;

    std::vector<char> buffer(sizeof(PacketHeader) + len);
    PacketHeader* header = reinterpret_cast<PacketHeader*>(buffer.data());

    header->magic = htons(PACKET_MAGIC);
    header->version = htons(PACKET_VERSION);
    header->cmd = htons(cmd);
    header->seq = htons(0);
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


void ClientSsl::SendFromBuffer()
{
    if (!m_isHandshakeComplete)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(m_sendBufferMutex);
    if (m_sendBuffer.empty())
    {
        return;
    }

    int ret = SSL_write(m_ssl, m_sendBuffer.data(), (int)m_sendBuffer.size());
    if (ret > 0)
    {
        m_sendBuffer.erase(m_sendBuffer.begin(), m_sendBuffer.begin() + ret);
    }
    else
    {
        int err = SSL_get_error(m_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            // wait
        }
        else
        {
            std::cout << "[ClientSsl] SSL_write error: " << err << std::endl;
            CloseSocket();
            m_state = ClientState::Disconnected;
        }
    }
}



void ClientSsl::RecvToBuffer()
{
    if (!m_isHandshakeComplete)
    {
        return;
    }

    char tempBuf[4096];
    int ret = SSL_read(m_ssl, tempBuf, sizeof(tempBuf));
    if (ret > 0)
    {
        m_recvBuffer.insert(m_recvBuffer.end(), tempBuf, tempBuf + ret);
        m_lastPacketRecvTime = GetTickCount64();
    }
    else
    {
        int err = SSL_get_error(m_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            // wait
        }
        else
        {
            std::cout << "[ClientSsl] SSL_read error: " << err << std::endl;
            CloseSocket();
            m_state = ClientState::Disconnected;
        }
    }
}



void ClientSsl::ProcessBuffer()
{
    while (m_recvBuffer.size() >= sizeof(PacketHeader))
    {
        PacketHeader* rawHeader = reinterpret_cast<PacketHeader*>(m_recvBuffer.data());
        PacketHeader header;
        header.magic = ntohs(rawHeader->magic);
        header.version = ntohs(rawHeader->version);
        header.cmd = ntohs(rawHeader->cmd);
        header.seq = ntohs(rawHeader->seq);
        header.body_len = NetworkToHost64(rawHeader->body_len);

        if (header.magic != PACKET_MAGIC)
        {
            m_recvBuffer.clear();
            CloseSocket();
            m_state = ClientState::Disconnected;
            return;
        }
        if (header.body_len > MAX_PACKET_BODY_SIZE)
        {
            m_recvBuffer.clear();
            CloseSocket();
            m_state = ClientState::Disconnected;
            return;
        }

        size_t totalSize = sizeof(PacketHeader) + header.body_len;
        if (m_recvBuffer.size() >= totalSize)
        {
            std::vector<char> body;
            if (header.body_len > 0)
            {
                body.assign(m_recvBuffer.begin() + sizeof(PacketHeader), m_recvBuffer.begin() + totalSize);
            }
            HandlePacket(header, body);
            m_recvBuffer.erase(m_recvBuffer.begin(), m_recvBuffer.begin() + totalSize);
        }
        else
        {
            break;
        }
    }
}

void ClientSsl::HandlePacket(const PacketHeader& header, const std::vector<char>& body)
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
        break;
    }
}

void ClientSsl::OnLoginRes(const std::vector<char>& body)
{
    std::string msg(body.begin(), body.end());
    std::cout << "[ClientSsl] LoginRes: " << msg << std::endl;
    if (msg.find("Success") != std::string::npos)
    {
        m_state = ClientState::Authenticated;
    }
    else {

        //登陆失败
        std::cout << "[Client] Login Failed." << std::endl;
        // Maybe disconnect or retry?
        // CloseSocket();
        // m_state = ClientState::Disconnected; 
        // If we disconnect, it will retry connection loop.
    }
}

void ClientSsl::OnHeartbeatRes()
{
    // std::cout << "[ClientSsl] HeartbeatRes" << std::endl;
}

void ClientSsl::OnMessageRes(const std::vector<char>& body)
{
    std::string msg(body.begin(), body.end());
    std::cout << "[ClientSsl] Msg: " << msg << std::endl;
}


