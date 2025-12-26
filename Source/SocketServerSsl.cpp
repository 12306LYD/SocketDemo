#include "SocketServerSsl.h"
#include <iostream>

ServerSsl::ServerSsl()
    : m_listenSocket(INVALID_SOCKET)
    , m_running(false)
    , m_ctx(nullptr)
{
    // 初始化 Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 初始化 OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

ServerSsl::~ServerSsl()
{
    Stop();
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
    }
    WSACleanup();
}

bool ServerSsl::InitSSL(const std::string& certFile, const std::string& keyFile)
{
    m_ctx = SSL_CTX_new(TLS_server_method());
    if (!m_ctx) {
        std::cout << "[ServerSsl] Unable to create SSL context" << std::endl;
        return false;
    }

    // 设置证书
    if (SSL_CTX_use_certificate_file(m_ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cout << "[ServerSsl] Failed to load certificate" << std::endl;
        return false;
    }

    // 设置私钥
    if (SSL_CTX_use_PrivateKey_file(m_ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cout << "[ServerSsl] Failed to load private key" << std::endl;
        return false;
    }

    return true;
}

bool ServerSsl::Start(int port)
{
    if (!m_ctx) {
        std::cout << "[ServerSsl] SSL context not initialized. Call InitSSL first." << std::endl;
        return false;
    }

    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) return false;

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        closesocket(m_listenSocket);
        return false;
    }

    if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        closesocket(m_listenSocket);
        return false;
    }

    m_running = true;
    m_thread = std::thread(&ServerSsl::NetworkThreadFunc, this);
    
    std::cout << "[ServerSsl] Started on port " << port << " (SSL Enabled)" << std::endl;
    return true;
}

void ServerSsl::Stop()
{
    m_running = false;
    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }
    if (m_thread.joinable()) m_thread.join();
}

bool ServerSsl::SetNonBlocking(SOCKET sock, bool nonBlocking)
{
    u_long mode = nonBlocking ? 1 : 0;
    return ioctlsocket(sock, FIONBIO, &mode) != SOCKET_ERROR;
}

std::string ServerSsl::GetClientInfo(const std::shared_ptr<ClientSessionSsl>& session)
{
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &session->addr.sin_addr, ipStr, INET_ADDRSTRLEN);
    return std::string(ipStr) + ":" + std::to_string(ntohs(session->addr.sin_port));
}

// -----------------------------------------------------------------------------------------
// SSL 核心逻辑实现
// -----------------------------------------------------------------------------------------

int ServerSsl::DoSslHandshake(std::shared_ptr<ClientSessionSsl> session)
{
    if (session->isHandshakeComplete) return 0;

    int ret = SSL_accept(session->ssl);
    if (ret == 1)
    {
        std::cout << "[ServerSsl] Handshake success: " << GetClientInfo(session) << std::endl;
        session->isHandshakeComplete = true;
        return 0;
    }

    int err = SSL_get_error(session->ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    {
        // 需要继续等待 IO，返回 0 表示正在进行中
        return 0; 
    }
    else
    {
        std::cout << "[ServerSsl] Handshake failed error: " << err << std::endl;
        unsigned long e;
        while ((e = ERR_get_error()) != 0) {
             char msg[256];
             ERR_error_string_n(e, msg, sizeof(msg));
             std::cout << "[ServerSsl] OpenSSL Error: " << msg << std::endl;
        }
        return -1;
    }
}

void ServerSsl::RecvToBuffer(std::shared_ptr<ClientSessionSsl> session)
{
    if (!session->isHandshakeComplete) return;

    char tempBuf[4096];
    int ret = SSL_read(session->ssl, tempBuf, sizeof(tempBuf));

    if (ret > 0)
    {
        session->recvBuffer.insert(session->recvBuffer.end(), tempBuf, tempBuf + ret);
        session->lastHeartbeatTime = std::chrono::steady_clock::now();
    }
    else
    {
        int err = SSL_get_error(session->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            // Just wait
        }
        else
        {
            // Error or shutdown
            int err = SSL_get_error(session->ssl, ret);
            std::cout << "[ServerSsl] Client disconnected (error " << err << "): " 
                      << GetClientInfo(session) 
                      << (session->username.empty() ? "" : " (User: " + session->username + ")") 
                      << std::endl;
            
            closesocket(session->socket); 
            session->socket = INVALID_SOCKET; // Mark as invalid to be removed in main loop
        }
    }
}

void ServerSsl::SendFromBuffer(std::shared_ptr<ClientSessionSsl> session)
{
    if (!session->isHandshakeComplete) return;

    std::lock_guard<std::mutex> lock(session->sendMutex);
    if (session->sendBuffer.empty()) return;

    int ret = SSL_write(session->ssl, session->sendBuffer.data(), (int)session->sendBuffer.size());
    if (ret > 0)
    {
        session->sendBuffer.erase(session->sendBuffer.begin(), session->sendBuffer.begin() + ret);
    }
    else
    {
        int err = SSL_get_error(session->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            // Wait
        }
        else
        {
            std::cout << "[ServerSsl] SSL_write error: " << err << std::endl;
        }
    }
}

void ServerSsl::NetworkThreadFunc()
{
    while (m_running)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(m_listenSocket, &readfds);

        fd_set writefds;
        FD_ZERO(&writefds);

        SOCKET maxFd = m_listenSocket;

        {
            std::lock_guard<std::mutex> lock(m_clientsMutex);
            for (auto& pair : m_clients)
            {
                auto session = pair.second;
                SOCKET s = session->socket; // Use current socket from session

                if (s == INVALID_SOCKET) continue;

                // 无论是握手阶段还是数据传输阶段，只要 socket 有效，我们通常都监听读
                // 因为 OpenSSL 会缓存数据，或者重协商可能随时发生
                FD_SET(s, &readfds);
                if (s > maxFd) maxFd = s;

                // 检查写事件
                bool wantWrite = false;
                {
                    std::lock_guard<std::mutex> sendLock(session->sendMutex);
                    if (!session->sendBuffer.empty() && session->isHandshakeComplete)
                    {
                        wantWrite = true;
                    }
                }
                
                // 如果握手没完成，也可能需要写数据
                if (!session->isHandshakeComplete)
                {
                    // 这里简化处理：握手阶段总是监听读，如果 SSL_accept 返回 WANT_WRITE，我们下次循环再处理
                    // 或者更严谨一点：记录 SSL_get_error 的结果，如果是 WANT_WRITE 就监听写
                    // 但对于简单的握手，监听读通常足够触发下一次操作
                }

                if (wantWrite)
                {
                    FD_SET(s, &writefds);
                }
            }
        }

        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000; // 10ms

        // std::cout << "Select..." << std::endl; 
        int ret = select((int)maxFd + 1, &readfds, &writefds, NULL, &tv);

        if (ret == SOCKET_ERROR)
        {
             // Log error but continue to cleanup phase
             // std::cout << "[ServerSsl] Select error: " << WSAGetLastError() << std::endl;
        }
        else if (ret > 0)
        {
            // 1. Accept
            if (FD_ISSET(m_listenSocket, &readfds))
            {
                sockaddr_in clientAddr;
                int addrLen = sizeof(clientAddr);
                SOCKET clientSock = accept(m_listenSocket, (sockaddr*)&clientAddr, &addrLen);
                
                if (clientSock != INVALID_SOCKET)
                {
                    SetNonBlocking(clientSock, true);

                    auto session = std::make_shared<ClientSessionSsl>();
                    session->socket = clientSock;
                    session->addr = clientAddr;
                    session->lastHeartbeatTime = std::chrono::steady_clock::now();
                    
                    // SSL 初始化
                    session->ssl = SSL_new(m_ctx);
                    SSL_set_fd(session->ssl, (int)clientSock);
                    SSL_set_accept_state(session->ssl); // Server mode

                    std::cout << "[ServerSsl] New connection from " << GetClientInfo(session) << std::endl;

                    std::lock_guard<std::mutex> lock(m_clientsMutex);
                    m_clients[clientSock] = session;
                }
            }

            // 2. Process Clients
            std::vector<std::shared_ptr<ClientSessionSsl>> sessionsToProcess;
            {
                std::lock_guard<std::mutex> lock(m_clientsMutex);
                for (auto& pair : m_clients)
                {
                    if (FD_ISSET(pair.first, &readfds) || FD_ISSET(pair.first, &writefds))
                    {
                        sessionsToProcess.push_back(pair.second);
                    }
                }
            }

            for (auto& session : sessionsToProcess)
            {
                if (!session->isHandshakeComplete)
                {
                    if (DoSslHandshake(session) == -1)
                    {
                        closesocket(session->socket);
                        session->socket = INVALID_SOCKET;
                    }
                }
                else
                {
                    if (FD_ISSET(session->socket, &readfds))
                    {
                        RecvToBuffer(session);
                        ProcessBuffer(session);
                    }
                    if (FD_ISSET(session->socket, &writefds))
                    {
                        SendFromBuffer(session);
                    }
                }
            }
        }

        // 3. Cleanup & Heartbeat
        {
            std::lock_guard<std::mutex> lock(m_clientsMutex);
            auto now = std::chrono::steady_clock::now();
            for (auto it = m_clients.begin(); it != m_clients.end(); )
            {
                auto session = it->second;
                
                // 检查是否应该断开 (Socket 已无效 或 心跳超时)
                bool shouldRemove = false;

                if (session->socket == INVALID_SOCKET)
                {
                    shouldRemove = true;
                }
                else
                {
                    // 15秒超时
                    auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - session->lastHeartbeatTime).count();
                    if (diff > 15)
                    {
                        std::cout << "[ServerSsl] Client timeout (" << diff << "s), removing: " 
                                  << GetClientInfo(session) 
                                  << (session->username.empty() ? "" : " (" + session->username + ")") 
                                  << std::endl;
                        
                        // 关闭 SSL 和 Socket
                        if (session->ssl) {
                            SSL_shutdown(session->ssl);
                            // SSL_free 在析构中调用，但在 map erase 时 shared_ptr 计数减为0才会析构
                            // 这里我们手动关闭 socket 即可
                        }
                        closesocket(session->socket);
                        session->socket = INVALID_SOCKET; // 标记无效
                        shouldRemove = true;
                    }
                }

                if (shouldRemove)
                {
                    it = m_clients.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }
    }
}

bool ServerSsl::SendPacket(std::shared_ptr<ClientSessionSsl> session, uint16_t cmd, const void* data, uint64_t len)
{
    if (!session || !session->isHandshakeComplete) return false;

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
        std::lock_guard<std::mutex> lock(session->sendMutex);
        session->sendBuffer.insert(session->sendBuffer.end(), buffer.begin(), buffer.end());
    }
    return true;
}

void ServerSsl::ProcessBuffer(std::shared_ptr<ClientSessionSsl> session)
{
    while (session->recvBuffer.size() >= sizeof(PacketHeader))
    {
        PacketHeader* rawHeader = reinterpret_cast<PacketHeader*>(session->recvBuffer.data());
        PacketHeader header;
        header.magic = ntohs(rawHeader->magic);
        header.version = ntohs(rawHeader->version);
        header.cmd = ntohs(rawHeader->cmd);
        header.seq = ntohs(rawHeader->seq);
        header.body_len = NetworkToHost64(rawHeader->body_len);

        if (header.magic != PACKET_MAGIC)
        {
            std::cout << "[ServerSsl] Invalid magic" << std::endl;
            session->recvBuffer.clear();
            return;
        }

        if (header.body_len > MAX_PACKET_BODY_SIZE)
        {
             std::cout << "[ServerSsl] Packet too large" << std::endl;
             session->recvBuffer.clear();
             return;
        }

        size_t totalSize = sizeof(PacketHeader) + header.body_len;
        if (session->recvBuffer.size() >= totalSize)
        {
            std::vector<char> body;
            if (header.body_len > 0)
            {
                body.assign(session->recvBuffer.begin() + sizeof(PacketHeader), session->recvBuffer.begin() + totalSize);
            }
            HandlePacket(session, header, body);
            session->recvBuffer.erase(session->recvBuffer.begin(), session->recvBuffer.begin() + totalSize);
        }
        else
        {
            break;
        }
    }
}

void ServerSsl::HandlePacket(std::shared_ptr<ClientSessionSsl> session, const PacketHeader& header, const std::vector<char>& body)
{
    CommandType cmd = static_cast<CommandType>(header.cmd);
    switch (cmd)
    {
    case CommandType::LoginReq:
        OnLoginReq(session, body);
        break;
    case CommandType::HeartbeatReq:
        OnHeartbeatReq(session);
        break;
    case CommandType::MessageReq:
        OnMessageReq(session, body);
        break;
    default:
        break;
    }
}

void ServerSsl::OnLoginReq(std::shared_ptr<ClientSessionSsl> session, const std::vector<char>& body)
{
    std::string loginStr(body.begin(), body.end());
    size_t split = loginStr.find('|');
    if (split != std::string::npos)
    {
        session->username = loginStr.substr(0, split);
        session->isAuthenticated = true;
        std::cout << "[ServerSsl] User " << session->username << " logged in." << std::endl;
        
        std::string msg = "Success";
        SendPacket(session, static_cast<uint16_t>(CommandType::LoginRes), msg.c_str(), msg.size());
    }
}

void ServerSsl::OnHeartbeatReq(std::shared_ptr<ClientSessionSsl> session)
{
    // Update time already done in Recv
    // std::cout << "[ServerSsl] Heartbeat from " << session->username << std::endl;
    SendPacket(session, static_cast<uint16_t>(CommandType::HeartbeatRes), nullptr, 0);
}

void ServerSsl::OnMessageReq(std::shared_ptr<ClientSessionSsl> session, const std::vector<char>& body)
{
    std::string msg(body.begin(), body.end());
    std::cout << "[ServerSsl] Chat from " << session->username << ": " << msg << std::endl;
    
    // Echo back
    std::string reply = "[Echo] " + msg;
    SendPacket(session, static_cast<uint16_t>(CommandType::MessageRes), reply.c_str(), reply.size());
}
