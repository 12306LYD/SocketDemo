
#include "SocketServer.h"
#include <iostream>
#include <algorithm>
#include <sstream>

Server::Server()
    : m_listenSocket(INVALID_SOCKET)
    , m_port(0)
    , m_running(false)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

Server::~Server()
{
    Stop();
    WSACleanup();
}

bool Server::Start(int port)
{
    if (m_running) return false;

    m_port = port;
    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET)
    {
        std::cout << "[Server] Create socket failed." << std::endl;
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(m_port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cout << "[Server] Bind failed." << std::endl;
        closesocket(m_listenSocket);
        return false;
    }

    if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        std::cout << "[Server] Listen failed." << std::endl;
        closesocket(m_listenSocket);
        return false;
    }

    m_running = true;
    m_thread = std::thread(&Server::NetworkThreadFunc, this);
    std::cout << "[Server] Started on port " << m_port << std::endl;

    return true;
}

void Server::Stop()
{
    m_running = false;
    if (m_thread.joinable())
    {
        m_thread.join();
    }

    if (m_listenSocket != INVALID_SOCKET)
    {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }

    // Clean up all clients
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    for (auto& pair : m_clients)
    {
        closesocket(pair.first);
    }
    m_clients.clear();
}

void Server::NetworkThreadFunc()
{
    while (m_running)
    {
        fd_set readfds;
        FD_ZERO(&readfds);

        // Add listen socket
        FD_SET(m_listenSocket, &readfds);

        // Add all client sockets
        SOCKET maxSock = m_listenSocket;
        {
            std::lock_guard<std::mutex> lock(m_clientsMutex);
            for (auto& pair : m_clients)
            {
                FD_SET(pair.first, &readfds);
                if (pair.first > maxSock)
                {
                    maxSock = pair.first;
                }
            }
        }

        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000; // 100ms

        // In Windows, the first param (nfds) is ignored, but for logic sake let's keep it simple
        int ret = select(0, &readfds, NULL, NULL, &tv);

        if (ret > 0)
        {
            // 1. Check listen socket for new connections
            if (FD_ISSET(m_listenSocket, &readfds))
            {
                sockaddr_in clientAddr;
                int len = sizeof(clientAddr);
                SOCKET clientSock = accept(m_listenSocket, (sockaddr*)&clientAddr, &len);
                if (clientSock != INVALID_SOCKET)
                {
                    auto session = std::make_shared<ClientSession>();
                    session->socket = clientSock;
                    session->addr = clientAddr;
                    session->lastHeartbeatTime = std::chrono::steady_clock::now();

                    char ipStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, INET_ADDRSTRLEN);
                    std::cout << "[Server] New connection from " << ipStr << ":" << ntohs(clientAddr.sin_port) << std::endl;

                    std::lock_guard<std::mutex> lock(m_clientsMutex);
                    m_clients[clientSock] = session;
                }
            }

            // 2. Check client sockets for data
            // We need to copy keys first because we might modify the map (remove client) during iteration
            std::vector<std::shared_ptr<ClientSession>> sessionsToCheck;
            {
                std::lock_guard<std::mutex> lock(m_clientsMutex);
                for (auto& pair : m_clients)
                {
                    if (FD_ISSET(pair.first, &readfds))
                    {
                        sessionsToCheck.push_back(pair.second);
                    }
                }
            }

            for (auto& session : sessionsToCheck)
            {
                HandleClientPacket(session);
            }
        }

        // 3. Check heartbeats / timeouts
        {
            std::lock_guard<std::mutex> lock(m_clientsMutex);
            auto now = std::chrono::steady_clock::now();
            for (auto it = m_clients.begin(); it != m_clients.end(); )
            {
                auto session = it->second;
                auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - session->lastHeartbeatTime).count();
                if (diff > 15) // 15 seconds timeout
                {
                    std::cout << "[Server] Client timeout, removing: " << GetClientInfo(session) << std::endl;
                    closesocket(session->socket);
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

void Server::HandleClientPacket(std::shared_ptr<ClientSession> session)
{
    PacketHeader header;
    if (!RecvFixedSize(session->socket, &header, sizeof(header)))
    {
        std::cout << "[Server] Client disconnected (recv header failed): " << GetClientInfo(session) << std::endl;
        closesocket(session->socket);
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        m_clients.erase(session->socket);
        return;
    }

    if (header.magic != PACKET_MAGIC)
    {
        std::cout << "[Server] Invalid magic from client: " << GetClientInfo(session) << std::endl;
        closesocket(session->socket);
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        m_clients.erase(session->socket);
        return;
    }

    std::vector<char> body;
    if (header.body_len > 0)
    {
        body.resize(header.body_len);
        if (!RecvFixedSize(session->socket, body.data(), header.body_len))
        {
            std::cout << "[Server] Client disconnected (recv body failed): " << GetClientInfo(session) << std::endl;
            closesocket(session->socket);
            std::lock_guard<std::mutex> lock(m_clientsMutex);
            m_clients.erase(session->socket);
            return;
        }
    }

    // Refresh heartbeat
    session->lastHeartbeatTime = std::chrono::steady_clock::now();

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
        std::cout << "[Server] Unknown command: " << header.cmd << std::endl;
        break;
    }
}

void Server::OnLoginReq(std::shared_ptr<ClientSession> session, const std::vector<char>& body)
{
    // Parse username|password
    std::string data(body.begin(), body.end());
    size_t delimiter = data.find('|');
    if (delimiter != std::string::npos)
    {
        std::string username = data.substr(0, delimiter);
        std::string password = data.substr(delimiter + 1);

        // Simple Validation
        if (!username.empty() && !password.empty())
        {
            session->username = username;
            session->isAuthenticated = true;
            std::cout << "[Server] User " << username << " logged in." << std::endl;

            // Send LoginRes (Success)
            std::string msg = "Success";
            SendPacket(session->socket, static_cast<uint16_t>(CommandType::LoginRes), msg.c_str(), static_cast<uint32_t>(msg.size()));
        }
        else
        {
            // Fail
            std::string msg = "Fail: Invalid format";
            SendPacket(session->socket, static_cast<uint16_t>(CommandType::LoginRes), msg.c_str(), static_cast<uint32_t>(msg.size()));
        }
    }
    else
    {
         std::string msg = "Fail: Format error";
         SendPacket(session->socket, static_cast<uint16_t>(CommandType::LoginRes), msg.c_str(), static_cast<uint32_t>(msg.size()));
    }
}

void Server::OnHeartbeatReq(std::shared_ptr<ClientSession> session)
{
    // Respond with HeartbeatRes
    SendPacket(session->socket, static_cast<uint16_t>(CommandType::HeartbeatRes));
    // std::cout << "[Server] Heartbeat from " << session->socket << std::endl;
}

void Server::OnMessageReq(std::shared_ptr<ClientSession> session, const std::vector<char>& body)
{
    if (!session->isAuthenticated)
    {
        std::cout << "[Server] Ignored message from unauthenticated client." << std::endl;
        return;
    }

    std::string msg(body.begin(), body.end());
    std::cout << "[Server] Chat from " << session->username << ": " << msg << std::endl;

    // Broadcast to others
    std::string broadcastMsg = "[" + session->username + "]: " + msg;
    BroadcastMessage(broadcastMsg, session->socket);
}

void Server::BroadcastMessage(const std::string& msg, SOCKET excludeSock)
{
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    for (auto& pair : m_clients)
    {
        if (pair.first != excludeSock && pair.second->isAuthenticated)
        {
            SendPacket(pair.first, static_cast<uint16_t>(CommandType::MessageRes), msg.c_str(), static_cast<uint32_t>(msg.size()));
        }
    }
}

bool Server::SendPacket(SOCKET sock, uint16_t cmd, const void* data, uint32_t len)
{
    if (sock == INVALID_SOCKET) return false;

    std::vector<char> buffer(sizeof(PacketHeader) + len);
    PacketHeader* header = reinterpret_cast<PacketHeader*>(buffer.data());
    
    header->magic = PACKET_MAGIC;
    header->version = PACKET_VERSION;
    header->cmd = cmd;
    header->seq = 0;
    header->body_len = len;

    if (len > 0 && data != nullptr)
    {
        memcpy(buffer.data() + sizeof(PacketHeader), data, len);
    }

    int totalSent = 0;
    int totalSize = static_cast<int>(buffer.size());
    const char* bufPtr = buffer.data();

    while (totalSent < totalSize)
    {
        int sent = send(sock, bufPtr + totalSent, totalSize - totalSent, 0);
        if (sent == SOCKET_ERROR)
        {
            return false;
        }
        totalSent += sent;
    }

    return true;
}

bool Server::RecvFixedSize(SOCKET sock, void* buf, int len)
{
    int totalRecv = 0;
    char* bufPtr = (char*)buf;

    while (totalRecv < len)
    {
        int ret = recv(sock, bufPtr + totalRecv, len - totalRecv, 0);
        if (ret > 0)
        {
            totalRecv += ret;
        }
        else // 0 or -1
        {
            return false;
        }
    }
    return true;
}

std::string Server::GetClientInfo(const std::shared_ptr<ClientSession>& session)
{
    if (!session) return "Unknown";

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &session->addr.sin_addr, ipStr, INET_ADDRSTRLEN);
    
    std::stringstream ss;
    ss << ipStr << ":" << ntohs(session->addr.sin_port);
    
    if (session->isAuthenticated && !session->username.empty())
    {
        ss << " (User: " << session->username << ")";
    }
    
    return ss.str();
}
