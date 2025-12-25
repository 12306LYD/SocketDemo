#ifndef SOCKET_SERVER_HEADER_H
#define SOCKET_SERVER_HEADER_H

#include "DataDefine.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <mutex>
#include <vector>
#include <map>
#include <atomic>
#include <memory>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")

// 描述一个连接到服务器的客户端会话
struct ClientSession
{
    SOCKET socket;
    sockaddr_in addr;
    bool isAuthenticated; // 是否已登录
    std::chrono::steady_clock::time_point lastHeartbeatTime; // 最后一次心跳时间
    std::string username;
    
    // 接收缓冲区 (每个客户端独立)
    std::vector<char> recvBuffer;

    // 发送缓冲区
    std::vector<char> sendBuffer;
    std::mutex sendMutex;

    ClientSession() 
        : socket(INVALID_SOCKET)
        , isAuthenticated(false)
        , lastHeartbeatTime(std::chrono::steady_clock::now())
    {}
};

class Server
{
public:
    Server();
    virtual ~Server();

    // 启动服务器
    bool Start(int port);

    // 停止服务器
    void Stop();

private:
    // 网络线程主函数 (使用 Select 模型处理多路复用)
    void NetworkThreadFunc();
    
    // 设置 Socket 为非阻塞模式
    bool SetNonBlocking(SOCKET sock, bool nonBlocking);

    // 发送数据包给指定客户端 (追加到发送缓冲区)
    bool SendPacket(std::shared_ptr<ClientSession> session, uint16_t cmd, const void* data = nullptr, uint64_t len = 0);
    // 旧的 SendPacket (通过 socket 发送) 已废弃，为了兼容性保留重载，但内部会调用上面的版本
    bool SendPacket(SOCKET sock, uint16_t cmd, const void* data = nullptr, uint64_t len = 0);

    // 尝试发送 Session 发送缓冲区的数据
    void SendFromBuffer(std::shared_ptr<ClientSession> session);

    // 非阻塞接收数据并存入 Session 缓冲区
    void RecvToBuffer(std::shared_ptr<ClientSession> session);

    // 处理 Session 缓冲区中的数据 (切包)
    void ProcessBuffer(std::shared_ptr<ClientSession> session);

    // 处理单个数据包
    void HandlePacket(std::shared_ptr<ClientSession> session, const PacketHeader& header, const std::vector<char>& body);

    // 业务处理函数
    void OnLoginReq(std::shared_ptr<ClientSession> session, const std::vector<char>& body);
    void OnHeartbeatReq(std::shared_ptr<ClientSession> session);
    void OnMessageReq(std::shared_ptr<ClientSession> session, const std::vector<char>& body);

    // 广播消息给所有已登录用户
    void BroadcastMessage(const std::string& msg, SOCKET excludeSock = INVALID_SOCKET);

    // 获取客户端描述信息 (IP:Port [Username])
    std::string GetClientInfo(const std::shared_ptr<ClientSession>& session);

private:
    SOCKET m_listenSocket;
    int m_port;
    std::atomic<bool> m_running;
    std::thread m_thread;

    // 管理所有客户端连接
    // 使用 map <SOCKET, Session> 方便查找
    std::map<SOCKET, std::shared_ptr<ClientSession>> m_clients;
    std::mutex m_clientsMutex; // 保护 m_clients 的并发访问
};














#endif
