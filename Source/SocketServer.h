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

    // 发送数据包给指定客户端
    bool SendPacket(SOCKET sock, uint16_t cmd, const void* data = nullptr, uint32_t len = 0);

    // 接收指定长度的数据
    bool RecvFixedSize(SOCKET sock, void* buf, int len);

    // 处理单个客户端的消息
    void HandleClientPacket(std::shared_ptr<ClientSession> session);

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
