#ifndef SOCKET_SERVER_SSL_HEADER_H
#define SOCKET_SERVER_SSL_HEADER_H

#include "DataDefine.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <mutex>
#include <map>
#include <vector>
#include <memory>
#include <chrono>

#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Crypt32.lib")

struct ClientSessionSsl
{
    SOCKET socket;
    sockaddr_in addr;
    
    // SSL 相关
    SSL* ssl;
    bool isHandshakeComplete; // 握手是否完成

    bool isAuthenticated; 
    std::chrono::steady_clock::time_point lastHeartbeatTime; 
    std::string username;
    
    // 接收缓冲区
    std::vector<char> recvBuffer;

    // 发送缓冲区
    std::vector<char> sendBuffer;
    std::mutex sendMutex;

    ClientSessionSsl() 
        : socket(INVALID_SOCKET)
        , ssl(nullptr)
        , isHandshakeComplete(false)
        , isAuthenticated(false)
        , lastHeartbeatTime(std::chrono::steady_clock::now())
    {}
    
    ~ClientSessionSsl() {
        if (ssl) {
            SSL_free(ssl);
            ssl = nullptr;
        }
    }
};

class ServerSsl
{
public:
    ServerSsl();
    virtual ~ServerSsl();

    // 初始化 SSL 上下文 (加载证书)
    bool InitSSL(const std::string& certFile, const std::string& keyFile);

    // 启动服务器
    bool Start(int port);

    // 停止服务器
    void Stop();

private:
    void NetworkThreadFunc();
    bool SetNonBlocking(SOCKET sock, bool nonBlocking);

    // SSL 握手处理
    // 返回值: 0=成功/进行中, -1=失败
    int DoSslHandshake(std::shared_ptr<ClientSessionSsl> session);

    // 发送数据 (追加到 buffer)
    bool SendPacket(std::shared_ptr<ClientSessionSsl> session, uint16_t cmd, const void* data = nullptr, uint64_t len = 0);

    // 实际 SSL_write
    void SendFromBuffer(std::shared_ptr<ClientSessionSsl> session);

    // 实际 SSL_read
    void RecvToBuffer(std::shared_ptr<ClientSessionSsl> session);

    void ProcessBuffer(std::shared_ptr<ClientSessionSsl> session);
    void HandlePacket(std::shared_ptr<ClientSessionSsl> session, const PacketHeader& header, const std::vector<char>& body);

    // 业务
    void OnLoginReq(std::shared_ptr<ClientSessionSsl> session, const std::vector<char>& body);
    void OnHeartbeatReq(std::shared_ptr<ClientSessionSsl> session);
    void OnMessageReq(std::shared_ptr<ClientSessionSsl> session, const std::vector<char>& body);

    std::string GetClientInfo(const std::shared_ptr<ClientSessionSsl>& session);

private:
    SOCKET m_listenSocket;
    std::atomic<bool> m_running;
    std::thread m_thread;

    // SSL 上下文
    SSL_CTX* m_ctx;

    // 客户端管理
    std::map<SOCKET, std::shared_ptr<ClientSessionSsl>> m_clients;
    std::mutex m_clientsMutex;
};

#endif
