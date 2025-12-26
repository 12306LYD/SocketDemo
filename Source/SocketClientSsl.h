#ifndef SOCKET_CLIENT_SSL_HEADER_H
#define SOCKET_CLIENT_SSL_HEADER_H

#include "DataDefine.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Crypt32.lib")

class ClientSsl
{
public:
    ClientSsl();
    virtual ~ClientSsl();

    // 设置登录信息
    void SetToken(std::string Name, std::string PassWord, std::string DeviceId);

    // 启动客户端
    void Start(const std::string& ip, int port);

    // 停止
    void Stop();

    // 发送消息 (业务层调用)
    bool SendChatMessage(const std::string& msg);

private:
    void NetworkThreadFunc();
    bool ConnectToServer();
    bool SetNonBlocking(bool nonBlocking);
    void CloseSocket();

    // SSL 握手
    int DoSslHandshake();

    bool SendPacket(uint16_t cmd, const void* data = nullptr, uint64_t len = 0);
    void SendFromBuffer();
    void RecvToBuffer();
    void ProcessBuffer();
    void HandlePacket(const PacketHeader& header, const std::vector<char>& body);

    // 业务
    void OnLoginRes(const std::vector<char>& body);
    void OnHeartbeatRes();
    void OnMessageRes(const std::vector<char>& body);

private:
    SOCKET m_socket;
    std::string m_serverIp;
    int m_serverPort;

    // SSL 相关
    SSL_CTX* m_ctx;
    SSL* m_ssl;
    bool m_isHandshakeComplete;

    std::atomic<ClientState> m_state;
    std::atomic<bool> m_running;
    std::thread m_thread;

    std::vector<char> m_recvBuffer;
    
    std::vector<char> m_sendBuffer;
    std::mutex m_sendBufferMutex;

    ULONGLONG m_lastHeartbeatReqTime;
    ULONGLONG m_lastPacketRecvTime;

    std::string m_username;
    std::string m_password;
    std::string m_deviceId;
};

#endif

