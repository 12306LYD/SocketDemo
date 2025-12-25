#ifndef SOCKET_CLIENT_HEADER_H
#define SOCKET_CLIENT_HEADER_H

#include"DataDefine.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <functional>
#include <condition_variable>
#include <vector>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")

class Client
{
public:
	Client();
	virtual ~Client();

    void SetToken(std::string Name,std::string PassWord,std::string DeviceId);

    // 启动客户端
    void Start(const std::string& ip, int port);
    
    // 停止客户端
    void Stop();

    // 发送聊天消息 (只有在 Authenticated 状态下才允许)
    bool SendChatMessage(const std::string& msg);

private:
    // 网络线程主函数
    void NetworkThreadFunc();

    // 尝试连接服务器
    bool ConnectToServer();
    
    // 关闭 Socket
    void CloseSocket();

    // 发送协议包
    bool SendPacket(uint16_t cmd, const void* data = nullptr, uint32_t len = 0);
    
    // 接收指定长度的数据 (阻塞直到收满或出错)
    bool RecvFixedSize(void* buf, int len);

    // 接收并处理一个完整的数据包
    void ReceiveAndProcessPacket();

    // 处理接收到的包
    void HandlePacket(const PacketHeader& header, const std::vector<char>& body);

    // 业务处理
    void OnLoginRes(const std::vector<char>& body);
    void OnHeartbeatRes();
    void OnMessageRes(const std::vector<char>& body);

private:
    SOCKET m_socket;
    std::string m_serverIp;
    int m_serverPort;

    std::atomic<ClientState> m_state;
    std::atomic<bool> m_running;

    std::thread m_thread;
    std::mutex m_socketMutex; // 用于保护 Socket 的并发写入 (发送)

    // 心跳相关
    ULONGLONG m_lastHeartbeatReqTime; // 上次发送心跳的时间 (GetTickCount64)
    ULONGLONG m_lastPacketRecvTime;   // 上次收到包的时间 (用于超时判定)

    // 登录相关信息 (可以硬编码或传入)
    std::string m_username;
    std::string m_password;
    std::string m_deviceId;
};




#endif
