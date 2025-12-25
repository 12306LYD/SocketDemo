#ifndef DATA_DEFINE_HEADER_H
#define DATA_DEFINE_HEADER_H

#include <winsock2.h>
#include <windows.h>
#include <string>
#include <iostream>
#include <cstdint>
#include <vector>



// 确保结构体1字节对齐，防止不同编译器/平台产生不同的 Padding
#pragma pack(push, 1)


const uint16_t PACKET_MAGIC = 0xABCD;
const uint16_t PACKET_VERSION = 0x100;

const uint32_t MAX_PACKET_SIZE = 10 * 1024 * 1024;

// 最大包体长度限制 (10MB)，防止非法大包耗尽内存
const uint64_t MAX_PACKET_BODY_SIZE = 10 * 1024 * 1024;


//客户端和服务端通讯的消息类型定义
enum class CommandType : uint16_t 
{
    // 心跳
    HeartbeatReq = 0x0001, // 客户端 -> 服务器
    HeartbeatRes = 0x0002, // 服务器 -> 客户端

    // 登录
    LoginReq = 0x0003, // 客户端 -> 服务器
    LoginRes = 0x0004, // 服务器 -> 客户端

    // 聊天消息
    MessageReq = 0x0005, // 客户端 -> 服务器 (我发给服务器)
    MessageRes = 0x0006, // 服务器 -> 客户端 (服务器回我结果，或推送给我)

};

// 协议包头结构体
// 用于描述数据包的基础信息，位于每个数据包的最前端
// 注意：网络传输时必须使用网络字节序 (Big-Endian)
typedef struct PacketHeader
{
    uint16_t magic;      // 0xABCD
    uint16_t version;    // 0x0100
    uint16_t cmd;        // 命令字
    uint16_t seq;        // 序列号
    uint64_t body_len;   // 包体长度
} PacketHeader;

#pragma pack(pop)



//客户端和服务器通讯的数据类型
struct NetPacket {
    PacketHeader header;   //消息头
    void* body;            //消息体  消息体的大小由header.body_len 确定
};


//描述客户端的链接状态
enum class ClientState {
    Disconnected,   // [已断开]: 初始状态或连接丢失，网络线程会尝试重连
    Connecting,     // [连接中]: 正在进行 TCP 三次握手
    Connected,      // [已连接]: TCP 物理连接建立成功，但尚未进行业务认证
    Authenticating, // [认证中]: 已发送登录请求 (LoginReq)，正在等待服务器响应
    Authenticated   // [已认证]: 登录成功，可以正常收发业务数据和心跳
};

// 辅助函数：64位网络字节序转换 (避免与系统 htonll 冲突，使用自定义名称)
inline uint64_t HostToNetwork64(uint64_t val)
{
    static const int num = 42;
    if (*reinterpret_cast<const char*>(&num) == num)
    {
        // 小端序机器 (Intel/AMD)，需要转换
        return ((uint64_t)htonl((uint32_t)val)) << 32 | htonl((uint32_t)(val >> 32));
    }
    // 大端序机器，不需要转换
    return val;
}

inline uint64_t NetworkToHost64(uint64_t val)
{
    return HostToNetwork64(val);
}





#endif

