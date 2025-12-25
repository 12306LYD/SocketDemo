#ifndef DATA_DEFINE_HEADER_H
#define DATA_DEFINE_HEADER_H

#include<windows.h>
#include<string>
#include <iostream>

#pragma pack(push, 1)


const uint16_t PACKET_MAGIC = 0xABCD;
const uint16_t PACKET_VERSION = 0x100;

const uint32_t MAX_PACKET_SIZE = 10 * 1024 * 1024;


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
typedef struct _PacketHeader
{
    // 默认构造函数，初始化所有字段为 0
    _PacketHeader()
    {
        magic = 0;
        version = 0;
        cmd = 0;
        seq = 0;
        body_len = 0;
    }
    uint16_t magic;      // 魔数 (2字节): 固定值 0xABCD，用于校验数据包合法性，防止协议错乱
    uint16_t version;    // 版本号 (2字节): 协议版本，用于兼容性处理 (如 Ver 1, Ver 2)
    uint16_t cmd;        // 命令字 (2字节): 标识当前包的业务类型 (如 0x0003=登录请求)
    uint16_t seq;        // 序列号 (2字节): 用于请求/响应匹配，异步通信中标记是哪一次请求
    uint32_t body_len;   // 包体长度 (4字节): 标识 Header 之后跟随的数据长度，用于处理 TCP 粘包
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







#endif

