
import socket
import struct
import time
import threading

# 定义 PacketHeader 结构 (与 C++ 对齐)
# magic(2) + version(2) + cmd(2) + seq(2) + body_len(8) = 16 字节
# 使用网络字节序 (!)
HEADER_FORMAT = "!HHHHQ"
PACKET_MAGIC = 0xABCD
PACKET_VERSION = 0x100

def create_packet(cmd, body_bytes):
    body_len = len(body_bytes)
    header = struct.pack(HEADER_FORMAT, PACKET_MAGIC, PACKET_VERSION, cmd, 0, body_len)
    return header + body_bytes

def run_jittery_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 8081))
    server.listen(1)
    print("[Python Server] Listening on 8081...")

    while True:
        client, addr = server.accept()
        print(f"[Python Server] Client connected: {addr}")

        try:
            # 1. 接收登录请求 (假设客户端一上来就发登录)
            # 先收个 Header
            header_data = client.recv(16)
            if not header_data: break
            magic, ver, cmd, seq, body_len = struct.unpack(HEADER_FORMAT, header_data)
            print(f"[Python Server] Recv Header: cmd={cmd}, len={body_len}")
            
            if body_len > 0:
                body = client.recv(body_len)
                print(f"[Python Server] Recv Body: {body.decode(errors='ignore')}")

            # 2. 发送登录成功响应 (LoginRes = 0x0004)
            # 故意制造抖动：把包拆成两半发送
            resp_body = b"Success"
            full_packet = create_packet(0x0004, resp_body)
            
            # 先发前 5 个字节 (Header 的一部分)
            print("[Python Server] Sending partial packet (Part 1)...")
            client.send(full_packet[:5])
            
            # 模拟网络卡顿 2 秒
            time.sleep(2)
            
            # 再发剩下的
            print("[Python Server] Sending partial packet (Part 2)...")
            client.send(full_packet[5:])
            
            print("[Python Server] Full packet sent.")

            # 保持连接一会儿
            time.sleep(5)
            
        except Exception as e:
            print(f"[Python Server] Error: {e}")
        finally:
            client.close()
            print("[Python Server] Client closed.")

if __name__ == "__main__":
    run_jittery_server()
