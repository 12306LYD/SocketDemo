
import socket
import time

def test_connect():
    ip = "127.0.0.1"
    port = 8082
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        print(f"Connecting to {ip}:{port}...")
        s.connect((ip, port))
        print("Connected!")
        s.send(b"Hello")
        s.close()
    except Exception as e:
        print(f"Failed to connect: {e}")

if __name__ == "__main__":
    test_connect()
