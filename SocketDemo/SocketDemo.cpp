
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "../Source/SocketServer.h"
#include "../Source/SocketClient.h"
#include "../Source/SocketServerSsl.h"
#include "../Source/SocketClientSsl.h"

// 简单封装一个 Server 的启动逻辑
void RunServer() {
    Server server;
    if (server.Start(8081)) {
        std::cout << "Server started on port 8081. Press Ctrl+C to stop..." << std::endl;
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        server.Stop();
    } else {
        std::cout << "Failed to start server." << std::endl;
    }
}

// 简单封装一个 Client 的启动逻辑
void RunClient() {
    Client client;
    client.SetToken("User123", "123456", "Dev001");
    client.Start("127.0.0.1", 8081);
    
    std::cout << "Client started. Type 'quit' to exit or any other text to send message." << std::endl;
    std::string input;
    while (true) {
        std::getline(std::cin, input);
        if (input == "quit") {
            client.Stop();
            break;
        }
        client.SendChatMessage(input);
    }
}

void RunServerSsl() {
    ServerSsl server;
    // 假设证书文件在当前目录下
    std::string CrtPath = "C:\\Users\\12764\\Desktop\\34\\SocketDemo\\server.crt";
    std::string KeyPath = "C:\\Users\\12764\\Desktop\\34\\SocketDemo\\server.key";
    if (!server.InitSSL(CrtPath.c_str(), KeyPath.c_str())) {
        std::cout << "Failed to init SSL. Make sure server.crt and server.key exist." << std::endl;
        return;
    }

    if (server.Start(8082)) {
        std::cout << "SSL Server started on port 8082. Press Ctrl+C to stop..." << std::endl;
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        server.Stop();
    } else {
        std::cout << "Failed to start SSL server." << std::endl;
    }
}

void RunClientSsl() {
    ClientSsl client;
    client.SetToken("UserSSL", "123456", "Dev001");
    client.Start("127.0.0.1", 8082);
    
    std::cout << "SSL Client started. Type 'quit' to exit or any other text to send message." << std::endl;
    std::string input;
    while (true) {
        std::getline(std::cin, input);
        if (input == "quit") {
            client.Stop();
            break;
        }
        client.SendChatMessage(input);
    }
}

void RunClientSslTest() {
    ClientSsl client;
    client.SetToken("UserSSL", "123456", "Dev001");
    client.Start("127.0.0.1", 8082);
    
    std::cout << "SSL Client Test started..." << std::endl;
    
    // Keep running for 10 seconds
    for (int i = 0; i < 10; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (i == 3) {
            std::cout << "Sending Hello from Test..." << std::endl;
            client.SendChatMessage("Hello from Test");
        }
    }
    client.Stop();
}

int main(int argc, char* argv[]) {
    // 确保控制台支持中文输出
    system("chcp 65001"); 

    int choice = 0;
    if (argc > 1)
    {
        std::string arg = argv[1];
        if (arg == "--server") choice = 1;
        else if (arg == "--client") choice = 2;
        else if (arg == "--server-ssl") choice = 3;
        else if (arg == "--client-ssl") choice = 4;
        else if (arg == "--client-ssl-test") choice = 5;
    }

    if (choice == 0)
    {
        std::cout << "Select mode:" << std::endl;
        std::cout << "1. Server (TCP)" << std::endl;
        std::cout << "2. Client (TCP)" << std::endl;
        std::cout << "3. Server (SSL/TLS)" << std::endl;
        std::cout << "4. Client (SSL/TLS)" << std::endl;
        std::cout << "> ";

        std::cin >> choice;
        std::cin.get(); // Consume newline
    }

    if (choice == 1) {
        RunServer();
    } else if (choice == 2) {
        RunClient();
    } else if (choice == 3) {
        RunServerSsl();
    } else if (choice == 4) {
        RunClientSsl();
    } else if (choice == 5) {
        RunClientSslTest();
    } else {
        std::cout << "Invalid choice." << std::endl;
    }

    return 0;
}
