
#include "../Source/SocketClient.h"
#include "../Source/SocketServer.h"
#include <iostream>
#include <string>

// 简单封装一个 Server 的启动逻辑
void RunServer() {
    Server server;
    if (server.Start(8080)) {
        std::cout << "Press Enter to stop server..." << std::endl;
        std::cin.get();
        server.Stop();
    }
}

// 简单封装一个 Client 的启动逻辑
void RunClient() {
    Client client;
    client.SetToken("use123","2222","111111");
    client.Start("127.0.0.1", 8080);
    
    std::cout << "Client started. Type 'quit' to exit or any other text to send message." << std::endl;
    
    // 清除缓冲区，避免之前的输入影响
    std::cin.clear();
    // std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 
    
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "quit") break;
        client.SendChatMessage(line);
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
    }

    if (choice == 0)
    {
        std::cout << "Select mode:" << std::endl;
        std::cout << "1. Server" << std::endl;
        std::cout << "2. Client" << std::endl;
        std::cout << "> ";

        std::cin >> choice;
        std::cin.get(); // Consume newline
    }

    if (choice == 1) {
        RunServer();
    } else if (choice == 2) {
        RunClient();
    } else {
        std::cout << "Invalid choice." << std::endl;
    }

    return 0;
}
