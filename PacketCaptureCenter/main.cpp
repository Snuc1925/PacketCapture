#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>

int main() {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket failed");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8888);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return 1;
    }

    listen(server_sock, 1);
    std::cout << "Waiting for connection from agent...\n";

    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_sock = accept(server_sock, (sockaddr*)&client_addr, &client_len);
    if (client_sock < 0) {
        perror("Accept failed");
        return 1;
    }

    std::cout << "Agent connected.\n";

    while (true) {
        uint32_t len_net;
        int n = recv(client_sock, &len_net, sizeof(len_net), MSG_WAITALL);
        if (n <= 0) break;

        uint32_t len = ntohl(len_net);
        std::vector<char> buffer(len);

        n = recv(client_sock, buffer.data(), len, MSG_WAITALL);
        if (n <= 0) break;

        std::cout << "Received packet of size: " << len << " bytes\n";
        // Optional: Save to file or process packet
    }

    std::cout << "Connection closed.\n";
    close(client_sock);
    close(server_sock);

    return 0;
}
