#include "connection/PlainTcpConnection.hpp"

PlainTcpConnection::~PlainTcpConnection() {
    disconnect();
}

bool PlainTcpConnection::connect(const std::string& ip, int port) {
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0) {
        perror("Socket creation failed");
        return false;
    }

    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        return false;
    }

    if (::connect(sockfd_, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connect failed");
        close(sockfd_);
        sockfd_ = -1;
        return false;
    }

    std::cout << "Connection strategy: Plain TCP" << std::endl;
    return true;
}

bool PlainTcpConnection::send_data(const void* buffer, size_t length) {
    if (sockfd_ < 0) return false;
    const char* ptr = static_cast<const char*>(buffer);

    while (length > 0) {
        ssize_t sent = send(sockfd_, ptr, length, MSG_NOSIGNAL);
        if (sent <= 0) {
            if (sent < 0 && errno == EINTR) continue;
            std::cerr << "send_data error: " << strerror(errno) << std::endl;
            return false;
        }
        ptr += sent;
        length -= sent;
    }

    return true;
}

void PlainTcpConnection::disconnect() {
    if (sockfd_ != -1) {
        close(sockfd_);
        sockfd_ = -1;
    }
}
