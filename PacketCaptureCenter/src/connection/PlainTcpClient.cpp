#include "connection/PlainTcpClient.hpp"
#include <sys/socket.h>
#include <unistd.h>

PlainTcpClient::PlainTcpClient(int fd) : fd_(fd) {}

PlainTcpClient::~PlainTcpClient() {
    close_connection();
}

int PlainTcpClient::get_fd() const {
    return fd_;
}

ssize_t PlainTcpClient::read(char* buffer, size_t size) {
    return recv(fd_, buffer, size, 0);
}

void PlainTcpClient::close_connection() {
    if (fd_ != -1) {
        close(fd_);
        fd_ = -1;
    }
}

std::string PlainTcpClient::get_type() const {
    return "Plain TCP";
}
