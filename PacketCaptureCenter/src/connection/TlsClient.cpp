#include "connection/TlsClient.hpp"
#include <unistd.h>

TlsClient::TlsClient(int fd, SSL* ssl) : fd_(fd), ssl_(ssl) {}

TlsClient::~TlsClient() {
    close_connection();
}

int TlsClient::get_fd() const {
    return fd_;
}

ssize_t TlsClient::read(char* buffer, size_t size) {
    return SSL_read(ssl_, buffer, size);
}

void TlsClient::close_connection() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (fd_ != -1) {
        close(fd_);
        fd_ = -1;
    }
}

std::string TlsClient::get_type() const {
    return "TLS";
}
