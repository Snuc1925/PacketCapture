#pragma once
#include "IClientConnection.hpp"
#include <openssl/ssl.h>

class TlsClient : public IClientConnection {
private:
    int fd_;
    SSL* ssl_;
public:
    TlsClient(int fd, SSL* ssl);
    ~TlsClient() override;

    int get_fd() const override;
    ssize_t read(char* buffer, size_t size) override;
    void close_connection() override;
    std::string get_type() const override;
};
