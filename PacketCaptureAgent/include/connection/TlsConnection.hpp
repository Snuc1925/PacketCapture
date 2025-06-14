#pragma once

#include "IConnection.hpp"
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>

class TlsConnection : public IConnection {
private:
    int sockfd_ = -1;
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;

    void init_openssl();
    void cleanup_openssl();
    SSL_CTX* create_context();

public:
    TlsConnection();
    ~TlsConnection() override;

    bool connect(const std::string& ip, int port) override;
    bool send_data(const void* buffer, size_t length) override;
    void disconnect() override;
};
