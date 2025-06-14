#pragma once

#include "IConnection.hpp"
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>

class PlainTcpConnection : public IConnection {
private:
    int sockfd_ = -1;

public:
    ~PlainTcpConnection() override;
    bool connect(const std::string& ip, int port) override;
    bool send_data(const void* buffer, size_t length) override;
    void disconnect() override;
};
