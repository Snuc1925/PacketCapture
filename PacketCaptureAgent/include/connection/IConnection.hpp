#pragma once

#include <string>

class IConnection {
public:
    virtual ~IConnection() = default;
    virtual bool connect(const std::string& ip, int port) = 0;
    virtual bool send_data(const void* buffer, size_t length) = 0;
    virtual void disconnect() = 0;
};
