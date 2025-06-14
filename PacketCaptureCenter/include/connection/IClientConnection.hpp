#pragma once
#include <string>
#include <unistd.h>

class IClientConnection {
public:
    virtual ~IClientConnection() = default;
    virtual int get_fd() const = 0;
    virtual ssize_t read(char* buffer, size_t size) = 0;
    virtual void close_connection() = 0;
    virtual std::string get_type() const = 0;
};
