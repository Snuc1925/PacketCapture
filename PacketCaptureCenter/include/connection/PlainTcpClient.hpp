#pragma once
#include "IClientConnection.hpp"

class PlainTcpClient : public IClientConnection {
private:
    int fd_;
public:
    explicit PlainTcpClient(int fd);
    ~PlainTcpClient() override;

    int get_fd() const override;
    ssize_t read(char* buffer, size_t size) override;
    void close_connection() override;
    std::string get_type() const override;
};
