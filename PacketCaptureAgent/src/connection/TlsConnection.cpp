#include "connection/TlsConnection.hpp"

void TlsConnection::init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void TlsConnection::cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* TlsConnection::create_context() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

TlsConnection::TlsConnection() {
    init_openssl();
    ctx_ = create_context();
}

TlsConnection::~TlsConnection() {
    disconnect();
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
    cleanup_openssl();
}

bool TlsConnection::connect(const std::string& ip, int port) {
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0) {
        perror("Socket creation failed");
        return false;
    }

    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr);

    if (::connect(sockfd_, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("TCP connect failed for TLS");
        return false;
    }

    ssl_ = SSL_new(ctx_);
    SSL_set_fd(ssl_, sockfd_);

    if (SSL_connect(ssl_) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    std::cout << "Connection strategy: TLS (OpenSSL)" << std::endl;
    return true;
}

bool TlsConnection::send_data(const void* buffer, size_t length) {
    if (!ssl_) return false;

    int bytes_sent = SSL_write(ssl_, buffer, length);
    if (bytes_sent <= 0) {
        int err = SSL_get_error(ssl_, bytes_sent);
        std::cerr << "SSL_write failed with error code: " << err << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}

void TlsConnection::disconnect() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (sockfd_ != -1) {
        close(sockfd_);
        sockfd_ = -1;
    }
}
