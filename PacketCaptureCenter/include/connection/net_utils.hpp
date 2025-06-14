#pragma once
#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX* create_ssl_context();
void configure_ssl_context(SSL_CTX* ctx);
int create_listening_socket(int port);