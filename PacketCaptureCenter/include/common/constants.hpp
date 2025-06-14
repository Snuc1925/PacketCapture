#pragma once
#include <cstdint>
#include <cstddef>
#include <sys/select.h> // For FD_SETSIZE

// --- Cấu hình Server ---
namespace AppConfig {
    const int PLAIN_TCP_PORT = 8888;
    const int TLS_PORT = 8889;
    const size_t MAX_BUFFER_SIZE_PER_CLIENT = 1024 * 1024 * 1024; // 1 GB
    const int MAX_CLIENTS = FD_SETSIZE;

    // --- Cấu trúc thông điệp ---
    const uint8_t FLAG_COMPRESSED_ZSTD = (1 << 0);
    const uint8_t FLAG_COMPRESSED_ZLIB = (1 << 1);

    const size_t METADATA_SIZE_LINKTYPE = sizeof(uint32_t);
    const size_t BLOCK_HEADER_SIZE = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t);
    const size_t PCAP_FIELDS_HEADER_SIZE = sizeof(uint32_t) * 4;
}