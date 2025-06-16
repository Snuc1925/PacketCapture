#pragma once
#include <vector>
#include <string>
#include <memory>
#include <pcap/pcap.h>
#include <chrono>
#include "../connection/IClientConnection.hpp" // Giả sử interface ở đây
#include "../decompressor/IDecompressor.hpp" // Giả sử interface ở đây

struct PacketInfo {
    pcap_pkthdr header;
    std::vector<unsigned char> data;
};

struct LatencyInfo {
    size_t block_id = 0; // ID của block, ví dụ: thứ tự xử lý
    uint32_t payload_size = 0; // Kích thước payload nhận được
    uint32_t original_size = 0; // Kích thước gốc sau khi giải nén
    long long header_processing_time_us = 0; // Thời gian xử lý header (micro giây)
    long long decompression_time_us = 0; // Thời gian giải nén (micro giây)
    long long total_block_processing_time_us = 0; // Tổng thời gian từ khi bắt đầu xử lý header đến khi xong payload
};

struct ClientState {
    std::unique_ptr<IClientConnection> connection;
    std::string ip_address;
    uint16_t port;
    std::vector<PacketInfo> buffered_packets;
    size_t current_total_bytes;
    size_t total_bytes;
    long long current_total_packets;
    long long total_packets;
    std::vector<char> recv_buffer;
    std::unique_ptr<IDecompressor> decompressor;

    std::vector<LatencyInfo> latency_log; // Vector để lưu log độ trễ
    std::chrono::steady_clock::time_point current_block_start_time; // Thời điểm bắt đầu xử lý block hiện tại

    enum class ReceiveFSM {
        AWAITING_METADATA_LINKTYPE,
        AWAITING_BLOCK_HEADER,
        AWAITING_BLOCK_PAYLOAD
    };
    ReceiveFSM current_fsm_state;
    
    int datalink_type;

    uint8_t expected_flags;
    uint32_t expected_original_size;
    uint32_t expected_payload_size;
    std::vector<char> decompressed_buffer;

    ClientState() = delete; 

    ClientState(std::unique_ptr<IClientConnection> conn, std::string ip, uint16_t p);
};