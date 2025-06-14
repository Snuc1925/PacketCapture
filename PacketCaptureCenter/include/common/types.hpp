#pragma once
#include <vector>
#include <string>
#include <memory>
#include <pcap/pcap.h>
#include "../connection/IClientConnection.hpp" // Giả sử interface ở đây
#include "../decompressor/IDecompressor.hpp" // Giả sử interface ở đây

struct PacketInfo {
    pcap_pkthdr header;
    std::vector<unsigned char> data;
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