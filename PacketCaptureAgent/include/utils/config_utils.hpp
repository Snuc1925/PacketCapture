#pragma once

#include <string>
#include <vector>

struct AppConfig {
    std::string server_ip = "127.0.0.1";
    int server_port = 8888;
    std::vector<std::string> interfaces;
    int pcap_buffer_size_mb = 32;
    int batch_packet_count = 256;
    size_t max_queue_blocks = 1024;
    int send_buffer_size_kb = 4096;
    bool encrypt = false;
    bool compressed = false;
};

struct TrafficFilter {
    std::string ip_src;
    std::string ip_dst;
    std::string port;
    std::string protocol;
};

// Hàm tiện ích
std::string trim(const std::string& s);
bool parse_config(const std::string& filename, AppConfig& config);
bool parse_filter_config(const std::string& filename, TrafficFilter& filter);
std::string build_bpf_string(const TrafficFilter& filter);
