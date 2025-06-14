#include "logging/latency_logger.hpp"
#include <fstream>
#include <iostream>

// Định nghĩa thực sự của biến toàn cục
std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> latency_log_entries;

void flush_latency_log_to_csv(const std::string& filename) {
    std::ofstream ofs(filename);
    std::cout << "Open File successfully\n";
    ofs << "send_timestamp_us,recv_timestamp_us,latency_us\n";
    for (const auto& [send_us, recv_us, latency_us] : latency_log_entries) {
        ofs << send_us << "," << recv_us << "," << latency_us << "\n";
    }    
}