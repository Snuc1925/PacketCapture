#pragma once
#include <vector>
#include <tuple>
#include <cstdint>
#include <string>

// Khai báo biến là "extern" để các file khác biết nó tồn tại
extern std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> latency_log_entries;

// Khai báo hàm
void flush_latency_log_to_csv(const std::string& filename = "/home/maimanh/Downloads/Code/VDT/Project/test/center/latency_log.csv");