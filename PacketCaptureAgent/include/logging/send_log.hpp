#pragma once

#include <vector>
#include <mutex>
#include <string>
#include <fstream>
#include <iostream>
#include <iomanip>

struct SendLogEntry {
    size_t packet_count;
    size_t original_size;
    size_t compressed_size;
    uint64_t avg_waiting_time_us;
    uint64_t processing_duration_us;
    uint64_t processing_to_send_duration_us;
    double avg_delay_per_packet_us;
};

class SendLogger {
public:
    void add_entry(const SendLogEntry& entry);
    void save_to_file(const std::string& filename);

private:
    std::vector<SendLogEntry> logs_;
    std::mutex mutex_;
};
