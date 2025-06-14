#include "logging/send_log.hpp"

void SendLogger::add_entry(const SendLogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    logs_.push_back(entry);
}

void SendLogger::save_to_file(const std::string& filename) {
    std::ofstream log_file(filename);
    if (!log_file.is_open()) {
        std::cerr << "Failed to open log file: " << filename << std::endl;
        return;
    }

    log_file << "packet_count,original_size,compressed_size,avg_waiting_time_us,"
                "processing_duration_us,processing_to_send_duration_us,avg_delay_per_packet_us\n";

    log_file << std::fixed << std::setprecision(3);

    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : logs_) {
        log_file << entry.packet_count << ","
                 << entry.original_size << ","
                 << entry.compressed_size << ","
                 << entry.avg_waiting_time_us << ","
                 << entry.processing_duration_us << ","
                 << entry.processing_to_send_duration_us << ","
                 << entry.avg_delay_per_packet_us << "\n";
    }
}
