#include "utils/config_utils.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

std::string trim(const std::string& s) {
    size_t first = s.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return s;
    size_t last = s.find_last_not_of(" \t\n\r");
    return s.substr(first, (last - first + 1));
}

bool parse_config(const std::string& filename, AppConfig& config) {
    std::ifstream config_file(filename);
    if (!config_file.is_open()) {
        std::cerr << "Error: Could not open config file: " << filename << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(config_file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        std::stringstream ss(line);
        std::string key, value;
        if (std::getline(ss, key, '=')) {
            std::getline(ss, value);
            key = trim(key);
            value = trim(value);

            if (key == "server_ip") config.server_ip = value;
            else if (key == "server_port") config.server_port = std::stoi(value);
            else if (key == "pcap_buffer_size_mb") config.pcap_buffer_size_mb = std::stoi(value);
            else if (key == "batch_packet_count") config.batch_packet_count = std::stoi(value);
            else if (key == "max_queue_blocks") config.max_queue_blocks = std::stoul(value);
            else if (key == "send_buffer_size_kb") config.send_buffer_size_kb = std::stoi(value);
            else if (key == "encrypt") {
                std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                config.encrypt = (value == "true");
            }
            else if (key == "interfaces") {
                std::stringstream val_ss(value);
                std::string interface;
                while (std::getline(val_ss, interface, ',')) {
                    interface = trim(interface);
                    if (!interface.empty()) config.interfaces.push_back(interface);
                }
            } else if (key == "compression") {
                std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                if (value == "zstd") config.compression = CompressionType::ZSTD;
                else if (value == "zlib") config.compression = CompressionType::ZLIB;
                else config.compression = CompressionType::NONE;
            }        
        }
    }

    std::cout << "Loaded configuration:\n";
    std::cout << "  server_ip            = " << config.server_ip << "\n";
    std::cout << "  server_port          = " << config.server_port << "\n";
    std::cout << "  compressed           = " << config.compressed << "\n";
    std::cout << "  pcap_buffer_size_mb  = " << config.pcap_buffer_size_mb << "\n";
    std::cout << "  batch_packet_count   = " << config.batch_packet_count << "\n";
    std::cout << "  max_queue_blocks     = " << config.max_queue_blocks << "\n";
    std::cout << "  send_buffer_size_kb  = " << config.send_buffer_size_kb << "\n";

    return !config.interfaces.empty();
}

bool parse_filter_config(const std::string& filename, TrafficFilter& filter) {
    std::ifstream filter_file(filename);
    if (!filter_file.is_open()) {
        std::cout << "Info: Filter file '" << filename << "' not found. Proceeding without traffic filter." << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(filter_file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        std::stringstream ss(line);
        std::string key, value;
        if (std::getline(ss, key, '=')) {
            std::getline(ss, value);
            key = trim(key);
            value = trim(value);

            if (key == "ip_src") filter.ip_src = value;
            else if (key == "ip_dst") filter.ip_dst = value;
            else if (key == "port") filter.port = value;
            else if (key == "protocol") filter.protocol = value;
        }
    }
    return true;
}

std::string build_bpf_string(const TrafficFilter& filter) {
    std::vector<std::string> parts;
    if (!filter.ip_src.empty()) parts.push_back("src host " + filter.ip_src);
    if (!filter.ip_dst.empty()) parts.push_back("dst host " + filter.ip_dst);
    if (!filter.port.empty()) parts.push_back("port " + filter.port);
    if (!filter.protocol.empty()) parts.push_back(filter.protocol);

    if (parts.empty()) return "";

    std::string bpf_string = parts[0];
    for (size_t i = 1; i < parts.size(); ++i) {
        bpf_string += " and " + parts[i];
    }
    return bpf_string;
}
