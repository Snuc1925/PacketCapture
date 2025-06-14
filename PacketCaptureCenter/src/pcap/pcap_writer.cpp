#include "pcap/pcap_writer.hpp"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <pcap/pcap.h>

std::string generate_pcap_filename(const std::string& ip, uint16_t port) {
    // ... (dán code của hàm generate_pcap_filename vào đây)
    std::time_t t = std::time(nullptr);
    std::tm tm_struct = *std::localtime(&t);
    std::ostringstream oss;
    oss << ip << "_" << port << "_"
        << std::put_time(&tm_struct, "%Y%m%d_%H%M%S") << ".pcap";
    return oss.str();
}

void save_packets_to_pcap(ClientState& client) {
    if (client.buffered_packets.empty()) {
        return;
    }

    client.total_bytes += client.current_total_bytes;
    client.total_packets += client.current_total_packets;

    std::string filename = generate_pcap_filename(client.ip_address, client.port);
    std::cout << std::fixed << std::setprecision(2); 

    std::cout << "Server: Saving " 
            << static_cast<double>(client.current_total_bytes) / (1024 * 1024) << " MB, "
            << client.current_total_packets << " packets for client "
            << client.ip_address << ":" << client.port << std::endl;

    pcap_t* pcap_handle_write = pcap_open_dead(client.datalink_type, 65535); 
    if (!pcap_handle_write) {
        std::cerr << "Server Error: pcap_open_dead failed for datalink type " << client.datalink_type << std::endl;
        return;
    }
    
    pcap_dumper_t* dumper = pcap_dump_open(pcap_handle_write, filename.c_str());
    if (!dumper) {
        std::cerr << "Server Error: pcap_dump_open failed: " << pcap_geterr(pcap_handle_write) << std::endl;
        pcap_close(pcap_handle_write);
        return;
    }

    for (const auto& pkt_info : client.buffered_packets) {
        pcap_dump(reinterpret_cast<u_char*>(dumper), &pkt_info.header, pkt_info.data.data());
    }

    pcap_dump_close(dumper);    
    // Phần dump đã bị comment, tôi giữ nguyên
    pcap_close(pcap_handle_write);

    std::cout << "Server: Successfully saved " << filename << std::endl;

    client.buffered_packets.clear();
    client.current_total_bytes = 0;
    client.current_total_packets = 0;
}