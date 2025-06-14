#include "pcap/LivePcapStreamer.hpp"
#include <iostream>

LivePcapStreamer::~LivePcapStreamer() { close_stream(); }

bool LivePcapStreamer::open_stream(const std::string& pipe_path, int datalink_type) {
    // 1. Tạo một pcap handle "chết" (không dùng để bắt gói tin)
    // Nó chỉ là một context cần thiết cho việc ghi file.
    pcap_handle_ = pcap_open_dead(datalink_type, 65535 /* snaplen */);
    if (!pcap_handle_) {
        std::cerr << "LivePcapStreamer Error: pcap_open_dead failed." << std::endl;
        return false;
    }

    // 2. Mở dumper để ghi vào pipe. Libpcap sẽ tự động ghi Global Header.
    // Hàm này sẽ tự gọi fopen(pipe_path, "wb") bên trong.
    dumper_ = pcap_dump_open(pcap_handle_, pipe_path.c_str());
    if (!dumper_) {
        std::cerr << "LivePcapStreamer Error: pcap_dump_open failed: " << pcap_geterr(pcap_handle_) << std::endl;
        std::cerr << "Hint: Did you run 'mkfifo " << pipe_path << "' and run Wireshark first?" << std::endl;
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    std::cout << "Live Stream: Pcap dumper successfully opened on " << pipe_path << std::endl;
    return true;
}

void LivePcapStreamer::write_packet(const pcap_pkthdr* header, const unsigned char* data) {
    if (!dumper_) {
        return;
    }
    // Để libpcap lo tất cả mọi thứ: endianness, struct size, ...
    pcap_dump(reinterpret_cast<u_char*>(dumper_), header, data);
}

void LivePcapStreamer::close_stream() {
    if (dumper_) {
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
    }
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
    std::cout << "Live Stream: Closed." << std::endl;
}

bool LivePcapStreamer::is_open() const {
    return dumper_ != nullptr;
}