#pragma once
#include <string>
#include <pcap/pcap.h>

class LivePcapStreamer {
private:
    pcap_t* pcap_handle_ = nullptr;
    pcap_dumper_t* dumper_ = nullptr;

public:
    ~LivePcapStreamer();
    bool open_stream(const std::string& pipe_path, int datalink_type);
    void write_packet(const pcap_pkthdr* header, const unsigned char* data);
    void close_stream();
    bool is_open() const;
};