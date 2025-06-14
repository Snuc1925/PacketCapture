#pragma once
#include <string>
#include "../common/types.hpp" 

std::string generate_pcap_filename(const std::string& ip, uint16_t port);
void save_packets_to_pcap(ClientState& client);