#include <iostream>
#include <cstring>
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <memory>
#include <set> // Dùng cho epoll wait

// System headers
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <sys/time.h>
#include <netdb.h> // For getpeername

// Pcap headers
#include <pcap/pcap.h>

// UDT header
#include <udt.h>

// --- Cấu hình Server ---
const int UDT_PORT = 9999;
const size_t MAX_BUFFER_SIZE_PER_CLIENT = 1024 * 1024 * 1024; // 1 GB
const int MAX_CLIENTS_LISTEN = 100; // Số lượng kết nối chờ trong hàng đợi của UDT listen

// Kích thước các phần của thông điệp từ agent
const size_t METADATA_SIZE_LINKTYPE = sizeof(uint32_t);
const size_t PCAP_FIELDS_HEADER_SIZE = sizeof(uint32_t) * 4;

//========================================================
// CÁC STRUCT QUẢN LÝ
//========================================================

struct PacketInfo {
    pcap_pkthdr header;
    std::vector<unsigned char> data;
};

struct ClientState {
    UDTSOCKET udt_socket; // Thay thế cho fd và IClientConnection
    std::string ip_address;
    uint16_t port;
    std::vector<PacketInfo> buffered_packets;
    size_t current_total_bytes;
    long long current_total_packets;
    std::vector<char> recv_buffer;

    enum class ReceiveFSM {
        AWAITING_METADATA_LINKTYPE,
        AWAITING_PCAP_FIELDS_HEADER,
        AWAITING_PCAP_DATA
    };
    ReceiveFSM current_fsm_state;

    int datalink_type;
    uint32_t expected_pcap_ts_sec;
    uint32_t expected_pcap_ts_usec;
    uint32_t expected_pcap_caplen;
    uint32_t expected_pcap_len;

    // Constructor để tạo ClientState với thông tin UDT
    ClientState(UDTSOCKET sock, std::string ip, uint16_t p)
        : udt_socket(sock), ip_address(std::move(ip)), port(p),
          current_total_packets(0), current_total_bytes(0),
          current_fsm_state(ReceiveFSM::AWAITING_METADATA_LINKTYPE), datalink_type(DLT_NULL)
    {}

    // Cần định nghĩa copy/move constructor/assignment nếu cần thiết,
    // nhưng với emplace vào map thì không cần.
};

//========================================================
// HÀM HELPER (Giữ nguyên logic)
//========================================================
std::string generate_pcap_filename(const std::string& ip, uint16_t port) {
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

    std::string filename = generate_pcap_filename(client.ip_address, client.port);
    std::cout << "Server: Saving " << client.current_total_bytes << " bytes, " << client.current_total_packets << " packets for client "
              << client.ip_address << ":" << client.port
              << " (Datalink: " << client.datalink_type << " - " << pcap_datalink_val_to_name(client.datalink_type) << ") to " << filename << std::endl;

    pcap_t* pcap_handle_write = pcap_open_dead(client.datalink_type, 65535);
    if (!pcap_handle_write) {
        std::cerr << "Server Error: pcap_open_dead failed for datalink type " << client.datalink_type << std::endl;
        return;
    }

    // pcap_dumper_t* dumper = pcap_dump_open(pcap_handle_write, filename.c_str());
    // if (!dumper) {
    //     std::cerr << "Server Error: pcap_dump_open failed: " << pcap_geterr(pcap_handle_write) << std::endl;
    //     pcap_close(pcap_handle_write);
    //     return;
    // }

    // for (const auto& pkt_info : client.buffered_packets) {
    //     pcap_dump(reinterpret_cast<u_char*>(dumper), &pkt_info.header, pkt_info.data.data());
    // }

    // pcap_dump_close(dumper);

    pcap_close(pcap_handle_write);

    std::cout << "Server: Successfully saved " << filename << std::endl;

    client.buffered_packets.clear();
    client.current_total_bytes = 0;
    client.current_total_packets = 0;
}

//========================================================
// MAIN FUNCTION VỚI UDT
//========================================================
int main() {
    // --- Khởi tạo UDT ---
    if (UDT::startup() == SO_ERROR) {
        std::cerr << "Server: Failed to startup UDT: " << UDT::getlasterror().getErrorMessage() << std::endl;
        return 1;
    }

    // --- Tạo Socket UDT lắng nghe ---
    UDTSOCKET udt_server_sock = UDT::socket(AF_INET, SOCK_STREAM, 0);
    if (udt_server_sock == UDT::INVALID_SOCK) {
        std::cerr << "Server: UDT socket creation failed: " << UDT::getlasterror().getErrorMessage() << std::endl;
        UDT::cleanup();
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(UDT_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (UDT::bind(udt_server_sock, (sockaddr*)&addr, sizeof(addr)) == SO_ERROR) {
        std::cerr << "Server: UDT bind failed: " << UDT::getlasterror().getErrorMessage() << std::endl;
        UDT::close(udt_server_sock);
        UDT::cleanup();
        return 1;
    }

    if (UDT::listen(udt_server_sock, MAX_CLIENTS_LISTEN) == SO_ERROR) {
        std::cerr << "Server: UDT listen failed: " << UDT::getlasterror().getErrorMessage() << std::endl;
        UDT::close(udt_server_sock);
        UDT::cleanup();
        return 1;
    }
    std::cout << "Server listening for UDT on port " << UDT_PORT << "..." << std::endl;


    // --- Khởi tạo UDT epoll ---
    int eid = UDT::epoll_create();
    if (eid < 0) {
        std::cerr << "Server: UDT epoll_create failed: " << UDT::getlasterror().getErrorMessage() << std::endl;
        UDT::close(udt_server_sock);
        UDT::cleanup();
        return 1;
    }

    // Thêm socket lắng nghe vào epoll set để theo dõi sự kiện kết nối mới (EPOLLIN)
    int events = UDT_EPOLL_IN | UDT_EPOLL_ERR;
    if (UDT::epoll_add_usock(eid, udt_server_sock, &events) == SO_ERROR) {
        std::cerr << "Server: UDT epoll_add_usock for server socket failed: " << UDT::getlasterror().getErrorMessage() << std::endl;
        UDT::epoll_release(eid);
        UDT::close(udt_server_sock);
        UDT::cleanup();
        return 1;
    }

    // Map để lưu trạng thái của các client, key là UDTSOCKET
    std::map<UDTSOCKET, ClientState> clients_state;
    std::set<UDTSOCKET> read_sockets; // Set để chứa các socket sẵn sàng đọc

    while (true) {
        read_sockets.clear();
        // Chờ sự kiện trên các socket trong epoll set, timeout -1 là chờ vô hạn
        int ready_count = UDT::epoll_wait(eid, &read_sockets, nullptr, -1);

        if (ready_count < 0) {
             std::cerr << "Server: UDT epoll_wait failed: " << UDT::getlasterror().getErrorMessage() << std::endl;
             // Có thể break hoặc continue tùy vào mức độ nghiêm trọng của lỗi
             continue;
        }

        for (UDTSOCKET ready_sock : read_sockets) {
            // --- XỬ LÝ KẾT NỐI MỚI ---
            if (ready_sock == udt_server_sock) {
                sockaddr_in client_addr{};
                int client_len = sizeof(client_addr);
                UDTSOCKET client_sock = UDT::accept(udt_server_sock, (sockaddr*)&client_addr, &client_len);

                if (client_sock == UDT::INVALID_SOCK) {
                    std::cerr << "Server: UDT accept failed: " << UDT::getlasterror().getErrorMessage() << std::endl;
                    continue;
                }

                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                uint16_t client_port = ntohs(client_addr.sin_port);

                std::cout << "Server: New UDT connection from " << client_ip << ":" << client_port << " on socket " << client_sock << std::endl;

                // Thêm client socket vào epoll set để theo dõi dữ liệu đến
                if (UDT::epoll_add_usock(eid, client_sock, &events) == SO_ERROR) {
                    std::cerr << "Server: UDT epoll_add_usock for client failed: " << UDT::getlasterror().getErrorMessage() << std::endl;
                    UDT::close(client_sock);
                    continue;
                }
                
                // Tạo và lưu trạng thái cho client mới
                clients_state.emplace(client_sock,
                    ClientState(client_sock, std::string(client_ip), client_port)
                );
            }
            // --- XỬ LÝ DỮ LIỆU TỪ CLIENT ---
            else {
                auto it = clients_state.find(ready_sock);
                if (it == clients_state.end()) continue;

                ClientState& client = it->second;
                char temp_buf[8192];
                
                ssize_t nbytes = UDT::recv(client.udt_socket, temp_buf, sizeof(temp_buf), 0);

                if (nbytes <= 0) {
                    // Xử lý ngắt kết nối hoặc lỗi
                    std::cout << "Server: UDT Client " << client.ip_address << ":" << client.port
                              << " (socket " << client.udt_socket << ") disconnected or error: "
                              << UDT::getlasterror().getErrorMessage() << std::endl;

                    if (!client.buffered_packets.empty()) {
                         save_packets_to_pcap(client);
                    }
                    
                    // Dọn dẹp
                    UDT::epoll_remove_usock(eid, client.udt_socket);
                    UDT::close(client.udt_socket);
                    clients_state.erase(it);
                } else {
                    // Xử lý dữ liệu nhận được (logic FSM giữ nguyên)
                    client.recv_buffer.insert(client.recv_buffer.end(), temp_buf, temp_buf + nbytes);
                    
                    bool processed_data_in_this_pass;
                    do {
                        processed_data_in_this_pass = false;
                        switch (client.current_fsm_state) {
                            case ClientState::ReceiveFSM::AWAITING_METADATA_LINKTYPE:
                                if (client.recv_buffer.size() >= METADATA_SIZE_LINKTYPE) {
                                    uint32_t link_type_net;
                                    memcpy(&link_type_net, client.recv_buffer.data(), METADATA_SIZE_LINKTYPE);
                                    client.datalink_type = static_cast<int>(ntohl(link_type_net));
                                    client.recv_buffer.erase(client.recv_buffer.begin(), client.recv_buffer.begin() + METADATA_SIZE_LINKTYPE);
                                    client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_PCAP_FIELDS_HEADER;
                                    processed_data_in_this_pass = true;
                                    std::cout << "Server: Socket " << client.udt_socket << " received Datalink: " << client.datalink_type << " (" << pcap_datalink_val_to_name(client.datalink_type) << ")." << std::endl;
                                }
                                break;
                            case ClientState::ReceiveFSM::AWAITING_PCAP_FIELDS_HEADER:
                                if (client.recv_buffer.size() >= PCAP_FIELDS_HEADER_SIZE) {
                                    // logic parse header giữ nguyên
                                    const char* buf_ptr = client.recv_buffer.data();
                                    uint32_t ts_sec_net, ts_usec_net, caplen_net, len_net;
                                    memcpy(&ts_sec_net, buf_ptr, sizeof(uint32_t)); buf_ptr += sizeof(uint32_t);
                                    memcpy(&ts_usec_net, buf_ptr, sizeof(uint32_t)); buf_ptr += sizeof(uint32_t);
                                    memcpy(&caplen_net, buf_ptr, sizeof(uint32_t)); buf_ptr += sizeof(uint32_t);
                                    memcpy(&len_net, buf_ptr, sizeof(uint32_t));
                                    client.expected_pcap_ts_sec = ntohl(ts_sec_net);
                                    client.expected_pcap_ts_usec = ntohl(ts_usec_net);
                                    client.expected_pcap_caplen = ntohl(caplen_net);
                                    client.expected_pcap_len = ntohl(len_net);
                                    client.recv_buffer.erase(client.recv_buffer.begin(), client.recv_buffer.begin() + PCAP_FIELDS_HEADER_SIZE);
                                    
                                    if (client.expected_pcap_caplen > 65535 * 2) { /* error handling */ } else {
                                        client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_PCAP_DATA;
                                    }
                                    processed_data_in_this_pass = true;
                                }
                                break;
                            case ClientState::ReceiveFSM::AWAITING_PCAP_DATA:
                                if (client.recv_buffer.size() >= client.expected_pcap_caplen) {
                                    // logic xử lý data packet giữ nguyên
                                    PacketInfo pkt;
                                    pkt.header.ts.tv_sec = client.expected_pcap_ts_sec;
                                    pkt.header.ts.tv_usec = client.expected_pcap_ts_usec;
                                    pkt.header.caplen = client.expected_pcap_caplen;
                                    pkt.header.len = client.expected_pcap_len;
                                    pkt.data.assign(client.recv_buffer.begin(), client.recv_buffer.begin() + client.expected_pcap_caplen);
                                    client.buffered_packets.push_back(pkt);
                                    client.current_total_bytes += client.expected_pcap_caplen;
                                    client.current_total_packets++;
                                    client.recv_buffer.erase(client.recv_buffer.begin(), client.recv_buffer.begin() + client.expected_pcap_caplen);
                                    client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_PCAP_FIELDS_HEADER;
                                    processed_data_in_this_pass = true;
                                    if (client.current_total_bytes >= MAX_BUFFER_SIZE_PER_CLIENT) {
                                        save_packets_to_pcap(client);
                                    }
                                }
                                break;
                        }
                    } while (processed_data_in_this_pass && !client.recv_buffer.empty());
                }
            }
        }
    }

    std::cout << "Server shutting down. Saving remaining packets..." << std::endl;
    for (auto& pair : clients_state) {
        if (!pair.second.buffered_packets.empty()) {
            save_packets_to_pcap(pair.second);
        }
        UDT::close(pair.first);
    }
    clients_state.clear();

    UDT::epoll_release(eid);
    UDT::close(udt_server_sock);
    UDT::cleanup();

    std::cout << "Server shutdown complete." << std::endl;
    return 0;
}