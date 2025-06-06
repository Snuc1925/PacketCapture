#include <iostream>
#include <cstring> // Für strerror
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm> // For std::max

// System headers
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <cerrno>      // For errno
#include <sys/time.h> // For gettimeofday

// Pcap headers
#include <pcap/pcap.h>

const int PORT = 8888;
const size_t MAX_BUFFER_SIZE_PER_CLIENT = 1024 * 1024 * 1024; // 1 GB
const int MAX_CLIENTS = FD_SETSIZE; // Sử dụng giới hạn của hệ thống cho select

// Kích thước các phần của thông điệp từ agent
const size_t METADATA_SIZE_LINKTYPE = sizeof(uint32_t); // Chỉ có link_type
const size_t PCAP_FIELDS_HEADER_SIZE = sizeof(uint32_t) * 4; // ts_sec, ts_usec, caplen, len

// Thông tin của một gói tin đã nhận
struct PacketInfo {
    pcap_pkthdr header;
    std::vector<unsigned char> data;
};

// Trạng thái của mỗi client kết nối
struct ClientState {
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

    // Thông tin header pcap đang được đọc
    uint32_t expected_pcap_ts_sec;
    uint32_t expected_pcap_ts_usec;
    uint32_t expected_pcap_caplen;
    uint32_t expected_pcap_len;


    ClientState() : 
        current_total_packets(0),
        current_total_bytes(0), 
        current_fsm_state(ReceiveFSM::AWAITING_METADATA_LINKTYPE),
        datalink_type(DLT_NULL) // Giá trị mặc định an toàn
    {}
};

// Hàm tạo tên file pcap
std::string generate_pcap_filename(const std::string& ip, uint16_t port) {
    std::time_t t = std::time(nullptr);
    std::tm tm_struct = *std::localtime(&t); // Đổi tên để tránh xung đột
    
    std::ostringstream oss;
    oss << ip << "_" << port << "_"
        << std::put_time(&tm_struct, "%Y%m%d_%H%M%S") << ".pcap";
    return oss.str();
}

// Hàm lưu packets vào file pcap
void save_packets_to_pcap(ClientState& client) {
    if (client.buffered_packets.empty()) {
        return;
    }

    std::string filename = generate_pcap_filename(client.ip_address, client.port);
    std::cout << "Server: Saving " << client.current_total_bytes << " bytes, " << client.current_total_packets << " packets for client "
              << client.ip_address << ":" << client.port 
              << " (Datalink: " << client.datalink_type << " - " << pcap_datalink_val_to_name(client.datalink_type) << ") to " << filename << std::endl;

    pcap_t* pcap_handle_write = pcap_open_dead(client.datalink_type, 65535); // 65535 là snaplen
    if (!pcap_handle_write) {
        // pcap_open_dead không set errbuf, nó trả về NULL khi datalink không hợp lệ
        std::cerr << "Server Error: pcap_open_dead failed for " << client.ip_address 
                  << " with datalink type " << client.datalink_type 
                  << " (" << pcap_datalink_val_to_name(client.datalink_type) << ")."
                  << " This datalink type might not be supported by libpcap on this system for writing." << std::endl;
        return;
    }

    pcap_dumper_t* dumper = pcap_dump_open(pcap_handle_write, filename.c_str());
    if (!dumper) {
        std::cerr << "Server Error: pcap_dump_open failed for " << filename 
                  << ". Error: " << pcap_geterr(pcap_handle_write) << std::endl;
        pcap_close(pcap_handle_write);
        return;
    }

    for (const auto& pkt_info : client.buffered_packets) {
        pcap_dump(reinterpret_cast<u_char*>(dumper), &pkt_info.header, pkt_info.data.data());
    }

    pcap_dump_close(dumper);
    pcap_close(pcap_handle_write);

    std::cout << "Server: Successfully saved " << filename << std::endl;

    client.buffered_packets.clear();
    client.current_total_bytes = 0;
    client.current_total_packets = 0;
}


int main() { // Server main
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Server: Socket failed");
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Server: setsockopt(SO_REUSEADDR) failed");
        close(server_sock);
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Server: Bind failed");
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, MAX_CLIENTS) < 0) {
        perror("Server: Listen failed");
        close(server_sock);
        return 1;
    }

    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    fd_set master_fds, read_fds;
    FD_ZERO(&master_fds);
    FD_ZERO(&read_fds);

    FD_SET(server_sock, &master_fds);
    int fd_max = server_sock;

    std::map<int, ClientState> clients_state;

    while (true) {
        read_fds = master_fds; 

        if (select(fd_max + 1, &read_fds, nullptr, nullptr, nullptr) < 0) {
            if (errno == EINTR) continue;
            perror("Server: select failed");
            break; 
        }

        for (int current_fd = 0; current_fd <= fd_max; ++current_fd) { // Đổi tên biến lặp
            if (FD_ISSET(current_fd, &read_fds)) {
                if (current_fd == server_sock) { // Kết nối mới
                    sockaddr_in client_addr_struct{};
                    socklen_t client_len = sizeof(client_addr_struct);
                    int client_sock = accept(server_sock, (sockaddr*)&client_addr_struct, &client_len);

                    if (client_sock < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                             // Không có kết nối nào chờ, điều này không nên xảy ra nếu select() báo server_sock sẵn sàng
                             // nhưng vẫn kiểm tra để an toàn.
                        } else {
                            perror("Server: Accept failed");
                        }
                        continue;
                    }

                    int flags = fcntl(client_sock, F_GETFL, 0);
                    if (flags == -1 || fcntl(client_sock, F_SETFL, flags | O_NONBLOCK) == -1) {
                        perror("Server: fcntl O_NONBLOCK failed for new client");
                        close(client_sock);
                        continue;
                    }

                    FD_SET(client_sock, &master_fds);
                    if (client_sock > fd_max) fd_max = client_sock;

                    char client_ip_str[INET_ADDRSTRLEN]; // Đổi tên biến
                    inet_ntop(AF_INET, &client_addr_struct.sin_addr, client_ip_str, INET_ADDRSTRLEN);
                    uint16_t client_port_val = ntohs(client_addr_struct.sin_port);

                    clients_state[client_sock].ip_address = client_ip_str;
                    clients_state[client_sock].port = client_port_val;
                    clients_state[client_sock].current_fsm_state = ClientState::ReceiveFSM::AWAITING_METADATA_LINKTYPE;
                    clients_state[client_sock].recv_buffer.clear();


                    std::cout << "Server: New connection from " << client_ip_str << ":" << client_port_val
                              << " on socket " << client_sock << ". Awaiting link type." << std::endl;

                } else { // Dữ liệu từ client đã kết nối
                    ClientState& current_client = clients_state[current_fd];
                    char temp_buf[8192]; 
                    
                    ssize_t nbytes = recv(current_fd, temp_buf, sizeof(temp_buf), 0);

                    if (nbytes <= 0) { 
                        if (nbytes == 0) {
                            std::cout << "Server: Client " << current_client.ip_address << ":" << current_client.port
                                      << " (socket " << current_fd << ") disconnected." << std::endl;
                        } else { // nbytes < 0
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                // Không có dữ liệu để đọc ngay, bình thường với non-blocking
                                continue; 
                            } else if (errno == EINTR) {
                                // Bị ngắt bởi signal, thử lại vòng lặp select
                                continue;
                            }
                            perror("Server: recv failed");
                            std::cout << "Server: Error on socket " << current_fd << " for client "
                                      << current_client.ip_address << ":" << current_client.port << std::endl;
                        }
                        // Nếu còn dữ liệu chưa lưu, lưu lại trước khi đóng
                        if (current_client.current_total_bytes > 0) {
                             save_packets_to_pcap(current_client);
                        }
                        close(current_fd);
                        FD_CLR(current_fd, &master_fds);
                        clients_state.erase(current_fd);
                         // Cập nhật fd_max nếu cần
                        if (current_fd == fd_max) {
                            while (fd_max > server_sock && !FD_ISSET(fd_max, &master_fds)) {
                                fd_max--;
                            }
                        }
                    } else { // Nhận được dữ liệu
                        current_client.recv_buffer.insert(current_client.recv_buffer.end(), temp_buf, temp_buf + nbytes);
                        
                        bool processed_data_in_this_pass; // Đổi tên biến
                        do {
                            processed_data_in_this_pass = false;
                            switch (current_client.current_fsm_state) {
                                case ClientState::ReceiveFSM::AWAITING_METADATA_LINKTYPE:
                                    if (current_client.recv_buffer.size() >= METADATA_SIZE_LINKTYPE) {
                                        uint32_t link_type_net;
                                        memcpy(&link_type_net, current_client.recv_buffer.data(), METADATA_SIZE_LINKTYPE);
                                        current_client.datalink_type = static_cast<int>(ntohl(link_type_net));
                                        
                                        current_client.recv_buffer.erase(current_client.recv_buffer.begin(), 
                                                                         current_client.recv_buffer.begin() + METADATA_SIZE_LINKTYPE);
                                        
                                        current_client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_PCAP_FIELDS_HEADER;
                                        processed_data_in_this_pass = true;
                                        std::cout << "Server: Socket " << current_fd << " received Datalink: " 
                                                  << current_client.datalink_type << " (" 
                                                  << pcap_datalink_val_to_name(current_client.datalink_type) 
                                                  << "). Awaiting pcap header." << std::endl;
                                    }
                                    break;

                                case ClientState::ReceiveFSM::AWAITING_PCAP_FIELDS_HEADER:
                                    if (current_client.recv_buffer.size() >= PCAP_FIELDS_HEADER_SIZE) {
                                        const char* buf_ptr = current_client.recv_buffer.data();
                                        uint32_t ts_sec_net, ts_usec_net, caplen_net, len_net;

                                        memcpy(&ts_sec_net, buf_ptr, sizeof(uint32_t)); buf_ptr += sizeof(uint32_t);
                                        memcpy(&ts_usec_net, buf_ptr, sizeof(uint32_t)); buf_ptr += sizeof(uint32_t);
                                        memcpy(&caplen_net, buf_ptr, sizeof(uint32_t)); buf_ptr += sizeof(uint32_t);
                                        memcpy(&len_net, buf_ptr, sizeof(uint32_t));

                                        current_client.expected_pcap_ts_sec = ntohl(ts_sec_net);
                                        current_client.expected_pcap_ts_usec = ntohl(ts_usec_net);
                                        current_client.expected_pcap_caplen = ntohl(caplen_net);
                                        current_client.expected_pcap_len = ntohl(len_net);

                                        current_client.recv_buffer.erase(current_client.recv_buffer.begin(),
                                                                         current_client.recv_buffer.begin() + PCAP_FIELDS_HEADER_SIZE);
                                        
                                        if (current_client.expected_pcap_caplen == 0) { // Gói tin không có data
                                            PacketInfo pkt;
                                            pkt.header.ts.tv_sec = current_client.expected_pcap_ts_sec;
                                            pkt.header.ts.tv_usec = current_client.expected_pcap_ts_usec;
                                            pkt.header.caplen = current_client.expected_pcap_caplen;
                                            pkt.header.len = current_client.expected_pcap_len;
                                            // pkt.data is empty
                                            current_client.buffered_packets.push_back(pkt);
                                            // current_total_bytes không tăng vì caplen = 0
                                            current_client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_PCAP_FIELDS_HEADER; // Chờ header gói tiếp
                                            std::cout << "Server: Socket " << current_fd << " processed zero-caplen packet." << std::endl;
                                        } else if (current_client.expected_pcap_caplen > 65535 * 2) { // Kiểm tra caplen quá lớn bất thường
                                            std::cerr << "Server Error: Socket " << current_fd << " received abnormally large caplen: "
                                                      << current_client.expected_pcap_caplen << ". Closing connection." << std::endl;
                                            if (current_client.current_total_bytes > 0) save_packets_to_pcap(current_client);
                                            close(current_fd); FD_CLR(current_fd, &master_fds); clients_state.erase(current_fd);
                                            if (current_fd == fd_max) while (fd_max > server_sock && !FD_ISSET(fd_max, &master_fds)) fd_max--;
                                            goto next_fd_in_select_loop; // Thoát khỏi xử lý client này
                                        }
                                        else {
                                            current_client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_PCAP_DATA;
                                        }
                                        processed_data_in_this_pass = true;
                                    }
                                    break;

                                case ClientState::ReceiveFSM::AWAITING_PCAP_DATA:
                                    if (current_client.expected_pcap_caplen > 0 && current_client.recv_buffer.size() >= current_client.expected_pcap_caplen) {
                                        PacketInfo pkt;
                                        pkt.header.ts.tv_sec = current_client.expected_pcap_ts_sec;
                                        pkt.header.ts.tv_usec = current_client.expected_pcap_ts_usec;
                                        pkt.header.caplen = current_client.expected_pcap_caplen;
                                        pkt.header.len = current_client.expected_pcap_len;

                                        pkt.data.assign(current_client.recv_buffer.begin(), 
                                                        current_client.recv_buffer.begin() + current_client.expected_pcap_caplen);
                                        
                                        current_client.buffered_packets.push_back(pkt);
                                        current_client.current_total_bytes += current_client.expected_pcap_caplen;
                                        current_client.current_total_packets++;
                                        
                                        current_client.recv_buffer.erase(current_client.recv_buffer.begin(),
                                                                         current_client.recv_buffer.begin() + current_client.expected_pcap_caplen);
                                        
                                        current_client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_PCAP_FIELDS_HEADER;
                                        processed_data_in_this_pass = true;

                                        if (current_client.current_total_bytes >= MAX_BUFFER_SIZE_PER_CLIENT) {
                                            save_packets_to_pcap(current_client);
                                        }
                                    }
                                    break;
                            } // end switch
                        } while(processed_data_in_this_pass && !current_client.recv_buffer.empty());
                    }
                } // end data from client
            } // end FD_ISSET
            next_fd_in_select_loop:; // Label cho goto
        } // end loop through fds
    } // end while(true)

    // Dọn dẹp khi server tắt
    std::cout << "Server shutting down. Saving any remaining buffered packets..." << std::endl;
    for (auto const& [fd_client, client_state_val] : clients_state) { // Sử dụng C++17 structured binding
        ClientState& client_to_save = clients_state[fd_client]; // Cần non-const ref
        if (client_to_save.current_total_bytes > 0) {
            save_packets_to_pcap(client_to_save);
        }
        close(fd_client);
    }
    close(server_sock);
    std::cout << "Server shutdown complete." << std::endl;
    return 0;
}