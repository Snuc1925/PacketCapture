#include "connection/PlainTcpClient.hpp"
#include "connection/TlsClient.hpp"
#include "connection/net_utils.hpp"
#include "common/constants.hpp"
#include "common/types.hpp"
#include "pcap/pcap_writer.hpp"
#include "pcap/LivePcapStreamer.hpp"
#include "logging/latency_logger.hpp"
#include "decompressor/ZstdDecompressor.hpp"
#include "decompressor/NoOpDecompressor.hpp"
#include "decompressor/ZlibDecompressor.hpp"

#include <iostream>
#include <cstring>
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <memory> 
#include <chrono>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <cerrno>
#include <sys/time.h>
#include <fstream>
#include <atomic>
#include <pcap/pcap.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <csignal> 
#include <zstd.h> 


// ----------- Interupt -----------------
std::atomic<bool> server_interrupted(false);
void signal_handler(int signum) {
    std::cout << "\nSignal " << signum << " received. Shutting down..." << std::endl;
    server_interrupted = true;
}


int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    fprintf(stderr, ">>> sizeof(pcap_pkthdr) = %zu bytes\n", sizeof(pcap_pkthdr));
    // --- Khởi tạo Socket thường và TLS (không đổi) ---
    int tcp_server_sock = create_listening_socket(AppConfig::PLAIN_TCP_PORT);
    if (tcp_server_sock < 0) return 1;
    std::cout << "Server listening for PLAIN TCP on port " << AppConfig::PLAIN_TCP_PORT << "..." << std::endl;

    SSL_CTX *ssl_ctx = create_ssl_context();
    configure_ssl_context(ssl_ctx);
    int tls_server_sock = create_listening_socket(AppConfig::TLS_PORT);
    if (tls_server_sock < 0) return 1;
    std::cout << "Server listening for TLS on port " << AppConfig::TLS_PORT << "..." << std::endl;

    // --- Vòng lặp select (không đổi) ---
    fd_set master_fds, read_fds;
    FD_ZERO(&master_fds);
    FD_SET(tcp_server_sock, &master_fds);
    FD_SET(tls_server_sock, &master_fds);
    int fd_max = std::max(tcp_server_sock, tls_server_sock);
    std::map<int, ClientState> clients_state;

    LivePcapStreamer live_streamer;
    const std::string live_pipe_path = "/tmp/live_stream.pcap";
    bool streamer_initialized = false;    

    while (!server_interrupted) {
        read_fds = master_fds;
        if (select(fd_max + 1, &read_fds, nullptr, nullptr, nullptr) < 0) {
            if (errno == EINTR) continue;
            perror("Server: select failed");
            break;
        }

        for (int i = 0; i <= fd_max; ++i) {
            if (!FD_ISSET(i, &read_fds)) continue;

            // --- Xử lý kết nối mới (không đổi) ---
            if (i == tcp_server_sock || i == tls_server_sock) {
                sockaddr_in client_addr{};
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(i, (sockaddr*)&client_addr, &client_len);
                if (client_sock < 0) { /* ... error handling ... */ continue; }

                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                uint16_t client_port = ntohs(client_addr.sin_port);

                std::unique_ptr<IClientConnection> new_connection;
                if (i == tls_server_sock) {
                    SSL* ssl = SSL_new(ssl_ctx);
                    SSL_set_fd(ssl, client_sock);
                    if (SSL_accept(ssl) <= 0) {
                        ERR_print_errors_fp(stderr);
                        SSL_free(ssl);
                        close(client_sock);
                        continue;
                    }
                    new_connection = std::make_unique<TlsClient>(client_sock, ssl);
                } else { // Plain TCP
                    new_connection = std::make_unique<PlainTcpClient>(client_sock);
                }

                std::cout << "Server: New " << new_connection->get_type() << " connection from "
                          << client_ip << ":" << client_port << " on socket " << client_sock << std::endl;

                FD_SET(client_sock, &master_fds);
                if (client_sock > fd_max) fd_max = client_sock;
                
                // Sử dụng move constructor để tạo ClientState
                clients_state.emplace(client_sock,
                    ClientState(std::move(new_connection), std::string(client_ip), client_port)
                );

                if (!streamer_initialized) {
                    std::cout << "Live Stream: First client connected. Attempting to open pipe..." << std::endl;
                    // Chờ Wireshark mở pipe để đọc
                    // Ta sẽ thử mở streamer khi nhận được datalink_type
                }                
            }
            // --- XỬ LÝ DỮ LIỆU TỪ CLIENT (PHẦN THAY ĐỔI CHÍNH) ---
            else {
                int client_fd = i;
                auto it = clients_state.find(client_fd);
                if (it == clients_state.end()) continue;

                ClientState& client = it->second;
                char temp_buf[8192];
                
                ssize_t nbytes = client.connection->read(temp_buf, sizeof(temp_buf));

                if (nbytes <= 0) {
                    // Xử lý ngắt kết nối
                    std::cout << "Server: Client " << client.ip_address << ":" << client.port
                                      << " (socket " << client_fd << ") disconnected." << std::endl;
                    if (!client.buffered_packets.empty()) {
                         save_packets_to_pcap(client);
                    }
                    std::cout << "Server: Received " 
                            << static_cast<double>(client.total_bytes) / (1024 * 1024) << " MB, "
                            << client.total_packets << " packets for client!!!" << std::endl;
                    // Destructor của ClientState sẽ tự động gọi connection->close_connection()
                    FD_CLR(client_fd, &master_fds);
                    clients_state.erase(it);
                    if (client_fd == fd_max) {
                        while (fd_max > std::max(tcp_server_sock, tls_server_sock) && !FD_ISSET(fd_max, &master_fds)) {
                            fd_max--;
                        }
                    }
                } else {
                    // --- LOGIC FSM MỚI ĐỂ XỬ LÝ BLOCK ---
                    client.recv_buffer.insert(client.recv_buffer.end(), temp_buf, temp_buf + nbytes);
                    
                    bool processed_data_in_this_pass;
                    do {
                        processed_data_in_this_pass = false;
                        switch (client.current_fsm_state) {
                            case ClientState::ReceiveFSM::AWAITING_METADATA_LINKTYPE:
                                if (client.recv_buffer.size() >= AppConfig::METADATA_SIZE_LINKTYPE) {
                                    uint32_t link_type_net;
                                    memcpy(&link_type_net, client.recv_buffer.data(), AppConfig::METADATA_SIZE_LINKTYPE);
                                    client.datalink_type = static_cast<int>(ntohl(link_type_net));
                                    client.recv_buffer.erase(client.recv_buffer.begin(), client.recv_buffer.begin() + AppConfig::METADATA_SIZE_LINKTYPE);

                                    if (!streamer_initialized) {
                                        if (live_streamer.open_stream(live_pipe_path, client.datalink_type)) {
                                            streamer_initialized = true;
                                            std::cout << "Live Stream: Successfully opened for real-time analysis." << std::endl;
                                        } else {
                                            std::cout << "Live Stream: Failed to open. Run Wireshark first: "
                                                    << "'wireshark -k -i " << live_pipe_path << "'" << std::endl;
                                        }
                                    }                                    
                                    

                                    // Chuyển sang trạng thái chờ block header
                                    client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_BLOCK_HEADER;
                                    processed_data_in_this_pass = true;

                                    std::cout << "Server: Socket " << client_fd << " received Datalink: " << client.datalink_type 
                                              << " (" << pcap_datalink_val_to_name(client.datalink_type) << ")." << std::endl;
                                }
                                break;
                            
                            case ClientState::ReceiveFSM::AWAITING_BLOCK_HEADER:
                                if (client.recv_buffer.size() >= AppConfig::BLOCK_HEADER_SIZE) {
                                    const char* buf_ptr = client.recv_buffer.data();

                                    memcpy(&client.expected_flags, buf_ptr, sizeof(uint8_t));
                                    buf_ptr += sizeof(uint8_t);
                                    
                                    uint32_t original_size_net, payload_size_net;
                                    memcpy(&original_size_net, buf_ptr, sizeof(uint32_t));
                                    buf_ptr += sizeof(uint32_t);
                                    memcpy(&payload_size_net, buf_ptr, sizeof(uint32_t));

                                    client.expected_original_size = ntohl(original_size_net);
                                    client.expected_payload_size = ntohl(payload_size_net);

                                    // --- LOGIC CHỌN DECOMPRESSOR ĐƯỢC CHUYỂN LÊN ĐÂY ---
                                    if (client.expected_flags & AppConfig::FLAG_COMPRESSED_ZSTD) {
                                        client.decompressor = std::make_unique<ZstdDecompressor>();
                                        // std::cout << "DEBUG: ZSTD decompressor selected for fd " << client.socket_fd << std::endl; // Debugging
                                    } else if (client.expected_flags & AppConfig::FLAG_COMPRESSED_ZLIB) {
                                        client.decompressor = std::make_unique<ZlibDecompressor>();
                                        // std::cout << "DEBUG: ZLIB decompressor selected for fd " << client.socket_fd << std::endl; // Debugging
                                    } else {
                                        client.decompressor = std::make_unique<NoOpDecompressor>();
                                        // std::cout << "DEBUG: NoOp decompressor selected for fd " << client.socket_fd << std::endl; // Debugging
                                    }


                                    client.recv_buffer.erase(client.recv_buffer.begin(), client.recv_buffer.begin() + AppConfig::BLOCK_HEADER_SIZE);
                                    
                                    client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_BLOCK_PAYLOAD;
                                    processed_data_in_this_pass = true;
                                }
                                break;
                            
                            case ClientState::ReceiveFSM::AWAITING_BLOCK_PAYLOAD:
                                if (client.recv_buffer.size() >= client.expected_payload_size) {
                                    const char* payload_start = client.recv_buffer.data();
                                    const char* data_to_process = nullptr;
                                    size_t data_to_process_size = 0;

                                    bool decompression_successful = false; // Cờ để theo dõi việc giải nén có thành công không

                                    // Tại đây, chỉ cần gọi phương thức decompress trên đối tượng decompressor đã được chọn
                                    if (client.decompressor->decompress(
                                            payload_start,
                                            client.expected_payload_size,
                                            client.expected_original_size,
                                            client.decompressed_buffer // Buffer để chứa kết quả giải nén
                                        )) {
                                        decompression_successful = true;
                                        data_to_process = client.decompressed_buffer.data();
                                        data_to_process_size = client.decompressed_buffer.size();
                                    } else {
                                        std::cerr << "Decompression failed for socket " << client_fd << ". Discarding block." << std::endl;
                                        // decompression_successful vẫn là false
                                    }

                                    // Chỉ xử lý dữ liệu nếu giải nén thành công (hoặc không cần giải nén)
                                    if (decompression_successful) {
                                        const char* packet_ptr = data_to_process;
                                        size_t remaining_size = data_to_process_size;

                                        while (remaining_size >= AppConfig::PCAP_FIELDS_HEADER_SIZE) {
                                            uint32_t ts_sec_net, ts_usec_net, caplen_net, len_net;
                                            memcpy(&ts_sec_net, packet_ptr, sizeof(uint32_t));
                                            memcpy(&ts_usec_net, packet_ptr + 4, sizeof(uint32_t));
                                            memcpy(&caplen_net, packet_ptr + 8, sizeof(uint32_t));
                                            memcpy(&len_net, packet_ptr + 12, sizeof(uint32_t));
                                            
                                            packet_ptr += AppConfig::PCAP_FIELDS_HEADER_SIZE;
                                            remaining_size -= AppConfig::PCAP_FIELDS_HEADER_SIZE;
                                            
                                            uint32_t caplen = ntohl(caplen_net);
                                            if (remaining_size < caplen) {
                                                std::cerr << "Corrupted block data for socket " << client_fd << ". Not enough data for packet. Expected " << caplen << ", have " << remaining_size << std::endl;
                                                break;
                                            }

                                            PacketInfo pkt;
                                            pkt.header.ts.tv_sec = ntohl(ts_sec_net);
                                            pkt.header.ts.tv_usec = ntohl(ts_usec_net);
                                            pkt.header.caplen = caplen;
                                            pkt.header.len = ntohl(len_net);
                                            pkt.data.assign(reinterpret_cast<const unsigned char*>(packet_ptr), reinterpret_cast<const unsigned char*>(packet_ptr) + caplen);

                                            if (live_streamer.is_open()) {
                                                live_streamer.write_packet(&pkt.header, pkt.data.data());
                                            }     
                                            
                                            uint32_t ts_sec = ntohl(ts_sec_net);
                                            uint32_t ts_usec = ntohl(ts_usec_net);

                                            // Phục hồi lại thời gian gửi (us)
                                            uint64_t send_ts_us = static_cast<uint64_t>(ts_sec) * 1'000'000 + ts_usec;

                                            auto now = std::chrono::system_clock::now();
                                            uint64_t recv_ts_us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();

                                            uint64_t latency_us = recv_ts_us - send_ts_us;
                                            // std::cout << "Latency: " << latency_us << " us" << std::endl;

                                            // Lưu vào vector
                                            latency_log_entries.emplace_back(send_ts_us, recv_ts_us, latency_us);                                            
                                            

                                            client.buffered_packets.push_back(std::move(pkt));
                                            client.current_total_bytes += caplen;
                                            client.current_total_packets++;

                                            packet_ptr += caplen;
                                            remaining_size -= caplen;
                                        }
                                    }
                                    
                                    // Xóa payload đã xử lý khỏi buffer nhận
                                    client.recv_buffer.erase(client.recv_buffer.begin(), client.recv_buffer.begin() + client.expected_payload_size);


                                    // Quay lại chờ header của block tiếp theo
                                    client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_BLOCK_HEADER;
                                    processed_data_in_this_pass = true;

                                    if (client.current_total_bytes >= AppConfig::MAX_BUFFER_SIZE_PER_CLIENT) {
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

    flush_latency_log_to_csv();

    // --- Shutdown (không đổi) ---
    std::cout << "Server shutting down. Saving remaining packets..." << std::endl;
    for (auto& pair : clients_state) {
        if (!pair.second.buffered_packets.empty()) {
            save_packets_to_pcap(pair.second);
        }
        // Destructor sẽ tự động đóng kết nối
    }
    clients_state.clear();
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    close(tcp_server_sock);
    close(tls_server_sock);
    std::cout << "Server shutdown complete." << std::endl;
    live_streamer.close_stream();
    return 0;
}