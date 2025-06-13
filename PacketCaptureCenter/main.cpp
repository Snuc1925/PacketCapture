#include <iostream>
#include <cstring>
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <memory> // For std::unique_ptr
#include <chrono>
// System headers
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <cerrno>
#include <sys/time.h>
#include <fstream>
#include <atomic>

// Pcap headers
#include <pcap/pcap.h>

// OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <csignal> // Thêm dòng này
// Zstandard header
#include <zstd.h> // *** THÊM THƯ VIỆN ZSTD ***

// --- Cấu hình Server ---
const int PLAIN_TCP_PORT = 8888;
const int TLS_PORT = 8889;
const size_t MAX_BUFFER_SIZE_PER_CLIENT = 1024 * 1024 * 1024; // 1 GB
const int MAX_CLIENTS = FD_SETSIZE;

// Kích thước các phần của thông điệp từ agent
const uint8_t FLAG_COMPRESSED_ZSTD = (1 << 0);
const size_t METADATA_SIZE_LINKTYPE = sizeof(uint32_t);
const size_t BLOCK_HEADER_SIZE = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t);
const size_t PCAP_FIELDS_HEADER_SIZE = sizeof(uint32_t) * 4;


//========================================================
// LỚP TRỪU TƯỢNG VÀ CÁC LỚP CON CHO KẾT NỐI CLIENT
// (Không thay đổi)
//========================================================
class IClientConnection {
public:
    virtual ~IClientConnection() = default;
    virtual int get_fd() const = 0;
    virtual ssize_t read(char* buffer, size_t size) = 0;
    virtual void close_connection() = 0;
    virtual std::string get_type() const = 0;
};

class PlainTcpClient : public IClientConnection {
private:
    int fd_;
public:
    explicit PlainTcpClient(int fd) : fd_(fd) {}
    ~PlainTcpClient() override { close_connection(); }
    int get_fd() const override { return fd_; }
    ssize_t read(char* buffer, size_t size) override { return recv(fd_, buffer, size, 0); }
    void close_connection() override { if (fd_ != -1) { close(fd_); fd_ = -1; } }
    std::string get_type() const override { return "Plain TCP"; }
};

class TlsClient : public IClientConnection {
private:
    int fd_;
    SSL* ssl_;
public:
    TlsClient(int fd, SSL* ssl) : fd_(fd), ssl_(ssl) {}
    ~TlsClient() override { close_connection(); }
    int get_fd() const override { return fd_; }
    ssize_t read(char* buffer, size_t size) override { return SSL_read(ssl_, buffer, size); }
    void close_connection() override {
        if (ssl_) { SSL_shutdown(ssl_); SSL_free(ssl_); ssl_ = nullptr; }
        if (fd_ != -1) { close(fd_); fd_ = -1; }
    }
    std::string get_type() const override { return "TLS"; }
};

//========================================================
// STRUCTS VÀ HÀM HELPER
//========================================================
struct PacketInfo {
    pcap_pkthdr header;
    std::vector<unsigned char> data;
};

// *** CẬP NHẬT CLIENTSTATE VÀ FSM ***
struct ClientState {
    std::unique_ptr<IClientConnection> connection;
    std::string ip_address;
    uint16_t port;
    std::vector<PacketInfo> buffered_packets;
    size_t current_total_bytes;
    size_t total_bytes;
    long long current_total_packets;
    long long total_packets; 
    std::vector<char> recv_buffer;

    enum class ReceiveFSM {
        AWAITING_METADATA_LINKTYPE,
        AWAITING_BLOCK_HEADER,
        AWAITING_BLOCK_PAYLOAD
    };
    ReceiveFSM current_fsm_state;
    
    int datalink_type;

    // Các trường mới để xử lý block
    uint8_t expected_flags;
    uint32_t expected_original_size;
    uint32_t expected_payload_size;
    std::vector<char> decompressed_buffer; // Buffer để giải nén

    ClientState() = delete; // Xóa constructor mặc định để tránh lỗi

    ClientState(std::unique_ptr<IClientConnection> conn, std::string ip, uint16_t p)
        : connection(std::move(conn)), ip_address(std::move(ip)), port(p),
          current_total_bytes(0), current_total_packets(0), total_packets(0), total_bytes(0),
          current_fsm_state(ReceiveFSM::AWAITING_METADATA_LINKTYPE),
          datalink_type(DLT_NULL), expected_flags(0),
          expected_original_size(0), expected_payload_size(0)
    {}
};

// ... Các hàm generate_pcap_filename và save_packets_to_pcap giữ nguyên ...
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

    client.total_bytes += client.current_total_bytes;
    client.total_packets += client.current_total_packets;

    std::string filename = generate_pcap_filename(client.ip_address, client.port);
    std::cout << std::fixed << std::setprecision(2); 

    std::cout << "Server: Saving " 
            << static_cast<double>(client.current_total_bytes) / (1024 * 1024) << " MB, "
            << client.current_total_packets << " packets for client "
            << client.ip_address << ":" << client.port << std::endl;

            //   << " (Datalink: " << client.datalink_type << " - " << pcap_datalink_val_to_name(client.datalink_type) << ") to " << filename << std::endl;

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

// Các hàm TLS (create_ssl_context, configure_ssl_context) không đổi
SSL_CTX* create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_ssl_context(SSL_CTX* ctx) {
    // Load certificate và private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Hàm tiện ích để tạo một listening socket
int create_listening_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(sock);
        return -1;
    }
    if (listen(sock, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        close(sock);
        return -1;
    }
    return sock;
}

class LivePcapStreamer {
private:
    pcap_t* pcap_handle_ = nullptr;
    pcap_dumper_t* dumper_ = nullptr;

public:
    ~LivePcapStreamer() {
        close_stream();
    }

    // Mở stream bằng cách sử dụng chính các hàm của libpcap
    bool open_stream(const std::string& pipe_path, int datalink_type) {
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

    // Ghi một gói tin. Hàm này giờ trở nên cực kỳ đơn giản.
    void write_packet(const pcap_pkthdr* header, const unsigned char* data) {
        if (!dumper_) {
            return;
        }
        // Để libpcap lo tất cả mọi thứ: endianness, struct size, ...
        pcap_dump(reinterpret_cast<u_char*>(dumper_), header, data);
    }

    void close_stream() {
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

    bool is_open() const {
        return dumper_ != nullptr;
    }
};

// Khai báo global hoặc trong một class quản lý
std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> latency_log_entries;
void flush_latency_log_to_csv(const std::string& filename = "/home/maimanh/Downloads/Code/VDT/Project/test/center/latency_log.csv") {
    std::ofstream ofs(filename);
    std::cout << "Open File successfully\n";
    ofs << "send_timestamp_us,recv_timestamp_us,latency_us\n";
    for (const auto& [send_us, recv_us, latency_us] : latency_log_entries) {
        ofs << send_us << "," << recv_us << "," << latency_us << "\n";
    }
}


// ----------- Interupt -----------------
std::atomic<bool> server_interrupted(false);
void signal_handler(int signum) {
    std::cout << "\nSignal " << signum << " received. Shutting down..." << std::endl;
    server_interrupted = true;
}



//========================================================
// MAIN FUNCTION
//========================================================
int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    fprintf(stderr, ">>> sizeof(pcap_pkthdr) = %zu bytes\n", sizeof(pcap_pkthdr));
    // --- Khởi tạo Socket thường và TLS (không đổi) ---
    int tcp_server_sock = create_listening_socket(PLAIN_TCP_PORT);
    if (tcp_server_sock < 0) return 1;
    std::cout << "Server listening for PLAIN TCP on port " << PLAIN_TCP_PORT << "..." << std::endl;

    SSL_CTX *ssl_ctx = create_ssl_context();
    configure_ssl_context(ssl_ctx);
    int tls_server_sock = create_listening_socket(TLS_PORT);
    if (tls_server_sock < 0) return 1;
    std::cout << "Server listening for TLS on port " << TLS_PORT << "..." << std::endl;

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
                                if (client.recv_buffer.size() >= METADATA_SIZE_LINKTYPE) {
                                    uint32_t link_type_net;
                                    memcpy(&link_type_net, client.recv_buffer.data(), METADATA_SIZE_LINKTYPE);
                                    client.datalink_type = static_cast<int>(ntohl(link_type_net));
                                    client.recv_buffer.erase(client.recv_buffer.begin(), client.recv_buffer.begin() + METADATA_SIZE_LINKTYPE);

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
                                if (client.recv_buffer.size() >= BLOCK_HEADER_SIZE) {
                                    const char* buf_ptr = client.recv_buffer.data();

                                    memcpy(&client.expected_flags, buf_ptr, sizeof(uint8_t));
                                    buf_ptr += sizeof(uint8_t);
                                    
                                    uint32_t original_size_net, payload_size_net;
                                    memcpy(&original_size_net, buf_ptr, sizeof(uint32_t));
                                    buf_ptr += sizeof(uint32_t);
                                    memcpy(&payload_size_net, buf_ptr, sizeof(uint32_t));

                                    client.expected_original_size = ntohl(original_size_net);
                                    client.expected_payload_size = ntohl(payload_size_net);

                                    client.recv_buffer.erase(client.recv_buffer.begin(), client.recv_buffer.begin() + BLOCK_HEADER_SIZE);
                                    
                                    client.current_fsm_state = ClientState::ReceiveFSM::AWAITING_BLOCK_PAYLOAD;
                                    processed_data_in_this_pass = true;
                                }
                                break;
                            
                            case ClientState::ReceiveFSM::AWAITING_BLOCK_PAYLOAD:
                                if (client.recv_buffer.size() >= client.expected_payload_size) {
                                    const char* payload_start = client.recv_buffer.data();
                                    const char* data_to_process = nullptr;
                                    size_t data_to_process_size = 0;

                                    bool is_compressed = (client.expected_flags & FLAG_COMPRESSED_ZSTD);
                                    if (is_compressed) {
                                        client.decompressed_buffer.resize(client.expected_original_size);
                                        
                                        size_t const decompressed_size = ZSTD_decompress(
                                            client.decompressed_buffer.data(), client.expected_original_size,
                                            payload_start, client.expected_payload_size
                                        );

                                        if (ZSTD_isError(decompressed_size) || decompressed_size != client.expected_original_size) {
                                            std::cerr << "ZSTD decompression failed for socket " << client_fd << ". Discarding block." << std::endl;
                                        } else {
                                            data_to_process = client.decompressed_buffer.data();
                                            data_to_process_size = decompressed_size;
                                        }
                                    } else {
                                        data_to_process = payload_start;
                                        data_to_process_size = client.expected_payload_size;
                                    }

                                    // Vòng lặp xử lý các gói tin bên trong block
                                    if (data_to_process != nullptr && data_to_process_size > 0) {
                                        const char* packet_ptr = data_to_process;
                                        size_t remaining_size = data_to_process_size;

                                        while (remaining_size >= PCAP_FIELDS_HEADER_SIZE) {
                                            uint32_t ts_sec_net, ts_usec_net, caplen_net, len_net;
                                            memcpy(&ts_sec_net, packet_ptr, sizeof(uint32_t));
                                            memcpy(&ts_usec_net, packet_ptr + 4, sizeof(uint32_t));
                                            memcpy(&caplen_net, packet_ptr + 8, sizeof(uint32_t));
                                            memcpy(&len_net, packet_ptr + 12, sizeof(uint32_t));
                                            
                                            packet_ptr += PCAP_FIELDS_HEADER_SIZE;
                                            remaining_size -= PCAP_FIELDS_HEADER_SIZE;
                                            
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