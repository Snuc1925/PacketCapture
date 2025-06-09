#include <iostream>
#include <cstring>
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <memory> // For std::unique_ptr

// System headers
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <cerrno>
#include <sys/time.h>

// Pcap headers
#include <pcap/pcap.h>

// OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>

// --- Cấu hình Server ---
const int PLAIN_TCP_PORT = 8888;
const int TLS_PORT = 8889; // Cổng riêng cho TLS
const size_t MAX_BUFFER_SIZE_PER_CLIENT = 1024 * 1024 * 1024; // 1 GB
const int MAX_CLIENTS = FD_SETSIZE;

// Kích thước các phần của thông điệp từ agent
const size_t METADATA_SIZE_LINKTYPE = sizeof(uint32_t);
const size_t PCAP_FIELDS_HEADER_SIZE = sizeof(uint32_t) * 4;

//========================================================
// LỚP TRỪU TƯỢNG VÀ CÁC LỚP CON CHO KẾT NỐI CLIENT
//========================================================

class IClientConnection {
public:
    virtual ~IClientConnection() = default;
    virtual int get_fd() const = 0;
    virtual ssize_t read(char* buffer, size_t size) = 0;
    virtual void close_connection() = 0;
    virtual std::string get_type() const = 0;
};

// --- Lớp cho kết nối TCP thường ---
class PlainTcpClient : public IClientConnection {
private:
    int fd_;
public:
    explicit PlainTcpClient(int fd) : fd_(fd) {}
    ~PlainTcpClient() override { close_connection(); }

    int get_fd() const override { return fd_; }
    
    ssize_t read(char* buffer, size_t size) override {
        return recv(fd_, buffer, size, 0);
    }

    void close_connection() override {
        if (fd_ != -1) {
            close(fd_);
            fd_ = -1;
        }
    }
    std::string get_type() const override { return "Plain TCP"; }
};

// --- Lớp cho kết nối TLS ---
class TlsClient : public IClientConnection {
private:
    int fd_;
    SSL* ssl_;
public:
    TlsClient(int fd, SSL* ssl) : fd_(fd), ssl_(ssl) {}
    ~TlsClient() override { close_connection(); }

    int get_fd() const override { return fd_; }

    ssize_t read(char* buffer, size_t size) override {
        return SSL_read(ssl_, buffer, size);
    }
    
    void close_connection() override {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (fd_ != -1) {
            close(fd_);
            fd_ = -1;
        }
    }
    std::string get_type() const override { return "TLS"; }
};


// ... Các struct PacketInfo và ClientState giữ nguyên, nhưng ClientState sẽ thay đổi ...
struct PacketInfo {
    pcap_pkthdr header;
    std::vector<unsigned char> data;
};

struct ClientState {
    std::unique_ptr<IClientConnection> connection; // Thay thế int fd
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

    ClientState() : 
        connection(nullptr),
        current_total_packets(0),
        current_total_bytes(0), 
        current_fsm_state(ReceiveFSM::AWAITING_METADATA_LINKTYPE),
        datalink_type(DLT_NULL)
    {}

    // Constructor để di chuyển (move) connection vào
    ClientState(std::unique_ptr<IClientConnection> conn, std::string ip, uint16_t p)
        : connection(std::move(conn)), ip_address(std::move(ip)), port(p),
          current_total_packets(0), current_total_bytes(0), 
          current_fsm_state(ReceiveFSM::AWAITING_METADATA_LINKTYPE), datalink_type(DLT_NULL)
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

    std::string filename = generate_pcap_filename(client.ip_address, client.port);
    std::cout << "Server: Saving " << client.current_total_bytes << " bytes, " << client.current_total_packets << " packets for client "
              << client.ip_address << ":" << client.port 
              << " (Datalink: " << client.datalink_type << " - " << pcap_datalink_val_to_name(client.datalink_type) << ") to " << filename << std::endl;

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

    pcap_close(pcap_handle_write);

    std::cout << "Server: Successfully saved " << filename << std::endl;

    client.buffered_packets.clear();
    client.current_total_bytes = 0;
    client.current_total_packets = 0;
}

//========================================================
// HÀM HELPER CHO TLS
//========================================================
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


//========================================================
// MAIN FUNCTION
//========================================================
int main() {
    // --- Khởi tạo Socket thường ---
    int tcp_server_sock = create_listening_socket(PLAIN_TCP_PORT);
    if (tcp_server_sock < 0) return 1;
    std::cout << "Server listening for PLAIN TCP on port " << PLAIN_TCP_PORT << "..." << std::endl;

    // --- Khởi tạo Socket TLS ---
    SSL_CTX *ssl_ctx = create_ssl_context();
    configure_ssl_context(ssl_ctx);
    int tls_server_sock = create_listening_socket(TLS_PORT);
    if (tls_server_sock < 0) return 1;
    std::cout << "Server listening for TLS on port " << TLS_PORT << "..." << std::endl;


    fd_set master_fds, read_fds;
    FD_ZERO(&master_fds);
    FD_SET(tcp_server_sock, &master_fds);
    FD_SET(tls_server_sock, &master_fds);
    int fd_max = std::max(tcp_server_sock, tls_server_sock);

    std::map<int, ClientState> clients_state;

    while (true) {
        read_fds = master_fds;
        if (select(fd_max + 1, &read_fds, nullptr, nullptr, nullptr) < 0) {
            if (errno == EINTR) continue;
            perror("Server: select failed");
            break;
        }

        for (int i = 0; i <= fd_max; ++i) {
            if (!FD_ISSET(i, &read_fds)) continue;

            // --- XỬ LÝ KẾT NỐI MỚI ---
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

            }
            // --- XỬ LÝ DỮ LIỆU TỪ CLIENT ---
            else {
                int client_fd = i;
                auto it = clients_state.find(client_fd);
                if (it == clients_state.end()) continue; // Should not happen

                ClientState& client = it->second;
                char temp_buf[8192];
                
                // Dùng phương thức read() của interface
                ssize_t nbytes = client.connection->read(temp_buf, sizeof(temp_buf));

                if (nbytes <= 0) {
                    // Xử lý ngắt kết nối
                     std::cout << "Server: Client " << client.ip_address << ":" << client.port
                                      << " (socket " << client_fd << ") disconnected." << std::endl;
                    if (!client.buffered_packets.empty()) {
                         save_packets_to_pcap(client);
                    }
                    // Destructor của ClientState sẽ tự động gọi connection->close_connection()
                    FD_CLR(client_fd, &master_fds);
                    clients_state.erase(it);
                    if (client_fd == fd_max) {
                        while (fd_max > std::max(tcp_server_sock, tls_server_sock) && !FD_ISSET(fd_max, &master_fds)) {
                            fd_max--;
                        }
                    }
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
                                    std::cout << "Server: Socket " << client_fd << " received Datalink: " << client.datalink_type << " (" << pcap_datalink_val_to_name(client.datalink_type) << ")." << std::endl;
                                }
                                break;
                            case ClientState::ReceiveFSM::AWAITING_PCAP_FIELDS_HEADER:
                                if (client.recv_buffer.size() >= PCAP_FIELDS_HEADER_SIZE) {
                                    // ... logic parse header giữ nguyên ...
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
                                    // ... logic xử lý data packet giữ nguyên ...
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
        // Destructor sẽ tự động đóng kết nối
    }
    clients_state.clear();

    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    close(tcp_server_sock);
    close(tls_server_sock);

    std::cout << "Server shutdown complete." << std::endl;
    return 0;
}