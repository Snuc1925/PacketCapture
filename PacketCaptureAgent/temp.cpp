#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <csignal>
#include <atomic>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <pcap.h>
#include <cstring>
#include <unistd.h>
#include <cerrno>
#include <sys/socket.h>
#include <arpa/inet.h>

// --- Cấu trúc để chứa toàn bộ cấu hình ---
struct AppConfig {
    std::string server_ip = "127.0.0.1";
    int server_port = 8888;
    std::vector<std::string> interfaces;
    int pcap_buffer_size_mb = 32;
    int batch_packet_count = 256;
    size_t max_queue_blocks = 1024;
    int send_buffer_size_kb = 4096;
};

// --- Biến toàn cục ---
std::atomic<bool> capture_interrupted(false);
std::atomic<long long> total_bytes_sent(0);
std::atomic<long long> total_packets_sent(0);
std::vector<pcap_t*> global_pcap_handles;
std::mutex global_handles_mutex;

// --- Cấu trúc gói tin ---
struct CapturedPacket {
    pcap_pkthdr header;
    std::vector<u_char> data;
    CapturedPacket(const pcap_pkthdr* h, const u_char* d) : header(*h) {
        data.assign(d, d + h->caplen);
    }
};
using PacketBlock = std::vector<CapturedPacket>;

// --- Hàng đợi an toàn CÓ GIỚI HẠN (Bounded Thread-Safe Queue) ---
template<typename T>
class BoundedThreadSafeQueue {
private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cond_not_full_;
    std::condition_variable cond_not_empty_;
    size_t max_size_;
    std::atomic<bool> shutdown_ = {false};

public:
    explicit BoundedThreadSafeQueue(size_t max_size) : max_size_(max_size) {}

    void push(T item) {
        if (shutdown_) return;
        std::unique_lock<std::mutex> lock(mutex_);
        cond_not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;
        
        queue_.push(std::move(item));
        lock.unlock();
        cond_not_empty_.notify_one();
    }

    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_not_empty_.wait(lock, [this] { return !queue_.empty() || shutdown_; });
        if (shutdown_ && queue_.empty()) return false;
        
        item = std::move(queue_.front());
        queue_.pop();
        lock.unlock();
        cond_not_full_.notify_one();
        return true;
    }

    void shutdown() {
        shutdown_ = true;
        cond_not_full_.notify_all();
        cond_not_empty_.notify_all();
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
};

// --- Hàm tiện ích ---
bool send_all_data(int sockfd, const void* buffer, size_t length) {
    const char* ptr = static_cast<const char*>(buffer);
    while (length > 0) {
        ssize_t sent = send(sockfd, ptr, length, MSG_NOSIGNAL);
        if (sent <= 0) {
            if (sent < 0 && errno == EINTR) continue;
            std::cerr << "send_all_data error: " << strerror(errno) << std::endl;
            return false;
        }
        ptr += sent;
        length -= sent;
    }
    return true;
}

// Hàm trim để xóa khoảng trắng thừa
std::string trim(const std::string& s) {
    size_t first = s.find_first_not_of(" \t\n\r");
    if (std::string::npos == first) return s;
    size_t last = s.find_last_not_of(" \t\n\r");
    return s.substr(first, (last - first + 1));
}

// Hàm đọc cấu hình mới
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
            else if (key == "interfaces") {
                std::stringstream val_ss(value);
                std::string interface;
                while(std::getline(val_ss, interface, ',')) {
                    interface = trim(interface);
                    if (!interface.empty()) config.interfaces.push_back(interface);
                }
            }
        }
    }
    return !config.interfaces.empty();
}

// --- Luồng Capture (Producer) ---
void capture_thread_func(pcap_t* handle, const std::string& if_name, const AppConfig& config, BoundedThreadSafeQueue<PacketBlock>& queue) {
    std::cout << "Capture thread for " << if_name << " started." << std::endl;
    PacketBlock current_block;
    current_block.reserve(config.batch_packet_count);

    size_t packets_pushed = 0;
    size_t packets_received = 0;
    auto stats_start = std::chrono::steady_clock::now();

    while (!capture_interrupted) {
        pcap_pkthdr* header;
        const u_char* packet_data;
        int ret = pcap_next_ex(handle, &header, &packet_data);

        if (ret == 1) {
            current_block.emplace_back(header, packet_data);
            packets_received++; // Đếm luôn cả gói nhận được            
            if (current_block.size() >= static_cast<size_t>(config.batch_packet_count)) {
                queue.push(std::move(current_block));
                packets_pushed += config.batch_packet_count;                
                current_block.clear();
                current_block.reserve(config.batch_packet_count);
            }
        } else if (ret == 0) {
            if (!current_block.empty()) {
                queue.push(std::move(current_block));
                current_block.clear();
                current_block.reserve(config.batch_packet_count);
            }
        } else if (ret == PCAP_ERROR_BREAK) {
            break;
        } else if (ret < 0) {
            std::cerr << "Error reading packets on " << if_name << ": " << pcap_geterr(handle) << std::endl;
            capture_interrupted = true;
            break;
        }
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - stats_start);
        if (elapsed.count() >= 1) {
            std::cout << "Packets received in last second: " << packets_received
                    << ", Packets pushed to queue: " << packets_pushed << std::endl;
            packets_received = 0;
            packets_pushed = 0;
            stats_start = now;
        }        
    }
    if (!current_block.empty()) {
        queue.push(std::move(current_block));
    }
    std::cout << "Capture thread for " << if_name << " finished." << std::endl;
}

// --- Luồng Sender (Consumer) ---
void sender_thread_func(int client_socket, const AppConfig& config, BoundedThreadSafeQueue<PacketBlock>& queue) {
    std::cout << "Sender thread started." << std::endl;
    PacketBlock block_to_send;
    std::vector<char> send_buffer;
    send_buffer.reserve(static_cast<size_t>(config.send_buffer_size_kb) * 1024);

    while (true) {
        if (!queue.pop(block_to_send)) break;
        
        send_buffer.clear();
        for (const auto& packet : block_to_send) {
            uint32_t ts_sec_net = htonl(static_cast<uint32_t>(packet.header.ts.tv_sec));
            uint32_t ts_usec_net = htonl(static_cast<uint32_t>(packet.header.ts.tv_usec));
            uint32_t caplen_net = htonl(packet.header.caplen);
            uint32_t len_net = htonl(packet.header.len);
            
            size_t current_pos = send_buffer.size();
            size_t packet_total_size = sizeof(uint32_t) * 4 + packet.header.caplen;
            send_buffer.resize(current_pos + packet_total_size);
            
            char* ptr = send_buffer.data() + current_pos;
            memcpy(ptr, &ts_sec_net, sizeof(ts_sec_net)); ptr += sizeof(ts_sec_net);
            memcpy(ptr, &ts_usec_net, sizeof(ts_usec_net)); ptr += sizeof(ts_usec_net);
            memcpy(ptr, &caplen_net, sizeof(caplen_net)); ptr += sizeof(caplen_net);
            memcpy(ptr, &len_net, sizeof(len_net)); ptr += sizeof(len_net);
            if (packet.header.caplen > 0) {
                memcpy(ptr, packet.data.data(), packet.header.caplen);
            }
        }

        if (!send_buffer.empty()) {
            if (!send_all_data(client_socket, send_buffer.data(), send_buffer.size())) {
                std::cerr << "Failed to send data batch to server. Stopping." << std::endl;
                capture_interrupted = true;
                queue.shutdown();
                break;
            }
            total_bytes_sent += send_buffer.size();
            total_packets_sent += block_to_send.size();
        }
    }
    std::cout << "Sender thread finished." << std::endl;
}

// --- Signal Handler ---
BoundedThreadSafeQueue<PacketBlock>* global_queue_ptr = nullptr;
void signal_handler(int signum) {
    std::cout << "\nSignal " << signum << " received. Shutting down..." << std::endl;
    capture_interrupted = true;
    // if (global_queue_ptr) {
    //     global_queue_ptr->shutdown();
    // }
    std::lock_guard<std::mutex> lock(global_handles_mutex);
    for (pcap_t* handle : global_pcap_handles) {
        if (handle) pcap_breakloop(handle);
    }
}

// --- Main Function ---
int main() {
    AppConfig config;
    if (!parse_config("config.txt", config)) {
        std::cerr << "Failed to parse config.txt or no interfaces specified. Exiting." << std::endl;
        return 1;
    }
    
    // Tạo queue với kích thước từ config
    BoundedThreadSafeQueue<PacketBlock> packet_queue(config.max_queue_blocks);
    global_queue_ptr = &packet_queue;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::vector<std::thread> capture_threads;
    std::map<uint32_t, std::string> interface_map;
    char errbuf[PCAP_ERRBUF_SIZE];
    int link_type = -1;

    for (size_t i = 0; i < config.interfaces.size(); ++i) {
        const auto& if_name = config.interfaces[i];
        pcap_t* handle = pcap_create(if_name.c_str(), errbuf);
        if (!handle) { /* ... error handling ... */ continue; }
        
        pcap_set_buffer_size(handle, config.pcap_buffer_size_mb * 1024 * 1024);
        pcap_set_snaplen(handle, 65535);
        pcap_set_promisc(handle, 1);
        pcap_set_timeout(handle, 1);
        pcap_set_tstamp_precision(handle, PCAP_TSTAMP_PRECISION_NANO);
        
        if (pcap_activate(handle) < 0) { /* ... error handling ... */ continue; }
        
        if (link_type == -1) link_type = pcap_datalink(handle);
        
        std::cout << "Successfully activated interface: " << if_name << std::endl;
        
        { std::lock_guard<std::mutex> lock(global_handles_mutex); global_pcap_handles.push_back(handle); }
        interface_map[i] = if_name;
        capture_threads.emplace_back(capture_thread_func, handle, if_name, std::cref(config), std::ref(packet_queue));
    }

    if (global_pcap_handles.empty()) { /* ... error handling ... */ return 1; }

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(config.server_port);
    inet_pton(AF_INET, config.server_ip.c_str(), &serv_addr.sin_addr);
    
    if (connect(client_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connect failed");
        capture_interrupted = true;
        packet_queue.shutdown();
    } else {
        std::cout << "Agent: Connected to server." << std::endl;
        uint32_t link_type_net = htonl(static_cast<uint32_t>(link_type));
        if (!send_all_data(client_socket, &link_type_net, sizeof(link_type_net))) return 1;
    }

    auto capture_start_time = std::chrono::high_resolution_clock::now();
    std::cout << "\nAgent: Starting packet capture... Press Ctrl+C to stop.\n" << std::endl;
    
    std::thread sender_t;
    if (!capture_interrupted) {
        sender_t = std::thread(sender_thread_func, client_socket, std::cref(config), std::ref(packet_queue));
    }
    
    std::cout << "Main: Waiting for capture threads to finish..." << std::endl;
    for(auto& t : capture_threads) { if(t.joinable()) t.join(); }
    std::cout << "Main: All capture threads have finished." << std::endl;

    std::cout << "Main: Shutting down packet queue..." << std::endl;
    packet_queue.shutdown();

    std::cout << "Main: Waiting for sender thread to finish..." << std::endl;
    if (sender_t.joinable()) sender_t.join();
    std::cout << "Main: Sender thread has finished." << std::endl;
    
    // ... Phần in thống kê giữ nguyên ...
    auto capture_end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = capture_end_time - capture_start_time;

    std::cout << "\n\nAgent: Capture completed!\n";
    std::cout << "Total packets sent: " << total_packets_sent.load() << std::endl;
    std::cout << "Total bytes sent: " << std::fixed << std::setprecision(2) 
              << (double)total_bytes_sent.load() / (1024.0 * 1024.0) << " MB\n";
    std::cout << "Capture duration: " << std::fixed << std::setprecision(2) 
              << duration.count() << " seconds\n";
    if (duration.count() > 0) {
        double avg_mbps = (total_bytes_sent.load() * 8.0) / (1024.0 * 1024.0) / duration.count();
        std::cout << "Average sending rate: " << std::fixed << std::setprecision(2) << avg_mbps << " Mbps\n";
    }
    
    struct pcap_stat ps;
    {
        std::lock_guard<std::mutex> lock(global_handles_mutex);
        for(size_t i = 0; i < global_pcap_handles.size(); ++i) {
            if (pcap_stats(global_pcap_handles[i], &ps) == 0) {
                std::cout << "\nPcap stats for " << interface_map[i] << ":\n";
                std::cout << "  Packets received: " << ps.ps_recv << std::endl;
                std::cout << "  Packets dropped by kernel: " << ps.ps_drop << std::endl;
                std::cout << "  Packets dropped by interface: " << ps.ps_ifdrop << std::endl;
            }
            pcap_close(global_pcap_handles[i]);
        }
        global_pcap_handles.clear();
    }    
    
    close(client_socket);
    std::cout << "Agent: Exiting." << std::endl;
    return 0;
}