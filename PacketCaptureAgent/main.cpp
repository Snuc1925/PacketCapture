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

// --- Cấu hình ---
const char* CONFIG_FILE = "config.txt";
const int PCAP_BUFFER_SIZE_MB = 32;
const int BATCH_PACKET_COUNT = 256;
const int SEND_BUFFER_SIZE_BYTES = 2 * 1024 * 1024;
const char* SERVER_IP = "127.0.0.1";

// --- Biến toàn cục (sử dụng atomic và mutex để an toàn luồng) ---
std::atomic<bool> capture_interrupted(false);
std::atomic<long long> total_bytes_sent(0);
std::atomic<long long> total_packets_sent(0);
std::atomic<int> active_capture_threads(0);

std::vector<pcap_t*> global_pcap_handles;
std::mutex global_handles_mutex; // Mutex để bảo vệ vector handle toàn cục

// --- Cấu trúc dữ liệu ---
struct CapturedPacket {
    pcap_pkthdr header;
    std::vector<u_char> data;

    CapturedPacket(const pcap_pkthdr* h, const u_char* d)
        : header(*h) {
        data.assign(d, d + h->caplen);
    }
};

// --- Thread-Safe Queue (không thay đổi) ---
template<typename T>
class ThreadSafeQueue {
private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cond_var_;
    std::atomic<bool> shutdown_ = {false};
public:
    void push(T item) {
        if (shutdown_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(item));
        cond_var_.notify_one();
    }

    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_var_.wait(lock, [this] { return !queue_.empty() || shutdown_; });
        if (shutdown_ && queue_.empty()) return false;
        item = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    bool try_pop(T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) {
            return false;
        }
        item = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    void shutdown() {
        shutdown_ = true;
        cond_var_.notify_all();
    }
};

using PacketBlock = std::vector<CapturedPacket>;
ThreadSafeQueue<PacketBlock> packet_queue;

// --- Signal Handler ---
void signal_handler(int signum) {
    std::cout << "\nSignal " << signum << " received. Shutting down..." << std::endl;
    capture_interrupted = true;
    // packet_queue.shutdown();
    
    std::lock_guard<std::mutex> lock(global_handles_mutex);
    for (pcap_t* handle : global_pcap_handles) {
        if (handle) pcap_breakloop(handle);
    }
}

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

std::vector<std::string> read_config(const std::string& filename) {
    std::ifstream config_file(filename);
    std::vector<std::string> interfaces;
    std::string line;

    if (!config_file.is_open()) {
        std::cerr << "Error: Could not open config file: " << filename << std::endl;
        return interfaces;
    }

    while (std::getline(config_file, line)) {
        // Bỏ qua comment và dòng trống
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        std::stringstream ss(line);
        std::string key;
        if (std::getline(ss, key, '=')) {
            if (key == "interfaces") {
                std::string value;
                std::getline(ss, value);
                std::stringstream val_ss(value);
                std::string interface;
                while(std::getline(val_ss, interface, ',')) {
                    // Xóa khoảng trắng thừa
                    interface.erase(std::remove_if(interface.begin(), interface.end(), ::isspace), interface.end());
                    if (!interface.empty()) {
                        interfaces.push_back(interface);
                    }
                }
            }
        }
    }
    return interfaces;
}

// --- Luồng Capture (Producer) ---
void capture_thread_func(pcap_t* handle, const std::string& if_name) {
    std::cout << "Capture thread for " << if_name << " started." << std::endl;
    PacketBlock current_block;
    current_block.reserve(BATCH_PACKET_COUNT);

    while (!capture_interrupted) {
        pcap_pkthdr* header;
        const u_char* packet_data;

        int ret = pcap_next_ex(handle, &header, &packet_data);

        if (ret == 1) { // Got a packet
            current_block.emplace_back(header, packet_data);
            if (current_block.size() >= BATCH_PACKET_COUNT) {
                packet_queue.push(std::move(current_block));
                current_block.clear();
                current_block.reserve(BATCH_PACKET_COUNT);
            }
        } else if (ret == 0) { // Timeout
            if (!current_block.empty()) {
                packet_queue.push(std::move(current_block));
                current_block.clear();
                current_block.reserve(BATCH_PACKET_COUNT);
            }
            continue;
        } else if (ret == PCAP_ERROR_BREAK) {
            break; // Thoát vòng lặp khi bị ngắt
        } else if (ret < 0) {
            std::cerr << "Error reading packets on " << if_name << ": " << pcap_geterr(handle) << std::endl;
            capture_interrupted = true;
            break;
        }
    }
    if (!current_block.empty()) {
        packet_queue.push(std::move(current_block));
    }
    active_capture_threads--;
    std::cout << "Capture thread for " << if_name << " finished." << std::endl;
}

// --- Luồng Sender (Consumer) ---
void sender_thread_func(int client_socket) {
    std::cout << "Sender thread started." << std::endl;
    PacketBlock block_to_send;
    std::vector<char> send_buffer;
    send_buffer.reserve(SEND_BUFFER_SIZE_BYTES);

    while (true) {
        if (!packet_queue.pop(block_to_send)) {
            // Queue đã bị shutdown và rỗng, thoát luồng
            break;
        }

        send_buffer.clear();
        long long block_packets = 0;
        long long block_bytes = 0;

        for (const auto& packet : block_to_send) {
            uint32_t ts_sec_net = htonl(static_cast<uint32_t>(packet.header.ts.tv_sec));
            uint32_t ts_usec_net = htonl(static_cast<uint32_t>(packet.header.ts.tv_usec));
            uint32_t caplen_net = htonl(packet.header.caplen);
            uint32_t len_net = htonl(packet.header.len);
            
            size_t current_pos = send_buffer.size();
            size_t packet_total_size = sizeof(ts_sec_net) * 4 + packet.header.caplen;
            send_buffer.resize(current_pos + packet_total_size);
            
            // Copy data vào buffer lớn
            char* ptr = send_buffer.data() + current_pos;
            memcpy(ptr, &ts_sec_net, sizeof(ts_sec_net)); ptr += sizeof(ts_sec_net);
            memcpy(ptr, &ts_usec_net, sizeof(ts_usec_net)); ptr += sizeof(ts_usec_net);
            memcpy(ptr, &caplen_net, sizeof(caplen_net)); ptr += sizeof(caplen_net);
            memcpy(ptr, &len_net, sizeof(len_net)); ptr += sizeof(len_net);
            if (packet.header.caplen > 0) {
                memcpy(ptr, packet.data.data(), packet.header.caplen);
            }
            
            block_packets++;
            block_bytes += packet_total_size;
        }

        if (!send_buffer.empty()) {
            if (!send_all_data(client_socket, send_buffer.data(), send_buffer.size())) {
                std::cerr << "Failed to send data batch to server. Stopping." << std::endl;
                capture_interrupted = true; // Báo cho luồng capture dừng
                packet_queue.shutdown(); // Dừng cả queue
                break;
            }
            total_bytes_sent += block_bytes;
            total_packets_sent += block_packets;
        }
    }
    std::cout << "Sender thread finished." << std::endl;
}

// --- Main Function ---
int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 1. Đọc cấu hình
    auto interfaces_to_capture = read_config(CONFIG_FILE);
    if (interfaces_to_capture.empty()) {
        std::cerr << "No interfaces specified in " << CONFIG_FILE << " or file not found. Exiting." << std::endl;
        return 1;
    }
    std::cout << "Agent will capture on: ";
    for(const auto& iface : interfaces_to_capture) std::cout << iface << " ";
    std::cout << std::endl;

    // 2. Kích hoạt Pcap handle cho từng interface
    std::vector<std::thread> capture_threads;
    std::map<uint32_t, std::string> interface_map;
    uint32_t current_id = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    int link_type = -1; // Giả định tất cả interface có cùng link-type

    for (const auto& if_name : interfaces_to_capture) {
        pcap_t* handle = pcap_create(if_name.c_str(), errbuf);
        if (!handle) {
            std::cerr << "pcap_create() for " << if_name << " failed: " << errbuf << std::endl;
            continue;
        }
        pcap_set_buffer_size(handle, PCAP_BUFFER_SIZE_MB * 1024 * 1024);
        pcap_set_snaplen(handle, 65535);
        pcap_set_promisc(handle, 1);
        pcap_set_timeout(handle, 1);
        pcap_set_tstamp_precision(handle, PCAP_TSTAMP_PRECISION_NANO);
        
        int status = pcap_activate(handle);
        if (status < 0) {
            std::cerr << "pcap_activate() for " << if_name << " failed: " << pcap_statustostr(status) << " - " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            continue;
        }
        
        if (link_type == -1) {
            link_type = pcap_datalink(handle);
        } else if (link_type != pcap_datalink(handle)) {
            std::cerr << "Warning: Mismatched datalink types between interfaces. This might cause issues on the server." << std::endl;
        }

        std::cout << "Successfully activated interface: " << if_name << " with ID: " << current_id << std::endl;
        
        { // Thêm handle vào vector toàn cục một cách an toàn
            std::lock_guard<std::mutex> lock(global_handles_mutex);
            global_pcap_handles.push_back(handle);
        }
        interface_map[current_id] = if_name;
        capture_threads.emplace_back(capture_thread_func, handle, if_name);
        current_id++;
    }

    if (global_pcap_handles.empty()) {
        std::cerr << "No interfaces could be activated. Exiting." << std::endl;
        return 1;
    }

    // 3. Kết nối Socket đến Server
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    // ... connect to server ... (thay IP nếu cần)
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8888);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);
    if (connect(client_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connect failed");
        capture_interrupted = true; // Báo các luồng capture dừng lại
    } else {
        std::cout << "Agent: Connected to server." << std::endl;

        // 4. Gửi thông tin khởi tạo (Datalink Type và Interface Map)
        // Gửi Datalink Type
        uint32_t link_type_net = htonl(static_cast<uint32_t>(link_type));
        if (!send_all_data(client_socket, &link_type_net, sizeof(link_type_net))) return 1;

        // Gửi số lượng interface
        // uint32_t map_size_net = htonl(interface_map.size());
        // if (!send_all_data(client_socket, &map_size_net, sizeof(map_size_net))) return 1;

        // Gửi từng cặp ID-Name
        // for(const auto& pair : interface_map) {
        //     uint32_t id_net = htonl(pair.first);
        //     uint32_t name_len_net = htonl(pair.second.length());
            
        //     if (!send_all_data(client_socket, &id_net, sizeof(id_net))) return 1;
        //     if (!send_all_data(client_socket, &name_len_net, sizeof(name_len_net))) return 1;
        //     if (!send_all_data(client_socket, pair.second.c_str(), pair.second.length())) return 1;
        // }
        // std::cout << "Agent: Sent initialization data to server." << std::endl;
    }

    // 5. Khởi chạy và chờ các luồng
    auto capture_start_time = std::chrono::high_resolution_clock::now();
    std::cout << "\nAgent: Starting packet capture... Press Ctrl+C to stop.\n" << std::endl;
    
    std::thread sender_t;
    if (!capture_interrupted) { // Chỉ chạy sender nếu kết nối thành công
        sender_t = std::thread(sender_thread_func, client_socket);
    }

    active_capture_threads = capture_threads.size();
    
    // 1. Chờ TẤT CẢ các luồng capture kết thúc.
    // Điều này đảm bảo tất cả các gói tin đã được đẩy hết vào queue.
    std::cout << "Main: Waiting for capture threads to finish..." << std::endl;
    for(auto& t : capture_threads) {
        if(t.joinable()) t.join();
    }
    std::cout << "Main: All capture threads have finished." << std::endl;

    // 2. SAU KHI tất cả các producer đã chết, báo cho queue rằng sẽ không có thêm hàng mới.
    // Điều này sẽ đánh thức luồng sender nếu nó đang chờ.
    std::cout << "Main: Shutting down packet queue..." << std::endl;
    packet_queue.shutdown();

    // 3. Bây giờ mới chờ luồng sender kết thúc.
    // Nó sẽ xử lý nốt các gói tin trong queue rồi tự thoát.
    std::cout << "Main: Waiting for sender thread to finish..." << std::endl;
    if (sender_t.joinable()) {
        sender_t.join();
    }
    std::cout << "Main: Sender thread has finished." << std::endl;
    
    // 6. Dọn dẹp và In thống kê
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