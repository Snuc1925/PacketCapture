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
#include <pcap.h>
#include <cstring> // For strerror, memcpy
#include <unistd.h> // For close, geteuid
#include <cerrno>   // For errno
#include <sys/socket.h>
#include <arpa/inet.h>

// --- Cấu hình ---
const int PCAP_BUFFER_SIZE_MB = 32; // Buffer lớn cho pcap để giảm drop
const int BATCH_PACKET_COUNT = 256; // Số gói tin gom lại trước khi đẩy vào queue
const int SEND_BUFFER_SIZE_BYTES = 2 * 1024 * 1024; // 2MB buffer để gửi socket

// --- Biến toàn cục (sử dụng atomic để an toàn luồng) ---
std::atomic<bool> capture_interrupted(false);
std::atomic<long long> total_bytes_sent(0);
std::atomic<long long> total_packets_sent(0);

// --- Packet Data Structure ---
// Struct để lưu trữ một gói tin (header và data)
struct CapturedPacket {
    pcap_pkthdr header;
    std::vector<u_char> data;

    CapturedPacket(const pcap_pkthdr* h, const u_char* d) : header(*h) {
        data.assign(d, d + h->caplen);
    }
};

// --- Thread-Safe Queue ---
// Hàng đợi an toàn cho việc giao tiếp giữa các luồng
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
        std::unique_lock<std::mutex> lock(mutex_);
        queue_.push(std::move(item));
        lock.unlock();
        cond_var_.notify_one();
    }

    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_var_.wait(lock, [this] { return !queue_.empty() || shutdown_; });
        
        if (shutdown_ && queue_.empty()) {
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

    size_t size() {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
};

// Hàng đợi của chúng ta sẽ chứa các block gói tin
using PacketBlock = std::vector<CapturedPacket>;
ThreadSafeQueue<PacketBlock> packet_queue;

// --- Signal Handler ---
void signal_handler(int signum) {
    std::cout << "\nSignal " << signum << " received. Shutting down..." << std::endl;
    capture_interrupted = true;
    packet_queue.shutdown(); // Báo cho các luồng đang chờ trong queue thoát ra
}

// --- Hàm tiện ích gửi dữ liệu an toàn ---
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

// --- Luồng Capture (Producer) ---
void capture_thread_func(pcap_t* handle) {
    std::cout << "Capture thread started." << std::endl;
    PacketBlock current_block;
    current_block.reserve(BATCH_PACKET_COUNT);

    while (!capture_interrupted) {
        pcap_pkthdr* header;
        const u_char* packet_data;

        // Dùng pcap_next_ex() thay cho pcap_loop()
        int ret = pcap_next_ex(handle, &header, &packet_data);

        if (ret == 1) { // Got a packet
            current_block.emplace_back(header, packet_data);

            if (current_block.size() >= BATCH_PACKET_COUNT) {
                packet_queue.push(std::move(current_block));
                current_block.clear();
                current_block.reserve(BATCH_PACKET_COUNT);
            }
        } else if (ret == 0) { // Timeout
            // Nếu có gói đang chờ, đẩy nốt vào queue
            if (!current_block.empty()) {
                packet_queue.push(std::move(current_block));
                current_block.clear();
                current_block.reserve(BATCH_PACKET_COUNT);
            }
            continue;
        } else if (ret == -1) { // Error
            std::cerr << "Error reading packets: " << pcap_geterr(handle) << std::endl;
            capture_interrupted = true;
        } else if (ret == -2) { // End of file (for offline captures)
            std::cout << "End of capture file." << std::endl;
            capture_interrupted = true;
        }
    }

    // Đẩy nốt block cuối cùng nếu có
    if (!current_block.empty()) {
        packet_queue.push(std::move(current_block));
    }
    
    std::cout << "Capture thread finished." << std::endl;
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
            // Bỏ qua các gói tin nhỏ
            if (packet.header.caplen < 100) continue;
            
            // Chuẩn bị header để gửi
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

    // ... (Phần code chọn device của bạn giữ nguyên) ...
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) { /* ... error handling ... */ return 1; }
    // ... hiển thị và chọn device ...

    std::vector<pcap_if_t*> deviceList;
    int i = 0;
    std::cout << "Agent: Available network devices:\n";
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << i << ": " << d->name;
        if (d->description) {
            std::cout << " - " << d->description;
        } else {
            std::cout << " - No description available";
        }
        std::cout << std::endl;
        deviceList.push_back(d);
        i++;
    }

    if (deviceList.empty()) {
        std::cerr << "Agent: No devices found.\n";
        pcap_freealldevs(alldevs);
        return 1;
    }


    // Giả sử dev là device đã chọn
    std::cout << "Agent: Enter the number of the device to use: ";
    int choice;
    std::cin >> choice;
    pcap_if_t* dev = alldevs;
    for(int i=0; i<choice; ++i) dev = dev->next;
    std::cout << "Agent: Using device: " << dev->name << std::endl;


    // --- Kích hoạt Pcap với MMAP ---
    pcap_t* handle = pcap_create(dev->name, errbuf);
    if (!handle) { /* ... */ return 1; }
    pcap_set_buffer_size(handle, PCAP_BUFFER_SIZE_MB * 1024 * 1024);
    pcap_set_snaplen(handle, 65535);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1);
    pcap_set_tstamp_precision(handle, PCAP_TSTAMP_PRECISION_NANO);
    int status = pcap_activate(handle);
    if (status < 0) {
        std::cerr << "pcap_activate() failed: " << pcap_statustostr(status) << " - " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }
    std::cout << "Agent: Pcap activated successfully." << std::endl;
    int link_type = pcap_datalink(handle);
    
    // ... (Phần code kết nối socket của bạn giữ nguyên) ...
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    // ... connect to server ...
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8888);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    if (connect(client_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connect failed");
        return 1;
    }
    std::cout << "Agent: Connected to server." << std::endl;

    // Gửi Datalink Type
    uint32_t link_type_net = htonl(static_cast<uint32_t>(link_type));
    if (!send_all_data(client_socket, &link_type_net, sizeof(link_type_net))) { /* ... error ...*/ return 1; }
    std::cout << "Agent: Sent datalink type to server." << std::endl;

    // --- Khởi chạy các luồng ---
    auto capture_start_time = std::chrono::high_resolution_clock::now();
    std::cout << "Agent: Starting capture and sender threads..." << std::endl;

    std::thread capture_t(capture_thread_func, handle);
    std::thread sender_t(sender_thread_func, client_socket);

    // Chờ các luồng kết thúc (sau khi có tín hiệu Ctrl+C)
    capture_t.join();
    sender_t.join();

    // --- Dọn dẹp và In thống kê ---
    auto capture_end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_capture_duration = capture_end_time - capture_start_time;

    std::cout << "\n\nAgent: Capture completed!\n";
    std::cout << "Total packets sent: " << total_packets_sent.load() << std::endl;
    std::cout << "Total bytes sent (payload): " << std::fixed << std::setprecision(2) 
              << (double)total_bytes_sent.load() / (1024.0 * 1024.0) << " MB\n";
    std::cout << "Capture duration: " << std::fixed << std::setprecision(2) 
              << total_capture_duration.count() << " seconds\n";
    if (total_capture_duration.count() > 0) {
        double avg_mbps = (total_bytes_sent.load() * 8.0) / (1024.0 * 1024.0) / total_capture_duration.count();
        std::cout << "Average sending rate: " << std::fixed << std::setprecision(2) << avg_mbps << " Mbps\n";
    }
    
    // In thống kê từ pcap
    struct pcap_stat ps;
    if (pcap_stats(handle, &ps) == 0) {
        std::cout << "\nPcap stats:\n";
        std::cout << "  Packets received by filter: " << ps.ps_recv << std::endl;
        std::cout << "  Packets dropped by kernel:  " << ps.ps_drop << std::endl; // Quan trọng!!!
        std::cout << "  Packets dropped by interface: " << ps.ps_ifdrop << std::endl;
    }

    close(client_socket);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    std::cout << "Agent: Exiting." << std::endl;
    return 0;
}