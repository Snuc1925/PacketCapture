// --- Cấu trúc để chứa toàn bộ cấu hình ---
struct AppConfig {
    std::string server_ip = "127.0.0.1";
    int server_port = 8888;
    std::vector<std::string> interfaces;
    int pcap_buffer_size_mb = 32;
    int batch_packet_count = 256;
    size_t max_queue_blocks = 1024;
    int send_buffer_size_kb = 4096;
    bool encrypt = false; // Thêm cấu hình mã hóa
};

struct TrafficFilter {
    std::string ip_src;
    std::string ip_dst;
    std::string port;
    std::string protocol;
};

// ... Các phần khác như BoundedThreadSafeQueue, CapturedPacket giữ nguyên ...
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

class IConnection {
public:
    virtual ~IConnection() = default; // Destructor ảo là BẮT BUỘC
    virtual bool connect(const std::string& ip, int port) = 0;
    virtual bool send_data(const void* buffer, size_t length) = 0;
    virtual void disconnect() = 0;
};


// --- Lớp cho kết nối TCP thông thường (không mã hóa) ---
class PlainTcpConnection : public IConnection {
private:
    int sockfd_ = -1;

public: {
    ...
}

class TlsConnection : public IConnection {
private:
public:
}

std::unique_ptr<IConnection> create_connection(const AppConfig& config) {
    if (config.encrypt) {
        std::cout << "TLS Connection!!!" << std::endl;
        return std::make_unique<TlsConnection>();
    } else {
        return std::make_unique<PlainTcpConnection>();
        std::cout << "PlainTCP Connection!!!" << std::endl;
    }
}
// ----------------------------------------------------------

void capture_thread_func(pcap_t* handle, const std::string& if_name, const AppConfig& config, BoundedThreadSafeQueue<PacketBlock>& queue) {
    std::cout << "Capture thread for " << if_name << " started." << std::endl;
    PacketBlock current_block;
    current_block.reserve(config.batch_packet_count);

    size_t packets_pushed = 0;
    size_t packets_received = 0;
    size_t bytes_received = 0;

    auto stats_start = std::chrono::steady_clock::now();

    while (!capture_interrupted) {
        pcap_pkthdr* header;
        const u_char* packet_data;
        int ret = pcap_next_ex(handle, &header, &packet_data);

        if (ret == 1) {
            current_block.emplace_back(header, packet_data);
            packets_received++;
            bytes_received += header->caplen;

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
        auto elapsed = std::chrono::duration<double>(now - stats_start);
        if (elapsed.count() >= 1.0) {
            double mbps = (bytes_received * 8.0) / 1e6; // Megabit
            std::cout << std::fixed << std::setprecision(2)
                      << "Stats (" << if_name << ") [elapsed: " << elapsed.count() << "s]: "
                      << "Packets received: " << packets_received
                      << ", Pushed: " << packets_pushed
                      << ", Traffic: " << mbps << " Mb/s" << std::endl;

            packets_received = 0;
            packets_pushed = 0;
            bytes_received = 0;
            stats_start = now;
        }
    }

    if (!current_block.empty()) {
        queue.push(std::move(current_block));
    }

    std::cout << "Capture thread for " << if_name << " finished." << std::endl;
}

// ======================================================================================
// *** PHẦN MỚI: INTERFACE VÀ CÁC LỚP XỬ LÝ DỮ LIỆU (NÉN) ***
// ======================================================================================

// --- Interface cho xử lý dữ liệu (nén, etc.) ---
class IDataProcessor {
public:
    virtual ~IDataProcessor() = default;
    // Xử lý một khối dữ liệu, trả về khối dữ liệu đã được xử lý
    // Trả về một vector rỗng nếu có lỗi
    virtual std::vector<char> process(const std::vector<char>& input_buffer) = 0;
};

// --- Lớp xử lý "không làm gì cả" (khi không nén) ---
class PassThroughProcessor : public IDataProcessor {
public:
    std::vector<char> process(const std::vector<char>& input_buffer) override {
        // Chỉ đơn giản là trả về buffer gốc
        return input_buffer;
    }
};

// --- Lớp xử lý nén dữ liệu bằng Zstandard ---
class ZstdProcessor : public IDataProcessor {
public:
    std::vector<char> process(const std::vector<char>& input_buffer) override {
        if (input_buffer.empty()) {
            return {};
        }

        // Ước tính kích thước tối đa sau khi nén
        size_t const compressed_bound = ZSTD_compressBound(input_buffer.size());
        std::vector<char> compressed_buffer(compressed_bound);

        // Nén dữ liệu
        size_t const compressed_size = ZSTD_compress(
            compressed_buffer.data(), compressed_buffer.size(),
            input_buffer.data(), input_buffer.size(),
            1 // Mức nén, 1 là nhanh nhất, có thể tăng lên (e.g., 3) để nén tốt hơn
        );

        // Kiểm tra lỗi
        if (ZSTD_isError(compressed_size)) {
            std::cerr << "ZSTD compression error: " << ZSTD_getErrorName(compressed_size) << std::endl;
            return {}; // Trả về vector rỗng để báo lỗi
        }

        // Thay đổi kích thước vector về đúng kích thước đã nén
        compressed_buffer.resize(compressed_size);
        return compressed_buffer;
    }
};

// --- Factory để tạo ra đối tượng Processor phù hợp ---
std::unique_ptr<IDataProcessor> create_processor(const AppConfig& config) {
    if (config.compressed) {
        std::cout << "Data processing enabled: Zstandard Compression" << std::endl;
        return std::make_unique<ZstdProcessor>();
    } else {
        std::cout << "Data processing disabled: Pass-through" << std::endl;
        return std::make_unique<PassThroughProcessor>();
    }
}
// ======================================================================================



void sender_thread_func(IConnection& connection, const AppConfig& config, BoundedThreadSafeQueue<PacketBlock>& queue) {
    std::cout << "Sender thread started." << std::endl;

    PacketBlock block_to_send;
    std::vector<char> send_buffer;
    send_buffer.reserve(static_cast<size_t>(config.send_buffer_size_kb) * 1024);

    size_t total_bytes_sent_local = 0;
    size_t total_packets_sent_local = 0;
    auto stats_start = std::chrono::steady_clock::now();

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
            if (!connection.send_data(send_buffer.data(), send_buffer.size())) {
                std::cerr << "Failed to send data batch to server. Stopping." << std::endl;
                capture_interrupted = true;
                queue.shutdown();
                break;
            }
            total_bytes_sent += send_buffer.size();
            total_packets_sent += block_to_send.size();

            total_bytes_sent_local += send_buffer.size();
            total_packets_sent_local += block_to_send.size();
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration<double>(now - stats_start);
        if (elapsed.count() >= 1.0) {
            double mbps = (total_bytes_sent_local * 8.0) / 1e6; // megabits per second
            std::cout << std::fixed << std::setprecision(2)
                      << "Sender stats [elapsed: " << elapsed.count() << "s]: "
                      << "Packets sent: " << total_packets_sent_local
                      << ", Bytes sent: " << total_bytes_sent_local
                      << ", Bandwidth: " << mbps << " Mb/s" << std::endl;

            total_bytes_sent_local = 0;
            total_packets_sent_local = 0;
            stats_start = now;
        }
    }

    std::cout << "Sender thread finished." << std::endl;
}

int main() {
    AppConfig config;
    if (!parse_config("config.txt", config)) {
        std::cerr << "Failed to parse config.txt or no interfaces specified. Exiting." << std::endl;
        return 1;
    }

    // --- ĐỌC CẤU HÌNH LỌC VÀ TẠO CHUỖI BPF ---
    TrafficFilter filter_config;
    parse_filter_config("filter.txt", filter_config);
    std::string bpf_filter_string = build_bpf_string(filter_config);

    if (!bpf_filter_string.empty()) {
        std::cout << "Agent: Applying BPF filter: \"" << bpf_filter_string << "\"" << std::endl;
    }    

    BoundedThreadSafeQueue<PacketBlock> packet_queue(config.max_queue_blocks);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Phần capture threads giữ nguyên
    std::vector<std::thread> capture_threads;
    std::map<uint32_t, std::string> interface_map;
    char errbuf[PCAP_ERRBUF_SIZE];
    int link_type = -1;

    for (size_t i = 0; i < config.interfaces.size(); ++i) {
        // ... code khởi tạo pcap giữ nguyên ...
        const auto& if_name = config.interfaces[i];
        pcap_t* handle = pcap_create(if_name.c_str(), errbuf);
        if (!handle) { /* ... */ continue; }
        
        pcap_set_buffer_size(handle, config.pcap_buffer_size_mb * 1024 * 1024);
        pcap_set_snaplen(handle, 65535);
        pcap_set_promisc(handle, 1);
        pcap_set_timeout(handle, 1);
        pcap_set_tstamp_precision(handle, PCAP_TSTAMP_PRECISION_NANO);
        
        if (pcap_activate(handle) < 0) {
            std::cerr << "Error activating interface " << if_name << ": " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            continue;
        }

        // --- ÁP DỤNG BỘ LỌC BPF ---
        if (!bpf_filter_string.empty()) {
            struct bpf_program fp;
            // Chú ý: pcap_compile cần handle đã được activate
            if (pcap_compile(handle, &fp, bpf_filter_string.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
                std::cerr << "Error compiling BPF filter for " << if_name << ": " << pcap_geterr(handle) << std::endl;
                pcap_close(handle);
                continue; // Bỏ qua interface này nếu filter bị lỗi
            }

            if (pcap_setfilter(handle, &fp) == -1) {
                std::cerr << "Error setting BPF filter for " << if_name << ": " << pcap_geterr(handle) << std::endl;
                pcap_freecode(&fp);
                pcap_close(handle);
                continue; // Bỏ qua interface này nếu không set được filter
            }
            pcap_freecode(&fp); // Giải phóng bộ nhớ của chương trình filter đã compile
        }        

        
        if (link_type == -1) link_type = pcap_datalink(handle);
        
        std::cout << "Successfully activated interface: " << if_name << std::endl;
        
        { std::lock_guard<std::mutex> lock(global_handles_mutex); global_pcap_handles.push_back(handle); }
        interface_map[i] = if_name;
        capture_threads.emplace_back(capture_thread_func, handle, if_name, std::cref(config), std::ref(packet_queue));
    }

    
    if (global_pcap_handles.empty()) {
        std::cerr << "Agent: No interfaces were successfully initialized. Exiting." << std::endl;
        return 1;
    }

    auto connection = create_connection(config);

    if (!connection->connect(config.server_ip, config.server_port)) {
        std::cerr << "Agent: Could not connect to server. Shutting down capture." << std::endl;
        capture_interrupted = true;
        packet_queue.shutdown();
    } else {
        std::cout << "Agent: Connected to server." << std::endl;
        uint32_t link_type_net = htonl(static_cast<uint32_t>(link_type));
        if (!connection->send_data(&link_type_net, sizeof(link_type_net))) {
             std::cerr << "Agent: Failed to send link type. Exiting." << std::endl;
             return 1;
        }
    }

    auto capture_start_time = std::chrono::high_resolution_clock::now();
    std::cout << "\nAgent: Starting packet capture... Press Ctrl+C to stop.\n" << std::endl;
    
    std::thread sender_t;
    if (!capture_interrupted) {
        sender_t = std::thread(sender_thread_func, std::ref(*connection), std::cref(config), std::ref(packet_queue));
    }
    
    std::cout << "Main: Waiting for capture threads to finish..." << std::endl;
    for(auto& t : capture_threads) { if(t.joinable()) t.join(); }
    std::cout << "Main: All capture threads have finished." << std::endl;

    std::cout << "Main: Shutting down packet queue..." << std::endl;
    packet_queue.shutdown();

    std::cout << "Main: Waiting for sender thread to finish..." << std::endl;
    if (sender_t.joinable()) sender_t.join();
    std::cout << "Main: Sender thread has finished." << std::endl;
    
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
    
    std::cout << "Agent: Exiting." << std::endl;
    return 0;
}