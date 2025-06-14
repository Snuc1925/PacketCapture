#include "connection/PlainTcpConnection.hpp"
#include "connection/TlsConnection.hpp"
#include "processor/ZstdProcessor.hpp"
#include "processor/ZlibProcessor.hpp"
#include "processor/PassThroughProcessor.hpp"
#include "utils/config_utils.hpp"
#include "concurrent/bounded_queue.hpp"
#include "logging/send_log.hpp"
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
#include <memory> 
#include <pcap.h>
#include <cstring>
#include <unistd.h>
#include <cerrno>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <zstd.h> 
#include <openssl/ssl.h>
#include <openssl/err.h>

const uint8_t FLAG_COMPRESSED_ZSTD = (1 << 0); // Bit 0 cho cờ nén ZSTD
const uint8_t FLAG_COMPRESSED_ZLIB = (1 << 1); // Bit 1: Zlib

const size_t BLOCK_HEADER_SIZE = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t);

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

// --- Factory để tạo ra đối tượng Connection phù hợp ---
std::unique_ptr<IConnection> create_connection(const AppConfig& config) {
    if (config.encrypt) {
        std::cout << "TLS Connection!!!" << std::endl;
        return std::make_unique<TlsConnection>();
    } else {
        return std::make_unique<PlainTcpConnection>();
        std::cout << "PlainTCP Connection!!!" << std::endl;
    }
}

// --- Factory để tạo ra đối tượng Processor phù hợp ---
std::unique_ptr<IDataProcessor> create_processor(const AppConfig& config) {
    if (config.compression == CompressionType::ZSTD) {
        std::cout << "Data processing enabled: Zstandard Compression" << std::endl;
        return std::make_unique<ZstdProcessor>();
    } else if (config.compression == CompressionType::ZLIB) {
        std::cout << "Data processing enabled: Zlib Compression" << std::endl;
        return std::make_unique<ZlibProcessor>();
    } else {
        std::cout << "Data processing disabled: Pass-through" << std::endl;
        return std::make_unique<PassThroughProcessor>();
    }
}


// --- Signal Handler ---
void signal_handler(int signum) {
    std::cout << "\nSignal " << signum << " received. Shutting down..." << std::endl;
    capture_interrupted = true;
    std::lock_guard<std::mutex> lock(global_handles_mutex);
    for (pcap_t* handle : global_pcap_handles) {
        if (handle) pcap_breakloop(handle);
    }
}


void capture_thread_func(pcap_t* handle, const std::string& if_name, const AppConfig& config,
                         BoundedThreadSafeQueue<PacketBlock>& queue) {
    PacketBlock current_block;
    current_block.reserve(config.batch_packet_count);

    while (!capture_interrupted) {
        pcap_pkthdr* header;
        const u_char* packet_data;
        int ret = pcap_next_ex(handle, &header, &packet_data);

        if (ret == 1) {
            current_block.emplace_back(header, packet_data);

            if (current_block.size() >= static_cast<size_t>(config.batch_packet_count)) {
                int sz = (int)current_block.size();
                queue.push(std::move(current_block));
                current_block.clear();
                current_block.reserve(config.batch_packet_count);
            }
        } else if (ret == 0) {
            if (!current_block.empty()) {
                int sz = (int)current_block.size();
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
    }

    if (!current_block.empty()) {
        int sz = (int)current_block.size();
        queue.push(std::move(current_block));
    }
}

void sender_thread_func(IConnection& connection, IDataProcessor& processor, const AppConfig& config, BoundedThreadSafeQueue<PacketBlock>& queue, SendLogger& send_logger) {
    std::cout << "Sender thread started." << std::endl;

    PacketBlock block_to_send;
    std::vector<char> serialization_buffer;
    std::vector<char> final_send_buffer; 
    serialization_buffer.reserve(static_cast<size_t>(config.send_buffer_size_kb) * 1024);

    size_t total_bytes_sent_local = 0;
    size_t total_packets_sent_local = 0;
    auto stats_start = std::chrono::steady_clock::now();

    while (true) {
        if (!queue.pop(block_to_send)) break;

        // === BẮT ĐẦU ĐO LƯỜNG CHO BLOCK HIỆN TẠI ===
        // Thời điểm bắt đầu xử lý block (sau khi lấy từ queue)
        auto block_processing_start_time = std::chrono::steady_clock::now();
        
        uint64_t total_waiting_time_us = 0;

        // Serialize dữ liệu và tính toán thời gian chờ
        serialization_buffer.clear();
        for (const auto& packet : block_to_send) {
            // Chuyển đổi pcap timestamp (system_clock) sang steady_clock để tính toán
            auto packet_capture_time_point = std::chrono::system_clock::from_time_t(packet.header.ts.tv_sec)
                                           + std::chrono::microseconds(packet.header.ts.tv_usec);

            // Thời gian chờ = thời điểm bắt đầu xử lý (của cả block) - thời điểm packet được capture
            // Lưu ý: Có thể ra số âm nếu đồng hồ hệ thống thay đổi. Dùng steady_clock cho block_processing_start_time để giảm thiểu vấn đề này.
            // Để tính toán chính xác, ta nên so sánh system_clock với system_clock.
            auto waiting_duration = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now() - packet_capture_time_point);
            
            // Lấy thời điểm bắt đầu xử lý của block dưới dạng system_clock để tính toán
            auto block_processing_start_system = std::chrono::system_clock::now();
            auto waiting_time = std::chrono::duration_cast<std::chrono::microseconds>(
                block_processing_start_system - packet_capture_time_point).count();

            total_waiting_time_us += (waiting_time > 0) ? waiting_time : 0;

            // ------------------ TEST LATENCY (Giữ nguyên logic của bạn) ------------------------
            std::chrono::system_clock::time_point now_sys = std::chrono::system_clock::now();
            uint64_t send_ts_us = std::chrono::duration_cast<std::chrono::microseconds>(now_sys.time_since_epoch()).count();
            uint32_t ts_sec = static_cast<uint32_t>(send_ts_us / 1000000);
            uint32_t ts_usec = static_cast<uint32_t>(send_ts_us % 1000000);
            uint32_t ts_sec_net = htonl(ts_sec);    
            uint32_t ts_usec_net = htonl(ts_usec);   
            // -----------------------------------------------------------------------------------

            uint32_t caplen_net = htonl(packet.header.caplen);
            uint32_t len_net = htonl(packet.header.len);

            size_t current_pos = serialization_buffer.size();
            size_t packet_total_size = sizeof(uint32_t) * 4 + packet.header.caplen;
            serialization_buffer.resize(current_pos + packet_total_size);

            char* ptr = serialization_buffer.data() + current_pos;
            memcpy(ptr, &ts_sec_net, sizeof(ts_sec_net)); ptr += sizeof(ts_sec_net);
            memcpy(ptr, &ts_usec_net, sizeof(ts_usec_net)); ptr += sizeof(ts_usec_net);
            memcpy(ptr, &caplen_net, sizeof(caplen_net)); ptr += sizeof(caplen_net);
            memcpy(ptr, &len_net, sizeof(len_net)); ptr += sizeof(len_net);
            if (packet.header.caplen > 0) {
                memcpy(ptr, packet.data.data(), packet.header.caplen);
            }
        }

        if (serialization_buffer.empty()) {
            continue;
        }

        // <<< THÊM MỚI: Đo lường thời gian xử lý (nén)
        auto processing_start_time = std::chrono::steady_clock::now();
        std::vector<char> processed_payload = processor.process(serialization_buffer);
        auto processing_end_time = std::chrono::steady_clock::now();

        if (processed_payload.empty() && config.compression != CompressionType::NONE) {
            std::cerr << "Compression failed, skipping block." << std::endl;
            continue;
        }

        uint8_t flags = 0;

        if (config.compression == CompressionType::ZSTD) {
            flags |= FLAG_COMPRESSED_ZSTD;
        } else if (config.compression == CompressionType::ZLIB) {
            flags |= FLAG_COMPRESSED_ZLIB;
        }

        uint32_t original_size = static_cast<uint32_t>(serialization_buffer.size());
        uint32_t payload_size = static_cast<uint32_t>(processed_payload.size());
        uint32_t original_size_net = htonl(original_size);
        uint32_t payload_size_net = htonl(payload_size);

        final_send_buffer.clear();
        final_send_buffer.resize(BLOCK_HEADER_SIZE + payload_size);
        char* ptr = final_send_buffer.data();
        memcpy(ptr, &flags, sizeof(flags)); ptr += sizeof(flags);
        memcpy(ptr, &original_size_net, sizeof(original_size_net)); ptr += sizeof(original_size_net);
        memcpy(ptr, &payload_size_net, sizeof(payload_size_net)); ptr += sizeof(payload_size_net);
        memcpy(ptr, processed_payload.data(), payload_size);

        // Gửi dữ liệu và ghi nhận thời gian kết thúc
        bool sent_success = connection.send_data(final_send_buffer.data(), final_send_buffer.size());
        auto send_end_time = std::chrono::steady_clock::now(); // Thời điểm gửi xong

        if (!sent_success) {
            std::cerr << "Failed to send data block to server. Stopping." << std::endl;
            capture_interrupted = true;
            queue.shutdown();
            break;
        }

        // === TÍNH TOÁN VÀ LƯU LOG ===
        // Yêu cầu 1: Thời gian chờ trung bình
        uint64_t avg_waiting_time_us = block_to_send.empty() ? 0 : total_waiting_time_us / block_to_send.size();
        
        // <<< THÊM MỚI: Tính toán thời gian xử lý/nén
        auto proc_duration = std::chrono::duration_cast<std::chrono::microseconds>(processing_end_time - processing_start_time);
        uint64_t processing_duration_us = proc_duration.count();

        // Tính toán tổng thời gian xử lý đến khi gửi xong
        auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(send_end_time - block_processing_start_time);
        uint64_t processing_to_send_duration_us = total_duration.count();

        // <<< MỚI: Tính toán avg_delay_per_packet_us
        double avg_delay_per_packet_us = 1.0 * (avg_waiting_time_us + processing_to_send_duration_us) / block_to_send.size();

        {
            send_logger.add_entry(SendLogEntry{
                block_to_send.size(),
                original_size,
                payload_size,
                avg_waiting_time_us,
                processing_duration_us,          // Giá trị mới   
                processing_to_send_duration_us,             
                avg_delay_per_packet_us
            });
        }            

        // Cập nhật thống kê (không thay đổi)
        total_bytes_sent_local += final_send_buffer.size();
        total_packets_sent_local += block_to_send.size();
        total_bytes_sent += serialization_buffer.size();
        total_packets_sent += block_to_send.size();

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration<double>(now - stats_start);
        if (elapsed.count() >= 1.0) {
            double mbps = (total_bytes_sent_local * 8.0) / 1e6;
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
    TrafficFilter filter_config;

    SendLogger send_logger;
    BoundedThreadSafeQueue<PacketBlock> packet_queue(config.max_queue_blocks);


    if (!parse_config("config.txt", config)) {
        std::cerr << "Failed to parse config.txt or no interfaces specified. Exiting." << std::endl;
        return 1;
    }

    // --- ĐỌC CẤU HÌNH LỌC VÀ TẠO CHUỖI BPF ---
    parse_filter_config("filter.txt", filter_config);
    std::string bpf_filter_string = build_bpf_string(filter_config);

    if (!bpf_filter_string.empty()) {
        std::cout << "Agent: Applying BPF filter: \"" << bpf_filter_string << "\"" << std::endl;
    }    

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Phần capture threads giữ nguyên
    std::vector<std::thread> capture_threads;
    std::map<uint32_t, std::string> interface_map;
    char errbuf[PCAP_ERRBUF_SIZE];
    int link_type = -1;

    for (size_t i = 0; i < config.interfaces.size(); ++i) {
        const auto& if_name = config.interfaces[i];
        pcap_t* handle = pcap_create(if_name.c_str(), errbuf);
        if (!handle) { /* ... */ continue; }
        
        pcap_set_buffer_size(handle, config.pcap_buffer_size_mb * 1024 * 1024);
        pcap_set_snaplen(handle, 65535);
        pcap_set_promisc(handle, 1);
        pcap_set_timeout(handle, 1);
        pcap_set_tstamp_precision(handle, PCAP_TSTAMP_PRECISION_MICRO);
        
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
    auto processor = create_processor(config);

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
        sender_t = std::thread(sender_thread_func, std::ref(*connection), std::ref(*processor), std::cref(config), std::ref(packet_queue), std::ref(send_logger));
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

    send_logger.save_to_file("/home/maimanh/Downloads/Code/VDT/Project/test/agent/send_log.csv");
    
    std::cout << "Agent: Exiting." << std::endl;
    return 0;
}