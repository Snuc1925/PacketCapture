#include <pcap.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cstring> // For strerror, memcpy
#include <csignal> // For signal, SIGINT, SIGTERM
#include <algorithm> // For std::min if needed

// Socket headers for Linux
#include <sys/socket.h>
#include <arpa/inet.h> // For htonl, htons, inet_pton
#include <unistd.h>    // For close, geteuid
#include <cerrno>      // For errno

// Global variables
pcap_t* global_handle = nullptr;
int global_client_socket = -1; // Socket để gửi dữ liệu
volatile sig_atomic_t capture_interrupted = 0; // Dùng volatile vì được sửa trong signal handler

// Thống kê
long long total_bytes_sent = 0;
long long total_packets_sent = 0;
std::chrono::time_point<std::chrono::high_resolution_clock> capture_start_time;


// Signal handler for graceful shutdown
void signal_handler_agent(int signum) {
    std::cout << "\nAgent: Signal " << signum << " received. Interrupting capture..." << std::endl;
    capture_interrupted = 1;
    if (global_handle) {
        // Yêu cầu pcap_loop dừng lại. Nó sẽ không dừng ngay lập tức
        // mà sẽ dừng sau khi xử lý xong gói tin hiện tại (nếu có)
        // hoặc khi timeout của pcap_open_live hết hạn (nếu không có gói tin nào)
        pcap_breakloop(global_handle);
    }
    // Không đóng socket ở đây vì pcap_loop có thể vẫn đang gửi gói cuối cùng.
    // Socket sẽ được đóng trong main sau khi pcap_loop kết thúc.
}

// Hàm tiện ích để gửi dữ liệu an toàn, đảm bảo gửi đủ số byte yêu cầu
bool send_all_data(int sockfd, const void* buffer, size_t length) {
    const char* ptr = static_cast<const char*>(buffer);
    while (length > 0) {
        ssize_t sent = send(sockfd, ptr, length, 0); // MSG_NOSIGNAL có thể hữu ích để tránh SIGPIPE
        if (sent <= 0) {
            if (sent < 0) { // Lỗi thực sự
                 if (errno == EINTR) continue; // Bị ngắt bởi signal, thử lại
                 std::cerr << "Agent: send_all_data error: " << strerror(errno) << std::endl;
            } else { // sent == 0, kết nối có thể đã đóng bởi peer
                 std::cerr << "Agent: send_all_data returned 0 (connection closed by peer?)" << std::endl;
            }
            return false; // Không gửi được
        }
        ptr += sent;
        length -= sent;
    }
    return true; // Gửi thành công
}

// Callback function cho pcap_loop
void packet_handler_callback(u_char *user_data_socket, const struct pcap_pkthdr *header, const u_char *packet_bytes) {
    if (capture_interrupted) { // Kiểm tra lại cờ ngắt
        return;
    }

    int client_sock = *(reinterpret_cast<int*>(user_data_socket));

    // Bỏ qua các gói tin quá nhỏ nếu vẫn muốn logic này
    if (header->caplen < 100) { // Giữ lại logic filter của bạn
        return;
    }

    // Chuẩn bị pcap_pkthdr để gửi (chuyển sang Network Byte Order)
    uint32_t ts_sec_net = htonl(static_cast<uint32_t>(header->ts.tv_sec));
    uint32_t ts_usec_net = htonl(static_cast<uint32_t>(header->ts.tv_usec));
    uint32_t caplen_net = htonl(header->caplen);
    uint32_t len_net = htonl(header->len); // Original length

    // Gửi tuần tự: ts_sec, ts_usec, caplen, len, packet_data
    bool success = true;
    if (success) success = send_all_data(client_sock, &ts_sec_net, sizeof(ts_sec_net));
    if (success) success = send_all_data(client_sock, &ts_usec_net, sizeof(ts_usec_net));
    if (success) success = send_all_data(client_sock, &caplen_net, sizeof(caplen_net));
    if (success) success = send_all_data(client_sock, &len_net, sizeof(len_net));
    
    if (success && header->caplen > 0) { // Chỉ gửi data nếu có
        success = send_all_data(client_sock, packet_bytes, header->caplen);
    }

    if (!success) {
        std::cerr << "Agent: Failed to send packet data to server. Stopping capture." << std::endl;
        capture_interrupted = 1;
        if (global_handle) {
            pcap_breakloop(global_handle); // Yêu cầu dừng pcap_loop
        }
        return; // Thoát callback
    }

    // Cập nhật thống kê
    total_bytes_sent += sizeof(ts_sec_net) + sizeof(ts_usec_net) + sizeof(caplen_net) + sizeof(len_net) + header->caplen;
    total_packets_sent++;
    
    // Bạn có thể thêm lại logic tính Mbps ở đây nếu muốn,
    // nhưng nó sẽ làm callback phức tạp hơn.
    // Cân nhắc tính toán ở main thread dựa trên total_bytes_sent và thời gian.
}


int main() {
    // Set up signal handlers
    signal(SIGINT, signal_handler_agent);
    signal(SIGTERM, signal_handler_agent);
    
    pcap_if_t* alldevs = nullptr; // Khởi tạo nullptr
    char errbuf[PCAP_ERRBUF_SIZE];

    if (geteuid() != 0) {
        std::cerr << "Agent Warning: This program may need to run as root for packet capture.\n";
        // std::cerr << "Try: sudo " << "./your_program_name" << std::endl; // Thay your_program_name
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Agent Error finding devices: " << errbuf << std::endl;
        return 1;
    }

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

    int choice = -1;
    std::cout << "\nAgent: Enter the number of the device to use (0-" << (deviceList.size()-1) << "): ";
    std::cin >> choice;

    if (std::cin.fail() || choice < 0 || choice >= static_cast<int>(deviceList.size())) {
        std::cerr << "Agent: Invalid choice.\n";
        if (std::cin.fail()) { // Xử lý lỗi nhập không phải số
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_if_t* dev = deviceList[choice];
    std::cout << "Agent: Using device: " << dev->name << std::endl;

    // Mở device để capture
    // snaplen 65535 (thường được dùng), promisc on, timeout 1000ms
    global_handle = pcap_open_live(dev->name, 65535, 1, 1000, errbuf);
    
    if (!global_handle) {
        std::cerr << "Agent: Unable to open device " << dev->name << ": " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    int link_type = pcap_datalink(global_handle);
    std::cout << "Agent: Link layer type for " << dev->name << ": " 
              << link_type << " (" << pcap_datalink_val_to_name(link_type) << ")" << std::endl;


    // Tạo socket kết nối đến center
    global_client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (global_client_socket < 0) {
        perror("Agent: Socket creation failed");
        pcap_close(global_handle); // Đóng pcap handle đã mở
        pcap_freealldevs(alldevs);
        return 1;
    }

    sockaddr_in center_addr{};
    center_addr.sin_family = AF_INET;
    center_addr.sin_port = htons(8888);  // Port phía center (mặc định trong server code)
    // Lấy IP server từ người dùng hoặc hardcode
    const char* server_ip_env = getenv("PACKET_SERVER_IP");
    std::string server_ip_str = server_ip_env ? server_ip_env : "127.0.0.1";
    
    std::cout << "Agent: Attempting to connect to server at " << server_ip_str << ":8888" << std::endl;

    if (inet_pton(AF_INET, server_ip_str.c_str(), &center_addr.sin_addr) <= 0) {
        std::cerr << "Agent: Invalid server IP address format." << std::endl;
        close(global_client_socket);
        pcap_close(global_handle);
        pcap_freealldevs(alldevs);
        return 1;
    }


    if (connect(global_client_socket, (sockaddr*)&center_addr, sizeof(center_addr)) < 0) {
        perror("Agent: Connect to center failed");
        close(global_client_socket);
        pcap_close(global_handle);
        pcap_freealldevs(alldevs);
        return 1;
    }
    std::cout << "Agent: Connected to center." << std::endl;

    // Gửi Datalink Type cho server
    uint32_t link_type_net = htonl(static_cast<uint32_t>(link_type));
    if (!send_all_data(global_client_socket, &link_type_net, sizeof(link_type_net))) {
        std::cerr << "Agent: Failed to send datalink type to server. Closing." << std::endl;
        close(global_client_socket);
        pcap_close(global_handle);
        pcap_freealldevs(alldevs);
        return 1;
    }
    std::cout << "Agent: Sent datalink type (" << link_type << ") to server." << std::endl;


    std::cout << "Agent: Starting packet capture... Press Ctrl+C to stop.\n\n";
    capture_start_time = std::chrono::high_resolution_clock::now();

    // Bắt đầu vòng lặp capture gói tin
    // Tham số thứ 2 của pcap_loop:
    //   -1: loop vô hạn cho đến khi pcap_breakloop được gọi hoặc lỗi
    //   0:  loop vô hạn (giống -1 trên nhiều hệ thống)
    //   N > 0: dừng sau N gói tin
    int pcap_loop_status = pcap_loop(global_handle, -1, packet_handler_callback, reinterpret_cast<u_char*>(&global_client_socket));

    if (pcap_loop_status == -1) { // Lỗi từ pcap_loop
        std::cerr << "Agent: pcap_loop error: " << pcap_geterr(global_handle) << std::endl;
    } else if (pcap_loop_status == -2) { // pcap_breakloop được gọi
        std::cout << "Agent: pcap_loop was interrupted by pcap_breakloop (signal or send error)." << std::endl;
    } else if (pcap_loop_status == 0){ // Nếu count là 0 (ko nên với -1) hoặc đã xử lý đủ số gói tin (nếu count > 0)
        std::cout << "Agent: pcap_loop finished normally." << std::endl;
    } else {
        std::cout << "Agent: pcap_loop returned: " << pcap_loop_status << std::endl;
    }

    auto capture_end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_capture_duration = capture_end_time - capture_start_time;
    
    std::cout << "\n\nAgent: Capture completed!\n";
    std::cout << "Total packets sent to server: " << total_packets_sent << std::endl;
    std::cout << "Total bytes sent (including headers): " << std::fixed << std::setprecision(2) 
              << (double)total_bytes_sent / (1024.0 * 1024.0) << " MB\n";
    std::cout << "Capture duration: " << std::fixed << std::setprecision(2) 
              << total_capture_duration.count() << " seconds\n";
    if (total_capture_duration.count() > 0) {
        double avg_mbps = (total_bytes_sent * 8.0) / (1024.0 * 1024.0) / total_capture_duration.count();
        std::cout << "Average sending rate: " << std::fixed << std::setprecision(2) << avg_mbps << " Mbps\n";
    }

    // Dọn dẹp
    if (global_client_socket != -1) {
        std::cout << "Agent: Closing connection to server." << std::endl;
        close(global_client_socket);
        global_client_socket = -1;
    }
    if (global_handle) {
        pcap_close(global_handle);
        global_handle = nullptr;
    }
    if (alldevs) {
        pcap_freealldevs(alldevs);
        alldevs = nullptr;
    }

    std::cout << "Agent: Exiting." << std::endl;
    return 0;
}