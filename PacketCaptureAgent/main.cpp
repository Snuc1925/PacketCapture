#include <pcap.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <signal.h>

// Socket headers for Linux
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

const char* SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 8888;

// Global variables for cleanup
pcap_t* global_handle = nullptr;
pcap_dumper_t* global_dumper = nullptr;
bool capture_interrupted = false;

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    capture_interrupted = true;
    
    // if (global_dumper) {
    //     pcap_dump_close(global_dumper);
    //     global_dumper = nullptr;
    // }
    // if (global_handle) {
    //     pcap_close(global_handle);
    //     global_handle = nullptr;
    // }
}

int main() {
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    // signal(SIGTERM, signal_handler);
    
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Check if running as root (required for packet capture)
    if (geteuid() != 0) {
        std::cerr << "Warning: This program may need to run as root for packet capture.\n";
        std::cerr << "Try: sudo " << "./your_program_name" << std::endl;
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    std::vector<pcap_if_t*> deviceList;
    int i = 0;
    std::cout << "Available network devices:\n";
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
        std::cerr << "No devices found.\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    int choice = -1;
    std::cout << "\nEnter the number of the device to use (0-" << (deviceList.size()-1) << "): ";
    std::cin >> choice;

    if (choice < 0 || choice >= static_cast<int>(deviceList.size())) {
        std::cerr << "Invalid choice.\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_if_t* dev = deviceList[choice];
    std::cout << "Using device: " << dev->name << std::endl;

    // Open device with more appropriate parameters for Linux
    global_handle = pcap_open_live(dev->name, 
                                  65536,    // snaplen - capture entire packet
                                  1,        // promiscuous mode
                                  1000,     // timeout in ms
                                  errbuf);
    
    if (!global_handle) {
        std::cerr << "Unable to open device " << dev->name << ": " << errbuf << std::endl;
        std::cerr << "Make sure you have proper permissions (try running as root)\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Check if we can capture on this device
    // int link_type = pcap_datalink(global_handle);
    // std::cout << "Link layer type: " << pcap_datalink_val_to_name(link_type) << std::endl;

    std::cout << "Press Ctrl+C to stop capture early.\n\n";

    // Tạo socket kết nối đến center
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    sockaddr_in center_addr{};
    center_addr.sin_family = AF_INET;
    center_addr.sin_port = htons(8888);  // Port phía center
    inet_pton(AF_INET, "127.0.0.1", &center_addr.sin_addr);  // IP phía center

    if (connect(sock, (sockaddr*)&center_addr, sizeof(center_addr)) < 0) {
        perror("Connect to center failed");
        return 1;
    }

    std::cout << "Connected to center.\n";


    struct pcap_pkthdr* header;
    const u_char* data;
    int packet_count = 0;

    long long total_size = 0;

    int total_packets = 11398767;

    std::vector<double> speeds;  // Lưu tốc độ mỗi giây
    long long bytes_this_second = 0;

    auto start_capture = std::chrono::high_resolution_clock::now();
    auto last_print = std::chrono::high_resolution_clock::now();

    while (!capture_interrupted) {
        int res = pcap_next_ex(global_handle, &header, &data);

        if (header->caplen < 100) {
            continue;
        }

        if (res == 1) {
            total_size += header->caplen; 
            packet_count++;
            bytes_this_second += header->caplen;
            
            // Gửi độ dài và data sang center
            uint32_t len_net = htonl(header->caplen);  // network byte order
            if (send(sock, &len_net, sizeof(len_net), 0) <= 0) break;
            if (send(sock, data, header->caplen, 0) <= 0) break;

        } else if (res == -2) {
            // EOF
            break;
        } else if (res < 0) {
            std::cerr << "Capture error: " << pcap_geterr(global_handle) << std::endl;
            break;
        }
        auto now = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = now - last_print;
        if (elapsed.count() >= 1.0) {

            double mbps = (bytes_this_second * 8.0) / (1024 * 1024);  // Mbps
            std::cout << "Second " << (int)speeds.size() + 1 << ": " << mbps << " Mbps\n";
            speeds.push_back(mbps);

            bytes_this_second = 0;
            last_print = now;
        }
    }

    auto end_capture = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_time = end_capture - start_capture;
    
    std::cout << "\n\nCapture completed!\n";
    std::cout << "Total packets captured: " << packet_count << std::endl;
    std::cout << "Total size: " << std::fixed << std::setprecision(2) 
              << (double)total_size / (1024.0 * 1024.0) << " MB\n";
    std::cout << "Capture time: " << std::fixed << std::setprecision(2) 
              << total_time.count() << " seconds\n";

 
}