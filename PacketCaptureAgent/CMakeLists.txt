cmake_minimum_required(VERSION 3.10)
project(PacketCaptureAgent)

set(CMAKE_CXX_STANDARD 11)

# Tìm thư viện pcap (Linux)
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Install with: sudo apt-get install libpcap-dev")
endif()

# Tìm threads
find_package(Threads REQUIRED)

add_executable(PacketCaptureAgent main.cpp)

# Link với pcap và threads cho Linux
target_link_libraries(PacketCaptureAgent ${PCAP_LIBRARY} Threads::Threads)

# Thêm include directories nếu cần
target_include_directories(PacketCaptureAgent PRIVATE /usr/include/pcap)