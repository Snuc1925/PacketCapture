cmake_minimum_required(VERSION 3.10)
project(PacketCaptureCenter)

set(CMAKE_CXX_STANDARD 17)

# Tìm thư viện pcap (Linux)
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Install with: sudo apt-get install libpcap-dev")
endif()

find_library(UDT_LIBRARY udt
  PATHS
    /usr/local/lib
    /usr/lib
    ${CMAKE_SOURCE_DIR}/udt/lib # Ví dụ nếu bạn build UDT trong thư mục con 'udt'
    # Thêm các đường dẫn tùy chỉnh khác nếu cần
)

find_path(UDT_INCLUDE_DIR udt.h
  PATHS
    /usr/local/include
    /usr/include/udt
    ${CMAKE_SOURCE_DIR}/udt/include # Ví dụ nếu bạn build UDT trong thư mục con 'udt'
    # Thêm các đường dẫn tùy chỉnh khác nếu cần
)

# Kiểm tra xem UDT đã được tìm thấy cả thư viện và header chưa
if(NOT UDT_LIBRARY OR NOT UDT_INCLUDE_DIR)
    message(FATAL_ERROR "UDT not found. Ensure UDT library (libudt) and headers (udt.h) are installed or built correctly. Check expected lib/ and include/ paths.")
endif()

# Tìm thư viện Zstd
find_library(ZSTD_LIBRARY zstd
  PATHS /usr/lib /usr/local/lib
)

# Tìm header Zstd
find_path(ZSTD_INCLUDE_DIR zstd.h
  PATHS /usr/include /usr/local/include
)


find_package(OpenSSL REQUIRED)
# Tìm threads
find_package(Threads REQUIRED)

add_executable(PacketCaptureCenter main.cpp)

# Link với pcap và threads cho Linux
target_link_libraries(PacketCaptureCenter 
    ${PCAP_LIBRARY} 
    ${UDT_LIBRARY}  
    ${ZSTD_LIBRARY}
    Threads::Threads
    OpenSSL::SSL          # Thư viện SSL của OpenSSL
    OpenSSL::Crypto       # Thư viện Crypto của OpenSSL
)

# Thêm include directories nếu cần
target_include_directories(PacketCaptureCenter PRIVATE 
    ${UDT_INCLUDE_DIR}
    ${ZSTD_INCLUDE_DIR}
    /usr/include/pcap
)