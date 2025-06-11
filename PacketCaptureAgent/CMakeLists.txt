cmake_minimum_required(VERSION 3.10)
project(PacketCaptureAgent)

set(CMAKE_CXX_STANDARD 17)

# Tìm thư viện PF_RING
find_library(PFRING_LIBRARY pfring
  PATHS
    /usr/lib
    /usr/local/lib
  NO_DEFAULT_PATH
)

# PF_RING headers thường ở /usr/local/include
find_path(PFRING_INCLUDE_DIR pfring.h
  PATHS
    /usr/include
    /usr/local/include
  NO_DEFAULT_PATH
)

# Kiểm tra xem PF_RING đã được tìm thấy cả thư viện và header chưa
if(NOT PFRING_LIBRARY OR NOT PFRING_INCLUDE_DIR)
    message(FATAL_ERROR "PF_RING not found. Ensure PF_RING library (libpfring) and headers (pfring.h) are installed. Check /usr/local/lib and /usr/local/include.")
endif()

# === THAY ĐỔI: Tìm thư viện pcap (Linux) ===
# Vẫn cần link với libpcap vì libpfring có thể phụ thuộc vào nó
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

if(NOT ZSTD_LIBRARY OR NOT ZSTD_INCLUDE_DIR)
    message(FATAL_ERROR "Zstd not found. Install with: sudo apt install libzstd-dev")
endif()


# Sử dụng các biến trả về từ FindPackage cho OpenSSL và Threads
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(PacketCaptureAgent main.cpp)

# === THAY ĐỔI: Liên kết với cả pfring và pcap ===
target_link_libraries(PacketCaptureAgent
    ${PFRING_LIBRARY}       # Liên kết với thư viện pfring
    ${PCAP_LIBRARY}  
    ${UDT_LIBRARY}          # Liên kết với thư viện pcap
    ${ZSTD_LIBRARY}
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Thêm include directories
target_include_directories(PacketCaptureAgent PRIVATE
    ${PFRING_INCLUDE_DIR} # Sử dụng biến chứa đường dẫn header của PF_RING
    ${OpenSSL_INCLUDE_DIRS} # Sử dụng biến chứa đường dẫn header của OpenSSL
    ${UDT_INCLUDE_DIR}
    ${ZSTD_INCLUDE_DIR}
)

message(STATUS "Configured PacketCaptureAgent with PF_RING, pcap, OpenSSL, and Threads.")
message(STATUS "PFRING_LIBRARY: ${PFRING_LIBRARY}")
message(STATUS "PFRING_INCLUDE_DIR: ${PFRING_INCLUDE_DIR}")
message(STATUS "PCAP_LIBRARY: ${PCAP_LIBRARY}")
message(STATUS "OpenSSL_INCLUDE_DIRS: ${OpenSSL_INCLUDE_DIRS}")