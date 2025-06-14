cmake_minimum_required(VERSION 3.10)
project(PacketCaptureAgent)

set(CMAKE_CXX_STANDARD 17)

# === Tìm thư viện pcap ===
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Install with: sudo apt-get install libpcap-dev")
endif()

# === Tìm thư viện UDT ===
find_library(UDT_LIBRARY udt
  PATHS
    /usr/local/lib
    /usr/lib
    ${CMAKE_SOURCE_DIR}/udt/lib
)

find_path(UDT_INCLUDE_DIR udt.h
  PATHS
    /usr/local/include
    /usr/include/udt
    ${CMAKE_SOURCE_DIR}/udt/include
)

if(NOT UDT_LIBRARY OR NOT UDT_INCLUDE_DIR)
    message(FATAL_ERROR "UDT not found.")
endif()

# === Tìm thư viện Zstd ===
find_library(ZSTD_LIBRARY zstd PATHS /usr/lib /usr/local/lib)
find_path(ZSTD_INCLUDE_DIR zstd.h PATHS /usr/include /usr/local/include)

if(NOT ZSTD_LIBRARY OR NOT ZSTD_INCLUDE_DIR)
    message(FATAL_ERROR "Zstd not found. Install with: sudo apt install libzstd-dev")
endif()

# === Tìm OpenSSL & Threads ===
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# === Danh sách source file ===
set(SOURCE_FILES
    main.cpp
    src/connection/PlainTcpConnection.cpp
    src/connection/TlsConnection.cpp
    src/processor/PassThroughProcessor.cpp
    src/processor/ZstdProcessor.cpp
    src/utils/config_utils.cpp
    src/logging/send_log.cpp
)


# === Tạo executable ===
add_executable(PacketCaptureAgent ${SOURCE_FILES})

# === Include paths ===
target_include_directories(PacketCaptureAgent PRIVATE
    include
    ${OpenSSL_INCLUDE_DIRS}
    ${UDT_INCLUDE_DIR}
    ${ZSTD_INCLUDE_DIR}
)

# === Link các thư viện ===
target_link_libraries(PacketCaptureAgent
    ${PCAP_LIBRARY}
    ${UDT_LIBRARY}
    ${ZSTD_LIBRARY}
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

# === In thông tin ra để debug ===
message(STATUS "PCAP_LIBRARY: ${PCAP_LIBRARY}")
message(STATUS "OpenSSL_INCLUDE_DIRS: ${OpenSSL_INCLUDE_DIRS}")
