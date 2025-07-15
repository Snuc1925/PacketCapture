cmake_minimum_required(VERSION 3.10)
project(PacketCaptureAgent VERSION 1.0.0) # Thêm VERSION vào project

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

# === Tìm zlib =========
find_package(ZLIB REQUIRED)

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
    src/processor/ZlibProcessor.cpp
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
    ${ZLIB_INCLUDE_DIRS}
)

# === Link các thư viện ===
target_link_libraries(PacketCaptureAgent
    ${PCAP_LIBRARY}
    ${UDT_LIBRARY}
    ${ZSTD_LIBRARY}
    ${ZLIB_LIBRARIES}
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

# === In thông tin ra để debug ===
message(STATUS "PCAP_LIBRARY: ${PCAP_LIBRARY}")
message(STATUS "OpenSSL_INCLUDE_DIRS: ${OpenSSL_INCLUDE_DIRS}")


#################################################################
# BỔ SUNG CHO ĐÓNG GÓI DEB VỚI CPACK                          #
#################################################################

# 1. Khai báo các file cần được cài đặt
#   - Binary chính sẽ được cài vào /usr/bin/
install(TARGETS PacketCaptureAgent
        RUNTIME DESTINATION bin
        # Thường thì các executable sẽ vào /usr/bin hoặc /usr/local/bin
        # CPack sẽ dùng CMAKE_INSTALL_PREFIX để prefix, mặc định là /usr/local
        # Để cài vào /usr, bạn sẽ cần chạy cmake với -DCMAKE_INSTALL_PREFIX=/usr
)

#   - Nếu có file cấu hình, ví dụ config.json, bạn sẽ đặt nó vào /etc/packetcaptureagent/
#     Giả sử bạn có một file config.json trong thư mục gốc của project
#     Bạn nên tạo một thư mục riêng cho config để tránh xung đột
# install(FILES config.json DESTINATION etc/packetcaptureagent) # Ví dụ

#   - Nếu bạn muốn cài đặt một service Systemd (rất phổ biến cho các ứng dụng chạy nền)
#     Bạn sẽ tạo một file `packetcaptureagent.service` và cài đặt nó vào `/lib/systemd/system/`
#     (Xem phần 2 & 3 bên dưới để tạo file này)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/packetcaptureagent.service" # Đường dẫn tới file service
        DESTINATION lib/systemd/system/
        OPTIONAL # Tùy chọn, nếu file service không tồn tại thì không lỗi
)


# 2. Cấu hình CPack
#   Bao gồm module CPack
include(CPack)

#   Tên gói DEB (nên viết thường, không dấu, không khoảng trắng)
set(CPACK_DEBIAN_PACKAGE_NAME "packetcaptureagent")
#   Phiên bản gói (lấy từ project, hoặc đặt cứng)
set(CPACK_DEBIAN_PACKAGE_VERSION "${PROJECT_VERSION}") # Sử dụng PROJECT_VERSION đã khai báo ở trên

#   Kiến trúc CPU (amd64 cho 64-bit Intel/AMD)
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")

#   Người duy trì gói
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Your Name <your.email@example.com>")

#   Mô tả ngắn gọn về gói
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "A network packet capture and processing agent.")

#   Mô tả chi tiết (có thể nhiều dòng)
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION_LONG
"This agent captures network packets using libpcap, processes them (e.g., compression
 with Zstd/Zlib), and can potentially forward them using UDT or TLS connections.
 It's designed for efficient and secure data transmission."
)

#   Phần loại gói (networking, utilities, system, etc.)
set(CPACK_DEBIAN_PACKAGE_SECTION "net")

#   Độ ưu tiên của gói
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")

#   Liệt kê các gói DEB mà ứng dụng của bạn phụ thuộc vào (runtime dependencies)
#   Quan trọng: Đây là tên các gói thư viện runtime, không phải thư viện -dev
set(CPACK_DEBIAN_PACKAGE_DEPENDS
    "libpcap0.8, libudt, libzstd1, zlib1g, libssl3, libcrypto3, libc6"
    # Lưu ý:
    #   - libpcap-dev -> libpcap0.8
    #   - libzstd-dev -> libzstd1
    #   - zlib -> zlib1g
    #   - OpenSSL: libssl3, libcrypto3 (hoặc libssl1.1, libcrypto1.1 tùy phiên bản Ubuntu)
    #   - UDT: Nếu UDT không có gói Debian chính thức, bạn cần phải:
    #     1. Đóng gói UDT thành một DEB riêng (phức tạp hơn).
    #     2. Link tĩnh UDT vào ứng dụng của bạn (khuyến nghị nếu UDT là custom build).
    #        Để link tĩnh, bạn có thể cần thay đổi cách find_library và target_link_libraries.
    #        Nếu link tĩnh, bạn không cần liệt kê nó ở đây.
    #   - Threads: Thường là một phần của libc6.
)

#   Cho phép CPack tự động dò tìm các thư viện dùng chung (có thể hữu ích nhưng không hoàn hảo)
#   set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

#   Xác định nơi chứa các script điều khiển Debian (postinst, prerm, control, v.v.)
#   Chúng ta sẽ tạo thư mục này ở bước tiếp theo.
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/debian_control")

#   Đặt tên chung cho gói được tạo ra
set(CPACK_PACKAGE_NAME "${CPACK_DEBIAN_PACKAGE_NAME}")
set(CPACK_PACKAGE_VERSION "${CPACK_DEBIAN_PACKAGE_VERSION}")

#   Chỉ định generator là DEB
set(CPACK_GENERATOR "DEB")