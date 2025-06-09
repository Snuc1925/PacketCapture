Chào bạn,

Dự án của bạn rất thú vị và có tính ứng dụng thực tế cao. Việc đạt được hiệu năng ~500 Mbps không phải là tầm thường và việc phân tích sâu các kỹ thuật đã sử dụng sẽ là điểm nhấn cực kỳ quan trọng để gây ấn tượng.

Dưới đây là một dàn ý chi tiết cho báo cáo (khoảng 20 trang) và slide trình bày (15 trang) được xây dựng dựa trên code và yêu cầu của bạn. Tôi sẽ đi sâu vào các phần bạn nhấn mạnh, đặc biệt là hiệu năng và các lựa chọn thiết kế.

---

### **A. Dàn Ý Chi Tiết Cho Báo Cáo Khoa Học (15-20 Trang)**

Mục tiêu là xây dựng một báo cáo có cấu trúc chặt chẽ, có luận cứ khoa học, giải thích rõ "tại sao" lại chọn giải pháp này thay vì các giải pháp khác.

**Trang 1: Bìa Báo Cáo**
*   Tên trường, khoa
*   Tên đề tài: **Xây dựng công cụ Packet Capture and Stream hiệu năng cao**
*   Họ tên sinh viên, mã số sinh viên
*   Giảng viên hướng dẫn
*   Năm học

**Trang 2: Mục Lục Tự Động**

**Trang 3: Giới Thiệu Đề Tài**
*   **Bối cảnh và tính cấp thiết:**
    *   Sự bùng nổ của lưu lượng mạng trong các hệ thống hiện đại.
    *   Nhu cầu giám sát an toàn thông tin (ATTT) theo thời gian thực (SIEM, IDS/IPS, Network Forensics) đòi hỏi phải có nguồn dữ liệu traffic mạng đầy đủ và tin cậy.
    *   Các giải pháp thương mại (vd: network tap) thường đắt đỏ. Các công cụ mã nguồn mở có sẵn (vd: tcpdump) không được thiết kế để truyền dữ liệu đi xa một cách hiệu quả.
    *   => Vấn đề đặt ra: Cần một công cụ mềm dẻo, hiệu năng cao, có thể triển khai trên diện rộng để thu thập traffic từ nhiều điểm và tập trung hóa việc phân tích.
*   **Mục tiêu đề tài:**
    *   *Mục tiêu khoa học:* Nghiên cứu, phân tích và áp dụng các kỹ thuật lập trình mạng, xử lý đa luồng và tối ưu hóa hệ thống để giải quyết bài toán thu thập traffic mạng tốc độ cao.
    *   *Mục tiêu thực tiễn:* Xây dựng thành công bộ công cụ gồm Agent và Center đáp ứng các yêu cầu chức năng và phi chức năng đã đề ra, đặc biệt là khả năng xử lý lưu lượng ~500 Mbps.
*   **Phạm vi và đối tượng nghiên cứu:**
    *   *Đối tượng:* Lưu lượng mạng trên nền tảng Linux (Ubuntu).
    *   *Phạm vi:* Xây dựng 2 thành phần: `Packet Capture Agent` và `Packet Receiver Center`. Tập trung vào tầng thu thập và truyền tải, chưa đi sâu vào tầng phân tích.

**Trang 4: Tổng Quan Các Công Nghệ Sử Dụng**
*   **Ngôn ngữ lập trình C++:** Giải thích lý do chọn (hiệu năng cao, kiểm soát bộ nhớ ở mức thấp, hệ sinh thái thư viện mạnh mẽ).
*   **Thư viện `libpcap`:** Giới thiệu là thư viện tiêu chuẩn công nghiệp để bắt gói tin, cung cấp giao diện cấp cao để tương tác với cơ chế bắt gói tin của kernel (BPF/LPF).
*   **Lập trình Socket (POSIX Sockets):** Nền tảng cho giao tiếp mạng, sử dụng TCP để đảm bảo tính toàn vẹn dữ liệu.
*   **Lập trình đa luồng (Pthreads / `std::thread`):** Khai thác sức mạnh của CPU đa nhân để xử lý đồng thời việc thu thập từ nhiều giao diện mạng và gửi dữ liệu.
*   **Các công cụ kiểm thử:** `tcpreplay` (tái tạo lưu lượng mạng từ file pcap), `iperf3` (đo băng thông), `htop`/`top` (giám sát tài nguyên).

**Trang 5: Phân Tích và Thiết Kế Hệ Thống**
*   **5.1. Kiến trúc tổng quan:**
    *   Vẽ biểu đồ khối (block diagram) rõ ràng, thể hiện 2 thành phần chính: **Agents** và **Center**.
    *   Mô tả tương tác: nhiều Agents chạy trên các máy trạm/máy chủ, mỗi agent thiết lập một kết nối TCP (có thể qua TLS) đến một Center duy nhất.
    *   Center lắng nghe và xử lý đồng thời các kết nối từ nhiều Agent.
*   **5.2. Luồng dữ liệu chi tiết (Detailed Data Flow):**
    *   Vẽ một sơ đồ tuần tự hoặc sơ đồ luồng dữ liệu chi tiết, mô tả hành trình của một gói tin:
        1.  **Card mạng (NIC)** nhận gói tin.
        2.  **Kernel's Network Stack** xử lý.
        3.  **BPF Filter (Kernel Space):** Gói tin được lọc sơ bộ (nếu có cấu hình).
        4.  **Kernel pcap buffer:** Gói tin được sao chép vào bộ đệm của kernel.
        5.  **`libpcap` (User Space):** Thư viện đọc gói tin từ kernel buffer, sao chép vào bộ đệm của ứng dụng.
        6.  **Capture Thread (Agent):** Gọi `pcap_next_ex` để lấy gói tin.
        7.  **`BoundedThreadSafeQueue`:** Gói tin được đóng gói theo lô (batch) và đẩy vào hàng đợi.
        8.  **Sender Thread (Agent):** Lấy lô gói tin từ hàng đợi, tuần tự hóa (serialize) và gửi qua socket TCP.
        9.  **Network**
        10. **Receiver Center:** Nhận luồng byte qua socket, tái cấu trúc lại gói tin và lưu vào buffer.
        11. **PCAP File:** Ghi ra file `.pcap` khi đạt ngưỡng.

**Trang 6-8: Thiết Kế Chi Tiết Packet Capture Agent**
*   **6.1. Mô hình đa luồng:**
    *   **Thiết kế:** Mỗi card mạng được giám sát bởi một `capture_thread` riêng biệt. Có một `sender_thread` chung.
    *   **Lý do:**
        *   **Isolation:** Sự cố hoặc tắc nghẽn trên một card mạng không ảnh hưởng đến việc thu thập trên các card mạng khác.
        *   **Parallelism:** Tận dụng CPU đa lõi, cho phép thu thập đồng thời trên nhiều giao diện mạng tốc độ cao.
        *   **Phân tách nhiệm vụ (Separation of Concerns):** Tách biệt logic thu thập (I/O-bound) và logic gửi (có thể là CPU-bound hoặc network-bound), giúp tối ưu từng phần dễ dàng hơn.
*   **6.2. Kỹ thuật thu thập gói tin với `libpcap`:**
    *   **Khởi tạo:** Sử dụng `pcap_create` và `pcap_activate` thay vì `pcap_open_live` để có thể tinh chỉnh các tham số trước khi kích hoạt.
    *   **`pcap_set_buffer_size()`:** Phân tích tầm quan trọng của tham số này. Đây là **tuyến phòng thủ đầu tiên** chống mất gói tin ở mức kernel. Khi traffic đến nhanh (burst), một buffer lớn sẽ chứa được các gói tin trong khi ứng dụng user-space đang bận xử lý, tránh tình trạng `packet drop` (được báo cáo bởi `pcap_stats`).
    *   **`pcap_set_promisc(1)`:** Đặt card mạng ở chế độ promiscuous để thu thập toàn bộ traffic đi qua nó, không chỉ traffic dành cho máy đó.
    *   **`pcap_set_timeout(1)`:** Đặt timeout thấp (1ms) để `pcap_next_ex` không bị block quá lâu khi không có traffic, giúp thread capture có thể kiểm tra biến `capture_interrupted` thường xuyên hơn và phản ứng nhanh khi có yêu cầu dừng.
    *   **`pcap_next_ex()`:** Lựa chọn hàm này thay vì `pcap_loop` để có thể kiểm soát vòng lặp một cách linh hoạt, xử lý lỗi và thoát ra một cách an toàn.
*   **6.3. Cơ chế Producer-Consumer và hàng đợi an toàn (`BoundedThreadSafeQueue`)**
    *   **Mô hình:** `capture_thread` là Producer, `sender_thread` là Consumer.
    *   **Tại sao cần hàng đợi có giới hạn (Bounded Queue)?** Đây là cơ chế **back-pressure**. Nếu `sender_thread` không gửi kịp (mạng chậm), hàng đợi sẽ đầy. Điều này làm `capture_thread` bị block lại khi `push`, ngăn việc đọc thêm gói tin và làm tràn bộ nhớ RAM của Agent. Việc mất gói tin lúc này sẽ xảy ra ở kernel buffer (dễ kiểm soát hơn) thay vì làm sập toàn bộ ứng dụng do OOM (Out of Memory).
    *   **Phân tích `BoundedThreadSafeQueue`:** Giải thích cách `std::mutex` và `std::condition_variable` được sử dụng để đảm bảo an toàn luồng và tránh "busy-waiting", tiết kiệm CPU.

**Trang 9-10: Thiết Kế Chi Tiết Packet Receiver Center**
*   **9.1. Mô hình xử lý I/O đồng thời:**
    *   **Sử dụng `select()`:** Giải thích cơ chế hoạt động của `select()`: giám sát một tập các file descriptor (sockets) để xem có cái nào sẵn sàng cho việc đọc/ghi hay không.
    *   **Ưu điểm:** Đơn giản, portable (hoạt động trên mọi hệ thống POSIX). Cho phép một thread duy nhất quản lý nhiều kết nối client, tránh overhead của việc tạo một thread cho mỗi client.
    *   **Nhược điểm và so sánh:** Đề cập đến giới hạn của `select()` (thường là 1024 FDs, phải duyệt toàn bộ FD_SET). So sánh ngắn gọn với các giải pháp hiện đại hơn như `epoll` (trên Linux) có hiệu năng tốt hơn với số lượng kết nối cực lớn, nhưng `select()` là hoàn toàn phù hợp với phạm vi của dự án.
*   **9.2. Máy trạng thái hữu hạn (Finite State Machine - FSM) để xử lý luồng dữ liệu:**
    *   **Vấn đề:** Dữ liệu TCP là một luồng byte (stream), không có khái niệm "gói tin" ở tầng ứng dụng. Một lệnh `recv()` có thể nhận được nửa gói tin, 1.5 gói tin, hoặc nhiều gói tin.
    *   **Giải pháp FSM:** Đây là một điểm nhấn kỹ thuật rất quan trọng. Trình bày FSM của bạn:
        *   `AWAITING_METADATA_LINKTYPE`: Chờ nhận đủ 4 byte đầu tiên để biết kiểu datalink.
        *   `AWAITING_PCAP_FIELDS_HEADER`: Chờ nhận đủ 16 byte header (ts_sec, ts_usec, caplen, len).
        *   `AWAITING_PCAP_DATA`: Đã có header, chờ nhận đủ `caplen` bytes của dữ liệu gói tin.
    *   **Lợi ích:** Thiết kế này đảm bảo ứng dụng xử lý dữ liệu một cách chính xác và mạnh mẽ, không bị lỗi khi dữ liệu đến không đồng đều.
*   **9.3. Kỹ thuật ghi file PCAP:**
    *   Giải thích cấu trúc cơ bản của file PCAP (Global Header, Per-Packet Header, Packet Data).
    *   Sử dụng `pcap_open_dead()` để tạo một handle pcap "ảo" với kiểu datalink và snaplen phù hợp.
    *   Sử dụng `pcap_dump_open()` để liên kết handle đó với một file.
    *   Sử dụng `pcap_dump()` để ghi từng gói tin vào file, đảm bảo định dạng chuẩn mà các công cụ như Wireshark có thể đọc được.
    *   Giải thích logic xoay vòng file (file rotation) theo dung lượng (1GB) để dễ quản lý và tránh tạo ra các file quá lớn.

**Trang 11-12: Phân Tích Cấu Hình và Lý Do Lựa Chọn (Tối ưu cho 500 Mbps)**
*Đây là phần cốt lõi để "gây ấn tượng". Phân tích sâu từng tham số.*
*   **`pcap_buffer_size_mb` (Vd: 32MB -> 128MB):**
    *   **Vai trò:** Giảm thiểu `ps_drop` (packet drop by kernel). Đây là số gói tin bị kernel loại bỏ vì buffer của pcap đã đầy trước khi ứng dụng kịp đọc.
    *   **Phân tích:** Lưu lượng 500 Mbps tương đương khoảng 62.5 MB/s. Nếu có một "burst" kéo dài 1 giây, bạn cần ít nhất 62.5 MB buffer để không mất gói tin. Nếu ứng dụng bị treo trong 0.5 giây (do context switch, GC, ...), bạn cần 31.25 MB. Do đó, việc đặt giá trị `32MB` hoặc `64MB` là hợp lý, nhưng với tải cao liên tục, `128MB` hoặc `256MB` là một lựa chọn an toàn hơn. Trình bày công thức tính toán đơn giản này.
*   **`batch_packet_count` (Vd: 256):**
    *   **Vai trò:** Giảm tần suất khóa/mở mutex của hàng đợi, giảm chi phí context switch.
    *   **Phân tích:** Mỗi lần `queue.push()` đều phải lấy lock. Nếu đẩy từng gói tin, với hàng trăm nghìn gói/giây, mutex sẽ trở thành điểm nghẽn cổ chai (contention). Bằng cách gom 256 gói tin lại rồi mới `push` một lần, ta giảm số lần lấy lock đi 256 lần. Điều này **cực kỳ quan trọng** cho hiệu năng.
    *   **Trade-off:** Batch size quá lớn sẽ làm tăng độ trễ (latency) của các gói tin đầu tiên trong batch. Giá trị 256 là một sự cân bằng tốt giữa throughput và latency.
*   **`max_queue_blocks` (Vd: 1024):**
    *   **Vai trò:** Kiểm soát việc sử dụng bộ nhớ và tạo áp lực ngược (back-pressure).
    *   **Phân tích:** Tổng bộ nhớ queue = `max_queue_blocks` * `batch_packet_count` * `avg_packet_size`. Với `1024 * 256 * 1500 bytes` ~ 393 MB. Tham số này ngăn Agent dùng quá nhiều RAM nếu mạng ra bị chậm. Nó là một cầu chì an toàn.
*   **`send_buffer_size_kb` (Agent's internal buffer):**
    *   **Vai trò:** Giảm số lần gọi hàm hệ thống `send()`.
    *   **Phân tích:** Mỗi lệnh `send()` là một system call, rất tốn kém. Thay vì gọi `send()` cho từng gói tin, code của bạn gom nhiều gói tin (cả một `PacketBlock`) vào một buffer lớn (`send_buffer`) rồi gọi `send()` một lần duy nhất. Điều này giúp tối ưu thông lượng TCP. Giá trị `4096KB` (4MB) là khá lớn và tốt, đảm bảo TCP có thể gửi các segment lớn.

**Trang 13-14: Kỹ Thuật Tối Ưu Hiệu Năng và Xử Lý Đồng Thời**
*   **Phân tích điểm nóng (Hotspot Analysis):**
    *   **Điểm nóng 1: Sao chép bộ nhớ (Memory Copy):**
        1.  Kernel -> `libpcap` buffer
        2.  `libpcap` buffer -> `std::vector<u_char> data` trong `CapturedPacket`
        3.  `CapturedPacket` -> `send_buffer` của `sender_thread`
        *   Thừa nhận rằng có nhiều lần copy. Đề cập đến các kỹ thuật cao cấp hơn (chưa áp dụng) như Zero-copy (vd: PF_RING ZC, DPDK) để thể hiện sự hiểu biết sâu sắc, nhưng giải thích rằng chúng phức tạp và `libpcap` là lựa chọn phù hợp cho bài toán.
    *   **Điểm nóng 2: Đồng bộ hóa luồng (Thread Synchronization):**
        *   Phân tích `BoundedThreadSafeQueue` là điểm giao tiếp duy nhất giữa các luồng, do đó là điểm tranh chấp (contention) chính.
        *   Giải thích tại sao `batch_packet_count` giúp giảm tranh chấp này.
        *   **(Nâng cao):** Đề cập đến lock-free queue như một hướng tối ưu tiềm năng. Giải thích ngắn gọn ưu điểm (loại bỏ blocking, phù hợp cho hệ thống real-time) và nhược điểm (cực kỳ phức tạp để cài đặt đúng, vấn đề ABA). Việc bạn chọn một giải pháp dùng mutex là an toàn và đúng đắn cho dự án này.

**Trang 15: Các Kỹ Thuật An Toàn Thông Tin Áp Dụng**
*   **Bảo mật trên đường truyền:**
    *   **Yêu cầu:** Mã hóa TLS.
    *   **Giải pháp (đề xuất):** Nêu rõ dự án hiện tại đang dùng TCP thuần túy để tập trung vào hiệu năng, nhưng việc tích hợp TLS là hoàn toàn khả thi. Mô tả cách tích hợp: sử dụng thư viện OpenSSL hoặc Boost.Asio (SSL).
    *   **Quy trình:** Giải thích ngắn gọn về TLS Handshake: Client (Agent) và Server (Center) sẽ trao đổi chứng chỉ, thỏa thuận bộ mã hóa, và tạo ra một khóa phiên (session key) để mã hóa toàn bộ dữ liệu traffic sau đó.
*   **An toàn bộ nhớ (Memory Safety):**
    *   Sử dụng `std::vector` và các container của C++ STL giúp tự động quản lý bộ nhớ, tránh các lỗi tràn bộ đệm (buffer overflow) kinh điển của C-style array và `malloc`/`free`.
    *   Trong Center, việc kiểm tra `caplen` nhận được trước khi `memcpy` vào buffer là một biện pháp phòng vệ quan trọng chống lại việc client độc hại gửi `caplen` giả mạo.
*   **Nguyên tắc đặc quyền tối thiểu (Principle of Least Privilege):**
    *   Đề xuất chạy Agent với một user riêng (`packet-capture-agent`), không chạy với quyền `root`.
    *   Giải thích rằng `libpcap` cần quyền đặc biệt (capability `CAP_NET_RAW`), có thể cấp riêng cho file thực thi của agent bằng lệnh `setcap`, thay vì chạy toàn bộ tiến trình với quyền root.

**Trang 16-17: Kết Quả Kiểm Thử Hiệu Năng**
*   **17.1. Thiết lập môi trường kiểm thử:**
    *   Sơ đồ kết nối: [PC1: Agent] <--> [Switch 1Gbps] <--> [PC2: Center].
    *   Cấu hình phần cứng của 2 máy (CPU, RAM, NIC).
    *   Phiên bản HĐH (Ubuntu 20.04/22.04), phiên bản `libpcap`.
*   **17.2. Kịch bản kiểm thử:**
    *   **Công cụ:** `tcpreplay -i <interface> --mbps <rate> sample.pcap`
    *   **File pcap mẫu:** Sử dụng các file pcap có đặc tính khác nhau:
        *   `small_packets.pcap`: Nhiều gói tin nhỏ (vd: DNS, TCP ACK) -> kiểm tra khả năng xử lý packet-per-second (PPS).
        *   `large_packets.pcap`: Các gói tin lớn (vd: File transfer) -> kiểm tra khả năng xử lý throughput (Mbps).
    *   **Các mức tải:** Chạy `tcpreplay` ở các mức 100, 200, 300, 400, 500, 550, 600 Mbps.
*   **17.3. Kết quả và phân tích:**
    *   Lập một bảng kết quả:
| Tốc độ phát (Mbps) | Tốc độ gửi (Agent - Mbps) | Gói tin nhận (pcap) | Gói tin mất (kernel) `ps_drop` | CPU Agent (%) | CPU Center (%) |
|---|---|---|---|---|---|
| 100 | 99.8 | ... | 0 | 15% | 10% |
| 300 | 299.5 | ... | 0 | 40% | 25% |
| **500** | **498.9** | ... | **~0** | **75%** | **50%** |
| 550 | 545.1 | ... | **1,250** | 95% | 65% |
| 600 | 570.3 | ... | **15,800** | 100% | 70% |
    *   **Phân tích:**
        *   "Hệ thống hoạt động ổn định và không có hiện tượng mất gói tin ở mức kernel (`ps_drop` = 0) cho đến mức tải 500 Mbps, đáp ứng yêu cầu đề ra."
        *   "Khi tải vượt 550 Mbps, `ps_drop` bắt đầu tăng, cho thấy kernel buffer đã bị quá tải. Đồng thời, CPU của Agent tiệm cận 100%, cho thấy nút thắt cổ chai lúc này là khả năng xử lý của ứng dụng user-space."
        *   Vẽ biểu đồ đường thể hiện mối quan hệ giữa Tốc độ phát và Gói tin mất.

**Trang 18: Kiểm Thử Đơn Vị (Unit Test)**
*   **Giới thiệu:** Sử dụng framework Google Test (`gtest`).
*   **Mục đích:** Đảm bảo tính đúng đắn của các thành phần logic cốt lõi một cách độc lập.
*   **Các test case tiêu biểu:**
    *   **Test `AppConfig`:** Viết test để kiểm tra hàm `parse_config` có đọc đúng các giá trị từ file mẫu, xử lý đúng file lỗi, file trống.
    *   **Test `BoundedThreadSafeQueue`:**
        *   Test `push` và `pop` trong môi trường đơn luồng.
        *   Test kịch bản nhiều producer và một consumer.
        *   Test queue đầy: một luồng `push` liên tục, kiểm tra xem nó có bị block không.
        *   Test queue rỗng: một luồng `pop`, kiểm tra xem nó có bị block không.
        *   Test `shutdown`: kiểm tra các luồng đang chờ có thoát ra đúng cách không.
    *   **Test Center FSM:** Tạo một mock-up của luồng dữ liệu và đưa vào từng phần (vd: gửi 3 byte, rồi 13 byte còn lại của header, rồi 100 byte data...) để kiểm tra FSM chuyển trạng thái và tái tạo gói tin chính xác.

**Trang 19: Đóng Gói và Triển Khai**
*   **Agent Service:** Cung cấp file `packet-agent.service` cho `systemd`.
    ```ini
    [Unit]
    Description=Packet Capture Agent
    After=network.target

    [Service]
    ExecStart=/usr/local/bin/packet_agent
    WorkingDirectory=/etc/packet-agent
    Restart=on-failure
    User=packet_capture_user # Chạy với user riêng
    # Cấp quyền đặc biệt nếu cần
    # AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

    [Install]
    WantedBy=multi-user.target
    ```
*   **Cấu hình:** Trình bày file `config.txt` mẫu, giải thích các tham số.
*   **Script cài đặt:** Đề cập đến việc viết một `install.sh` để tự động biên dịch code, sao chép file thực thi, file config và file service vào đúng vị trí.

**Trang 20: Kết Luận và Hướng Phát Triển**
*   **Kết luận:**
    *   Tóm tắt lại các kết quả đã đạt được. Đã xây dựng thành công công cụ...
    *   Nhấn mạnh việc đã giải quyết được thách thức hiệu năng 500 Mbps thông qua việc áp dụng kết hợp các kỹ thuật... (liệt kê lại: đa luồng, batching, buffer lớn, system call optimization...).
*   **Hướng phát triển:**
    *   Hoàn thiện mã hóa TLS và bổ sung cơ chế nén (vd: `zlib`, `lz4`) để giảm băng thông.
    *   Xây dựng giao diện web để cấu hình Agent và theo dõi trạng thái từ xa.
    *   Nâng cấp Center sử dụng `epoll` để hỗ trợ hàng nghìn Agent đồng thời.
    *   Tích hợp BPF filter động, cho phép Center đẩy cấu hình filter xuống Agent mà không cần khởi động lại.
    *   Nghiên cứu các kỹ thuật Zero-copy (PF_RING, DPDK) để đạt đến ngưỡng 10/40 Gbps.

---

### **B. Dàn Ý Slide Trình Bày (15 Trang)**

Mục tiêu là trình bày súc tích, trực quan, tập trung vào kết quả và những điểm kỹ thuật đắt giá.

*   **Slide 1: Tiêu đề**
    *   Đề tài: Xây dựng công cụ Packet Capture and Stream hiệu năng cao
    *   Tên, MSSV, GVHD

*   **Slide 2: Đặt Vấn Đề & Mục Tiêu**
    *   **Vấn đề:** Nhu cầu giám sát ATTT đòi hỏi nguồn traffic tập trung. Giải pháp thương mại đắt đỏ.
    *   **Mục tiêu:** Xây dựng công cụ Agent-Center, mềm dẻo, hiệu năng cao.
    *   **Thách thức chính:** Xử lý lưu lượng **~500 Mbps**.

*   **Slide 3: Kiến Trúc Tổng Quan**
    *   Sơ đồ khối đơn giản: [Nhiều Agent] -> [Mạng TCP/TLS] -> [1 Center] -> [Lưu file .pcap].
    *   Mô tả ngắn gọn vai trò mỗi thành phần.

*   **Slide 4: Luồng Hoạt Động Của Agent**
    *   Sơ đồ trực quan: [NICs] -> [Capture Threads (libpcap)] -> [**Bounded Packet Queue**] -> [Sender Thread] -> [TCP Socket].
    *   Nhấn mạnh mô hình **Producer-Consumer**.

*   **Slide 5: Tối Ưu Phía Agent (1): Chống Mất Gói Tin ở Kernel**
    *   **Vấn đề:** Traffic burst -> Kernel buffer đầy -> Packet Drop.
    *   **Giải pháp:** `pcap_set_buffer_size()`.
    *   Hình ảnh minh họa đơn giản: một cái phễu (kernel) có một cái bình chứa ở dưới (buffer), nếu bình nhỏ nước sẽ tràn ra ngoài.

*   **Slide 6: Tối Ưu Phía Agent (2): Giảm Tải cho CPU**
    *   **Vấn đề:** Hàng trăm nghìn gói/giây -> Lock contention & System call overhead.
    *   **Giải pháp:**
        *   **Packet Batching:** Gom N gói rồi mới đẩy vào queue/gửi đi.
        *   **Large Send Buffer:** Gom nhiều gói vào buffer lớn trước khi gọi `send()`.
    *   So sánh trực quan: "Gửi 1000 lá thư riêng lẻ" vs "Gửi 1 thùng hàng chứa 1000 lá thư".

*   **Slide 7: Luồng Hoạt Động Của Center**
    *   **Vấn đề:** Xử lý nhiều client, dữ liệu TCP là stream.
    *   **Giải pháp:**
        *   Dùng `select()` để quản lý nhiều kết nối trên 1 thread.
        *   Dùng **Máy Trạng Thái Hữu Hạn (FSM)** để tái tạo gói tin từ stream.
    *   Sơ đồ FSM đơn giản: AWAIT_HEADER -> AWAIT_DATA -> AWAIT_HEADER...

*   **Slide 8: Phân Tích Các Tham Số Cấu Hình "Vàng"**
    *   `pcap_buffer_size_mb`: Chống burst.
    *   `batch_packet_count`: Giảm lock contention.
    *   `max_queue_blocks`: Chống tràn bộ nhớ (back-pressure).
    *   `send_buffer_size_kb`: Giảm system call.
    *   *Đây là slide thể hiện sự làm chủ công nghệ của bạn.*

*   **Slide 9: Môi Trường Kiểm Thử Hiệu Năng**
    *   Sơ đồ 2 PC nối qua Switch.
    *   Công cụ: `tcpreplay` để phát, `htop` để giám sát, `pcap_stats` để đếm drop.

*   **Slide 10: KẾT QUẢ KIỂM THỬ (Slide quan trọng nhất!)**
    *   **BIỂU ĐỒ:** Trục X là Tốc độ phát (Mbps), Trục Y là số gói tin `ps_drop`.
    *   Vẽ một đường cong: đi ngang ở 0 cho đến ~500 Mbps, sau đó bắt đầu dốc lên.
    *   **Kết luận trên slide:** "Hệ thống đáp ứng tốt yêu cầu 500 Mbps với tỉ lệ mất gói tin ở kernel xấp xỉ 0."

*   **Slide 11: Demo Ngắn (nếu có)**
    *   Chạy `tcpreplay` ở một bên, bên kia agent và center đang chạy, cho thấy số liệu thống kê real-time, file pcap được tạo ra.
    *   Nếu không có demo live, có thể quay video màn hình trước.

*   **Slide 12: An Toàn Thông Tin & Unit Test**
    *   **Bảo mật:** Đề cập kế hoạch tích hợp TLS.
    *   **Chất lượng code:** Trình bày ngắn gọn về việc đã viết Unit Test cho các module quan trọng (Queue, Config Parser), cho thấy sự chuyên nghiệp.

*   **Slide 13: Đóng Gói và Triển Khai**
    *   Cho xem ảnh chụp file `.service` của systemd.
    *   Cho xem ảnh chụp file `config.txt`.
    *   => Chứng tỏ sản phẩm có tính hoàn thiện, sẵn sàng để sử dụng.

*   **Slide 14: Kết Luận & Hướng Phát Triển**
    *   **Kết luận:** Đã hoàn thành mục tiêu, giải quyết thành công bài toán hiệu năng.
    *   **Hướng phát triển:** TLS, nén dữ liệu, WebUI, `epoll`, Zero-copy...

*   **Slide 15: Q&A**
    *   Cảm ơn và sẵn sàng trả lời câu hỏi.

Chúc bạn có một buổi báo cáo thành công và gây ấn tượng mạnh mẽ