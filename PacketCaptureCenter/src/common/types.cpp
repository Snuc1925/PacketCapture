#include "common/types.hpp"
#include "decompressor/NoOpDecompressor.hpp"
#include <utility> // for std::move

ClientState::ClientState(std::unique_ptr<IClientConnection> conn, std::string ip, uint16_t p)
    : connection(std::move(conn)), // Khởi tạo connection
      ip_address(std::move(ip)),    // Khởi tạo ip_address
      port(p),                      // Khởi tạo port
      buffered_packets(),           // Khởi tạo buffered_packets (có thể bỏ qua nếu default constructor đủ)
      current_total_bytes(0),       // Khởi tạo các biến số
      total_bytes(0),
      current_total_packets(0),
      total_packets(0),
      recv_buffer(),                // Khởi tạo recv_buffer (có thể bỏ qua nếu default constructor đủ)
      decompressor(std::make_unique<NoOpDecompressor>()), // <--- THÊM DÒNG NÀY VÀO ĐÂY
      current_fsm_state(ReceiveFSM::AWAITING_METADATA_LINKTYPE), // Khởi tạo FSM
      datalink_type(DLT_NULL),      // Khởi tạo datalink_type
      expected_flags(0),            // Khởi tạo các biến header
      expected_original_size(0),
      expected_payload_size(0),
      decompressed_buffer()         // Khởi tạo decompressed_buffer (có thể bỏ qua nếu default constructor đủ)
{
    // Thân hàm constructor rỗng, vì tất cả đã được khởi tạo trong danh sách khởi tạo
}