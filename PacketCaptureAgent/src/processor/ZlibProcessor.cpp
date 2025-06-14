#include "processor/ZlibProcessor.hpp"
#include <zlib.h>     // Header chính của thư viện zlib
#include <iostream>

std::vector<char> ZlibProcessor::process(const std::vector<char>& input_buffer) {
    if (input_buffer.empty()) {
        return {};
    }

    // Lấy kích thước của dữ liệu đầu vào. zlib sử dụng kiểu 'uLong'.
    uLong source_len = input_buffer.size();

    // 1. Tính toán kích thước tối đa của buffer sau khi nén.
    // Tương tự ZSTD_compressBound, zlib cung cấp compressBound.
    uLong compressed_bound = compressBound(source_len);
    std::vector<char> compressed_buffer(compressed_bound);

    // zlib yêu cầu một biến để lưu kích thước buffer đích, và sẽ cập nhật nó
    // với kích thước nén thực tế sau khi hàm chạy xong.
    uLongf dest_len = compressed_buffer.size();

    // 2. Thực hiện nén dữ liệu
    // Hàm compress() là hàm nén "one-shot" đơn giản nhất của zlib.
    // Nó nhận con trỏ Bytef*, ta cần ép kiểu (reinterpret_cast).
    int result = compress(
        reinterpret_cast<Bytef*>(compressed_buffer.data()), // Con trỏ buffer đích
        &dest_len,                                          // Con trỏ tới biến kích thước đích
        reinterpret_cast<const Bytef*>(input_buffer.data()),// Con trỏ buffer nguồn
        source_len                                          // Kích thước nguồn
    );

    // 3. Kiểm tra lỗi
    if (result != Z_OK) {
        std::cerr << "zlib compression error: ";
        switch (result) {
            case Z_MEM_ERROR:
                std::cerr << "not enough memory." << std::endl;
                break;
            case Z_BUF_ERROR:
                // Lỗi này không nên xảy ra nếu dùng compressBound()
                std::cerr << "output buffer was not large enough." << std::endl;
                break;
            default:
                std::cerr << "unknown error code " << result << "." << std::endl;
                break;
        }
        return {}; // Trả về vector rỗng nếu nén thất bại
    }

    // 4. Thay đổi kích thước buffer về kích thước nén thực tế
    compressed_buffer.resize(dest_len);

    return compressed_buffer;
}