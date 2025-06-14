#include "IDecompressor.hpp"
#include <iostream>

class NoOpDecompressor : public IDecompressor {
public:
    bool decompress(const char* compressed_data, size_t compressed_size,
                    size_t original_size, std::vector<char>& decompressed_buffer) override {
        // Với NoOp, dữ liệu đã "giải nén" chính là dữ liệu đã nhận
        // Chúng ta không cần copy vào decompressed_buffer ở đây,
        // chỉ cần trả về true và logic bên ngoài sẽ sử dụng compressed_data
        // Tuy nhiên, nếu bạn muốn luồng dữ liệu nhất quán, bạn có thể copy:
        if (compressed_size != original_size) {
            // Lỗi logic: kích thước nén và kích thước gốc phải bằng nhau khi không nén
            std::cout << "NoOpDecompressor: compressed_size != original_size. Logic error." << std::endl;
            return false;
        }
        decompressed_buffer.assign(compressed_data, compressed_data + compressed_size);
        return true;
    }
};