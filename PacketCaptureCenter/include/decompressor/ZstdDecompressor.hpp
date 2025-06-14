#include "IDecompressor.hpp"
#include <zstd.h> // Đảm bảo đã include ZSTD
#include <iostream>

class ZstdDecompressor : public IDecompressor {
public:
    bool decompress(const char* compressed_data, size_t compressed_size,
                    size_t original_size, std::vector<char>& decompressed_buffer) override {
        decompressed_buffer.resize(original_size);
        size_t const decompressed_actual_size = ZSTD_decompress(
            decompressed_buffer.data(), original_size,
            compressed_data, compressed_size
        );

        if (ZSTD_isError(decompressed_actual_size) || decompressed_actual_size != original_size) {
            // Có thể log chi tiết lỗi ZSTD_getErrorName(decompressed_actual_size) ở đây
            return false;
        }
        return true;
    }
};