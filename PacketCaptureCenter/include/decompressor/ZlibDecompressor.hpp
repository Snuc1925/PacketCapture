#include "IDecompressor.hpp"
#include <zlib.h> 
#include <iostream>

class ZlibDecompressor : public IDecompressor {
public:
    bool decompress(const char* compressed_data, size_t compressed_size,
                    size_t original_size, std::vector<char>& decompressed_buffer) override {
        decompressed_buffer.resize(original_size);

        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        strm.avail_in = compressed_size;
        strm.next_in = (Bytef*)compressed_data;
        strm.avail_out = original_size;
        strm.next_out = (Bytef*)decompressed_buffer.data();

        int ret = inflateInit2(&strm, 15 + 32); // 15+32 để tự động phát hiện zlib hoặc gzip header
        if (ret != Z_OK) {
            std::cout << "ZLIB inflateInit failed: " << strm.msg << std::endl; // Nên log cụ thể hơn
            return false;
        }

        ret = inflate(&strm, Z_FINISH);
        inflateEnd(&strm);

        if (ret != Z_STREAM_END) {
            std::cout << "ZLIB inflate failed: " << strm.msg << " (Return code: " << ret << ")" << std::endl; // Nên log cụ thể hơn
            return false;
        }
        // Kiểm tra xem tất cả dữ liệu gốc đã được điền đầy đủ chưa
        if (strm.avail_out != 0) {
             std::cout << "ZLIB decompressed size mismatch. Expected " << original_size << ", got " << (original_size - strm.avail_out) << std::endl;
             return false;
        }
        return true;
    }
};