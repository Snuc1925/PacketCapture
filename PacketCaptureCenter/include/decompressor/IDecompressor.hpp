#pragma once // Hoặc cặp include guard truyền thống

#include <vector>
#include <cstddef> // For size_t
#include <stdexcept> // For std::runtime_error

// Base interface cho các bộ giải nén
class IDecompressor {
public:
    virtual ~IDecompressor() = default;

    // Phương thức chính để giải nén
    // @param compressed_data: con trỏ tới dữ liệu đã nén
    // @param compressed_size: kích thước dữ liệu đã nén
    // @param original_size: kích thước dữ liệu gốc (trước khi nén)
    // @param decompressed_buffer: buffer để chứa dữ liệu đã giải nén. Phương thức này sẽ resize nó.
    // @return true nếu giải nén thành công và kích thước đúng, false nếu thất bại.
    virtual bool decompress(const char* compressed_data, size_t compressed_size,
                            size_t original_size, std::vector<char>& decompressed_buffer) = 0;
};