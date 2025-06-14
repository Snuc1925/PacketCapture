#include "processor/ZstdProcessor.hpp"

std::vector<char> ZstdProcessor::process(const std::vector<char>& input_buffer) {
    if (input_buffer.empty()) {
        return {};
    }

    size_t const compressed_bound = ZSTD_compressBound(input_buffer.size());
    std::vector<char> compressed_buffer(compressed_bound);

    size_t const compressed_size = ZSTD_compress(
        compressed_buffer.data(), compressed_buffer.size(),
        input_buffer.data(), input_buffer.size(),
        1
    );

    if (ZSTD_isError(compressed_size)) {
        std::cerr << "ZSTD compression error: " << ZSTD_getErrorName(compressed_size) << std::endl;
        return {};
    }

    compressed_buffer.resize(compressed_size);
    return compressed_buffer;
}
