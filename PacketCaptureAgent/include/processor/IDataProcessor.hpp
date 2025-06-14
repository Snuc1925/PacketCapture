#pragma once
#include <vector>

class IDataProcessor {
public:
    virtual ~IDataProcessor() = default;

    // Trả về một vector rỗng nếu có lỗi
    virtual std::vector<char> process(const std::vector<char>& input_buffer) = 0;
};
