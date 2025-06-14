#pragma once

#include "processor/IDataProcessor.hpp"
#include <vector>

class ZlibProcessor : public IDataProcessor {
public:
    std::vector<char> process(const std::vector<char>& input_buffer) override;
};