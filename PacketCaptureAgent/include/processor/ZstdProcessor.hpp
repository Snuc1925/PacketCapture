#pragma once

#include "processor/IDataProcessor.hpp"
#include <zstd.h>
#include <vector>
#include <iostream>

class ZstdProcessor : public IDataProcessor {
public:
    std::vector<char> process(const std::vector<char>& input_buffer) override;
};
