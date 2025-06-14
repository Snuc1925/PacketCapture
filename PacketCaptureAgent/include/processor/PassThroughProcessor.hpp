#pragma once
#include "processor/IDataProcessor.hpp"

class PassThroughProcessor : public IDataProcessor {
public:
    std::vector<char> process(const std::vector<char>& input_buffer) override;
};
