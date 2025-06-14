#include "processor/PassThroughProcessor.hpp"

std::vector<char> PassThroughProcessor::process(const std::vector<char>& input_buffer) {
    return input_buffer;
}
