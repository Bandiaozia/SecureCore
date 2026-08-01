#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace secure::fuzz {

constexpr std::size_t maximum_input_size = 64 * 1024;

inline std::string input_string(
    const std::uint8_t* data,
    std::size_t size
) {
    if (data == nullptr) {
        return {};
    }

    if (size > maximum_input_size) {
        size = maximum_input_size;
    }

    return std::string(
        reinterpret_cast<const char*>(data),
        size
    );
}

inline void sanitize_http_field_value(
    std::string& value
) {
    for (char& character : value) {
        if (character == '\r' || character == '\n') {
            character = ' ';
        }
    }
}

}  // namespace secure::fuzz
