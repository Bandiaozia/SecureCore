#include "secure/config/server_config.hpp"

#include <charconv>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <system_error>

namespace secure {

namespace {

std::string trim(std::string_view value) {
    const auto first =
        value.find_first_not_of(" \t\r\n");

    if (first == std::string_view::npos) {
        return {};
    }

    const auto last =
        value.find_last_not_of(" \t\r\n");

    return std::string(
        value.substr(first, last - first + 1)
    );
}

std::uint16_t parse_port(
    const std::string& value,
    std::size_t line_number
) {
    unsigned int port = 0;

    const char* begin = value.data();
    const char* end = value.data() + value.size();

    const auto [position, error] =
        std::from_chars(begin, end, port);

    if (
        error != std::errc{} ||
        position != end ||
        port == 0 ||
        port > 65535
    ) {
        throw std::runtime_error(
            "Invalid listen_port at line " +
            std::to_string(line_number)
        );
    }

    return static_cast<std::uint16_t>(port);
}

}  // namespace

ServerConfig ServerConfig::load_from_file(
    const std::string& path
) {
    std::ifstream input(path);

    if (!input.is_open()) {
        throw std::runtime_error(
            "Failed to open configuration file: " + path
        );
    }

    ServerConfig config;

    std::string raw_line;
    std::size_t line_number = 0;

    while (std::getline(input, raw_line)) {
        ++line_number;

        const std::string line = trim(raw_line);

        if (line.empty() || line.front() == '#') {
            continue;
        }

        const auto separator = line.find('=');

        if (separator == std::string::npos) {
            throw std::runtime_error(
                "Missing '=' at configuration line " +
                std::to_string(line_number)
            );
        }

        const std::string key =
            trim(std::string_view(line).substr(
                0,
                separator
            ));

        const std::string value =
            trim(std::string_view(line).substr(
                separator + 1
            ));

        if (key.empty() || value.empty()) {
            throw std::runtime_error(
                "Empty key or value at configuration line " +
                std::to_string(line_number)
            );
        }

        if (key == "listen_address") {
            config.listen_address_ = value;
        } else if (key == "listen_port") {
            config.listen_port_ =
                parse_port(value, line_number);
        } else {
            throw std::runtime_error(
                "Unknown configuration key '" +
                key +
                "' at line " +
                std::to_string(line_number)
            );
        }
    }

    return config;
}

const std::string&
ServerConfig::listen_address() const noexcept {
    return listen_address_;
}

std::uint16_t
ServerConfig::listen_port() const noexcept {
    return listen_port_;
}

}  // namespace secure
