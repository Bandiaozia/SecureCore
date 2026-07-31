#include "secure/config/server_config.hpp"

#include <charconv>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <system_error>

namespace secure {

namespace {

std::string trim(
    std::string_view value
) {
    const auto first =
        value.find_first_not_of(
            " \t\r\n"
        );

    if (first == std::string_view::npos) {
        return {};
    }

    const auto last =
        value.find_last_not_of(
            " \t\r\n"
        );

    return std::string(
        value.substr(
            first,
            last - first + 1
        )
    );
}

std::uint64_t parse_unsigned(
    const std::string& value,
    std::string_view key,
    std::size_t line_number,
    std::uint64_t minimum,
    std::uint64_t maximum
) {
    std::uint64_t result = 0;

    const char* begin = value.data();
    const char* end =
        begin + value.size();

    const auto [position, error] =
        std::from_chars(
            begin,
            end,
            result
        );

    if (
        error != std::errc{} ||
        position != end ||
        result < minimum ||
        result > maximum
    ) {
        throw std::runtime_error(
            "Invalid " +
            std::string(key) +
            " at line " +
            std::to_string(line_number)
        );
    }

    return result;
}

}  // namespace

ServerConfig ServerConfig::load_from_file(
    const std::string& path
) {
    std::ifstream input(path);

    if (!input.is_open()) {
        throw std::runtime_error(
            "Failed to open configuration file: " +
            path
        );
    }

    ServerConfig config;

    std::string raw_line;
    std::size_t line_number = 0;

    while (std::getline(input, raw_line)) {
        ++line_number;

        const std::string line =
            trim(raw_line);

        if (
            line.empty() ||
            line.front() == '#'
        ) {
            continue;
        }

        const auto separator =
            line.find('=');

        if (
            separator ==
            std::string::npos
        ) {
            throw std::runtime_error(
                "Missing '=' at configuration line " +
                std::to_string(line_number)
            );
        }

        const std::string key =
            trim(
                std::string_view(line).substr(
                    0,
                    separator
                )
            );

        const std::string value =
            trim(
                std::string_view(line).substr(
                    separator + 1
                )
            );

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
                static_cast<std::uint16_t>(
                    parse_unsigned(
                        value,
                        key,
                        line_number,
                        1,
                        65535
                    )
                );
        } else if (key == "log_file") {
            config.log_file_ = value;
        } else if (
            key == "http_max_header_bytes"
        ) {
            config.http_max_header_bytes_ =
                static_cast<std::uint32_t>(
                    parse_unsigned(
                        value,
                        key,
                        line_number,
                        1024,
                        1024ULL * 1024ULL
                    )
                );
        } else if (
            key == "http_max_body_bytes"
        ) {
            config.http_max_body_bytes_ =
                parse_unsigned(
                    value,
                    key,
                    line_number,
                    1,
                    1024ULL *
                        1024ULL *
                        1024ULL
                );
        } else if (
            key ==
            "http_read_timeout_seconds"
        ) {
            config
                .http_read_timeout_seconds_ =
                static_cast<std::uint32_t>(
                    parse_unsigned(
                        value,
                        key,
                        line_number,
                        1,
                        3600
                    )
                );
        } else if (
            key ==
            "http_write_timeout_seconds"
        ) {
            config
                .http_write_timeout_seconds_ =
                static_cast<std::uint32_t>(
                    parse_unsigned(
                        value,
                        key,
                        line_number,
                        1,
                        3600
                    )
                );
        } else if (
            key ==
            "http_idle_timeout_seconds"
        ) {
            config
                .http_idle_timeout_seconds_ =
                static_cast<std::uint32_t>(
                    parse_unsigned(
                        value,
                        key,
                        line_number,
                        1,
                        3600
                    )
                );
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

const std::string&
ServerConfig::log_file() const noexcept {
    return log_file_;
}

std::uint32_t
ServerConfig::http_max_header_bytes()
    const noexcept {
    return http_max_header_bytes_;
}

std::uint64_t
ServerConfig::http_max_body_bytes()
    const noexcept {
    return http_max_body_bytes_;
}

std::uint32_t
ServerConfig::http_read_timeout_seconds()
    const noexcept {
    return http_read_timeout_seconds_;
}

std::uint32_t
ServerConfig::http_write_timeout_seconds()
    const noexcept {
    return http_write_timeout_seconds_;
}

std::uint32_t
ServerConfig::http_idle_timeout_seconds()
    const noexcept {
    return http_idle_timeout_seconds_;
}

}  // namespace secure
