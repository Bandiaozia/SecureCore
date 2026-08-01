#include "secure/http/request_id.hpp"

#include "secure/http/api_error.hpp"

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <sstream>
#include <string>

namespace secure {

namespace {

std::atomic<std::uint64_t>
    request_sequence{0};

bool is_valid_request_id_character(
    char character
) {
    const auto value =
        static_cast<unsigned char>(
            character
        );

    return (
        std::isalnum(value) != 0 ||
        character == '-' ||
        character == '_' ||
        character == '.'
    );
}

bool is_valid_request_id(
    const std::string& request_id
) {
    if (
        request_id.empty() ||
        request_id.size() > 64
    ) {
        return false;
    }

    for (const char character : request_id) {
        if (
            !is_valid_request_id_character(
                character
            )
        ) {
            return false;
        }
    }

    return true;
}

}  // namespace

std::string generate_request_id() {
    const auto timestamp =
        std::chrono::duration_cast<
            std::chrono::nanoseconds
        >(
            std::chrono::steady_clock::
                now().time_since_epoch()
        ).count();

    const auto sequence =
        request_sequence.fetch_add(
            1,
            std::memory_order_relaxed
        );

    std::ostringstream stream;

    stream
        << std::hex
        << static_cast<std::uint64_t>(
            timestamp
        )
        << '-'
        << sequence;

    return stream.str();
}

std::string resolve_request_id(
    const HttpRequest& request
) {
    const auto iterator =
        request.find("X-Request-ID");

    if (iterator != request.end()) {
        const auto value =
            iterator->value();

        std::string request_id(
            value.data(),
            value.size()
        );

        if (is_valid_request_id(request_id)) {
            return request_id;
        }
    }

    return generate_request_id();
}

void apply_request_id(
    HttpResponse& response,
    std::string_view request_id
) {
    response.set(
        "X-Request-ID",
        request_id
    );

    attach_request_id_to_api_error(
        response,
        request_id
    );
}

}  // namespace secure
