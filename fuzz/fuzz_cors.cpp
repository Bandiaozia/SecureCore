#include "fuzz_common.hpp"

#include "secure/http/cors_policy.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <vector>

namespace {

const secure::CorsPolicy& exact_policy() {
    static const secure::CorsPolicy policy(
        {
            "https://example.com",
            "http://localhost:3000"
        },
        true,
        600
    );

    return policy;
}

const secure::CorsPolicy& wildcard_policy() {
    static const secure::CorsPolicy policy(
        {"*"},
        false,
        600
    );

    return policy;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(
    const std::uint8_t* data,
    std::size_t size
) {
    if (data == nullptr || size == 0) {
        return 0;
    }

    const std::string input =
        secure::fuzz::input_string(data + 1, size - 1);

    // Keep a fast path that exercises matching on already validated policy
    // objects, and a construction path that fuzzes origin validation.
    if ((data[0] & 1U) == 0U) {
        static_cast<void>(exact_policy().allows(input));
        static_cast<void>(wildcard_policy().allows(input));
        return 0;
    }

    std::vector<std::string> origins;
    std::size_t start = 0;

    while (start <= input.size() && origins.size() < 8) {
        const std::size_t separator = input.find('\0', start);
        const std::size_t end = separator == std::string::npos
            ? input.size()
            : separator;

        origins.emplace_back(
            input.substr(start, end - start)
        );

        if (separator == std::string::npos) {
            break;
        }
        start = separator + 1;
    }

    try {
        secure::CorsPolicy policy(
            origins,
            (data[0] & 2U) != 0U,
            static_cast<std::uint32_t>(size)
        );

        static_cast<void>(policy.allows(input));
        static_cast<void>(policy.allows("https://example.com"));
    } catch (const std::exception&) {
    }

    return 0;
}
