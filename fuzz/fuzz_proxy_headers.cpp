#include "fuzz_common.hpp"

#include "secure/http/http_types.hpp"
#include "secure/net/trusted_proxy.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

namespace {

const secure::TrustedProxyResolver& resolver() {
    static const secure::TrustedProxyResolver instance(
        {
            "127.0.0.1/32",
            "10.0.0.0/8",
            "::1/128"
        },
        4096
    );

    return instance;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(
    const std::uint8_t* data,
    std::size_t size
) {
    if (data == nullptr || size == 0) {
        return 0;
    }

    std::string value =
        secure::fuzz::input_string(data + 1, size - 1);
    secure::fuzz::sanitize_http_field_value(value);

    secure::HttpRequest request;
    request.version(11);

    const char* header_name = nullptr;
    switch (data[0] % 4U) {
        case 0:
            header_name = "Forwarded";
            break;
        case 1:
            header_name = "X-Forwarded-For";
            break;
        case 2:
            header_name = "X-Real-IP";
            break;
        default:
            header_name = "X-Forwarded-Proto";
            break;
    }

    try {
        request.set(header_name, value);

        static_cast<void>(
            resolver().resolve(
                "127.0.0.1",
                request,
                (data[0] & 0x80U) != 0U
            )
        );
    } catch (const std::exception&) {
    }

    return 0;
}
