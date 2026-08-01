#include "fuzz_common.hpp"

#include "secure/http/http_types.hpp"
#include "secure/http/request_id.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(
    const std::uint8_t* data,
    std::size_t size
) {
    std::string value =
        secure::fuzz::input_string(data, size);
    secure::fuzz::sanitize_http_field_value(value);

    try {
        secure::HttpRequest request;
        request.version(11);
        request.set("X-Request-ID", value);

        const std::string request_id =
            secure::resolve_request_id(request);

        secure::HttpResponse response;
        secure::apply_request_id(response, request_id);
    } catch (const std::exception&) {
    }

    return 0;
}
