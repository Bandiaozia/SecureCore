#include "fuzz_common.hpp"

#include "secure/http/api_error.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/request_validation.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

#include <boost/beast/http.hpp>

extern "C" int LLVMFuzzerTestOneInput(
    const std::uint8_t* data,
    std::size_t size
) {
    secure::HttpRequest request;
    request.version(11);
    request.method(boost::beast::http::verb::post);
    request.set(
        boost::beast::http::field::content_type,
        "application/json"
    );
    request.body() = secure::fuzz::input_string(data, size);

    try {
        const secure::Json object =
            secure::parse_json_object(request);

        secure::JsonObjectValidator validator(object);
        static_cast<void>(
            validator.required_string("username", 1, 64)
        );
        static_cast<void>(
            validator.required_string("password", 1, 128)
        );
        static_cast<void>(
            validator.required_boolean("enabled")
        );
        validator.throw_if_invalid();
    } catch (const secure::ApiException&) {
    } catch (const std::exception&) {
    }

    return 0;
}
