#include "secure/http/json_utils.hpp"

#include <cstddef>
#include <string>

#include <boost/beast/core/string.hpp>

namespace secure {

namespace beast = boost::beast;
namespace http = beast::http;

namespace {

beast::string_view trim(
    beast::string_view value
) {
    std::size_t first = 0;
    std::size_t last = value.size();

    while (
        first < last &&
        (
            value[first] == ' ' ||
            value[first] == '\t'
        )
    ) {
        ++first;
    }

    while (
        last > first &&
        (
            value[last - 1] == ' ' ||
            value[last - 1] == '\t'
        )
    ) {
        --last;
    }

    return value.substr(
        first,
        last - first
    );
}

}  // namespace

bool has_json_content_type(
    const HttpRequest& request
) {
    const beast::string_view content_type =
        request[http::field::content_type];

    if (content_type.empty()) {
        return false;
    }

    const auto separator =
        content_type.find(';');

    const beast::string_view media_type =
        trim(
            content_type.substr(
                0,
                separator
            )
        );

    return beast::iequals(
        media_type,
        "application/json"
    );
}

HttpResponse make_json_response(
    http::status status,
    const Json& body
) {
    HttpResponse response;

    response.result(status);

    response.set(
        http::field::content_type,
        "application/json; charset=utf-8"
    );

    response.body() = body.dump();

    return response;
}

HttpResponse make_json_error(
    http::status status,
    std::string_view error_code
) {
    return make_json_response(
        status,
        Json{
            {
                "error",
                std::string(error_code)
            }
        }
    );
}

}  // namespace secure
