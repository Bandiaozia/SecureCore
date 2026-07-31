#include "secure/http/routes.hpp"

#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/router.hpp"

#include <cstddef>
#include <string>

#include <boost/beast/http.hpp>

namespace secure {

namespace http = boost::beast::http;

namespace {

constexpr std::size_t max_echo_message_size =
    1024;

HttpResponse health_handler(
    const HttpRequest&
) {
    return make_json_response(
        http::status::ok,
        Json{
            {"status", "ok"}
        }
    );
}

HttpResponse echo_handler(
    const HttpRequest& request
) {
    if (!has_json_content_type(request)) {
        return make_json_error(
            http::status::unsupported_media_type,
            "unsupported_media_type"
        );
    }

    if (request.body().empty()) {
        return make_json_error(
            http::status::bad_request,
            "empty_body"
        );
    }

    Json body;

    try {
        body = Json::parse(
            request.body()
        );
    } catch (const Json::parse_error&) {
        return make_json_error(
            http::status::bad_request,
            "invalid_json"
        );
    }

    if (!body.is_object()) {
        return make_json_error(
            http::status::bad_request,
            "json_object_required"
        );
    }

    const auto message_iterator =
        body.find("message");

    if (message_iterator == body.end()) {
        return make_json_error(
            http::status::bad_request,
            "message_required"
        );
    }

    if (!message_iterator->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "message_must_be_string"
        );
    }

    std::string message =
        message_iterator->get<std::string>();

    if (message.empty()) {
        return make_json_error(
            http::status::bad_request,
            "message_must_not_be_empty"
        );
    }

    if (
        message.size() >
        max_echo_message_size
    ) {
        return make_json_error(
            http::status::bad_request,
            "message_too_long"
        );
    }

    return make_json_response(
        http::status::ok,
        Json{
            {"message", message},
            {"received", true}
        }
    );
}

}  // namespace

void register_routes(
    Router& router
) {
    router.get(
        "/health",
        health_handler
    );

    router.post(
        "/v1/echo",
        echo_handler
    );
}

}  // namespace secure
