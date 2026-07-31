#include "secure/http/routes.hpp"

#include "secure/database/database.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/router.hpp"
#include "secure/model/user.hpp"
#include "secure/service/user_service.hpp"

#include <cstddef>
#include <string>
#include <string_view>

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

HttpResponse ready_handler(
    Database& database,
    const HttpRequest&
) {
    if (database.healthy()) {
        return make_json_response(
            http::status::ok,
            Json{
                {"status", "ready"},
                {"database", "ok"}
            }
        );
    }

    return make_json_response(
        http::status::service_unavailable,
        Json{
            {"status", "not_ready"},
            {"database", "unavailable"}
        }
    );
}

Json make_public_user_json(
    const User& user
) {
    return Json{
        {"id", user.id},
        {"username", user.username},
        {"email", user.email},
        {"role", user.role},
        {"enabled", user.enabled},
        {"created_at", user.created_at},
        {"updated_at", user.updated_at}
    };
}

HttpResponse register_handler(
    UserService& user_service,
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
    } catch (
        const Json::parse_error&
    ) {
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

    const auto username_iterator =
        body.find("username");

    if (
        username_iterator ==
        body.end()
    ) {
        return make_json_error(
            http::status::bad_request,
            "username_required"
        );
    }

    if (!username_iterator->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "username_must_be_string"
        );
    }

    const auto email_iterator =
        body.find("email");

    if (
        email_iterator ==
        body.end()
    ) {
        return make_json_error(
            http::status::bad_request,
            "email_required"
        );
    }

    if (!email_iterator->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "email_must_be_string"
        );
    }

    const auto password_iterator =
        body.find("password");

    if (
        password_iterator ==
        body.end()
    ) {
        return make_json_error(
            http::status::bad_request,
            "password_required"
        );
    }

    if (!password_iterator->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "password_must_be_string"
        );
    }

    try {
        const User user =
            user_service.register_user(
                username_iterator
                    ->get<std::string>(),

                email_iterator
                    ->get<std::string>(),

                password_iterator
                    ->get<std::string>()
            );

        HttpResponse response =
            make_json_response(
                http::status::created,
                Json{
                    {
                        "user",
                        make_public_user_json(
                            user
                        )
                    }
                }
            );

        response.set(
            http::field::location,
            "/v1/users/" +
                std::to_string(user.id)
        );

        return response;
    } catch (
        const RegistrationError& error
    ) {
        const http::status status =
            error.code() ==
                RegistrationErrorCode::
                    duplicate_user
                ? http::status::conflict
                : http::status::bad_request;

        return make_json_error(
            status,
            registration_error_name(
                error.code()
            )
        );
    }
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
    } catch (
        const Json::parse_error&
    ) {
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

    if (
        message_iterator ==
        body.end()
    ) {
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
        message_iterator
            ->get<std::string>();

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
    Router& router,
    Database& database,
    UserService& user_service
) {
    router.get(
        "/health",
        health_handler
    );

    router.get(
        "/ready",
        [&database](
            const HttpRequest& request
        ) {
            return ready_handler(
                database,
                request
            );
        }
    );

    router.post(
        "/v1/auth/register",
        [&user_service](
            const HttpRequest& request
        ) {
            return register_handler(
                user_service,
                request
            );
        }
    );

    router.post(
        "/v1/echo",
        echo_handler
    );
}

}  // namespace secure
