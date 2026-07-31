#include "secure/http/routes.hpp"

#include "secure/database/database.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/router.hpp"
#include "secure/model/user.hpp"
#include "secure/service/auth_service.hpp"
#include "secure/service/user_service.hpp"

#include <cstddef>
#include <optional>
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

Json make_login_result_json(
    const LoginResult& result
) {
    return Json{
        {"token_type", "Bearer"},

        {
            "access_token",
            result.tokens.access_token
        },

        {
            "refresh_token",
            result.tokens.refresh_token
        },

        {
            "access_expires_at",
            result.tokens.access_expires_at
        },

        {
            "refresh_expires_at",
            result.tokens.refresh_expires_at
        },

        {
            "user",
            make_public_user_json(
                result.user
            )
        }
    };
}

std::optional<std::string>
extract_bearer_token(
    const HttpRequest& request
) {
    const auto iterator =
        request.find(
            http::field::authorization
        );

    if (iterator == request.end()) {
        return std::nullopt;
    }

    const auto value =
        iterator->value();

    constexpr std::string_view prefix{
        "Bearer "
    };

    if (
        value.size() <= prefix.size() ||
        value.substr(
            0,
            prefix.size()
        ) != prefix
    ) {
        return std::nullopt;
    }

    return std::string(
        value.data() + prefix.size(),
        value.size() - prefix.size()
    );
}

http::status auth_error_status(
    AuthErrorCode code
) {
    switch (code) {
    case AuthErrorCode::
        invalid_credentials:

    case AuthErrorCode::
        invalid_access_token:

    case AuthErrorCode::
        access_token_expired:

    case AuthErrorCode::
        invalid_refresh_token:

    case AuthErrorCode::
        refresh_token_expired:
        return http::status::unauthorized;

    case AuthErrorCode::
        account_disabled:
        return http::status::forbidden;

    case AuthErrorCode::
        token_creation_failed:
        return http::status::
            internal_server_error;
    }

    return http::status::
        internal_server_error;
}

HttpResponse make_auth_error_response(
    const AuthError& error
) {
    const http::status status =
        auth_error_status(
            error.code()
        );

    HttpResponse response =
        make_json_error(
            status,
            auth_error_name(
                error.code()
            )
        );

    if (
        status ==
        http::status::unauthorized
    ) {
        response.set(
            http::field::www_authenticate,
            "Bearer"
        );
    }

    return response;
}

HttpResponse make_missing_token_response() {
    HttpResponse response =
        make_json_error(
            http::status::unauthorized,
            "missing_access_token"
        );

    response.set(
        http::field::www_authenticate,
        "Bearer"
    );

    return response;
}

HttpResponse register_handler(
    UserService& user_service,
    const HttpRequest& request
) {
    if (!has_json_content_type(request)) {
        return make_json_error(
            http::status::
                unsupported_media_type,
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

    const auto username =
        body.find("username");

    const auto email =
        body.find("email");

    const auto password =
        body.find("password");

    if (username == body.end()) {
        return make_json_error(
            http::status::bad_request,
            "username_required"
        );
    }

    if (!username->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "username_must_be_string"
        );
    }

    if (email == body.end()) {
        return make_json_error(
            http::status::bad_request,
            "email_required"
        );
    }

    if (!email->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "email_must_be_string"
        );
    }

    if (password == body.end()) {
        return make_json_error(
            http::status::bad_request,
            "password_required"
        );
    }

    if (!password->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "password_must_be_string"
        );
    }

    try {
        const User user =
            user_service.register_user(
                username->get<std::string>(),
                email->get<std::string>(),
                password->get<std::string>()
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
                : http::status::
                    bad_request;

        return make_json_error(
            status,
            registration_error_name(
                error.code()
            )
        );
    }
}

HttpResponse login_handler(
    AuthService& auth_service,
    const HttpRequest& request
) {
    if (!has_json_content_type(request)) {
        return make_json_error(
            http::status::
                unsupported_media_type,
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

    const auto login =
        body.find("login");

    const auto password =
        body.find("password");

    if (login == body.end()) {
        return make_json_error(
            http::status::bad_request,
            "login_required"
        );
    }

    if (!login->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "login_must_be_string"
        );
    }

    if (password == body.end()) {
        return make_json_error(
            http::status::bad_request,
            "password_required"
        );
    }

    if (!password->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "password_must_be_string"
        );
    }

    try {
        const LoginResult result =
            auth_service.login(
                login->get<std::string>(),
                password->get<std::string>()
            );

        return make_json_response(
            http::status::ok,
            make_login_result_json(
                result
            )
        );
    } catch (
        const AuthError& error
    ) {
        return make_auth_error_response(
            error
        );
    }
}

HttpResponse refresh_handler(
    AuthService& auth_service,
    const HttpRequest& request
) {
    if (!has_json_content_type(request)) {
        return make_json_error(
            http::status::
                unsupported_media_type,
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

    const auto refresh_token =
        body.find("refresh_token");

    if (refresh_token == body.end()) {
        return make_json_error(
            http::status::bad_request,
            "refresh_token_required"
        );
    }

    if (!refresh_token->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "refresh_token_must_be_string"
        );
    }

    try {
        const LoginResult result =
            auth_service.refresh(
                refresh_token
                    ->get<std::string>()
            );

        return make_json_response(
            http::status::ok,
            make_login_result_json(
                result
            )
        );
    } catch (
        const AuthError& error
    ) {
        return make_auth_error_response(
            error
        );
    }
}

HttpResponse logout_handler(
    AuthService& auth_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(
            request
        );

    if (!access_token.has_value()) {
        return make_missing_token_response();
    }

    /*
     * 提供了格式正确的 Bearer Token 后，
     * logout 保持幂等。
     */
    static_cast<void>(
        auth_service.logout_access_token(
            *access_token
        )
    );

    HttpResponse response{
        http::status::no_content,
        request.version()
    };

    response.keep_alive(
        request.keep_alive()
    );

    response.prepare_payload();

    return response;
}

HttpResponse logout_all_handler(
    AuthService& auth_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(
            request
        );

    if (!access_token.has_value()) {
        return make_missing_token_response();
    }

    try {
        const auto revoked_sessions =
            auth_service
                .logout_all_access_token(
                    *access_token
                );

        return make_json_response(
            http::status::ok,
            Json{
                {
                    "revoked_sessions",
                    revoked_sessions
                }
            }
        );
    } catch (
        const AuthError& error
    ) {
        return make_auth_error_response(
            error
        );
    }
}

HttpResponse me_handler(
    AuthService& auth_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(
            request
        );

    if (!access_token.has_value()) {
        return make_missing_token_response();
    }

    try {
        const User user =
            auth_service
                .authenticate_access_token(
                    *access_token
                );

        return make_json_response(
            http::status::ok,
            Json{
                {
                    "user",
                    make_public_user_json(
                        user
                    )
                }
            }
        );
    } catch (
        const AuthError& error
    ) {
        return make_auth_error_response(
            error
        );
    }
}

HttpResponse echo_handler(
    const HttpRequest& request
) {
    if (!has_json_content_type(request)) {
        return make_json_error(
            http::status::
                unsupported_media_type,
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

    const auto message =
        body.find("message");

    if (message == body.end()) {
        return make_json_error(
            http::status::bad_request,
            "message_required"
        );
    }

    if (!message->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "message_must_be_string"
        );
    }

    const std::string value =
        message->get<std::string>();

    if (value.empty()) {
        return make_json_error(
            http::status::bad_request,
            "message_must_not_be_empty"
        );
    }

    if (
        value.size() >
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
            {"message", value},
            {"received", true}
        }
    );
}

}  // namespace

void register_routes(
    Router& router,
    Database& database,
    UserService& user_service,
    AuthService& auth_service
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
        "/v1/auth/login",
        [&auth_service](
            const HttpRequest& request
        ) {
            return login_handler(
                auth_service,
                request
            );
        }
    );

    router.post(
        "/v1/auth/refresh",
        [&auth_service](
            const HttpRequest& request
        ) {
            return refresh_handler(
                auth_service,
                request
            );
        }
    );

    router.post(
        "/v1/auth/logout",
        [&auth_service](
            const HttpRequest& request
        ) {
            return logout_handler(
                auth_service,
                request
            );
        }
    );

    router.post(
        "/v1/auth/logout-all",
        [&auth_service](
            const HttpRequest& request
        ) {
            return logout_all_handler(
                auth_service,
                request
            );
        }
    );

    router.get(
        "/v1/users/me",
        [&auth_service](
            const HttpRequest& request
        ) {
            return me_handler(
                auth_service,
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
