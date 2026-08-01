#include "secure/http/routes.hpp"

#include "secure/database/database.hpp"
#include "secure/http/api_error.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/request_validation.hpp"
#include "secure/http/router.hpp"
#include "secure/model/user.hpp"
#include "secure/runtime/service_state.hpp"
#include "secure/service/auth_service.hpp"
#include "secure/service/user_service.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
    ServiceState& service_state,
    const HttpRequest&
) {
    const bool database_ready = database.healthy();

    if (!service_state.ready()) {
        return make_json_response(
            http::status::service_unavailable,
            Json{
                {
                    "status",
                    std::string(
                        ServiceState::name(
                            service_state.phase()
                        )
                    )
                },
                {
                    "database",
                    database_ready
                        ? "ok"
                        : "unavailable"
                }
            }
        );
    }

    if (database_ready) {
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

    const auto value = iterator->value();

    constexpr std::string_view prefix{
        "Bearer "
    };

    if (
        value.size() <= prefix.size() ||
        value.substr(0, prefix.size()) != prefix
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
    case AuthErrorCode::invalid_credentials:
    case AuthErrorCode::invalid_access_token:
    case AuthErrorCode::access_token_expired:
    case AuthErrorCode::invalid_refresh_token:
    case AuthErrorCode::refresh_token_expired:
        return http::status::unauthorized;

    case AuthErrorCode::account_disabled:
        return http::status::forbidden;

    case AuthErrorCode::token_creation_failed:
        return http::status::internal_server_error;
    }

    return http::status::internal_server_error;
}

HttpResponse make_auth_error_response(
    const AuthError& error
) {
    const http::status status =
        auth_error_status(error.code());

    HttpResponse response =
        make_json_error(
            status,
            auth_error_name(error.code())
        );

    if (status == http::status::unauthorized) {
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

HttpResponse registration_error_response(
    const RegistrationError& error
) {
    if (
        error.code() ==
        RegistrationErrorCode::duplicate_user
    ) {
        return make_json_error(
            http::status::conflict,
            "duplicate_user"
        );
    }

    std::string field;
    std::string reason;

    switch (error.code()) {
    case RegistrationErrorCode::invalid_username:
        field = "username";
        reason =
            "must contain 3 to 32 ASCII letters, "
            "digits, '_' or '-'";
        break;

    case RegistrationErrorCode::invalid_email:
        field = "email";
        reason = "must be a valid email address";
        break;

    case RegistrationErrorCode::weak_password:
        field = "password";
        reason =
            "must contain between 8 and 128 bytes";
        break;

    case RegistrationErrorCode::duplicate_user:
        break;
    }

    return make_validation_error(
        {
            ApiErrorDetail{
                std::move(field),
                std::move(reason)
            }
        }
    );
}

HttpResponse register_handler(
    UserService& user_service,
    const HttpRequest& request
) {
    const Json body =
        parse_json_object(request);

    JsonObjectValidator validator(body);

    auto username = validator.required_string(
        "username",
        1,
        254
    );

    auto email = validator.required_string(
        "email",
        1,
        254
    );

    auto password = validator.required_string(
        "password",
        1,
        128
    );

    if (
        username.has_value() &&
        !valid_username_input(*username)
    ) {
        validator.add_error(
            "username",
            "must contain 3 to 32 ASCII letters, "
            "digits, '_' or '-'"
        );
    }

    if (
        email.has_value() &&
        !valid_email_input(*email)
    ) {
        validator.add_error(
            "email",
            "must be a valid email address"
        );
    }

    if (
        password.has_value() &&
        !valid_password_input(*password)
    ) {
        validator.add_error(
            "password",
            "must contain between 8 and 128 bytes"
        );
    }

    validator.throw_if_invalid();

    try {
        const User user =
            user_service.register_user(
                std::move(*username),
                std::move(*email),
                std::move(*password)
            );

        HttpResponse response =
            make_json_response(
                http::status::created,
                Json{
                    {
                        "user",
                        make_public_user_json(user)
                    }
                }
            );

        response.set(
            http::field::location,
            "/v1/users/" +
                std::to_string(user.id)
        );

        return response;
    } catch (const RegistrationError& error) {
        return registration_error_response(error);
    }
}

HttpResponse login_handler(
    AuthService& auth_service,
    const HttpRequest& request
) {
    const Json body =
        parse_json_object(request);

    JsonObjectValidator validator(body);

    auto login = validator.required_string(
        "login",
        1,
        254
    );

    auto password = validator.required_string(
        "password",
        1,
        128
    );

    validator.throw_if_invalid();

    try {
        const LoginResult result =
            auth_service.login(
                std::move(*login),
                std::move(*password)
            );

        return make_json_response(
            http::status::ok,
            make_login_result_json(result)
        );
    } catch (const AuthError& error) {
        return make_auth_error_response(error);
    }
}

HttpResponse refresh_handler(
    AuthService& auth_service,
    const HttpRequest& request
) {
    const Json body =
        parse_json_object(request);

    JsonObjectValidator validator(body);

    auto refresh_token =
        validator.required_string(
            "refresh_token",
            1,
            512
        );

    validator.throw_if_invalid();

    try {
        const LoginResult result =
            auth_service.refresh(
                *refresh_token
            );

        return make_json_response(
            http::status::ok,
            make_login_result_json(result)
        );
    } catch (const AuthError& error) {
        return make_auth_error_response(error);
    }
}

HttpResponse logout_handler(
    AuthService& auth_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return make_missing_token_response();
    }

    static_cast<void>(
        auth_service.logout_access_token(
            *access_token
        )
    );

    HttpResponse response{
        http::status::no_content,
        request.version()
    };

    response.keep_alive(request.keep_alive());
    response.prepare_payload();

    return response;
}

HttpResponse logout_all_handler(
    AuthService& auth_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return make_missing_token_response();
    }

    try {
        const auto revoked_sessions =
            auth_service.logout_all_access_token(
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
    } catch (const AuthError& error) {
        return make_auth_error_response(error);
    }
}

HttpResponse me_handler(
    AuthService& auth_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return make_missing_token_response();
    }

    try {
        const User user =
            auth_service.authenticate_access_token(
                *access_token
            );

        return make_json_response(
            http::status::ok,
            Json{
                {
                    "user",
                    make_public_user_json(user)
                }
            }
        );
    } catch (const AuthError& error) {
        return make_auth_error_response(error);
    }
}

HttpResponse echo_handler(
    const HttpRequest& request
) {
    const Json body =
        parse_json_object(request);

    JsonObjectValidator validator(body);

    auto message = validator.required_string(
        "message",
        1,
        max_echo_message_size
    );

    validator.throw_if_invalid();

    return make_json_response(
        http::status::ok,
        Json{
            {"message", *message},
            {"received", true}
        }
    );
}

}  // namespace

void register_routes(
    Router& router,
    Database& database,
    ServiceState& service_state,
    UserService& user_service,
    AuthService& auth_service
) {
    router.get(
        "/health",
        health_handler
    );

    router.get(
        "/ready",
        [&database, &service_state](
            const HttpRequest& request
        ) {
            return ready_handler(
                database,
                service_state,
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
