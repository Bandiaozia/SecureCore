#include "secure/http/account_routes.hpp"

#include "secure/http/api_error.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/request_validation.hpp"
#include "secure/http/router.hpp"
#include "secure/model/auth_session.hpp"
#include "secure/service/account_security_service.hpp"
#include "secure/service/auth_service.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <boost/beast/http.hpp>

namespace secure {

namespace http = boost::beast::http;

namespace {

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

    const boost::beast::string_view prefix{
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

HttpResponse missing_token_response() {
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

HttpResponse auth_error_response(
    const AuthError& error
) {
    http::status status =
        http::status::unauthorized;

    if (
        error.code() ==
        AuthErrorCode::account_disabled
    ) {
        status = http::status::forbidden;
    } else if (
        error.code() ==
        AuthErrorCode::token_creation_failed
    ) {
        status = http::status::internal_server_error;
    }

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

HttpResponse account_error_response(
    const AccountSecurityError& error
) {
    switch (error.code()) {
    case AccountSecurityErrorCode::session_not_found:
        return make_json_error(
            http::status::not_found,
            "session_not_found"
        );

    case AccountSecurityErrorCode::invalid_current_password:
        return make_json_error(
            http::status::bad_request,
            "invalid_current_password"
        );

    case AccountSecurityErrorCode::weak_new_password:
        return make_validation_error(
            {
                ApiErrorDetail{
                    "new_password",
                    "must contain between 8 and 128 bytes"
                }
            }
        );

    case AccountSecurityErrorCode::same_password:
        return make_json_error(
            http::status::conflict,
            "same_password"
        );
    }

    return make_json_error(
        http::status::internal_server_error,
        "internal_server_error"
    );
}

HttpResponse list_sessions_handler(
    AccountSecurityService& account_security_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return missing_token_response();
    }

    try {
        const SessionListResult result =
            account_security_service.list_sessions(
                *access_token
            );

        Json sessions = Json::array();

        for (const AuthSession& session : result.sessions) {
            sessions.push_back(
                Json{
                    {"id", session.id},
                    {
                        "current",
                        session.id ==
                            result.current_session_id
                    },
                    {
                        "access_expires_at",
                        session.access_expires_at
                    },
                    {
                        "refresh_expires_at",
                        session.refresh_expires_at
                    },
                    {"created_at", session.created_at}
                }
            );
        }

        return make_json_response(
            http::status::ok,
            Json{
                {"sessions", sessions},
                {"count", sessions.size()}
            }
        );
    } catch (const AuthError& error) {
        return auth_error_response(error);
    }
}

HttpResponse revoke_session_handler(
    AccountSecurityService& account_security_service,
    const HttpRequest& request,
    const RouteParameters& parameters
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return missing_token_response();
    }

    const std::int64_t session_id =
        require_path_integer(
            parameters,
            "id"
        );

    try {
        account_security_service.revoke_session(
            *access_token,
            session_id
        );

        HttpResponse response{
            http::status::no_content,
            request.version()
        };

        response.keep_alive(request.keep_alive());
        response.prepare_payload();

        return response;
    } catch (const AuthError& error) {
        return auth_error_response(error);
    } catch (const AccountSecurityError& error) {
        return account_error_response(error);
    }
}

HttpResponse change_password_handler(
    AccountSecurityService& account_security_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return missing_token_response();
    }

    const Json body =
        parse_json_object(request);

    JsonObjectValidator validator(body);

    auto current_password =
        validator.required_string(
            "current_password",
            1,
            128
        );

    auto new_password =
        validator.required_string(
            "new_password",
            1,
            128
        );

    if (
        new_password.has_value() &&
        !valid_password_input(*new_password)
    ) {
        validator.add_error(
            "new_password",
            "must contain between 8 and 128 bytes"
        );
    }

    validator.throw_if_invalid();

    try {
        const PasswordChangeResult result =
            account_security_service.change_password(
                *access_token,
                std::move(*current_password),
                std::move(*new_password)
            );

        return make_json_response(
            http::status::ok,
            Json{
                {"password_changed", true},
                {
                    "revoked_sessions",
                    result.revoked_sessions
                }
            }
        );
    } catch (const AuthError& error) {
        return auth_error_response(error);
    } catch (const AccountSecurityError& error) {
        return account_error_response(error);
    }
}

}  // namespace

void register_account_routes(
    Router& router,
    AccountSecurityService& account_security_service
) {
    router.get(
        "/v1/auth/sessions",
        [&account_security_service](
            const HttpRequest& request
        ) {
            return list_sessions_handler(
                account_security_service,
                request
            );
        }
    );

    router.remove(
        "/v1/auth/sessions/{id}",
        [&account_security_service](
            const HttpRequest& request,
            const RouteParameters& parameters
        ) {
            return revoke_session_handler(
                account_security_service,
                request,
                parameters
            );
        }
    );

    router.post(
        "/v1/users/me/password",
        [&account_security_service](
            const HttpRequest& request
        ) {
            return change_password_handler(
                account_security_service,
                request
            );
        }
    );
}

}  // namespace secure
