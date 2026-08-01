#include "secure/http/account_routes.hpp"

#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/router.hpp"
#include "secure/model/auth_session.hpp"
#include "secure/service/account_security_service.hpp"
#include "secure/service/auth_service.hpp"

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

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

    const auto value =
        iterator->value();

    const boost::beast::string_view prefix{
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

std::optional<std::int64_t>
parse_positive_integer(
    std::string_view value
) {
    if (value.empty()) {
        return std::nullopt;
    }

    std::int64_t result = 0;

    const char* begin =
        value.data();

    const char* end =
        begin + value.size();

    const auto [position, error] =
        std::from_chars(
            begin,
            end,
            result
        );

    if (
        error != std::errc{} ||
        position != end ||
        result <= 0
    ) {
        return std::nullopt;
    }

    return result;
}

std::optional<std::int64_t>
path_session_id(
    const RouteParameters& parameters
) {
    const auto iterator =
        parameters.find("id");

    if (iterator == parameters.end()) {
        return std::nullopt;
    }

    return parse_positive_integer(
        iterator->second
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
        AuthErrorCode::
            token_creation_failed
    ) {
        status =
            http::status::
                internal_server_error;
    }

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

HttpResponse account_error_response(
    const AccountSecurityError& error
) {
    http::status status =
        http::status::bad_request;

    if (
        error.code() ==
        AccountSecurityErrorCode::
            session_not_found
    ) {
        status = http::status::not_found;
    }

    return make_json_error(
        status,
        account_security_error_name(
            error.code()
        )
    );
}

HttpResponse list_sessions_handler(
    AccountSecurityService&
        account_security_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return missing_token_response();
    }

    try {
        const SessionListResult result =
            account_security_service
                .list_sessions(
                    *access_token
                );

        Json sessions = Json::array();

        for (
            const AuthSession& session :
            result.sessions
        ) {
            sessions.push_back(
                Json{
                    {"id", session.id},
                    {
                        "current",
                        session.id ==
                            result
                                .current_session_id
                    },
                    {
                        "access_expires_at",
                        session
                            .access_expires_at
                    },
                    {
                        "refresh_expires_at",
                        session
                            .refresh_expires_at
                    },
                    {
                        "created_at",
                        session.created_at
                    }
                }
            );
        }

        return make_json_response(
            http::status::ok,
            Json{
                {
                    "sessions",
                    sessions
                },
                {
                    "count",
                    sessions.size()
                }
            }
        );
    } catch (const AuthError& error) {
        return auth_error_response(error);
    }
}

HttpResponse revoke_session_handler(
    AccountSecurityService&
        account_security_service,
    const HttpRequest& request,
    const RouteParameters& parameters
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return missing_token_response();
    }

    const auto session_id =
        path_session_id(parameters);

    if (!session_id.has_value()) {
        return make_json_error(
            http::status::bad_request,
            "invalid_session_id"
        );
    }

    try {
        account_security_service
            .revoke_session(
                *access_token,
                *session_id
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
    } catch (const AuthError& error) {
        return auth_error_response(error);
    } catch (
        const AccountSecurityError& error
    ) {
        return account_error_response(error);
    }
}

HttpResponse change_password_handler(
    AccountSecurityService&
        account_security_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return missing_token_response();
    }

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

    const auto current_password =
        body.find("current_password");

    const auto new_password =
        body.find("new_password");

    if (
        current_password ==
        body.end()
    ) {
        return make_json_error(
            http::status::bad_request,
            "current_password_required"
        );
    }

    if (!current_password->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "current_password_must_be_string"
        );
    }

    if (new_password == body.end()) {
        return make_json_error(
            http::status::bad_request,
            "new_password_required"
        );
    }

    if (!new_password->is_string()) {
        return make_json_error(
            http::status::bad_request,
            "new_password_must_be_string"
        );
    }

    try {
        const PasswordChangeResult result =
            account_security_service
                .change_password(
                    *access_token,
                    current_password
                        ->get<std::string>(),
                    new_password
                        ->get<std::string>()
                );

        return make_json_response(
            http::status::ok,
            Json{
                {
                    "password_changed",
                    true
                },
                {
                    "revoked_sessions",
                    result.revoked_sessions
                }
            }
        );
    } catch (const AuthError& error) {
        return auth_error_response(error);
    } catch (
        const AccountSecurityError& error
    ) {
        return account_error_response(error);
    }
}

}  // namespace

void register_account_routes(
    Router& router,
    AccountSecurityService&
        account_security_service
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
