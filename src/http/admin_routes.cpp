#include "secure/http/admin_routes.hpp"

#include "secure/http/api_error.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/request_validation.hpp"
#include "secure/http/router.hpp"
#include "secure/model/user.hpp"
#include "secure/service/admin_service.hpp"
#include "secure/service/auth_service.hpp"

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <boost/beast/http.hpp>

namespace secure {

namespace http = boost::beast::http;

namespace {

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

HttpResponse admin_error_response(
    const AdminError& error
) {
    switch (error.code()) {
    case AdminErrorCode::forbidden:
        return make_json_error(
            http::status::forbidden,
            "admin_permission_required"
        );

    case AdminErrorCode::invalid_pagination:
        return make_validation_error(
            {
                ApiErrorDetail{
                    "pagination",
                    "limit and offset are outside the allowed range"
                }
            }
        );

    case AdminErrorCode::user_not_found:
        return make_json_error(
            http::status::not_found,
            "user_not_found"
        );

    case AdminErrorCode::cannot_disable_self:
        return make_json_error(
            http::status::conflict,
            "cannot_disable_self"
        );
    }

    return make_json_error(
        http::status::internal_server_error,
        "internal_server_error"
    );
}

HttpResponse list_users_handler(
    AdminService& admin_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return missing_token_response();
    }

    const std::int64_t limit =
        query_integer_or_default(
            request,
            "limit",
            50,
            1,
            100
        );

    const std::int64_t offset =
        query_integer_or_default(
            request,
            "offset",
            0,
            0,
            std::numeric_limits<
                std::int64_t
            >::max()
        );

    try {
        const UserListResult result =
            admin_service.list_users(
                *access_token,
                limit,
                offset
            );

        Json users = Json::array();

        for (const User& user : result.users) {
            users.push_back(
                make_public_user_json(user)
            );
        }

        return make_json_response(
            http::status::ok,
            Json{
                {"users", std::move(users)},
                {"total", result.total},
                {"limit", result.limit},
                {"offset", result.offset}
            }
        );
    } catch (const AuthError& error) {
        return auth_error_response(error);
    } catch (const AdminError& error) {
        return admin_error_response(error);
    }
}

HttpResponse get_user_handler(
    AdminService& admin_service,
    const HttpRequest& request,
    const RouteParameters& parameters
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return missing_token_response();
    }

    const std::int64_t user_id =
        require_path_integer(
            parameters,
            "id"
        );

    try {
        const User user =
            admin_service.get_user(
                *access_token,
                user_id
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
        return auth_error_response(error);
    } catch (const AdminError& error) {
        return admin_error_response(error);
    }
}

HttpResponse set_user_status_handler(
    AdminService& admin_service,
    const HttpRequest& request,
    const RouteParameters& parameters
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return missing_token_response();
    }

    const std::int64_t user_id =
        require_path_integer(
            parameters,
            "id"
        );

    const Json body =
        parse_json_object(request);

    JsonObjectValidator validator(body);

    auto enabled =
        validator.required_boolean(
            "enabled"
        );

    validator.throw_if_invalid();

    try {
        const UserStatusResult result =
            admin_service.set_user_enabled(
                *access_token,
                user_id,
                *enabled
            );

        return make_json_response(
            http::status::ok,
            Json{
                {
                    "user",
                    make_public_user_json(
                        result.user
                    )
                },
                {
                    "revoked_sessions",
                    result.revoked_sessions
                }
            }
        );
    } catch (const AuthError& error) {
        return auth_error_response(error);
    } catch (const AdminError& error) {
        return admin_error_response(error);
    }
}

}  // namespace

void register_admin_routes(
    Router& router,
    AdminService& admin_service
) {
    router.get(
        "/v1/admin/users",
        [&admin_service](
            const HttpRequest& request
        ) {
            return list_users_handler(
                admin_service,
                request
            );
        }
    );

    router.get(
        "/v1/admin/users/{id}",
        [&admin_service](
            const HttpRequest& request,
            const RouteParameters& parameters
        ) {
            return get_user_handler(
                admin_service,
                request,
                parameters
            );
        }
    );

    router.patch(
        "/v1/admin/users/{id}/status",
        [&admin_service](
            const HttpRequest& request,
            const RouteParameters& parameters
        ) {
            return set_user_status_handler(
                admin_service,
                request,
                parameters
            );
        }
    );
}

}  // namespace secure
