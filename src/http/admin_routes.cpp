#include "secure/http/admin_routes.hpp"

#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/router.hpp"
#include "secure/model/user.hpp"
#include "secure/service/admin_service.hpp"
#include "secure/service/auth_service.hpp"

#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
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
parse_integer(
    std::string_view value,
    std::int64_t minimum,
    std::int64_t maximum
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
        result < minimum ||
        result > maximum
    ) {
        return std::nullopt;
    }

    return result;
}

std::optional<std::int64_t>
path_user_id(
    const RouteParameters& parameters
) {
    const auto iterator =
        parameters.find("id");

    if (iterator == parameters.end()) {
        return std::nullopt;
    }

    return parse_integer(
        iterator->second,
        1,
        std::numeric_limits<
            std::int64_t
        >::max()
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

HttpResponse admin_error_response(
    const AdminError& error
) {
    http::status status;

    switch (error.code()) {
    case AdminErrorCode::forbidden:
        status = http::status::forbidden;
        break;

    case AdminErrorCode::
        invalid_pagination:
        status = http::status::bad_request;
        break;

    case AdminErrorCode::user_not_found:
        status = http::status::not_found;
        break;

    case AdminErrorCode::
        cannot_disable_self:
        status = http::status::conflict;
        break;

    default:
        status =
            http::status::
                internal_server_error;
        break;
    }

    return make_json_error(
        status,
        admin_error_name(
            error.code()
        )
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

    std::int64_t limit = 50;
    std::int64_t offset = 0;

    if (
        const auto value =
            query_parameter(
                request.target(),
                "limit"
            );
        value.has_value()
    ) {
        const auto parsed =
            parse_integer(
                *value,
                1,
                100
            );

        if (!parsed.has_value()) {
            return make_json_error(
                http::status::bad_request,
                "invalid_pagination"
            );
        }

        limit = *parsed;
    }

    if (
        const auto value =
            query_parameter(
                request.target(),
                "offset"
            );
        value.has_value()
    ) {
        const auto parsed =
            parse_integer(
                *value,
                0,
                std::numeric_limits<
                    std::int64_t
                >::max()
            );

        if (!parsed.has_value()) {
            return make_json_error(
                http::status::bad_request,
                "invalid_pagination"
            );
        }

        offset = *parsed;
    }

    try {
        const UserListResult result =
            admin_service.list_users(
                *access_token,
                limit,
                offset
            );

        Json users = Json::array();

        for (
            const User& user :
            result.users
        ) {
            users.push_back(
                make_public_user_json(user)
            );
        }

        return make_json_response(
            http::status::ok,
            Json{
                {
                    "users",
                    std::move(users)
                },
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

    const auto user_id =
        path_user_id(parameters);

    if (!user_id.has_value()) {
        return make_json_error(
            http::status::bad_request,
            "invalid_user_id"
        );
    }

    try {
        const User user =
            admin_service.get_user(
                *access_token,
                *user_id
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

    const auto user_id =
        path_user_id(parameters);

    if (!user_id.has_value()) {
        return make_json_error(
            http::status::bad_request,
            "invalid_user_id"
        );
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

    const auto enabled =
        body.find("enabled");

    if (enabled == body.end()) {
        return make_json_error(
            http::status::bad_request,
            "enabled_required"
        );
    }

    if (!enabled->is_boolean()) {
        return make_json_error(
            http::status::bad_request,
            "enabled_must_be_boolean"
        );
    }

    try {
        const UserStatusResult result =
            admin_service.set_user_enabled(
                *access_token,
                *user_id,
                enabled->get<bool>()
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
