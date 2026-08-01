#include "secure/http/rbac_routes.hpp"

#include "secure/http/api_error.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/request_validation.hpp"
#include "secure/http/router.hpp"
#include "secure/model/rbac.hpp"
#include "secure/service/admin_service.hpp"
#include "secure/service/audit_service.hpp"
#include "secure/service/auth_service.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/beast/http.hpp>

namespace secure {

namespace http = boost::beast::http;

namespace {

std::optional<std::string> bearer_token(
    const HttpRequest& request
) {
    const auto iterator = request.find(http::field::authorization);
    if (iterator == request.end()) {
        return std::nullopt;
    }
    const auto value = iterator->value();
    constexpr std::string_view prefix{"Bearer "};
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
    HttpResponse response = make_json_error(
        http::status::unauthorized,
        "missing_access_token"
    );
    response.set(http::field::www_authenticate, "Bearer");
    return response;
}

HttpResponse auth_error_response(const AuthError& error) {
    http::status status = http::status::unauthorized;
    if (error.code() == AuthErrorCode::account_disabled) {
        status = http::status::forbidden;
    } else if (error.code() == AuthErrorCode::token_creation_failed) {
        status = http::status::internal_server_error;
    }
    HttpResponse response = make_json_error(
        status, auth_error_name(error.code())
    );
    if (status == http::status::unauthorized) {
        response.set(http::field::www_authenticate, "Bearer");
    }
    return response;
}

HttpResponse admin_error_response(const AdminError& error) {
    switch (error.code()) {
    case AdminErrorCode::forbidden:
        return make_json_error(
            http::status::forbidden,
            "permission_required"
        );
    case AdminErrorCode::user_not_found:
        return make_json_error(http::status::not_found, "user_not_found");
    case AdminErrorCode::role_not_found:
        return make_json_error(http::status::not_found, "role_not_found");
    case AdminErrorCode::cannot_remove_last_super_admin:
        return make_json_error(
            http::status::conflict,
            "cannot_remove_last_super_admin"
        );
    case AdminErrorCode::cannot_remove_base_role:
        return make_json_error(
            http::status::conflict,
            "cannot_remove_base_role"
        );
    case AdminErrorCode::cannot_disable_self:
        return make_json_error(http::status::conflict, "cannot_disable_self");
    case AdminErrorCode::invalid_pagination:
        return make_json_error(
            http::status::unprocessable_entity,
            "validation_failed"
        );
    }
    return make_json_error(
        http::status::internal_server_error,
        "internal_server_error"
    );
}

Json permission_json(const Permission& permission) {
    return Json{
        {"id", permission.id},
        {"name", permission.name},
        {"description", permission.description}
    };
}

Json role_json(const Role& role) {
    Json permissions = Json::array();
    for (const Permission& permission : role.permissions) {
        permissions.push_back(permission_json(permission));
    }
    return Json{
        {"id", role.id},
        {"name", role.name},
        {"description", role.description},
        {"built_in", role.built_in},
        {"permissions", std::move(permissions)}
    };
}

Json roles_json(const std::vector<Role>& roles) {
    Json result = Json::array();
    for (const Role& role : roles) {
        result.push_back(role_json(role));
    }
    return result;
}

HttpResponse list_roles_handler(
    AdminService& admin_service,
    const HttpRequest& request
) {
    const auto token = bearer_token(request);
    if (!token.has_value()) {
        return missing_token_response();
    }
    try {
        const auto roles = admin_service.list_roles(*token);
        return make_json_response(
            http::status::ok,
            Json{{"roles", roles_json(roles)}}
        );
    } catch (const AuthError& error) {
        return auth_error_response(error);
    } catch (const AdminError& error) {
        return admin_error_response(error);
    }
}

HttpResponse list_permissions_handler(
    AdminService& admin_service,
    const HttpRequest& request
) {
    const auto token = bearer_token(request);
    if (!token.has_value()) {
        return missing_token_response();
    }
    try {
        const auto permissions = admin_service.list_permissions(*token);
        Json body = Json::array();
        for (const Permission& permission : permissions) {
            body.push_back(permission_json(permission));
        }
        return make_json_response(
            http::status::ok,
            Json{{"permissions", std::move(body)}}
        );
    } catch (const AuthError& error) {
        return auth_error_response(error);
    } catch (const AdminError& error) {
        return admin_error_response(error);
    }
}

HttpResponse list_user_roles_handler(
    AdminService& admin_service,
    const HttpRequest& request,
    const RouteParameters& parameters
) {
    const auto token = bearer_token(request);
    if (!token.has_value()) {
        return missing_token_response();
    }
    const std::int64_t user_id = require_path_integer(parameters, "id");
    try {
        const auto roles = admin_service.list_user_roles(*token, user_id);
        return make_json_response(
            http::status::ok,
            Json{{"user_id", user_id}, {"roles", roles_json(roles)}}
        );
    } catch (const AuthError& error) {
        return auth_error_response(error);
    } catch (const AdminError& error) {
        return admin_error_response(error);
    }
}

HttpResponse assign_role_handler(
    AdminService& admin_service,
    AuditService& audit_service,
    const HttpRequest& request,
    const RouteParameters& parameters
) {
    const auto token = bearer_token(request);
    if (!token.has_value()) {
        return missing_token_response();
    }
    const std::int64_t user_id = require_path_integer(parameters, "id");
    const Json body = parse_json_object(request);
    JsonObjectValidator validator(body);
    auto role = validator.required_string("role", 1, 64);
    validator.throw_if_invalid();

    try {
        const RoleChangeResult result = admin_service.assign_role(
            *token, user_id, *role
        );
        audit_service.record(AuditRecord{
            result.administrator_id,
            "rbac.role_assign",
            "success",
            "user",
            user_id,
            Json{{"role", *role}, {"changed", result.changed}}.dump()
        });
        return make_json_response(
            http::status::ok,
            Json{
                {"user_id", result.user.id},
                {"role", *role},
                {"changed", result.changed},
                {"roles", roles_json(result.roles)}
            }
        );
    } catch (const AuthError& error) {
        audit_service.record(AuditRecord{
            std::nullopt,
            "rbac.role_assign",
            "failure",
            "user",
            user_id,
            Json{{"role", *role}, {"reason", auth_error_name(error.code())}}.dump()
        });
        return auth_error_response(error);
    } catch (const AdminError& error) {
        audit_service.record(AuditRecord{
            std::nullopt,
            "rbac.role_assign",
            "failure",
            "user",
            user_id,
            Json{{"role", *role}, {"reason", admin_error_name(error.code())}}.dump()
        });
        return admin_error_response(error);
    }
}

HttpResponse revoke_role_handler(
    AdminService& admin_service,
    AuditService& audit_service,
    const HttpRequest& request,
    const RouteParameters& parameters
) {
    const auto token = bearer_token(request);
    if (!token.has_value()) {
        return missing_token_response();
    }
    const std::int64_t user_id = require_path_integer(parameters, "id");
    const auto role_iterator = parameters.find("role");
    if (role_iterator == parameters.end() || role_iterator->second.empty()) {
        throw ApiException(
            http::status::unprocessable_entity,
            ApiError{
                "validation_failed",
                default_api_error_message("validation_failed"),
                {ApiErrorDetail{"role", "must be a non-empty role name"}}
            }
        );
    }
    const std::string role = role_iterator->second;

    try {
        const RoleChangeResult result = admin_service.revoke_role(
            *token, user_id, role
        );
        audit_service.record(AuditRecord{
            result.administrator_id,
            "rbac.role_revoke",
            "success",
            "user",
            user_id,
            Json{{"role", role}, {"changed", result.changed}}.dump()
        });
        return make_json_response(
            http::status::ok,
            Json{
                {"user_id", result.user.id},
                {"role", role},
                {"changed", result.changed},
                {"roles", roles_json(result.roles)}
            }
        );
    } catch (const AuthError& error) {
        audit_service.record(AuditRecord{
            std::nullopt,
            "rbac.role_revoke",
            "failure",
            "user",
            user_id,
            Json{{"role", role}, {"reason", auth_error_name(error.code())}}.dump()
        });
        return auth_error_response(error);
    } catch (const AdminError& error) {
        audit_service.record(AuditRecord{
            std::nullopt,
            "rbac.role_revoke",
            "failure",
            "user",
            user_id,
            Json{{"role", role}, {"reason", admin_error_name(error.code())}}.dump()
        });
        return admin_error_response(error);
    }
}

}  // namespace

void register_rbac_routes(
    Router& router,
    AdminService& admin_service,
    AuditService& audit_service
) {
    router.get(
        "/v1/admin/roles",
        [&admin_service](const HttpRequest& request) {
            return list_roles_handler(admin_service, request);
        }
    );
    router.get(
        "/v1/admin/permissions",
        [&admin_service](const HttpRequest& request) {
            return list_permissions_handler(admin_service, request);
        }
    );
    router.get(
        "/v1/admin/users/{id}/roles",
        [&admin_service](
            const HttpRequest& request,
            const RouteParameters& parameters
        ) {
            return list_user_roles_handler(
                admin_service, request, parameters
            );
        }
    );
    router.post(
        "/v1/admin/users/{id}/roles",
        [&admin_service, &audit_service](
            const HttpRequest& request,
            const RouteParameters& parameters
        ) {
            return assign_role_handler(
                admin_service, audit_service, request, parameters
            );
        }
    );
    router.remove(
        "/v1/admin/users/{id}/roles/{role}",
        [&admin_service, &audit_service](
            const HttpRequest& request,
            const RouteParameters& parameters
        ) {
            return revoke_role_handler(
                admin_service, audit_service, request, parameters
            );
        }
    );
}

}  // namespace secure
