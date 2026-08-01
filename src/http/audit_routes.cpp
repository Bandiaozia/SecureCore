#include "secure/http/audit_routes.hpp"

#include "secure/http/api_error.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/request_validation.hpp"
#include "secure/http/router.hpp"
#include "secure/model/audit_event.hpp"
#include "secure/service/admin_service.hpp"
#include "secure/service/audit_service.hpp"
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

std::optional<std::string>
extract_bearer_token(
    const HttpRequest& request
) {
    const auto iterator = request.find(
        http::field::authorization
    );

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
        status =
            http::status::internal_server_error;
    }

    HttpResponse response = make_json_error(
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
    if (error.code() == AdminErrorCode::forbidden) {
        return make_json_error(
            http::status::forbidden,
            "admin_permission_required"
        );
    }

    return make_json_error(
        http::status::internal_server_error,
        "internal_server_error"
    );
}

std::optional<std::string>
optional_query_string(
    const HttpRequest& request,
    std::string_view name,
    std::size_t maximum_size
) {
    auto value = query_parameter(
        request.target(),
        name
    );

    if (!value.has_value()) {
        return std::nullopt;
    }

    if (
        value->empty() ||
        value->size() > maximum_size
    ) {
        throw ApiException(
            http::status::unprocessable_entity,
            ApiError{
                "validation_failed",
                "Request validation failed.",
                {
                    ApiErrorDetail{
                        std::string(name),
                        "must be a non-empty value within the allowed length"
                    }
                }
            }
        );
    }

    return value;
}

std::optional<std::int64_t>
optional_positive_integer_query(
    const HttpRequest& request,
    std::string_view name
) {
    auto value = query_parameter(
        request.target(),
        name
    );

    if (!value.has_value()) {
        return std::nullopt;
    }

    std::int64_t parsed = 0;

    const auto result = std::from_chars(
        value->data(),
        value->data() + value->size(),
        parsed
    );

    if (
        result.ec != std::errc{} ||
        result.ptr != value->data() + value->size() ||
        parsed <= 0
    ) {
        throw ApiException(
            http::status::unprocessable_entity,
            ApiError{
                "validation_failed",
                "Request validation failed.",
                {
                    ApiErrorDetail{
                        std::string(name),
                        "must be a positive integer"
                    }
                }
            }
        );
    }

    return parsed;
}

Json audit_event_json(
    const AuditEvent& event
) {
    Json metadata = Json::parse(
        event.metadata_json,
        nullptr,
        false
    );

    if (metadata.is_discarded()) {
        metadata = Json::object();
    }

    Json result{
        {"id", event.id},
        {"event_type", event.event_type},
        {"outcome", event.outcome},
        {"target_type", event.target_type},
        {"request_id", event.request_id},
        {"client_ip", event.client_ip},
        {"user_agent", event.user_agent},
        {"metadata", std::move(metadata)},
        {"created_at", event.created_at}
    };

    if (event.actor_user_id.has_value()) {
        result["actor_user_id"] =
            *event.actor_user_id;
    } else {
        result["actor_user_id"] = nullptr;
    }

    if (event.target_id.has_value()) {
        result["target_id"] = *event.target_id;
    } else {
        result["target_id"] = nullptr;
    }

    return result;
}

HttpResponse list_audit_events_handler(
    AdminService& admin_service,
    AuditService& audit_service,
    const HttpRequest& request
) {
    const auto access_token =
        extract_bearer_token(request);

    if (!access_token.has_value()) {
        return missing_token_response();
    }

    AuditEventFilter filter;

    filter.limit = query_integer_or_default(
        request,
        "limit",
        50,
        1,
        100
    );

    filter.offset = query_integer_or_default(
        request,
        "offset",
        0,
        0,
        std::numeric_limits<std::int64_t>::max()
    );

    filter.actor_user_id =
        optional_positive_integer_query(
            request,
            "actor_user_id"
        );

    if (const auto event_type =
            optional_query_string(
                request,
                "event_type",
                96
            );
        event_type.has_value()
    ) {
        filter.event_type = *event_type;
    }

    if (const auto outcome =
            optional_query_string(
                request,
                "outcome",
                16
            );
        outcome.has_value()
    ) {
        if (
            *outcome != "success" &&
            *outcome != "failure"
        ) {
            throw ApiException(
                http::status::unprocessable_entity,
                ApiError{
                    "validation_failed",
                    "Request validation failed.",
                    {
                        ApiErrorDetail{
                            "outcome",
                            "must be success or failure"
                        }
                    }
                }
            );
        }

        filter.outcome = *outcome;
    }

    try {
        const User administrator =
            admin_service.authenticate_admin(
                *access_token
            );

        const AuditListResult result =
            audit_service.list_events(filter);

        Json events = Json::array();

        for (const AuditEvent& event : result.events) {
            events.push_back(
                audit_event_json(event)
            );
        }

        audit_service.record(
            AuditRecord{
                administrator.id,
                "audit.events.read",
                "success",
                "audit_event",
                std::nullopt,
                Json{
                    {"returned", events.size()},
                    {"offset", result.offset},
                    {"limit", result.limit}
                }.dump()
            }
        );

        return make_json_response(
            http::status::ok,
            Json{
                {"events", std::move(events)},
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

}  // namespace

void register_audit_routes(
    Router& router,
    AdminService& admin_service,
    AuditService& audit_service
) {
    router.get(
        "/v1/admin/audit-events",
        [&admin_service, &audit_service](
            const HttpRequest& request
        ) {
            return list_audit_events_handler(
                admin_service,
                audit_service,
                request
            );
        }
    );
}

}  // namespace secure
