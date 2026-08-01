#include "secure/service/audit_service.hpp"

#include "secure/audit/request_audit_context.hpp"
#include "secure/log/logger.hpp"
#include "secure/observability/metrics_registry.hpp"
#include "secure/repository/audit_repository.hpp"

#include <algorithm>
#include <cctype>
#include <exception>
#include <stdexcept>
#include <string>
#include <utility>


namespace secure {

namespace {

std::string sanitize_text(
    std::string value,
    std::size_t maximum_size
) {
    value.erase(
        std::remove_if(
            value.begin(),
            value.end(),
            [](char character) {
                const auto byte =
                    static_cast<unsigned char>(
                        character
                    );

                return (
                    byte < 0x20U ||
                    byte == 0x7fU
                );
            }
        ),
        value.end()
    );

    if (value.size() > maximum_size) {
        value.resize(maximum_size);
    }

    return value;
}


}  // namespace

AuditService::AuditService(
    AuditRepository& audit_repository,
    Logger& logger,
    MetricsRegistry& metrics_registry
)
    : audit_repository_(audit_repository),
      logger_(logger),
      metrics_registry_(metrics_registry) {
}

void AuditService::record(
    AuditRecord record
) noexcept {
    try {
        if (
            record.request_id.empty() ||
            record.client_ip.empty() ||
            record.user_agent.empty()
        ) {
            const auto context =
                current_request_audit_context();

            if (context.has_value()) {
                if (record.request_id.empty()) {
                    record.request_id =
                        context->request_id;
                }

                if (record.client_ip.empty()) {
                    record.client_ip =
                        context->client_ip;
                }

                if (record.user_agent.empty()) {
                    record.user_agent =
                        context->user_agent;
                }
            }
        }

        record.request_id = sanitize_text(
            std::move(record.request_id),
            128
        );

        record.client_ip = sanitize_text(
            std::move(record.client_ip),
            128
        );

        record.user_agent = sanitize_text(
            std::move(record.user_agent),
            512
        );

        static_cast<void>(
            audit_repository_.create(
                CreateAuditEvent{
                    record.actor_user_id,
                    std::move(record.event_type),
                    std::move(record.outcome),
                    std::move(record.target_type),
                    record.target_id,
                    std::move(record.request_id),
                    std::move(record.client_ip),
                    std::move(record.user_agent),
                    std::move(record.metadata_json)
                }
            )
        );

        metrics_registry_.audit_event_recorded();
    } catch (const std::exception& error) {
        metrics_registry_.audit_event_failed();

        logger_.error(
            "Failed to persist security audit event: ",
            error.what()
        );
    } catch (...) {
        metrics_registry_.audit_event_failed();

        logger_.error(
            "Failed to persist security audit event: "
            "unknown error"
        );
    }
}

AuditListResult AuditService::list_events(
    const AuditEventFilter& filter
) {
    return AuditListResult{
        audit_repository_.list(filter),
        audit_repository_.count(filter),
        filter.limit,
        filter.offset
    };
}

std::int64_t AuditService::purge_expired(
    std::int64_t retention_days
) {
    return audit_repository_
        .delete_older_than_days(
            retention_days
        );
}

}  // namespace secure
