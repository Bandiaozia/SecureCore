#pragma once

#include "secure/model/audit_event.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace secure {

class AuditRepository;
class Logger;
class MetricsRegistry;

struct AuditRecord final {
    AuditRecord() = default;

    AuditRecord(
        std::optional<std::int64_t> actor,
        std::string event,
        std::string event_outcome,
        std::string target,
        std::optional<std::int64_t> target_identifier,
        std::string metadata
    )
        : actor_user_id(actor),
          event_type(std::move(event)),
          outcome(std::move(event_outcome)),
          target_type(std::move(target)),
          target_id(target_identifier),
          metadata_json(std::move(metadata)) {
    }

    std::optional<std::int64_t> actor_user_id;

    std::string event_type;

    std::string outcome{"success"};

    std::string target_type;

    std::optional<std::int64_t> target_id;

    std::string metadata_json{"{}"};

    std::string request_id;

    std::string client_ip;

    std::string user_agent;
};

struct AuditListResult final {
    std::vector<AuditEvent> events;

    std::int64_t total{0};

    std::int64_t limit{0};

    std::int64_t offset{0};
};

class AuditService final {
public:
    AuditService(
        AuditRepository& audit_repository,
        Logger& logger,
        MetricsRegistry& metrics_registry
    );

    void record(
        AuditRecord record
    ) noexcept;

    [[nodiscard]]
    AuditListResult list_events(
        const AuditEventFilter& filter
    );

    [[nodiscard]]
    std::int64_t purge_expired(
        std::int64_t retention_days
    );

private:
    AuditRepository& audit_repository_;

    Logger& logger_;

    MetricsRegistry& metrics_registry_;
};

}  // namespace secure
