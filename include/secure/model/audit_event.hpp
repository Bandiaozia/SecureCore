#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace secure {

struct AuditEvent final {
    std::int64_t id{0};

    std::optional<std::int64_t> actor_user_id;

    std::string event_type;

    std::string outcome;

    std::string target_type;

    std::optional<std::int64_t> target_id;

    std::string request_id;

    std::string client_ip;

    std::string user_agent;

    std::string metadata_json{"{}"};

    std::string created_at;
};

struct CreateAuditEvent final {
    std::optional<std::int64_t> actor_user_id;

    std::string event_type;

    std::string outcome;

    std::string target_type;

    std::optional<std::int64_t> target_id;

    std::string request_id;

    std::string client_ip;

    std::string user_agent;

    std::string metadata_json{"{}"};
};

struct AuditEventFilter final {
    std::optional<std::int64_t> actor_user_id;

    std::string event_type;

    std::string outcome;

    std::int64_t limit{50};

    std::int64_t offset{0};
};

}  // namespace secure
