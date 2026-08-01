#pragma once

#include "secure/model/audit_event.hpp"

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace secure {

class Database;

class AuditRepositoryError final
    : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class AuditRepository final {
public:
    explicit AuditRepository(
        Database& database
    );

    [[nodiscard]]
    AuditEvent create(
        const CreateAuditEvent& input
    );

    [[nodiscard]]
    std::vector<AuditEvent> list(
        const AuditEventFilter& filter
    );

    [[nodiscard]]
    std::int64_t count(
        const AuditEventFilter& filter
    );

    [[nodiscard]]
    std::int64_t delete_older_than_days(
        std::int64_t retention_days
    );

private:
    Database& database_;
};

}  // namespace secure
