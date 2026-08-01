#include "secure/audit/request_audit_context.hpp"
#include "secure/database/database.hpp"
#include "secure/database/migration.hpp"
#include "secure/log/logger.hpp"
#include "secure/model/audit_event.hpp"
#include "secure/model/user.hpp"
#include "secure/observability/metrics_registry.hpp"
#include "secure/repository/audit_repository.hpp"
#include "secure/repository/user_repository.hpp"
#include "secure/service/audit_service.hpp"

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

namespace {

void require(
    bool condition,
    const std::string& message
) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::filesystem::path test_root() {
    const auto root =
        std::filesystem::temp_directory_path() /
        "securecore-audit-unit";

    std::error_code error;
    std::filesystem::remove_all(root, error);
    std::filesystem::create_directories(root);

    return root;
}

}  // namespace

int main() {
    try {
        const auto root = test_root();

        secure::Database database(
            root / "audit.db",
            2
        );

        secure::MigrationRunner migrations(
            database
        );

        migrations.apply();

        secure::UserRepository users(database);
        secure::AuditRepository audit(database);
        secure::Logger logger(
            (root / "audit.log").string()
        );
        secure::MetricsRegistry metrics;
        secure::AuditService service(
            audit,
            logger,
            metrics
        );

        const secure::User user = users.create(
            secure::CreateUser{
                "audit-user",
                "audit@example.com",
                "test-password-hash",
                "user"
            }
        );

        const secure::AuditEvent first =
            audit.create(
                secure::CreateAuditEvent{
                    user.id,
                    "auth.login",
                    "success",
                    "user",
                    user.id,
                    "request-1",
                    "127.0.0.1",
                    "unit-test",
                    R"JSON({"method":"password"})JSON"
                }
            );

        require(first.id > 0, "audit id");
        require(
            first.actor_user_id == user.id,
            "audit actor"
        );

        static_cast<void>(
            audit.create(
                secure::CreateAuditEvent{
                    std::nullopt,
                    "auth.login",
                    "failure",
                    "user",
                    std::nullopt,
                    "request-2",
                    "192.0.2.1",
                    "unit-test",
                    R"JSON({"reason":"invalid_credentials"})JSON"
                }
            )
        );

        {
            secure::ScopedRequestAuditContext context(
                secure::RequestAuditContext{
                    "request-context",
                    "198.51.100.5",
                    "context-agent"
                }
            );

            service.record(
                secure::AuditRecord{
                    user.id,
                    "account.password_change",
                    "success",
                    "user",
                    user.id,
                    R"JSON({"revoked_sessions":2})JSON"
                }
            );
        }

        secure::AuditEventFilter all;
        all.limit = 100;

        require(
            audit.count(all) == 3,
            "audit count"
        );

        const auto events = audit.list(all);
        require(
            events.size() == 3,
            "audit list size"
        );
        require(
            events.front().request_id ==
                "request-context",
            "request context id"
        );
        require(
            events.front().client_ip ==
                "198.51.100.5",
            "request context ip"
        );

        secure::AuditEventFilter failures;
        failures.outcome = "failure";
        failures.limit = 100;

        require(
            audit.count(failures) == 1,
            "failure filter"
        );

        secure::AuditEventFilter login_events;
        login_events.event_type = "auth.login";
        login_events.limit = 100;

        require(
            audit.list(login_events).size() == 2,
            "event type filter"
        );

        bool update_rejected = false;

        try {
            database.execute(
                "UPDATE audit_events "
                "SET outcome = 'failure' "
                "WHERE id = 1;"
            );
        } catch (const std::exception&) {
            update_rejected = true;
        }

        require(
            update_rejected,
            "audit rows must be append-only"
        );

        database.execute(
            R"SQL(
INSERT INTO audit_events (
    event_type,
    outcome,
    target_type,
    metadata_json,
    created_at
)
VALUES (
    'test.expired',
    'success',
    'test',
    '{}',
    '2000-01-01T00:00:00.000Z'
);
)SQL"
        );

        require(
            service.purge_expired(30) == 1,
            "expired audit purge"
        );

        const auto snapshot = metrics.snapshot();
        require(
            snapshot.audit_events_recorded_total == 1,
            "audit metric recorded"
        );
        require(
            snapshot.audit_events_failed_total == 0,
            "audit metric failures"
        );

        std::cout
            << "Security audit repository tests passed.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Security audit repository test failed: "
            << error.what()
            << '\n';

        return 1;
    }
}
