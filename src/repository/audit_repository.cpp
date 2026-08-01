#include "secure/repository/audit_repository.hpp"

#include "secure/database/database.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sqlite3.h>

namespace secure {

namespace {

std::string make_sqlite_error(
    sqlite3* handle,
    std::string_view operation,
    int result
) {
    std::ostringstream message;

    message
        << operation
        << " failed with SQLite code "
        << result
        << ": "
        << sqlite3_errmsg(handle);

    return message.str();
}

class Statement final {
public:
    Statement(
        sqlite3* handle,
        std::string_view sql
    )
        : handle_(handle) {
        const std::string sql_text(sql);

        const int result = sqlite3_prepare_v2(
            handle_,
            sql_text.c_str(),
            static_cast<int>(sql_text.size()),
            &statement_,
            nullptr
        );

        if (result != SQLITE_OK) {
            throw AuditRepositoryError(
                make_sqlite_error(
                    handle_,
                    "Preparing audit query",
                    result
                )
            );
        }
    }

    ~Statement() {
        if (statement_ != nullptr) {
            sqlite3_finalize(statement_);
        }
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    void bind_int64(
        int index,
        std::int64_t value
    ) {
        check(
            sqlite3_bind_int64(
                statement_,
                index,
                value
            ),
            "Binding audit integer"
        );
    }

    void bind_optional_int64(
        int index,
        const std::optional<std::int64_t>& value
    ) {
        if (value.has_value()) {
            bind_int64(index, *value);
        } else {
            check(
                sqlite3_bind_null(
                    statement_,
                    index
                ),
                "Binding audit null"
            );
        }
    }

    void bind_text(
        int index,
        std::string_view value
    ) {
        check(
            sqlite3_bind_text(
                statement_,
                index,
                value.data(),
                static_cast<int>(value.size()),
                SQLITE_TRANSIENT
            ),
            "Binding audit text"
        );
    }

    int step() {
        return sqlite3_step(statement_);
    }

    [[nodiscard]]
    std::int64_t column_int64(int index) const {
        return sqlite3_column_int64(
            statement_,
            index
        );
    }

    [[nodiscard]]
    std::optional<std::int64_t>
    column_optional_int64(int index) const {
        if (
            sqlite3_column_type(
                statement_,
                index
            ) == SQLITE_NULL
        ) {
            return std::nullopt;
        }

        return column_int64(index);
    }

    [[nodiscard]]
    std::string column_text(int index) const {
        const auto* value = sqlite3_column_text(
            statement_,
            index
        );

        if (value == nullptr) {
            return {};
        }

        const int bytes = sqlite3_column_bytes(
            statement_,
            index
        );

        return std::string(
            reinterpret_cast<const char*>(value),
            static_cast<std::size_t>(bytes)
        );
    }

private:
    void check(
        int result,
        std::string_view operation
    ) {
        if (result != SQLITE_OK) {
            throw AuditRepositoryError(
                make_sqlite_error(
                    handle_,
                    operation,
                    result
                )
            );
        }
    }

    sqlite3* handle_{nullptr};
    sqlite3_stmt* statement_{nullptr};
};

AuditEvent read_event(
    const Statement& statement
) {
    AuditEvent event;

    event.id = statement.column_int64(0);
    event.actor_user_id =
        statement.column_optional_int64(1);
    event.event_type = statement.column_text(2);
    event.outcome = statement.column_text(3);
    event.target_type = statement.column_text(4);
    event.target_id =
        statement.column_optional_int64(5);
    event.request_id = statement.column_text(6);
    event.client_ip = statement.column_text(7);
    event.user_agent = statement.column_text(8);
    event.metadata_json = statement.column_text(9);
    event.created_at = statement.column_text(10);

    return event;
}

AuditEvent find_by_id_locked(
    sqlite3* handle,
    std::int64_t event_id
) {
    Statement statement{
        handle,
        R"SQL(
SELECT
    id,
    actor_user_id,
    event_type,
    outcome,
    target_type,
    target_id,
    request_id,
    client_ip,
    user_agent,
    metadata_json,
    created_at
FROM audit_events
WHERE id = ?1
LIMIT 1;
)SQL"
    };

    statement.bind_int64(1, event_id);

    const int result = statement.step();

    if (result == SQLITE_ROW) {
        return read_event(statement);
    }

    throw AuditRepositoryError(
        result == SQLITE_DONE
            ? "Created audit event could not be read back"
            : make_sqlite_error(
                  handle,
                  "Reading created audit event",
                  result
              )
    );
}

void validate_input(
    const CreateAuditEvent& input
) {
    if (
        input.event_type.empty() ||
        input.event_type.size() > 96
    ) {
        throw std::invalid_argument(
            "Audit event type must contain 1 to 96 bytes"
        );
    }

    if (
        input.outcome != "success" &&
        input.outcome != "failure"
    ) {
        throw std::invalid_argument(
            "Audit outcome must be success or failure"
        );
    }

    if (input.target_type.size() > 64) {
        throw std::invalid_argument(
            "Audit target type is too long"
        );
    }

    if (input.request_id.size() > 128) {
        throw std::invalid_argument(
            "Audit request ID is too long"
        );
    }

    if (input.client_ip.size() > 128) {
        throw std::invalid_argument(
            "Audit client IP is too long"
        );
    }

    if (input.user_agent.size() > 512) {
        throw std::invalid_argument(
            "Audit user agent is too long"
        );
    }

    if (
        input.metadata_json.empty() ||
        input.metadata_json.size() > 8192
    ) {
        throw std::invalid_argument(
            "Audit metadata must contain 1 to 8192 bytes"
        );
    }
}

std::string build_filter_sql(
    const AuditEventFilter& filter,
    bool count_only
) {
    std::string sql;

    if (count_only) {
        sql = "SELECT COUNT(*) FROM audit_events WHERE 1 = 1";
    } else {
        sql = R"SQL(
SELECT
    id,
    actor_user_id,
    event_type,
    outcome,
    target_type,
    target_id,
    request_id,
    client_ip,
    user_agent,
    metadata_json,
    created_at
FROM audit_events
WHERE 1 = 1
)SQL";
    }

    int parameter = 1;

    if (filter.actor_user_id.has_value()) {
        sql += " AND actor_user_id = ?" +
            std::to_string(parameter++);
    }

    if (!filter.event_type.empty()) {
        sql += " AND event_type = ?" +
            std::to_string(parameter++);
    }

    if (!filter.outcome.empty()) {
        sql += " AND outcome = ?" +
            std::to_string(parameter++);
    }

    if (!count_only) {
        sql += " ORDER BY id DESC LIMIT ?" +
            std::to_string(parameter++);
        sql += " OFFSET ?" +
            std::to_string(parameter);
    }

    sql += ';';
    return sql;
}

void bind_filter(
    Statement& statement,
    const AuditEventFilter& filter,
    bool include_pagination
) {
    int parameter = 1;

    if (filter.actor_user_id.has_value()) {
        statement.bind_int64(
            parameter++,
            *filter.actor_user_id
        );
    }

    if (!filter.event_type.empty()) {
        statement.bind_text(
            parameter++,
            filter.event_type
        );
    }

    if (!filter.outcome.empty()) {
        statement.bind_text(
            parameter++,
            filter.outcome
        );
    }

    if (include_pagination) {
        statement.bind_int64(
            parameter++,
            filter.limit
        );
        statement.bind_int64(
            parameter,
            filter.offset
        );
    }
}

void validate_filter(
    const AuditEventFilter& filter
) {
    if (
        filter.limit <= 0 ||
        filter.limit > 100 ||
        filter.offset < 0
    ) {
        throw std::invalid_argument(
            "Invalid audit event pagination"
        );
    }

    if (filter.event_type.size() > 96) {
        throw std::invalid_argument(
            "Audit event type filter is too long"
        );
    }

    if (
        !filter.outcome.empty() &&
        filter.outcome != "success" &&
        filter.outcome != "failure"
    ) {
        throw std::invalid_argument(
            "Audit outcome filter must be success or failure"
        );
    }
}

}  // namespace

AuditRepository::AuditRepository(
    Database& database
)
    : database_(database) {
}

AuditEvent AuditRepository::create(
    const CreateAuditEvent& input
) {
    validate_input(input);

    return database_.with_locked_handle(
        [&input](sqlite3* handle) {
            Statement statement{
                handle,
                R"SQL(
INSERT INTO audit_events (
    actor_user_id,
    event_type,
    outcome,
    target_type,
    target_id,
    request_id,
    client_ip,
    user_agent,
    metadata_json
)
VALUES (
    ?1,
    ?2,
    ?3,
    ?4,
    ?5,
    ?6,
    ?7,
    ?8,
    ?9
);
)SQL"
            };

            statement.bind_optional_int64(
                1,
                input.actor_user_id
            );
            statement.bind_text(2, input.event_type);
            statement.bind_text(3, input.outcome);
            statement.bind_text(4, input.target_type);
            statement.bind_optional_int64(
                5,
                input.target_id
            );
            statement.bind_text(6, input.request_id);
            statement.bind_text(7, input.client_ip);
            statement.bind_text(8, input.user_agent);
            statement.bind_text(9, input.metadata_json);

            const int result = statement.step();

            if (result != SQLITE_DONE) {
                throw AuditRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Creating audit event",
                        result
                    )
                );
            }

            return find_by_id_locked(
                handle,
                sqlite3_last_insert_rowid(handle)
            );
        }
    );
}

std::vector<AuditEvent> AuditRepository::list(
    const AuditEventFilter& filter
) {
    validate_filter(filter);

    return database_.with_locked_handle(
        [&filter](sqlite3* handle) {
            Statement statement{
                handle,
                build_filter_sql(
                    filter,
                    false
                )
            };

            bind_filter(
                statement,
                filter,
                true
            );

            std::vector<AuditEvent> events;

            while (true) {
                const int result = statement.step();

                if (result == SQLITE_ROW) {
                    events.push_back(
                        read_event(statement)
                    );
                    continue;
                }

                if (result == SQLITE_DONE) {
                    break;
                }

                throw AuditRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Listing audit events",
                        result
                    )
                );
            }

            return events;
        }
    );
}

std::int64_t AuditRepository::count(
    const AuditEventFilter& filter
) {
    validate_filter(filter);

    return database_.with_locked_handle(
        [&filter](sqlite3* handle) {
            Statement statement{
                handle,
                build_filter_sql(
                    filter,
                    true
                )
            };

            bind_filter(
                statement,
                filter,
                false
            );

            const int result = statement.step();

            if (result != SQLITE_ROW) {
                throw AuditRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Counting audit events",
                        result
                    )
                );
            }

            return statement.column_int64(0);
        }
    );
}

std::int64_t
AuditRepository::delete_older_than_days(
    std::int64_t retention_days
) {
    if (
        retention_days <= 0 ||
        retention_days > 3650
    ) {
        throw std::invalid_argument(
            "Audit retention days must be between 1 and 3650"
        );
    }

    return database_.with_locked_handle(
        [retention_days](sqlite3* handle) {
            Statement statement{
                handle,
                R"SQL(
DELETE FROM audit_events
WHERE created_at < strftime(
    '%Y-%m-%dT%H:%M:%fZ',
    'now',
    ?1
);
)SQL"
            };

            const std::string modifier =
                "-" +
                std::to_string(retention_days) +
                " days";

            statement.bind_text(1, modifier);

            const int result = statement.step();

            if (result != SQLITE_DONE) {
                throw AuditRepositoryError(
                    make_sqlite_error(
                        handle,
                        "Deleting expired audit events",
                        result
                    )
                );
            }

            return static_cast<std::int64_t>(
                sqlite3_changes(handle)
            );
        }
    );
}

}  // namespace secure
