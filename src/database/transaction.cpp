#include "secure/database/transaction.hpp"

#include "secure/database/database.hpp"

#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include <sqlite3.h>

namespace secure {

namespace {

std::string make_database_error(
    sqlite3* handle,
    std::string_view operation,
    int result_code
) {
    std::ostringstream message;

    message
        << operation
        << " failed with SQLite code "
        << result_code
        << ": ";

    if (handle != nullptr) {
        message << sqlite3_errmsg(handle);
    } else {
        message << sqlite3_errstr(result_code);
    }

    return message.str();
}

std::string_view begin_statement(
    TransactionMode mode
) {
    switch (mode) {
    case TransactionMode::deferred:
        return "BEGIN DEFERRED;";

    case TransactionMode::immediate:
        return "BEGIN IMMEDIATE;";

    case TransactionMode::exclusive:
        return "BEGIN EXCLUSIVE;";
    }

    throw std::invalid_argument(
        "Unknown database transaction mode"
    );
}

void execute_sql(
    sqlite3* handle,
    std::string_view sql,
    std::string_view operation
) {
    if (sql.empty()) {
        throw std::invalid_argument(
            "SQL statement must not be empty"
        );
    }

    const std::string sql_text(sql);

    char* raw_error = nullptr;

    const int result = sqlite3_exec(
        handle,
        sql_text.c_str(),
        nullptr,
        nullptr,
        &raw_error
    );

    if (result == SQLITE_OK) {
        return;
    }

    std::string error_message;

    if (raw_error != nullptr) {
        error_message = raw_error;
        sqlite3_free(raw_error);
    } else {
        error_message = sqlite3_errmsg(handle);
    }

    throw std::runtime_error(
        std::string(operation) +
        " failed with SQLite code " +
        std::to_string(result) +
        ": " +
        error_message
    );
}

}  // namespace

DatabaseTransaction::DatabaseTransaction(
    Database& database,
    TransactionMode mode
)
    : database_(&database),
      lock_(database.mutex_) {
    execute_sql(
        database_->handle_,
        begin_statement(mode),
        "Beginning database transaction"
    );

    active_ = true;
}

DatabaseTransaction::~DatabaseTransaction()
    noexcept {
    finish_noexcept("ROLLBACK;");
}

DatabaseTransaction::DatabaseTransaction(
    DatabaseTransaction&& other
) noexcept
    : database_(other.database_),
      lock_(std::move(other.lock_)),
      active_(other.active_) {
    other.database_ = nullptr;
    other.active_ = false;
}

DatabaseTransaction&
DatabaseTransaction::operator=(
    DatabaseTransaction&& other
) noexcept {
    if (this == &other) {
        return *this;
    }

    finish_noexcept("ROLLBACK;");

    database_ = other.database_;
    lock_ = std::move(other.lock_);
    active_ = other.active_;

    other.database_ = nullptr;
    other.active_ = false;

    return *this;
}

void DatabaseTransaction::execute(
    std::string_view sql
) {
    execute_sql(
        handle(),
        sql,
        "Executing transactional SQL"
    );
}

std::int64_t
DatabaseTransaction::query_int64(
    std::string_view sql
) {
    if (sql.empty()) {
        throw std::invalid_argument(
            "SQL query must not be empty"
        );
    }

    const std::string sql_text(sql);

    sqlite3_stmt* raw_statement = nullptr;

    const int prepare_result =
        sqlite3_prepare_v2(
            handle(),
            sql_text.c_str(),
            static_cast<int>(
                sql_text.size()
            ),
            &raw_statement,
            nullptr
        );

    if (prepare_result != SQLITE_OK) {
        throw std::runtime_error(
            make_database_error(
                handle(),
                "Preparing transactional query",
                prepare_result
            )
        );
    }

    const auto statement =
        std::unique_ptr<
            sqlite3_stmt,
            decltype(&sqlite3_finalize)
        >(
            raw_statement,
            &sqlite3_finalize
        );

    const int step_result =
        sqlite3_step(statement.get());

    if (step_result != SQLITE_ROW) {
        throw std::runtime_error(
            make_database_error(
                handle(),
                "Reading transactional query",
                step_result
            )
        );
    }

    if (
        sqlite3_column_count(
            statement.get()
        ) < 1 ||
        sqlite3_column_type(
            statement.get(),
            0
        ) == SQLITE_NULL
    ) {
        throw std::runtime_error(
            "Transactional query returned "
            "no integer value"
        );
    }

    return sqlite3_column_int64(
        statement.get(),
        0
    );
}

void DatabaseTransaction::commit() {
    execute_sql(
        handle(),
        "COMMIT;",
        "Committing database transaction"
    );

    active_ = false;

    if (lock_.owns_lock()) {
        lock_.unlock();
    }
}

void DatabaseTransaction::rollback() {
    execute_sql(
        handle(),
        "ROLLBACK;",
        "Rolling back database transaction"
    );

    active_ = false;

    if (lock_.owns_lock()) {
        lock_.unlock();
    }
}

bool DatabaseTransaction::active()
    const noexcept {
    return active_;
}

bool DatabaseTransaction::belongs_to(
    const Database& database
) const noexcept {
    return database_ == &database;
}

sqlite3* DatabaseTransaction::handle()
    const {
    if (
        !active_ ||
        database_ == nullptr ||
        !lock_.owns_lock()
    ) {
        throw std::logic_error(
            "Database transaction is not active"
        );
    }

    return database_->handle_;
}

void DatabaseTransaction::finish_noexcept(
    std::string_view sql
) noexcept {
    if (
        !active_ ||
        database_ == nullptr
    ) {
        return;
    }

    try {
        execute_sql(
            database_->handle_,
            sql,
            "Finishing database transaction"
        );
    } catch (...) {
        /*
         * 析构和移动赋值不能抛出。
         * SQLite 连接稍后仍会由 Database 析构关闭。
         */
    }

    active_ = false;

    if (lock_.owns_lock()) {
        lock_.unlock();
    }
}

}  // namespace secure
