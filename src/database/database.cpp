#include "secure/database/database.hpp"

#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
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

}  // namespace

Database::Database(
    std::filesystem::path path
)
    : path_(std::move(path)) {
    if (path_.empty()) {
        throw std::invalid_argument(
            "Database path must not be empty"
        );
    }

    /*
     * 文件数据库需要先创建父目录。
     * :memory: 是 SQLite 的内存数据库标识，
     * 不对应真实文件。
     */
    if (path_ != ":memory:") {
        const auto parent =
            path_.parent_path();

        if (!parent.empty()) {
            std::error_code error;

            std::filesystem::
                create_directories(
                    parent,
                    error
                );

            if (error) {
                throw std::runtime_error(
                    "Failed to create database "
                    "directory '" +
                    parent.string() +
                    "': " +
                    error.message()
                );
            }
        }
    }

    sqlite3* opened_handle = nullptr;

    const std::string path_text =
        path_.string();

    const int open_result =
        sqlite3_open_v2(
            path_text.c_str(),
            &opened_handle,
            SQLITE_OPEN_READWRITE |
                SQLITE_OPEN_CREATE |
                SQLITE_OPEN_FULLMUTEX,
            nullptr
        );

    if (open_result != SQLITE_OK) {
        const std::string error =
            make_database_error(
                opened_handle,
                "Opening database",
                open_result
            );

        if (opened_handle != nullptr) {
            sqlite3_close_v2(
                opened_handle
            );
        }

        throw std::runtime_error(error);
    }

    handle_ = opened_handle;

    sqlite3_extended_result_codes(
        handle_,
        1
    );

    const int timeout_result =
        sqlite3_busy_timeout(
            handle_,
            5000
        );

    if (timeout_result != SQLITE_OK) {
        const std::string error =
            make_database_error(
                handle_,
                "Configuring database timeout",
                timeout_result
            );

        sqlite3_close_v2(handle_);
        handle_ = nullptr;

        throw std::runtime_error(error);
    }

    try {
        execute(
            "PRAGMA foreign_keys = ON;"
        );

        execute(
            "PRAGMA journal_mode = WAL;"
        );

        execute(
            "PRAGMA synchronous = NORMAL;"
        );
    } catch (...) {
        sqlite3_close_v2(handle_);
        handle_ = nullptr;

        throw;
    }
}

Database::~Database() {
    if (handle_ != nullptr) {
        sqlite3_close_v2(handle_);
        handle_ = nullptr;
    }
}

void Database::execute(
    std::string_view sql
) {
    if (sql.empty()) {
        throw std::invalid_argument(
            "SQL statement must not be empty"
        );
    }

    std::scoped_lock lock(mutex_);

    const std::string sql_text(sql);

    char* raw_error = nullptr;

    const int result =
        sqlite3_exec(
            handle_,
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
        error_message =
            sqlite3_errmsg(handle_);
    }

    throw std::runtime_error(
        "Executing SQL failed with SQLite "
        "code " +
        std::to_string(result) +
        ": " +
        error_message
    );
}

std::int64_t Database::query_int64(
    std::string_view sql
) {
    if (sql.empty()) {
        throw std::invalid_argument(
            "SQL query must not be empty"
        );
    }

    std::scoped_lock lock(mutex_);

    const std::string sql_text(sql);

    sqlite3_stmt* raw_statement = nullptr;

    const int prepare_result =
        sqlite3_prepare_v2(
            handle_,
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
                handle_,
                "Preparing SQL query",
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
        sqlite3_step(
            statement.get()
        );

    if (step_result != SQLITE_ROW) {
        throw std::runtime_error(
            make_database_error(
                handle_,
                "Reading SQL query result",
                step_result
            )
        );
    }

    if (
        sqlite3_column_count(
            statement.get()
        ) < 1
    ) {
        throw std::runtime_error(
            "SQL query returned no columns"
        );
    }

    if (
        sqlite3_column_type(
            statement.get(),
            0
        ) == SQLITE_NULL
    ) {
        throw std::runtime_error(
            "SQL query returned NULL"
        );
    }

    return sqlite3_column_int64(
        statement.get(),
        0
    );
}

bool Database::healthy() noexcept {
    try {
        return (
            query_int64("SELECT 1;") == 1
        );
    } catch (...) {
        return false;
    }
}

const std::filesystem::path&
Database::path() const noexcept {
    return path_;
}

}  // namespace secure
