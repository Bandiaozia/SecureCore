#include "secure/database/database.hpp"

#include "secure/database/transaction.hpp"

#include <algorithm>
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

void execute_sql(
    sqlite3* handle,
    std::string_view sql,
    std::string_view operation
) {
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

sqlite3* open_connection(
    const std::filesystem::path& path
) {
    sqlite3* handle = nullptr;

    const std::string path_text =
        path.string();

    const int result = sqlite3_open_v2(
        path_text.c_str(),
        &handle,
        SQLITE_OPEN_READWRITE |
            SQLITE_OPEN_CREATE |
            SQLITE_OPEN_FULLMUTEX |
            SQLITE_OPEN_URI,
        nullptr
    );

    if (result != SQLITE_OK) {
        const std::string error =
            make_database_error(
                handle,
                "Opening database connection",
                result
            );

        if (handle != nullptr) {
            sqlite3_close_v2(handle);
        }

        throw std::runtime_error(error);
    }

    sqlite3_extended_result_codes(
        handle,
        1
    );

    const int timeout_result =
        sqlite3_busy_timeout(
            handle,
            5000
        );

    if (timeout_result != SQLITE_OK) {
        const std::string error =
            make_database_error(
                handle,
                "Configuring database timeout",
                timeout_result
            );

        sqlite3_close_v2(handle);
        throw std::runtime_error(error);
    }

    return handle;
}

void configure_connection(
    sqlite3* handle,
    bool configure_journal
) {
    execute_sql(
        handle,
        "PRAGMA foreign_keys = ON;",
        "Enabling foreign keys"
    );

    if (configure_journal) {
        execute_sql(
            handle,
            "PRAGMA journal_mode = WAL;",
            "Enabling WAL mode"
        );
    }

    execute_sql(
        handle,
        "PRAGMA synchronous = NORMAL;",
        "Configuring SQLite synchronous mode"
    );
}

std::int64_t query_int64_on_handle(
    sqlite3* handle,
    std::string_view sql
) {
    const std::string sql_text(sql);

    sqlite3_stmt* raw_statement = nullptr;

    const int prepare_result =
        sqlite3_prepare_v2(
            handle,
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
                handle,
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
        sqlite3_step(statement.get());

    if (step_result != SQLITE_ROW) {
        throw std::runtime_error(
            make_database_error(
                handle,
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

}  // namespace

DatabaseConnectionLease::
DatabaseConnectionLease(
    Database& database,
    std::size_t index,
    sqlite3* handle
) noexcept
    : database_(&database),
      index_(index),
      handle_(handle) {
}

DatabaseConnectionLease::~DatabaseConnectionLease()
    noexcept {
    release();
}

DatabaseConnectionLease::
DatabaseConnectionLease(
    DatabaseConnectionLease&& other
) noexcept
    : database_(other.database_),
      index_(other.index_),
      handle_(other.handle_) {
    other.database_ = nullptr;
    other.handle_ = nullptr;
}

DatabaseConnectionLease&
DatabaseConnectionLease::operator=(
    DatabaseConnectionLease&& other
) noexcept {
    if (this == &other) {
        return *this;
    }

    release();

    database_ = other.database_;
    index_ = other.index_;
    handle_ = other.handle_;

    other.database_ = nullptr;
    other.handle_ = nullptr;

    return *this;
}

sqlite3* DatabaseConnectionLease::handle()
    const {
    if (
        database_ == nullptr ||
        handle_ == nullptr
    ) {
        throw std::logic_error(
            "Database connection lease is not active"
        );
    }

    return handle_;
}

DatabaseConnectionLease::operator bool()
    const noexcept {
    return (
        database_ != nullptr &&
        handle_ != nullptr
    );
}

void DatabaseConnectionLease::release()
    noexcept {
    if (database_ == nullptr) {
        return;
    }

    Database* database = database_;
    const std::size_t index = index_;

    database_ = nullptr;
    handle_ = nullptr;

    database->release_connection(index);
}

Database::Database(
    std::filesystem::path path,
    std::size_t pool_size,
    std::chrono::milliseconds acquire_timeout
)
    : path_(std::move(path)),
      pool_size_(pool_size),
      acquire_timeout_(acquire_timeout) {
    if (path_.empty()) {
        throw std::invalid_argument(
            "Database path must not be empty"
        );
    }

    if (pool_size_ == 0) {
        throw std::invalid_argument(
            "Database pool size must be positive"
        );
    }

    if (acquire_timeout_.count() <= 0) {
        throw std::invalid_argument(
            "Database acquire timeout must be positive"
        );
    }

    /*
     * 普通 :memory: 数据库的每条连接彼此隔离，因此强制只使用
     * 一条连接。需要共享内存连接池时可显式使用 SQLite URI。
     */
    if (path_ == ":memory:") {
        pool_size_ = 1;
    }

    const std::string path_text =
        path_.string();

    const bool is_uri =
        path_text.rfind("file:", 0) == 0;

    if (path_ != ":memory:" && !is_uri) {
        const auto parent =
            path_.parent_path();

        if (!parent.empty()) {
            std::error_code error;

            std::filesystem::create_directories(
                parent,
                error
            );

            if (error) {
                throw std::runtime_error(
                    "Failed to create database directory '" +
                    parent.string() +
                    "': " +
                    error.message()
                );
            }
        }
    }

    handles_.reserve(pool_size_);

    try {
        for (
            std::size_t index = 0;
            index < pool_size_;
            ++index
        ) {
            sqlite3* handle =
                open_connection(path_);

            try {
                configure_connection(
                    handle,
                    index == 0
                );
            } catch (...) {
                sqlite3_close_v2(handle);
                throw;
            }

            handles_.push_back(handle);
            available_indices_.push_back(index);
        }
    } catch (...) {
        for (sqlite3* handle : handles_) {
            sqlite3_close_v2(handle);
        }

        handles_.clear();
        available_indices_.clear();
        throw;
    }
}

Database::~Database() {
    {
        std::unique_lock lock(pool_mutex_);

        shutting_down_ = true;
        pool_condition_.notify_all();

        pool_condition_.wait(
            lock,
            [this] {
                return (
                    active_connections_.load(
                        std::memory_order_relaxed
                    ) == 0 &&
                    waiting_threads_.load(
                        std::memory_order_relaxed
                    ) == 0
                );
            }
        );
    }

    for (sqlite3* handle : handles_) {
        if (handle != nullptr) {
            sqlite3_close_v2(handle);
        }
    }

    handles_.clear();
    available_indices_.clear();
}

DatabaseTransaction Database::begin_transaction(
    TransactionMode mode
) {
    return DatabaseTransaction(*this, mode);
}

void Database::execute(
    std::string_view sql
) {
    if (sql.empty()) {
        throw std::invalid_argument(
            "SQL statement must not be empty"
        );
    }

    with_locked_handle(
        [sql](sqlite3* handle) {
            execute_sql(
                handle,
                sql,
                "Executing SQL"
            );
        }
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

    return with_locked_handle(
        [sql](sqlite3* handle) {
            return query_int64_on_handle(
                handle,
                sql
            );
        }
    );
}

bool Database::healthy() noexcept {
    try {
        return query_int64("SELECT 1;") == 1;
    } catch (...) {
        return false;
    }
}

const std::filesystem::path&
Database::path() const noexcept {
    return path_;
}

std::size_t Database::pool_size()
    const noexcept {
    return pool_size_;
}

std::chrono::milliseconds
Database::acquire_timeout() const noexcept {
    return acquire_timeout_;
}

DatabasePoolSnapshot Database::pool_snapshot()
    const noexcept {
    std::size_t available = 0;

    {
        std::scoped_lock lock(pool_mutex_);
        available = available_indices_.size();
    }

    return DatabasePoolSnapshot{
        pool_size_,
        static_cast<std::uint64_t>(available),
        active_connections_.load(
            std::memory_order_relaxed
        ),
        waiting_threads_.load(
            std::memory_order_relaxed
        ),
        acquisitions_total_.load(
            std::memory_order_relaxed
        ),
        timeouts_total_.load(
            std::memory_order_relaxed
        )
    };
}

DatabaseConnectionLease
Database::acquire_connection() {
    std::unique_lock lock(pool_mutex_);

    if (shutting_down_) {
        throw std::runtime_error(
            "Database connection pool is stopping"
        );
    }

    bool counted_waiter = false;

    if (available_indices_.empty()) {
        waiting_threads_.fetch_add(
            1,
            std::memory_order_relaxed
        );

        counted_waiter = true;
    }

    const bool available =
        pool_condition_.wait_for(
            lock,
            acquire_timeout_,
            [this] {
                return (
                    shutting_down_ ||
                    !available_indices_.empty()
                );
            }
        );

    if (counted_waiter) {
        waiting_threads_.fetch_sub(
            1,
            std::memory_order_relaxed
        );

        if (shutting_down_) {
            pool_condition_.notify_all();
        }
    }

    if (shutting_down_) {
        throw std::runtime_error(
            "Database connection pool is stopping"
        );
    }

    if (!available) {
        timeouts_total_.fetch_add(
            1,
            std::memory_order_relaxed
        );

        throw DatabasePoolTimeoutError(
            "Timed out waiting for a database connection"
        );
    }

    const std::size_t index =
        available_indices_.front();

    available_indices_.pop_front();

    active_connections_.fetch_add(
        1,
        std::memory_order_relaxed
    );

    acquisitions_total_.fetch_add(
        1,
        std::memory_order_relaxed
    );

    return DatabaseConnectionLease(
        *this,
        index,
        handles_.at(index)
    );
}

void Database::release_connection(
    std::size_t index
) noexcept {
    bool shutting_down = false;

    {
        std::scoped_lock lock(pool_mutex_);

        available_indices_.push_back(index);

        active_connections_.fetch_sub(
            1,
            std::memory_order_relaxed
        );

        shutting_down = shutting_down_;
    }

    if (shutting_down) {
        pool_condition_.notify_all();
    } else {
        pool_condition_.notify_one();
    }
}

}  // namespace secure
