#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

struct sqlite3;

namespace secure {

class Database;
class DatabaseTransaction;

enum class TransactionMode {
    deferred,
    immediate,
    exclusive
};

class DatabasePoolTimeoutError final
    : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct DatabasePoolSnapshot final {
    std::size_t pool_size{0};

    std::uint64_t available_connections{0};

    std::uint64_t active_connections{0};

    std::uint64_t waiting_threads{0};

    std::uint64_t acquisitions_total{0};

    std::uint64_t timeouts_total{0};
};

/*
 * 数据库连接租约。
 *
 * 每个租约在生命周期内独占一条 sqlite3 连接，析构时自动归还
 * 到连接池。调用者不得缓存 handle() 返回的指针，也不得在租约
 * 结束后继续使用它。
 */
class DatabaseConnectionLease final {
public:
    ~DatabaseConnectionLease() noexcept;

    DatabaseConnectionLease(
        const DatabaseConnectionLease&
    ) = delete;

    DatabaseConnectionLease& operator=(
        const DatabaseConnectionLease&
    ) = delete;

    DatabaseConnectionLease(
        DatabaseConnectionLease&& other
    ) noexcept;

    DatabaseConnectionLease& operator=(
        DatabaseConnectionLease&& other
    ) noexcept;

    [[nodiscard]]
    sqlite3* handle() const;

    [[nodiscard]]
    explicit operator bool() const noexcept;

private:
    friend class Database;
    friend class DatabaseTransaction;

    DatabaseConnectionLease(
        Database& database,
        std::size_t index,
        sqlite3* handle
    ) noexcept;

    void release() noexcept;

    Database* database_{nullptr};

    std::size_t index_{0};

    sqlite3* handle_{nullptr};
};

class Database final {
public:
    explicit Database(
        std::filesystem::path path,
        std::size_t pool_size = 4,
        std::chrono::milliseconds
            acquire_timeout =
                std::chrono::milliseconds{5000}
    );

    ~Database();

    Database(const Database&) = delete;

    Database& operator=(
        const Database&
    ) = delete;

    Database(Database&&) = delete;

    Database& operator=(
        Database&&
    ) = delete;

    [[nodiscard]]
    DatabaseTransaction begin_transaction(
        TransactionMode mode =
            TransactionMode::immediate
    );

    void execute(
        std::string_view sql
    );

    [[nodiscard]]
    std::int64_t query_int64(
        std::string_view sql
    );

    [[nodiscard]]
    bool healthy() noexcept;

    [[nodiscard]]
    const std::filesystem::path&
    path() const noexcept;

    [[nodiscard]]
    std::size_t pool_size() const noexcept;

    [[nodiscard]]
    std::chrono::milliseconds
    acquire_timeout() const noexcept;

    [[nodiscard]]
    DatabasePoolSnapshot pool_snapshot()
        const noexcept;

    /*
     * 从连接池获取一条独占连接，并在回调结束后自动归还。
     * 回调内部可以执行 SQLite 操作，但不要缓存 sqlite3*。
     */
    template <typename Function>
    decltype(auto) with_locked_handle(
        Function&& function
    ) {
        auto lease = acquire_connection();

        return std::invoke(
            std::forward<Function>(function),
            lease.handle()
        );
    }

private:
    friend class DatabaseConnectionLease;
    friend class DatabaseTransaction;

    [[nodiscard]]
    DatabaseConnectionLease
    acquire_connection();

    void release_connection(
        std::size_t index
    ) noexcept;

    std::filesystem::path path_;

    std::size_t pool_size_{0};

    std::chrono::milliseconds
        acquire_timeout_;

    std::vector<sqlite3*> handles_;

    std::deque<std::size_t>
        available_indices_;

    mutable std::mutex pool_mutex_;

    std::condition_variable
        pool_condition_;

    bool shutting_down_{false};

    std::atomic_uint64_t
        active_connections_{0};

    std::atomic_uint64_t
        waiting_threads_{0};

    std::atomic_uint64_t
        acquisitions_total_{0};

    std::atomic_uint64_t
        timeouts_total_{0};
};

}  // namespace secure
