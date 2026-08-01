#pragma once

#include "secure/database/transaction.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string_view>
#include <utility>

struct sqlite3;

namespace secure {

class Database final {
public:
    explicit Database(
        std::filesystem::path path
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

    /*
     * 在数据库互斥锁保护下访问 SQLite 连接。
     *
     * 回调执行完毕后锁才会释放，因此回调内部
     * 不要再次调用 Database::execute() 等方法，
     * 否则会重复获取同一个锁。
     */
    template <typename Function>
    decltype(auto) with_locked_handle(
        Function&& function
    ) {
        std::scoped_lock lock(mutex_);

        return std::invoke(
            std::forward<Function>(function),
            handle_
        );
    }

private:
    friend class DatabaseTransaction;

    sqlite3* handle_{nullptr};

    std::filesystem::path path_;

    mutable std::mutex mutex_;
};

}  // namespace secure
