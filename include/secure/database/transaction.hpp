#pragma once

#include <cstdint>
#include <mutex>
#include <string_view>

struct sqlite3;

namespace secure {

class Database;

enum class TransactionMode {
    deferred,
    immediate,
    exclusive
};

/*
 * SQLite 事务的 RAII 封装。
 *
 * Transaction 在整个生命周期内独占 Database 的连接互斥锁，
 * 因此同一连接上的其他仓储操作不能插入事务中间。
 * 未显式 commit() 的活动事务会在析构时自动回滚。
 */
class DatabaseTransaction final {
public:
    ~DatabaseTransaction() noexcept;

    DatabaseTransaction(
        const DatabaseTransaction&
    ) = delete;

    DatabaseTransaction& operator=(
        const DatabaseTransaction&
    ) = delete;

    DatabaseTransaction(
        DatabaseTransaction&& other
    ) noexcept;

    DatabaseTransaction& operator=(
        DatabaseTransaction&& other
    ) noexcept;

    void execute(
        std::string_view sql
    );

    [[nodiscard]]
    std::int64_t query_int64(
        std::string_view sql
    );

    void commit();

    void rollback();

    [[nodiscard]]
    bool active() const noexcept;

    [[nodiscard]]
    bool belongs_to(
        const Database& database
    ) const noexcept;

    /*
     * 仅供事务感知的仓储方法使用。
     * 调用者不得缓存该指针，也不得在事务结束后继续使用。
     */
    [[nodiscard]]
    sqlite3* handle() const;

private:
    friend class Database;

    DatabaseTransaction(
        Database& database,
        TransactionMode mode
    );

    void finish_noexcept(
        std::string_view sql
    ) noexcept;

    Database* database_{nullptr};

    std::unique_lock<std::mutex> lock_;

    bool active_{false};
};

}  // namespace secure
