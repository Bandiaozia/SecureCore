#pragma once

#include "secure/database/database.hpp"

#include <cstdint>
#include <string_view>

struct sqlite3;

namespace secure {

/*
 * SQLite 事务的 RAII 封装。
 *
 * Transaction 在整个生命周期内独占连接池中的同一条连接。
 * 未显式 commit() 的活动事务会在析构时自动回滚，之后连接
 * 自动归还连接池。
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

    DatabaseConnectionLease connection_;

    bool active_{false};
};

}  // namespace secure
