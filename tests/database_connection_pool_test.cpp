#include "secure/database/database.hpp"
#include "secure/database/migration.hpp"
#include "secure/database/transaction.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

#include <sqlite3.h>

namespace {

void require(
    bool condition,
    std::string_view message
) {
    if (!condition) {
        throw std::runtime_error(
            std::string(message)
        );
    }
}

}  // namespace

int main() {
    using namespace std::chrono_literals;

    const auto root =
        std::filesystem::temp_directory_path() /
        (
            "securecore-db-pool-test-" +
            std::to_string(::getpid())
        );

    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    try {
        const auto database_path =
            root / "pool.db";

        secure::Database database(
            database_path,
            2,
            100ms
        );

        secure::MigrationRunner migrations(
            database
        );

        migrations.apply();

        require(
            database.pool_size() == 2,
            "Database did not create the requested pool size"
        );

        database.execute(
            "CREATE TABLE IF NOT EXISTS pool_values ("
            "id INTEGER PRIMARY KEY, value INTEGER NOT NULL);"
        );

        database.execute(
            "INSERT INTO pool_values (id, value) VALUES (1, 42);"
        );

        std::mutex gate_mutex;
        std::condition_variable gate_condition;
        std::size_t entered = 0;
        bool release = false;

        auto hold_connection = [&] {
            database.with_locked_handle(
                [&](sqlite3* handle) {
                    require(
                        handle != nullptr,
                        "Pool returned a null SQLite handle"
                    );

                    std::unique_lock lock(gate_mutex);
                    ++entered;
                    gate_condition.notify_all();
                    gate_condition.wait(
                        lock,
                        [&] {
                            return release;
                        }
                    );
                }
            );
        };

        std::thread first(hold_connection);
        std::thread second(hold_connection);

        {
            std::unique_lock lock(gate_mutex);

            require(
                gate_condition.wait_for(
                    lock,
                    2s,
                    [&] {
                        return entered == 2;
                    }
                ),
                "Two workers did not acquire two separate connections"
            );
        }

        const auto busy_snapshot =
            database.pool_snapshot();

        require(
            busy_snapshot.active_connections == 2,
            "Active connection metric is incorrect"
        );

        require(
            busy_snapshot.available_connections == 0,
            "Available connection metric is incorrect"
        );

        bool timed_out = false;
        const auto timeout_started =
            std::chrono::steady_clock::now();

        try {
            static_cast<void>(
                database.query_int64("SELECT 1;")
            );
        } catch (
            const secure::DatabasePoolTimeoutError&
        ) {
            timed_out = true;
        }

        const auto timeout_elapsed =
            std::chrono::steady_clock::now() -
            timeout_started;

        require(
            timed_out,
            "Exhausted pool did not report an acquire timeout"
        );

        require(
            timeout_elapsed >= 75ms,
            "Database acquire timeout returned too early"
        );

        {
            std::scoped_lock lock(gate_mutex);
            release = true;
        }

        gate_condition.notify_all();
        first.join();
        second.join();

        const auto released_snapshot =
            database.pool_snapshot();

        require(
            released_snapshot.active_connections == 0,
            "Connections were not returned to the pool"
        );

        require(
            released_snapshot.available_connections == 2,
            "Returned connections are not available"
        );

        require(
            released_snapshot.timeouts_total == 1,
            "Acquire timeout metric was not recorded"
        );

        std::atomic_bool failed{false};
        std::vector<std::thread> readers;

        for (int index = 0; index < 8; ++index) {
            readers.emplace_back(
                [&] {
                    try {
                        for (int run = 0; run < 50; ++run) {
                            if (
                                database.query_int64(
                                    "SELECT value FROM pool_values WHERE id = 1;"
                                ) != 42
                            ) {
                                failed.store(true);
                            }
                        }
                    } catch (...) {
                        failed.store(true);
                    }
                }
            );
        }

        for (auto& reader : readers) {
            reader.join();
        }

        require(
            !failed.load(),
            "Concurrent pooled reads failed"
        );

        {
            auto transaction =
                database.begin_transaction();

            transaction.execute(
                "UPDATE pool_values SET value = 99 WHERE id = 1;"
            );

            require(
                transaction.query_int64(
                    "SELECT value FROM pool_values WHERE id = 1;"
                ) == 99,
                "Transaction did not remain on one connection"
            );

            transaction.rollback();
        }

        require(
            database.query_int64(
                "SELECT value FROM pool_values WHERE id = 1;"
            ) == 42,
            "Transaction rollback did not restore data"
        );

        secure::Database memory_database(
            ":memory:",
            8,
            100ms
        );

        require(
            memory_database.pool_size() == 1,
            ":memory: database must use one isolated connection"
        );

        std::filesystem::remove_all(root);

        std::cout
            << "Database connection pool tests passed.\n";

        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::filesystem::remove_all(root);

        std::cerr
            << "Database connection pool test failed: "
            << error.what()
            << '\n';

        return EXIT_FAILURE;
    }
}
