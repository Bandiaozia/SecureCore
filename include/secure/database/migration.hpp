#pragma once

namespace secure {

class Database;

class MigrationRunner final {
public:
    explicit MigrationRunner(
        Database& database
    );

    void apply();

private:
    Database& database_;
};

}  // namespace secure
