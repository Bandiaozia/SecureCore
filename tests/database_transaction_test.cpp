#include "secure/database/database.hpp"
#include "secure/database/migration.hpp"
#include "secure/database/transaction.hpp"
#include "secure/repository/auth_session_repository.hpp"
#include "secure/repository/user_repository.hpp"

#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(
    bool condition,
    const char* message
) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct Fixture final {
    secure::Database database{":memory:"};

    secure::MigrationRunner migrations{
        database
    };

    secure::UserRepository users{
        database
    };

    secure::AuthSessionRepository sessions{
        database
    };

    Fixture() {
        migrations.apply();
    }

    secure::User create_user() {
        return users.create(
            secure::CreateUser{
                "transaction-user",
                "transaction@example.com",
                "old-password-hash",
                "user"
            }
        );
    }

    secure::AuthSession create_session(
        std::int64_t user_id,
        std::string suffix
    ) {
        return sessions.create(
            secure::CreateAuthSession{
                user_id,
                "access-" + suffix,
                "refresh-" + suffix,
                2'000'000'000,
                2'100'000'000
            }
        );
    }
};

void test_commit_and_automatic_rollback() {
    secure::Database database{":memory:"};

    database.execute(
        "CREATE TABLE transaction_probe "
        "(value INTEGER NOT NULL);"
    );

    {
        auto transaction =
            database.begin_transaction();

        transaction.execute(
            "INSERT INTO transaction_probe "
            "(value) VALUES (10);"
        );

        require(
            transaction.query_int64(
                "SELECT COUNT(*) "
                "FROM transaction_probe;"
            ) == 1,
            "transaction must see its own write"
        );

        transaction.commit();
    }

    require(
        database.query_int64(
            "SELECT COUNT(*) "
            "FROM transaction_probe;"
        ) == 1,
        "committed row must remain"
    );

    try {
        auto transaction =
            database.begin_transaction();

        transaction.execute(
            "INSERT INTO transaction_probe "
            "(value) VALUES (20);"
        );

        throw std::runtime_error(
            "force scope rollback"
        );
    } catch (const std::runtime_error&) {
    }

    require(
        database.query_int64(
            "SELECT COUNT(*) "
            "FROM transaction_probe;"
        ) == 1,
        "uncommitted row must be rolled back"
    );
}

void test_password_and_session_failure_rolls_back() {
    Fixture fixture;

    const secure::User user =
        fixture.create_user();

    const secure::AuthSession current =
        fixture.create_session(
            user.id,
            "current"
        );

    const secure::AuthSession other =
        fixture.create_session(
            user.id,
            "other"
        );

    fixture.database.execute(
        R"SQL(
CREATE TRIGGER fail_session_revoke
BEFORE UPDATE OF revoked ON auth_sessions
WHEN NEW.revoked = 1
BEGIN
    SELECT RAISE(
        ABORT,
        'forced session revoke failure'
    );
END;
)SQL"
    );

    bool failed = false;

    try {
        auto transaction =
            fixture.database.begin_transaction();

        require(
            fixture.users.set_password_hash(
                transaction,
                user.id,
                "new-password-hash"
            ),
            "password update should affect user"
        );

        static_cast<void>(
            fixture.sessions
                .revoke_all_except_for_user(
                    transaction,
                    user.id,
                    current.id
                )
        );

        transaction.commit();
    } catch (
        const secure::AuthSessionRepositoryError&
    ) {
        failed = true;
    }

    require(
        failed,
        "forced revoke failure must be observed"
    );

    const auto stored_user =
        fixture.users.find_by_id(user.id);

    require(
        stored_user.has_value(),
        "user must still exist"
    );

    require(
        stored_user->password_hash ==
            "old-password-hash",
        "password update must roll back"
    );

    const auto stored_other =
        fixture.sessions
            .find_by_refresh_token_hash(
                other.refresh_token_hash
            );

    require(
        stored_other.has_value() &&
            !stored_other->revoked,
        "other session must remain active"
    );
}

void test_disable_failure_rolls_back() {
    Fixture fixture;

    const secure::User user =
        fixture.create_user();

    static_cast<void>(
        fixture.create_session(
            user.id,
            "disable"
        )
    );

    fixture.database.execute(
        R"SQL(
CREATE TRIGGER fail_disable_revoke
BEFORE UPDATE OF revoked ON auth_sessions
WHEN NEW.revoked = 1
BEGIN
    SELECT RAISE(
        ABORT,
        'forced disable revoke failure'
    );
END;
)SQL"
    );

    bool failed = false;

    try {
        auto transaction =
            fixture.database.begin_transaction();

        require(
            fixture.users.set_enabled(
                transaction,
                user.id,
                false
            ),
            "disable should affect user"
        );

        static_cast<void>(
            fixture.sessions.revoke_all_for_user(
                transaction,
                user.id
            )
        );

        transaction.commit();
    } catch (
        const secure::AuthSessionRepositoryError&
    ) {
        failed = true;
    }

    require(
        failed,
        "forced disable failure must be observed"
    );

    const auto stored_user =
        fixture.users.find_by_id(user.id);

    require(
        stored_user.has_value() &&
            stored_user->enabled,
        "user disable must roll back"
    );
}

void test_token_rotation_failure_restores_old_session() {
    Fixture fixture;

    const secure::User user =
        fixture.create_user();

    const secure::AuthSession old_session =
        fixture.create_session(
            user.id,
            "old"
        );

    fixture.database.execute(
        R"SQL(
CREATE TRIGGER fail_new_session
BEFORE INSERT ON auth_sessions
BEGIN
    SELECT RAISE(
        ABORT,
        'forced session creation failure'
    );
END;
)SQL"
    );

    bool failed = false;

    try {
        auto transaction =
            fixture.database.begin_transaction();

        require(
            fixture.sessions.revoke_by_id(
                transaction,
                old_session.id
            ),
            "old session should be revoked in transaction"
        );

        static_cast<void>(
            fixture.sessions.create(
                transaction,
                secure::CreateAuthSession{
                    user.id,
                    "access-new",
                    "refresh-new",
                    2'000'000'000,
                    2'100'000'000
                }
            )
        );

        transaction.commit();
    } catch (
        const secure::AuthSessionRepositoryError&
    ) {
        failed = true;
    }

    require(
        failed,
        "forced token creation failure must occur"
    );

    const auto stored_old =
        fixture.sessions
            .find_by_refresh_token_hash(
                old_session.refresh_token_hash
            );

    require(
        stored_old.has_value() &&
            !stored_old->revoked,
        "old session revocation must roll back"
    );

    require(
        fixture.database.query_int64(
            "SELECT COUNT(*) FROM auth_sessions;"
        ) == 1,
        "failed replacement session must not persist"
    );
}

void test_repository_rejects_foreign_transaction() {
    Fixture first;
    Fixture second;

    const secure::User user =
        first.create_user();

    auto transaction =
        second.database.begin_transaction();

    bool rejected = false;

    try {
        static_cast<void>(
            first.users.find_by_id(
                transaction,
                user.id
            )
        );
    } catch (const std::invalid_argument&) {
        rejected = true;
    }

    require(
        rejected,
        "repository must reject foreign transaction"
    );
}

}  // namespace

int main() {
    try {
        test_commit_and_automatic_rollback();
        test_password_and_session_failure_rolls_back();
        test_disable_failure_rolls_back();
        test_token_rotation_failure_restores_old_session();
        test_repository_rejects_foreign_transaction();

        std::cout
            << "Database transaction tests passed\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Database transaction test failed: "
            << error.what()
            << '\n';

        return 1;
    }
}
