#include "secure/service/account_security_service.hpp"

#include "secure/database/database.hpp"
#include "secure/database/transaction.hpp"
#include "secure/repository/auth_session_repository.hpp"
#include "secure/repository/user_repository.hpp"
#include "secure/security/password_hasher.hpp"
#include "secure/security/token_service.hpp"
#include "secure/service/auth_service.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace secure {

namespace {

std::int64_t current_unix_time() {
    return std::chrono::duration_cast<
        std::chrono::seconds
    >(
        std::chrono::system_clock::
            now().time_since_epoch()
    ).count();
}

bool valid_new_password(
    std::string_view password
) {
    return (
        password.size() >= 8 &&
        password.size() <= 128
    );
}

}  // namespace

std::string_view
account_security_error_name(
    AccountSecurityErrorCode code
) noexcept {
    switch (code) {
    case AccountSecurityErrorCode::
        session_not_found:
        return "session_not_found";

    case AccountSecurityErrorCode::
        invalid_current_password:
        return "invalid_current_password";

    case AccountSecurityErrorCode::
        weak_new_password:
        return "weak_new_password";

    case AccountSecurityErrorCode::
        same_password:
        return "same_password";
    }

    return "account_security_failed";
}

AccountSecurityError::
AccountSecurityError(
    AccountSecurityErrorCode code,
    std::string message
)
    : std::runtime_error(
          std::move(message)
      ),
      code_(code) {
}

AccountSecurityErrorCode
AccountSecurityError::code()
    const noexcept {
    return code_;
}

AccountSecurityService::
AccountSecurityService(
    Database& database,
    AuthService& auth_service,
    UserRepository& user_repository,
    AuthSessionRepository&
        auth_session_repository,
    PasswordHasher& password_hasher,
    TokenService& token_service
)
    : database_(database),
      auth_service_(auth_service),
      user_repository_(user_repository),
      auth_session_repository_(
          auth_session_repository
      ),
      password_hasher_(password_hasher),
      token_service_(token_service) {
}

AccountSecurityService::
CurrentAuthentication
AccountSecurityService::
authenticate_current_session(
    std::string_view access_token
) {
    const User user =
        auth_service_
            .authenticate_access_token(
                access_token
            );

    const std::string token_hash =
        token_service_.hash_token(
            access_token
        );

    const std::optional<AuthSession>
        session =
            auth_session_repository_
                .find_by_access_token_hash(
                    token_hash
                );

    if (
        !session.has_value() ||
        session->revoked ||
        session->user_id != user.id
    ) {
        throw AuthError(
            AuthErrorCode::
                invalid_access_token,
            "Access token is invalid"
        );
    }

    return CurrentAuthentication{
        user,
        *session
    };
}

SessionListResult
AccountSecurityService::list_sessions(
    std::string_view access_token
) {
    const CurrentAuthentication current =
        authenticate_current_session(
            access_token
        );

    return SessionListResult{
        auth_session_repository_
            .list_active_for_user(
                current.user.id,
                current_unix_time()
            ),
        current.session.id
    };
}

void AccountSecurityService::revoke_session(
    std::string_view access_token,
    std::int64_t session_id
) {
    const CurrentAuthentication current =
        authenticate_current_session(
            access_token
        );

    const std::optional<AuthSession> target =
        auth_session_repository_
            .find_by_id_for_user(
                session_id,
                current.user.id
            );

    if (!target.has_value()) {
        throw AccountSecurityError(
            AccountSecurityErrorCode::
                session_not_found,
            "Authentication session "
            "does not exist"
        );
    }

    if (!target->revoked) {
        static_cast<void>(
            auth_session_repository_
                .revoke_by_id_for_user(
                    session_id,
                    current.user.id
                )
        );
    }
}

PasswordChangeResult
AccountSecurityService::change_password(
    std::string_view access_token,
    std::string current_password,
    std::string new_password
) {
    const CurrentAuthentication current =
        authenticate_current_session(
            access_token
        );

    if (
        current_password.empty() ||
        !password_hasher_.verify(
            current_password,
            current.user.password_hash
        )
    ) {
        throw AccountSecurityError(
            AccountSecurityErrorCode::
                invalid_current_password,
            "Current password is invalid"
        );
    }

    if (!valid_new_password(new_password)) {
        throw AccountSecurityError(
            AccountSecurityErrorCode::
                weak_new_password,
            "New password must contain "
            "between 8 and 128 bytes"
        );
    }

    if (
        password_hasher_.verify(
            new_password,
            current.user.password_hash
        )
    ) {
        throw AccountSecurityError(
            AccountSecurityErrorCode::
                same_password,
            "New password must differ "
            "from the current password"
        );
    }

    const std::string new_password_hash =
        password_hasher_.hash(
            new_password
        );

    auto transaction =
        database_.begin_transaction();

    if (
        !user_repository_.set_password_hash(
            transaction,
            current.user.id,
            new_password_hash
        )
    ) {
        throw std::runtime_error(
            "Failed to update password"
        );
    }

    const std::int64_t revoked_sessions =
        auth_session_repository_
            .revoke_all_except_for_user(
                transaction,
                current.user.id,
                current.session.id
            );

    transaction.commit();

    return PasswordChangeResult{
        revoked_sessions
    };
}

}  // namespace secure
