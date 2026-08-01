#include "secure/service/admin_service.hpp"

#include "secure/database/database.hpp"
#include "secure/database/transaction.hpp"
#include "secure/repository/auth_session_repository.hpp"
#include "secure/repository/user_repository.hpp"
#include "secure/service/auth_service.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace secure {

std::string_view admin_error_name(
    AdminErrorCode code
) noexcept {
    switch (code) {
    case AdminErrorCode::forbidden:
        return "admin_permission_required";

    case AdminErrorCode::invalid_pagination:
        return "invalid_pagination";

    case AdminErrorCode::user_not_found:
        return "user_not_found";

    case AdminErrorCode::cannot_disable_self:
        return "cannot_disable_self";
    }

    return "admin_operation_failed";
}

AdminError::AdminError(
    AdminErrorCode code,
    std::string message
)
    : std::runtime_error(
          std::move(message)
      ),
      code_(code) {
}

AdminErrorCode AdminError::code()
    const noexcept {
    return code_;
}

AdminService::AdminService(
    Database& database,
    AuthService& auth_service,
    UserRepository& user_repository,
    AuthSessionRepository&
        auth_session_repository
)
    : database_(database),
      auth_service_(auth_service),
      user_repository_(user_repository),
      auth_session_repository_(
          auth_session_repository
      ) {
}

User AdminService::require_admin(
    std::string_view access_token
) {
    User user =
        auth_service_
            .authenticate_access_token(
                access_token
            );

    if (user.role != "admin") {
        throw AdminError(
            AdminErrorCode::forbidden,
            "Administrator permission "
            "is required"
        );
    }

    return user;
}

User AdminService::authenticate_admin(
    std::string_view access_token
) {
    return require_admin(access_token);
}

UserListResult AdminService::list_users(
    std::string_view access_token,
    std::int64_t limit,
    std::int64_t offset
) {
    static_cast<void>(
        require_admin(access_token)
    );

    if (
        limit <= 0 ||
        limit > 100 ||
        offset < 0
    ) {
        throw AdminError(
            AdminErrorCode::
                invalid_pagination,
            "Invalid user list pagination"
        );
    }

    return UserListResult{
        user_repository_.list(
            limit,
            offset
        ),
        user_repository_.count(),
        limit,
        offset
    };
}

User AdminService::get_user(
    std::string_view access_token,
    std::int64_t user_id
) {
    static_cast<void>(
        require_admin(access_token)
    );

    const std::optional<User> user =
        user_repository_.find_by_id(
            user_id
        );

    if (!user.has_value()) {
        throw AdminError(
            AdminErrorCode::user_not_found,
            "User does not exist"
        );
    }

    return *user;
}

UserStatusResult
AdminService::set_user_enabled(
    std::string_view access_token,
    std::int64_t target_user_id,
    bool enabled
) {
    const User administrator =
        require_admin(access_token);

    if (
        !enabled &&
        administrator.id == target_user_id
    ) {
        throw AdminError(
            AdminErrorCode::cannot_disable_self,
            "Administrator cannot disable "
            "their own account"
        );
    }

    auto transaction =
        database_.begin_transaction();

    const std::optional<User> target =
        user_repository_.find_by_id(
            transaction,
            target_user_id
        );

    if (!target.has_value()) {
        throw AdminError(
            AdminErrorCode::user_not_found,
            "User does not exist"
        );
    }

    if (
        !user_repository_.set_enabled(
            transaction,
            target_user_id,
            enabled
        )
    ) {
        throw AdminError(
            AdminErrorCode::user_not_found,
            "User does not exist"
        );
    }

    std::int64_t revoked_sessions = 0;

    if (!enabled) {
        revoked_sessions =
            auth_session_repository_
                .revoke_all_for_user(
                    transaction,
                    target_user_id
                );
    }

    const std::optional<User> updated_user =
        user_repository_.find_by_id(
            transaction,
            target_user_id
        );

    if (!updated_user.has_value()) {
        throw AdminError(
            AdminErrorCode::user_not_found,
            "Updated user could not be found"
        );
    }

    transaction.commit();

    return UserStatusResult{
        administrator.id,
        *updated_user,
        revoked_sessions
    };
}

}  // namespace secure
