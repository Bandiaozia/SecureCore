#pragma once

#include "secure/model/auth_session.hpp"
#include "secure/model/user.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace secure {

class AuthService;
class Database;
class AuthSessionRepository;
class PasswordHasher;
class TokenService;
class UserRepository;

enum class AccountSecurityErrorCode {
    session_not_found,
    invalid_current_password,
    weak_new_password,
    same_password
};

[[nodiscard]]
std::string_view account_security_error_name(
    AccountSecurityErrorCode code
) noexcept;

class AccountSecurityError final
    : public std::runtime_error {
public:
    AccountSecurityError(
        AccountSecurityErrorCode code,
        std::string message
    );

    [[nodiscard]]
    AccountSecurityErrorCode code()
        const noexcept;

private:
    AccountSecurityErrorCode code_;
};

struct SessionListResult final {
    std::vector<AuthSession> sessions;

    std::int64_t current_session_id{0};
};

struct SessionRevokeResult final {
    std::int64_t user_id{0};

    bool revoked{false};
};

struct PasswordChangeResult final {
    std::int64_t user_id{0};

    std::int64_t revoked_sessions{0};
};

class AccountSecurityService final {
public:
    AccountSecurityService(
        Database& database,
        AuthService& auth_service,
        UserRepository& user_repository,
        AuthSessionRepository&
            auth_session_repository,
        PasswordHasher& password_hasher,
        TokenService& token_service
    );

    [[nodiscard]]
    SessionListResult list_sessions(
        std::string_view access_token
    );

    [[nodiscard]]
    SessionRevokeResult revoke_session(
        std::string_view access_token,
        std::int64_t session_id
    );

    [[nodiscard]]
    PasswordChangeResult change_password(
        std::string_view access_token,
        std::string current_password,
        std::string new_password
    );

private:
    struct CurrentAuthentication final {
        User user;

        AuthSession session;
    };

    [[nodiscard]]
    CurrentAuthentication
    authenticate_current_session(
        std::string_view access_token
    );

    Database& database_;

    AuthService& auth_service_;

    UserRepository& user_repository_;

    AuthSessionRepository&
        auth_session_repository_;

    PasswordHasher& password_hasher_;

    TokenService& token_service_;
};

}  // namespace secure
