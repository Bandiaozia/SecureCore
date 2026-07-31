#pragma once

#include "secure/model/user.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace secure {

class AuthSessionRepository;
class PasswordHasher;
class TokenService;
class UserRepository;

enum class AuthErrorCode {
    invalid_credentials,
    account_disabled,
    invalid_access_token,
    access_token_expired,
    invalid_refresh_token,
    refresh_token_expired,
    token_creation_failed
};

[[nodiscard]]
std::string_view auth_error_name(
    AuthErrorCode code
) noexcept;

class AuthError final
    : public std::runtime_error {
public:
    AuthError(
        AuthErrorCode code,
        std::string message
    );

    [[nodiscard]]
    AuthErrorCode code()
        const noexcept;

private:
    AuthErrorCode code_;
};

struct AuthTokenPair final {
    std::string access_token;

    std::string refresh_token;

    std::int64_t access_expires_at{0};

    std::int64_t refresh_expires_at{0};
};

struct LoginResult final {
    User user;

    AuthTokenPair tokens;
};

class AuthService final {
public:
    AuthService(
        UserRepository& user_repository,
        AuthSessionRepository&
            auth_session_repository,
        PasswordHasher& password_hasher,
        TokenService& token_service,
        std::int64_t
            access_token_lifetime_seconds = 900,
        std::int64_t
            refresh_token_lifetime_seconds =
                30LL * 24LL * 60LL * 60LL
    );

    [[nodiscard]]
    LoginResult login(
        std::string login,
        std::string password
    );

    [[nodiscard]]
    LoginResult refresh(
        std::string_view refresh_token
    );

    [[nodiscard]]
    User authenticate_access_token(
        std::string_view access_token
    );

    /*
     * 登出保持幂等：
     * 已失效或不存在的令牌返回 false，
     * 不抛出认证错误。
     */
    bool logout_access_token(
        std::string_view access_token
    );

    [[nodiscard]]
    std::int64_t logout_all_access_token(
        std::string_view access_token
    );

private:
    [[nodiscard]]
    AuthTokenPair issue_tokens(
        std::int64_t user_id,
        std::int64_t current_time
    );

    UserRepository& user_repository_;

    AuthSessionRepository&
        auth_session_repository_;

    PasswordHasher& password_hasher_;

    TokenService& token_service_;

    std::int64_t
        access_token_lifetime_seconds_;

    std::int64_t
        refresh_token_lifetime_seconds_;
};

}  // namespace secure
