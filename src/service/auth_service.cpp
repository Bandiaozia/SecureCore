#include "secure/service/auth_service.hpp"

#include "secure/model/auth_session.hpp"
#include "secure/repository/auth_session_repository.hpp"
#include "secure/repository/user_repository.hpp"
#include "secure/security/password_hasher.hpp"
#include "secure/security/token_service.hpp"

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

std::string trim_copy(
    std::string_view value
) {
    const auto first =
        value.find_first_not_of(
            " \t\r\n"
        );

    if (
        first ==
        std::string_view::npos
    ) {
        return {};
    }

    const auto last =
        value.find_last_not_of(
            " \t\r\n"
        );

    return std::string(
        value.substr(
            first,
            last - first + 1
        )
    );
}

}  // namespace

std::string_view auth_error_name(
    AuthErrorCode code
) noexcept {
    switch (code) {
    case AuthErrorCode::
        invalid_credentials:
        return "invalid_credentials";

    case AuthErrorCode::
        account_disabled:
        return "account_disabled";

    case AuthErrorCode::
        invalid_access_token:
        return "invalid_access_token";

    case AuthErrorCode::
        access_token_expired:
        return "access_token_expired";

    case AuthErrorCode::
        invalid_refresh_token:
        return "invalid_refresh_token";

    case AuthErrorCode::
        refresh_token_expired:
        return "refresh_token_expired";

    case AuthErrorCode::
        token_creation_failed:
        return "token_creation_failed";
    }

    return "authentication_failed";
}

AuthError::AuthError(
    AuthErrorCode code,
    std::string message
)
    : std::runtime_error(
          std::move(message)
      ),
      code_(code) {
}

AuthErrorCode AuthError::code()
    const noexcept {
    return code_;
}

AuthService::AuthService(
    UserRepository& user_repository,
    AuthSessionRepository&
        auth_session_repository,
    PasswordHasher& password_hasher,
    TokenService& token_service,
    std::int64_t
        access_token_lifetime_seconds,
    std::int64_t
        refresh_token_lifetime_seconds
)
    : user_repository_(
          user_repository
      ),
      auth_session_repository_(
          auth_session_repository
      ),
      password_hasher_(
          password_hasher
      ),
      token_service_(
          token_service
      ),
      access_token_lifetime_seconds_(
          access_token_lifetime_seconds
      ),
      refresh_token_lifetime_seconds_(
          refresh_token_lifetime_seconds
      ) {
    if (
        access_token_lifetime_seconds_ <= 0
    ) {
        throw std::invalid_argument(
            "Access token lifetime must "
            "be positive"
        );
    }

    if (
        refresh_token_lifetime_seconds_ <=
        access_token_lifetime_seconds_
    ) {
        throw std::invalid_argument(
            "Refresh token lifetime must "
            "be longer than access token "
            "lifetime"
        );
    }
}

LoginResult AuthService::login(
    std::string login,
    std::string password
) {
    login = trim_copy(login);

    if (
        login.empty() ||
        password.empty()
    ) {
        throw AuthError(
            AuthErrorCode::
                invalid_credentials,
            "Invalid login or password"
        );
    }

    const std::optional<User> user =
        user_repository_.find_by_login(
            login
        );

    /*
     * 用户不存在和密码错误使用同一个错误，
     * 避免接口泄露账号是否存在。
     */
    if (
        !user.has_value() ||
        !password_hasher_.verify(
            password,
            user->password_hash
        )
    ) {
        throw AuthError(
            AuthErrorCode::
                invalid_credentials,
            "Invalid login or password"
        );
    }

    if (!user->enabled) {
        throw AuthError(
            AuthErrorCode::
                account_disabled,
            "User account is disabled"
        );
    }

    const std::int64_t now =
        current_unix_time();

    return LoginResult{
        *user,
        issue_tokens(
            user->id,
            now
        )
    };
}

LoginResult AuthService::refresh(
    std::string_view refresh_token
) {
    if (refresh_token.empty()) {
        throw AuthError(
            AuthErrorCode::
                invalid_refresh_token,
            "Refresh token is invalid"
        );
    }

    const std::string token_hash =
        token_service_.hash_token(
            refresh_token
        );

    const std::optional<AuthSession>
        session =
            auth_session_repository_
                .find_by_refresh_token_hash(
                    token_hash
                );

    if (
        !session.has_value() ||
        session->revoked
    ) {
        throw AuthError(
            AuthErrorCode::
                invalid_refresh_token,
            "Refresh token is invalid"
        );
    }

    const std::int64_t now =
        current_unix_time();

    if (
        session->refresh_expires_at <= now
    ) {
        auth_session_repository_
            .revoke_by_id(
                session->id
            );

        throw AuthError(
            AuthErrorCode::
                refresh_token_expired,
            "Refresh token has expired"
        );
    }

    const std::optional<User> user =
        user_repository_.find_by_id(
            session->user_id
        );

    if (!user.has_value()) {
        auth_session_repository_
            .revoke_by_id(
                session->id
            );

        throw AuthError(
            AuthErrorCode::
                invalid_refresh_token,
            "Refresh token is invalid"
        );
    }

    if (!user->enabled) {
        auth_session_repository_
            .revoke_by_id(
                session->id
            );

        throw AuthError(
            AuthErrorCode::
                account_disabled,
            "User account is disabled"
        );
    }

    /*
     * Refresh Token 轮换：
     * 使用一次后，旧会话立即撤销。
     */
    if (
        !auth_session_repository_
             .revoke_by_id(
                 session->id
             )
    ) {
        throw AuthError(
            AuthErrorCode::
                invalid_refresh_token,
            "Refresh token was already used"
        );
    }

    return LoginResult{
        *user,
        issue_tokens(
            user->id,
            now
        )
    };
}

User AuthService::
authenticate_access_token(
    std::string_view access_token
) {
    if (access_token.empty()) {
        throw AuthError(
            AuthErrorCode::
                invalid_access_token,
            "Access token is invalid"
        );
    }

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
        session->revoked
    ) {
        throw AuthError(
            AuthErrorCode::
                invalid_access_token,
            "Access token is invalid"
        );
    }

    const std::int64_t now =
        current_unix_time();

    if (
        session->access_expires_at <= now
    ) {
        throw AuthError(
            AuthErrorCode::
                access_token_expired,
            "Access token has expired"
        );
    }

    const std::optional<User> user =
        user_repository_.find_by_id(
            session->user_id
        );

    if (!user.has_value()) {
        throw AuthError(
            AuthErrorCode::
                invalid_access_token,
            "Access token is invalid"
        );
    }

    if (!user->enabled) {
        throw AuthError(
            AuthErrorCode::
                account_disabled,
            "User account is disabled"
        );
    }

    return *user;
}

bool AuthService::logout_access_token(
    std::string_view access_token
) {
    if (access_token.empty()) {
        return false;
    }

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
        session->revoked
    ) {
        return false;
    }

    return auth_session_repository_
        .revoke_by_id(
            session->id
        );
}

AuthTokenPair AuthService::issue_tokens(
    std::int64_t user_id,
    std::int64_t current_time
) {
    /*
     * 随机令牌碰撞概率极低，但数据库设置了
     * UNIQUE，因此这里最多重试三次。
     */
    for (
        int attempt = 0;
        attempt < 3;
        ++attempt
    ) {
        const GeneratedToken access =
            token_service_
                .generate_access_token();

        const GeneratedToken refresh =
            token_service_
                .generate_refresh_token();

        const std::int64_t
            access_expires_at =
                current_time +
                access_token_lifetime_seconds_;

        const std::int64_t
            refresh_expires_at =
                current_time +
                refresh_token_lifetime_seconds_;

        try {
            static_cast<void>(
                auth_session_repository_.create(
                    CreateAuthSession{
                        user_id,
                        access.hash,
                        refresh.hash,
                        access_expires_at,
                        refresh_expires_at
                    }
                )
            );

            return AuthTokenPair{
                access.value,
                refresh.value,
                access_expires_at,
                refresh_expires_at
            };
        } catch (
            const DuplicateTokenError&
        ) {
            /*
             * 重新生成随机令牌。
             */
        }
    }

    throw AuthError(
        AuthErrorCode::
            token_creation_failed,
        "Could not create authentication "
        "tokens"
    );
}

}  // namespace secure
