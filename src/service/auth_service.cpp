#include "secure/service/auth_service.hpp"

#include "secure/database/database.hpp"
#include "secure/database/transaction.hpp"
#include "secure/model/auth_session.hpp"
#include "secure/repository/auth_session_repository.hpp"
#include "secure/repository/user_repository.hpp"
#include "secure/observability/metrics_registry.hpp"
#include "secure/security/auth_abuse_protector.hpp"
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
        login_throttled:
        return "login_throttled";

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
        refresh_token_reused:
        return "refresh_token_reused";

    case AuthErrorCode::
        token_creation_failed:
        return "token_creation_failed";
    }

    return "authentication_failed";
}

AuthError::AuthError(
    AuthErrorCode code,
    std::string message,
    std::uint32_t retry_after_seconds
)
    : std::runtime_error(
          std::move(message)
      ),
      code_(code),
      retry_after_seconds_(retry_after_seconds) {
}

AuthErrorCode AuthError::code()
    const noexcept {
    return code_;
}

std::uint32_t AuthError::retry_after_seconds()
    const noexcept {
    return retry_after_seconds_;
}

AuthService::AuthService(
    Database& database,
    UserRepository& user_repository,
    AuthSessionRepository&
        auth_session_repository,
    PasswordHasher& password_hasher,
    TokenService& token_service,
    AuthAbuseProtector& auth_abuse_protector,
    MetricsRegistry& metrics_registry,
    std::int64_t
        access_token_lifetime_seconds,
    std::int64_t
        refresh_token_lifetime_seconds
)
    : database_(database),
      user_repository_(
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
      auth_abuse_protector_(
          auth_abuse_protector
      ),
      metrics_registry_(
          metrics_registry
      ),
      dummy_password_hash_(
          password_hasher_.hash(
              "SecureCore timing equalization password"
          )
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
    std::string password,
    std::string client_ip
) {
    login = trim_copy(login);
    client_ip = trim_copy(client_ip);

    if (client_ip.empty()) {
        client_ip = "<unknown>";
    }

    if (
        login.empty() ||
        password.empty()
    ) {
        metrics_registry_.auth_login_failure();

        throw AuthError(
            AuthErrorCode::invalid_credentials,
            "Invalid login or password"
        );
    }

    const AuthAbuseDecision before_attempt =
        auth_abuse_protector_.check(
            login,
            client_ip
        );

    if (!before_attempt.allowed) {
        metrics_registry_.auth_login_throttled();

        throw AuthError(
            AuthErrorCode::login_throttled,
            "Too many failed login attempts",
            before_attempt.retry_after_seconds
        );
    }

    const std::optional<User> user =
        user_repository_.find_by_login(
            login
        );

    /*
     * 不存在的用户同样执行一次 Argon2id 验证，
     * 避免通过响应时间判断账号是否存在。
     */
    const std::string_view password_hash =
        user.has_value()
            ? std::string_view(user->password_hash)
            : std::string_view(dummy_password_hash_);

    const bool password_valid =
        password_hasher_.verify(
            password,
            password_hash
        );

    if (
        !user.has_value() ||
        !password_valid
    ) {
        metrics_registry_.auth_login_failure();

        const AuthAbuseDecision after_failure =
            auth_abuse_protector_.record_failure(
                login,
                client_ip
            );

        if (!after_failure.allowed) {
            metrics_registry_.auth_login_throttled();

            throw AuthError(
                AuthErrorCode::login_throttled,
                "Too many failed login attempts",
                after_failure.retry_after_seconds
            );
        }

        throw AuthError(
            AuthErrorCode::invalid_credentials,
            "Invalid login or password"
        );
    }

    if (!user->enabled) {
        metrics_registry_.auth_login_failure();

        throw AuthError(
            AuthErrorCode::account_disabled,
            "User account is disabled"
        );
    }

    if (password_hasher_.needs_rehash(user->password_hash)) {
        const std::string upgraded_hash =
            password_hasher_.hash(password);

        if (!user_repository_.set_password_hash(
                user->id,
                upgraded_hash
            )) {
            throw std::runtime_error(
                "Failed to upgrade password hash"
            );
        }
    }

    auth_abuse_protector_.record_success(
        login,
        client_ip
    );

    metrics_registry_.auth_login_success();

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
            AuthErrorCode::invalid_refresh_token,
            "Refresh token is invalid"
        );
    }

    const std::string token_hash =
        token_service_.hash_token(
            refresh_token
        );

    const std::int64_t now =
        current_unix_time();

    auto transaction =
        database_.begin_transaction();

    const std::optional<AuthSession> session =
        auth_session_repository_
            .find_by_refresh_token_hash(
                transaction,
                token_hash
            );

    if (!session.has_value()) {
        throw AuthError(
            AuthErrorCode::invalid_refresh_token,
            "Refresh token is invalid"
        );
    }

    /*
     * 数据库仍保存已经轮换或撤销的 Refresh Token 哈希。
     * 再次提交同一令牌说明它可能被复制或重放。
     * 事务内撤销整个令牌家族，包含并发刷新刚创建的子会话。
     */
    if (session->revoked) {
        if (session->token_family_id.empty()) {
            static_cast<void>(
                auth_session_repository_
                    .revoke_all_for_user(
                        transaction,
                        session->user_id
                    )
            );
        } else {
            static_cast<void>(
                auth_session_repository_
                    .revoke_family(
                        transaction,
                        session->token_family_id
                    )
            );
        }

        transaction.commit();
        metrics_registry_.auth_refresh_reuse();

        throw AuthError(
            AuthErrorCode::refresh_token_reused,
            "Refresh token reuse was detected"
        );
    }

    if (session->refresh_expires_at <= now) {
        static_cast<void>(
            auth_session_repository_
                .revoke_by_id(
                    transaction,
                    session->id
                )
        );

        transaction.commit();

        throw AuthError(
            AuthErrorCode::refresh_token_expired,
            "Refresh token has expired"
        );
    }

    const std::optional<User> user =
        user_repository_.find_by_id(
            transaction,
            session->user_id
        );

    if (!user.has_value()) {
        static_cast<void>(
            auth_session_repository_
                .revoke_by_id(
                    transaction,
                    session->id
                )
        );

        transaction.commit();

        throw AuthError(
            AuthErrorCode::invalid_refresh_token,
            "Refresh token is invalid"
        );
    }

    if (!user->enabled) {
        static_cast<void>(
            auth_session_repository_
                .revoke_by_id(
                    transaction,
                    session->id
                )
        );

        transaction.commit();

        throw AuthError(
            AuthErrorCode::account_disabled,
            "User account is disabled"
        );
    }

    if (
        !auth_session_repository_
             .revoke_by_id(
                 transaction,
                 session->id
             )
    ) {
        static_cast<void>(
            auth_session_repository_
                .revoke_family(
                    transaction,
                    session->token_family_id
                )
        );

        transaction.commit();
        metrics_registry_.auth_refresh_reuse();

        throw AuthError(
            AuthErrorCode::refresh_token_reused,
            "Refresh token reuse was detected"
        );
    }

    const std::string family_id =
        session->token_family_id.empty()
            ? token_service_.generate_token_family_id()
            : session->token_family_id;

    AuthTokenPair tokens = issue_tokens(
        transaction,
        user->id,
        now,
        family_id,
        session->id
    );

    transaction.commit();

    return LoginResult{
        *user,
        std::move(tokens)
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

LogoutResult AuthService::logout_access_token(
    std::string_view access_token
) {
    if (access_token.empty()) {
        return LogoutResult{};
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
        return LogoutResult{};
    }

    return LogoutResult{
        session->user_id,
        auth_session_repository_
            .revoke_by_id(
                session->id
            )
    };
}

LogoutAllResult
AuthService::logout_all_access_token(
    std::string_view access_token
) {
    /*
     * 先验证 Access Token，
     * 防止攻击者仅凭用户 ID 撤销会话。
     */
    const User user =
        authenticate_access_token(
            access_token
        );

    return LogoutAllResult{
        user.id,
        auth_session_repository_
            .revoke_all_for_user(
                user.id
            )
    };
}

AuthTokenPair AuthService::issue_tokens(
    std::int64_t user_id,
    std::int64_t current_time
) {
    const std::string token_family_id =
        token_service_.generate_token_family_id();

    for (
        int attempt = 0;
        attempt < 3;
        ++attempt
    ) {
        const GeneratedToken access =
            token_service_.generate_access_token();

        const GeneratedToken refresh =
            token_service_.generate_refresh_token();

        const std::int64_t access_expires_at =
            current_time +
            access_token_lifetime_seconds_;

        const std::int64_t refresh_expires_at =
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
                        refresh_expires_at,
                        token_family_id,
                        std::nullopt
                    }
                )
            );

            return AuthTokenPair{
                access.value,
                refresh.value,
                access_expires_at,
                refresh_expires_at
            };
        } catch (const DuplicateTokenError&) {
            /* 重新生成随机令牌。 */
        }
    }

    throw AuthError(
        AuthErrorCode::token_creation_failed,
        "Could not create authentication tokens"
    );
}

AuthTokenPair AuthService::issue_tokens(
    DatabaseTransaction& transaction,
    std::int64_t user_id,
    std::int64_t current_time,
    std::string token_family_id,
    std::optional<std::int64_t> parent_session_id
) {
    if (token_family_id.empty()) {
        token_family_id =
            token_service_.generate_token_family_id();
    }

    for (
        int attempt = 0;
        attempt < 3;
        ++attempt
    ) {
        const GeneratedToken access =
            token_service_.generate_access_token();

        const GeneratedToken refresh =
            token_service_.generate_refresh_token();

        const std::int64_t access_expires_at =
            current_time +
            access_token_lifetime_seconds_;

        const std::int64_t refresh_expires_at =
            current_time +
            refresh_token_lifetime_seconds_;

        try {
            static_cast<void>(
                auth_session_repository_.create(
                    transaction,
                    CreateAuthSession{
                        user_id,
                        access.hash,
                        refresh.hash,
                        access_expires_at,
                        refresh_expires_at,
                        token_family_id,
                        parent_session_id
                    }
                )
            );

            return AuthTokenPair{
                access.value,
                refresh.value,
                access_expires_at,
                refresh_expires_at
            };
        } catch (const DuplicateTokenError&) {
            /* 重新生成随机令牌。 */
        }
    }

    throw AuthError(
        AuthErrorCode::token_creation_failed,
        "Could not create authentication tokens"
    );
}

}  // namespace secure
