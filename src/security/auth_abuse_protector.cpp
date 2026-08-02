#include "secure/security/auth_abuse_protector.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

namespace secure {

namespace {

std::string trim_copy(
    std::string_view value
) {
    const auto first = value.find_first_not_of(
        " \t\r\n"
    );

    if (first == std::string_view::npos) {
        return {};
    }

    const auto last = value.find_last_not_of(
        " \t\r\n"
    );

    return std::string(
        value.substr(
            first,
            last - first + 1
        )
    );
}

std::uint32_t ceil_seconds(
    AuthAbuseProtector::Clock::duration duration
) {
    if (duration <= AuthAbuseProtector::Clock::duration::zero()) {
        return 0;
    }

    const auto milliseconds =
        std::chrono::duration_cast<
            std::chrono::milliseconds
        >(duration);

    const auto rounded = std::max<long long>(
        1,
        (milliseconds.count() + 999) / 1000
    );

    if (
        rounded >
        static_cast<long long>(
            std::numeric_limits<std::uint32_t>::max()
        )
    ) {
        return std::numeric_limits<std::uint32_t>::max();
    }

    return static_cast<std::uint32_t>(rounded);
}

}  // namespace

AuthAbuseProtector::AuthAbuseProtector(
    AuthAbuseConfig config
)
    : config_(config) {
    if (
        config_.account_failure_limit == 0 ||
        config_.ip_failure_limit == 0
    ) {
        throw std::invalid_argument(
            "Authentication failure limits must be positive"
        );
    }

    if (
        config_.failure_window <= std::chrono::seconds::zero() ||
        config_.base_lockout <= std::chrono::seconds::zero() ||
        config_.maximum_lockout < config_.base_lockout
    ) {
        throw std::invalid_argument(
            "Authentication lockout durations are invalid"
        );
    }

    if (
        config_.maximum_tracked_accounts == 0 ||
        config_.maximum_tracked_ips == 0
    ) {
        throw std::invalid_argument(
            "Authentication tracking capacities must be positive"
        );
    }
}

AuthAbuseDecision AuthAbuseProtector::check(
    std::string_view login,
    std::string_view client_ip,
    Clock::time_point now
) {
    const std::string account_key = normalize_login(login);
    const std::string ip_key = normalize_ip(client_ip);

    std::lock_guard lock(mutex_);

    prune_if_needed(now);

    AuthAbuseDecision account_decision;
    AuthAbuseDecision ip_decision;

    if (const auto iterator = account_states_.find(account_key);
        iterator != account_states_.end()) {
        account_decision = check_state(
            iterator->second,
            now
        );
    }

    if (const auto iterator = ip_states_.find(ip_key);
        iterator != ip_states_.end()) {
        ip_decision = check_state(
            iterator->second,
            now
        );
    }

    if (
        account_decision.allowed &&
        ip_decision.allowed
    ) {
        return AuthAbuseDecision{};
    }

    return AuthAbuseDecision{
        false,
        std::max(
            account_decision.retry_after_seconds,
            ip_decision.retry_after_seconds
        ),
        false
    };
}

AuthAbuseDecision AuthAbuseProtector::record_failure(
    std::string_view login,
    std::string_view client_ip,
    Clock::time_point now
) {
    const std::string account_key = normalize_login(login);
    const std::string ip_key = normalize_ip(client_ip);

    std::lock_guard lock(mutex_);

    prune_if_needed(now);

    ensure_capacity(
        account_states_,
        account_key,
        config_.maximum_tracked_accounts
    );
    ensure_capacity(
        ip_states_,
        ip_key,
        config_.maximum_tracked_ips
    );

    auto& account_state = account_states_[account_key];
    auto& ip_state = ip_states_[ip_key];

    const AuthAbuseDecision account_decision =
        record_failure_state(
            account_state,
            config_.account_failure_limit,
            now
        );

    const AuthAbuseDecision ip_decision =
        record_failure_state(
            ip_state,
            config_.ip_failure_limit,
            now
        );

    if (
        account_decision.allowed &&
        ip_decision.allowed
    ) {
        return AuthAbuseDecision{};
    }

    return AuthAbuseDecision{
        false,
        std::max(
            account_decision.retry_after_seconds,
            ip_decision.retry_after_seconds
        ),
        account_decision.newly_locked ||
            ip_decision.newly_locked
    };
}

void AuthAbuseProtector::record_success(
    std::string_view login,
    std::string_view client_ip
) {
    const std::string account_key = normalize_login(login);

    /*
     * 成功登录只清除账户维度。若同时清除整个 IP 维度，
     * 攻击者可使用自己的有效账户重置同一来源地址的
     * 暴力尝试计数。IP 状态按窗口自然过期。
     */
    static_cast<void>(client_ip);

    std::lock_guard lock(mutex_);

    account_states_.erase(account_key);
}

std::size_t AuthAbuseProtector::tracked_accounts() const {
    std::lock_guard lock(mutex_);
    return account_states_.size();
}

std::size_t AuthAbuseProtector::tracked_ips() const {
    std::lock_guard lock(mutex_);
    return ip_states_.size();
}

std::string AuthAbuseProtector::normalize_login(
    std::string_view login
) {
    std::string normalized = trim_copy(login);

    if (normalized.empty()) {
        return "<empty>";
    }

    if (normalized.size() > 254) {
        normalized.resize(254);
    }

    for (char& character : normalized) {
        character = static_cast<char>(
            std::tolower(
                static_cast<unsigned char>(character)
            )
        );
    }

    return normalized;
}

std::string AuthAbuseProtector::normalize_ip(
    std::string_view client_ip
) {
    std::string normalized = trim_copy(client_ip);

    if (normalized.empty()) {
        return "<unknown>";
    }

    if (normalized.size() > 128) {
        normalized.resize(128);
    }

    return normalized;
}

AuthAbuseDecision AuthAbuseProtector::check_state(
    FailureState& state,
    Clock::time_point now
) const {
    const Clock::time_point previous_last_seen =
        state.last_seen;

    state.last_seen = now;

    if (state.locked_until > now) {
        return AuthAbuseDecision{
            false,
            ceil_seconds(state.locked_until - now),
            false
        };
    }

    const bool quiet_after_lock =
        state.locked_until != Clock::time_point{} &&
        now - state.locked_until > config_.failure_window;

    const bool quiet_without_lock =
        state.locked_until == Clock::time_point{} &&
        previous_last_seen != Clock::time_point{} &&
        now - previous_last_seen > config_.failure_window;

    if (quiet_after_lock || quiet_without_lock) {
        state.failures = 0;
        state.lockout_level = 0;
        state.window_started = now;
        state.locked_until = Clock::time_point{};

        return AuthAbuseDecision{};
    }

    if (
        state.window_started != Clock::time_point{} &&
        now - state.window_started > config_.failure_window
    ) {
        /*
         * 失败计数窗口重新开始，但刚结束的锁定等级保留。
         * 只有锁定结束后再安静一个完整窗口才重置退避等级。
         */
        state.failures = 0;
        state.window_started = now;
    }

    return AuthAbuseDecision{};
}

AuthAbuseDecision
AuthAbuseProtector::record_failure_state(
    FailureState& state,
    std::uint32_t failure_limit,
    Clock::time_point now
) const {
    const AuthAbuseDecision current = check_state(
        state,
        now
    );

    if (!current.allowed) {
        return current;
    }

    if (
        state.window_started == Clock::time_point{} ||
        now - state.window_started > config_.failure_window
    ) {
        state.failures = 0;
        state.lockout_level = 0;
        state.window_started = now;
    }

    ++state.failures;
    state.last_seen = now;

    if (state.failures < failure_limit) {
        return AuthAbuseDecision{};
    }

    state.failures = 0;
    ++state.lockout_level;

    const std::chrono::seconds duration =
        lockout_duration(state.lockout_level);

    state.locked_until = now + duration;

    return AuthAbuseDecision{
        false,
        static_cast<std::uint32_t>(duration.count()),
        true
    };
}

std::chrono::seconds
AuthAbuseProtector::lockout_duration(
    std::uint32_t level
) const {
    std::uint64_t multiplier = 1;

    for (
        std::uint32_t index = 1;
        index < level;
        ++index
    ) {
        if (
            multiplier >=
            static_cast<std::uint64_t>(
                config_.maximum_lockout.count()
            )
        ) {
            break;
        }

        multiplier *= 2;
    }

    const std::uint64_t base =
        static_cast<std::uint64_t>(
            config_.base_lockout.count()
        );

    const std::uint64_t maximum =
        static_cast<std::uint64_t>(
            config_.maximum_lockout.count()
        );

    const std::uint64_t seconds =
        std::min(
            maximum,
            base > maximum / multiplier
                ? maximum
                : base * multiplier
        );

    return std::chrono::seconds{seconds};
}

void AuthAbuseProtector::prune_if_needed(
    Clock::time_point now
) {
    ++operation_count_;

    if (operation_count_ % 256 != 0) {
        return;
    }

    const auto stale_after =
        config_.failure_window +
        config_.maximum_lockout;

    const auto prune = [now, stale_after](auto& states) {
        for (auto iterator = states.begin(); iterator != states.end();) {
            if (
                iterator->second.last_seen != Clock::time_point{} &&
                now - iterator->second.last_seen > stale_after
            ) {
                iterator = states.erase(iterator);
            } else {
                ++iterator;
            }
        }
    };

    prune(account_states_);
    prune(ip_states_);
}

void AuthAbuseProtector::ensure_capacity(
    std::unordered_map<std::string, FailureState>& states,
    std::string_view key,
    std::size_t maximum_size
) {
    if (
        states.contains(std::string(key)) ||
        states.size() < maximum_size
    ) {
        return;
    }

    states.erase(states.begin());
}

}  // namespace secure
