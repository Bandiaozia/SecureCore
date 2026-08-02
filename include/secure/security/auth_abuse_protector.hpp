#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace secure {

struct AuthAbuseConfig final {
    std::uint32_t account_failure_limit{5};

    std::uint32_t ip_failure_limit{20};

    std::chrono::seconds failure_window{300};

    std::chrono::seconds base_lockout{300};

    std::chrono::seconds maximum_lockout{3600};

    std::size_t maximum_tracked_accounts{65536};

    std::size_t maximum_tracked_ips{65536};
};

struct AuthAbuseDecision final {
    bool allowed{true};

    std::uint32_t retry_after_seconds{0};

    bool newly_locked{false};
};

class AuthAbuseProtector final {
public:
    using Clock = std::chrono::steady_clock;

    explicit AuthAbuseProtector(
        AuthAbuseConfig config
    );

    [[nodiscard]]
    AuthAbuseDecision check(
        std::string_view login,
        std::string_view client_ip,
        Clock::time_point now = Clock::now()
    );

    [[nodiscard]]
    AuthAbuseDecision record_failure(
        std::string_view login,
        std::string_view client_ip,
        Clock::time_point now = Clock::now()
    );

    void record_success(
        std::string_view login,
        std::string_view client_ip
    );

    [[nodiscard]]
    std::size_t tracked_accounts() const;

    [[nodiscard]]
    std::size_t tracked_ips() const;

private:
    struct FailureState final {
        std::uint32_t failures{0};

        std::uint32_t lockout_level{0};

        Clock::time_point window_started{};

        Clock::time_point locked_until{};

        Clock::time_point last_seen{};
    };

    [[nodiscard]]
    static std::string normalize_login(
        std::string_view login
    );

    [[nodiscard]]
    static std::string normalize_ip(
        std::string_view client_ip
    );

    [[nodiscard]]
    AuthAbuseDecision check_state(
        FailureState& state,
        Clock::time_point now
    ) const;

    [[nodiscard]]
    AuthAbuseDecision record_failure_state(
        FailureState& state,
        std::uint32_t failure_limit,
        Clock::time_point now
    ) const;

    [[nodiscard]]
    std::chrono::seconds lockout_duration(
        std::uint32_t level
    ) const;

    void prune_if_needed(
        Clock::time_point now
    );

    static void ensure_capacity(
        std::unordered_map<std::string, FailureState>& states,
        std::string_view key,
        std::size_t maximum_size
    );

    AuthAbuseConfig config_;

    mutable std::mutex mutex_;

    std::unordered_map<std::string, FailureState>
        account_states_;

    std::unordered_map<std::string, FailureState>
        ip_states_;

    std::uint64_t operation_count_{0};
};

}  // namespace secure
