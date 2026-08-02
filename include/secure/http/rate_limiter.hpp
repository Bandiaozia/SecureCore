#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

namespace secure {

struct RateLimitDecision final {
    bool allowed{true};

    std::size_t limit{0};

    std::size_t remaining{0};

    std::chrono::seconds retry_after{0};
};

class RateLimiter final {
public:
    RateLimiter(
        std::size_t max_requests,
        std::chrono::seconds window,
        std::size_t max_buckets = 65536
    );

    [[nodiscard]]
    RateLimitDecision check(
        const std::string& client_ip
    );

private:
    using Clock =
        std::chrono::steady_clock;

    struct Bucket final {
        Clock::time_point window_start;

        std::size_t request_count{0};
    };

    void cleanup_locked(
        Clock::time_point now
    );

    const std::size_t max_requests_;

    const std::chrono::seconds window_;

    const std::size_t max_buckets_;

    std::mutex mutex_;

    std::unordered_map<
        std::string,
        Bucket
    > buckets_;

    std::size_t check_count_{0};
};

}  // namespace secure
