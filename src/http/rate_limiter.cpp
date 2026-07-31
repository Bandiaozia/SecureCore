#include "secure/http/rate_limiter.hpp"

#include <stdexcept>

namespace secure {

RateLimiter::RateLimiter(
    std::size_t max_requests,
    std::chrono::seconds window
)
    : max_requests_(max_requests),
      window_(window) {
    if (window_.count() <= 0) {
        throw std::invalid_argument(
            "Rate-limit window must be positive"
        );
    }
}

RateLimitDecision RateLimiter::check(
    const std::string& client_ip
) {
    if (max_requests_ == 0) {
        return {
            true,
            0,
            0,
            std::chrono::seconds{0}
        };
    }

    const auto now = Clock::now();

    std::scoped_lock lock(mutex_);

    cleanup_locked(now);

    const auto [iterator, inserted] =
        buckets_.try_emplace(
            client_ip,
            Bucket{
                now,
                0
            }
        );

    Bucket& bucket = iterator->second;

    if (
        !inserted &&
        now - bucket.window_start >= window_
    ) {
        bucket.window_start = now;
        bucket.request_count = 0;
    }

    if (
        bucket.request_count >=
        max_requests_
    ) {
        const auto remaining_time =
            window_ -
            (now - bucket.window_start);

        auto retry_after =
            std::chrono::ceil<
                std::chrono::seconds
            >(remaining_time);

        if (
            retry_after <
            std::chrono::seconds{1}
        ) {
            retry_after =
                std::chrono::seconds{1};
        }

        return {
            false,
            max_requests_,
            0,
            retry_after
        };
    }

    ++bucket.request_count;

    return {
        true,
        max_requests_,
        max_requests_ -
            bucket.request_count,
        std::chrono::seconds{0}
    };
}

void RateLimiter::cleanup_locked(
    Clock::time_point now
) {
    ++check_count_;

    if (check_count_ % 1024 != 0) {
        return;
    }

    const auto stale_before =
        now - window_ * 2;

    for (
        auto iterator = buckets_.begin();
        iterator != buckets_.end();
    ) {
        if (
            iterator->second.window_start <
            stale_before
        ) {
            iterator =
                buckets_.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

}  // namespace secure
