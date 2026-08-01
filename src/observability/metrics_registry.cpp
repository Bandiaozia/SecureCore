#include "secure/observability/metrics_registry.hpp"

#include <chrono>
#include <cstdint>

namespace secure {

MetricsRegistry::MetricsRegistry() noexcept
    : started_at_(
          std::chrono::steady_clock::now()
      ) {
}

void MetricsRegistry::request_started() noexcept {
    http_requests_in_flight_.fetch_add(
        1,
        std::memory_order_relaxed
    );
}

void MetricsRegistry::request_finished() noexcept {
    std::uint64_t current =
        http_requests_in_flight_.load(
            std::memory_order_relaxed
        );

    while (
        current != 0 &&
        !http_requests_in_flight_
             .compare_exchange_weak(
                 current,
                 current - 1,
                 std::memory_order_relaxed,
                 std::memory_order_relaxed
             )
    ) {
    }
}

void MetricsRegistry::record_http_response(
    unsigned int status_code,
    std::chrono::microseconds elapsed
) noexcept {
    http_requests_total_.fetch_add(
        1,
        std::memory_order_relaxed
    );

    if (
        status_code >= 200 &&
        status_code < 300
    ) {
        http_responses_2xx_.fetch_add(
            1,
            std::memory_order_relaxed
        );
    } else if (
        status_code >= 300 &&
        status_code < 400
    ) {
        http_responses_3xx_.fetch_add(
            1,
            std::memory_order_relaxed
        );
    } else if (
        status_code >= 400 &&
        status_code < 500
    ) {
        http_responses_4xx_.fetch_add(
            1,
            std::memory_order_relaxed
        );
    } else if (
        status_code >= 500 &&
        status_code < 600
    ) {
        http_responses_5xx_.fetch_add(
            1,
            std::memory_order_relaxed
        );
    }

    if (elapsed.count() > 0) {
        http_request_duration_microseconds_total_
            .fetch_add(
                static_cast<std::uint64_t>(
                    elapsed.count()
                ),
                std::memory_order_relaxed
            );
    }
}

void MetricsRegistry::connection_opened()
    noexcept {
    http_connections_active_.fetch_add(
        1,
        std::memory_order_relaxed
    );

    http_connections_opened_total_.fetch_add(
        1,
        std::memory_order_relaxed
    );
}

void MetricsRegistry::connection_closed()
    noexcept {
    std::uint64_t current =
        http_connections_active_.load(
            std::memory_order_relaxed
        );

    while (
        current != 0 &&
        !http_connections_active_
             .compare_exchange_weak(
                 current,
                 current - 1,
                 std::memory_order_relaxed,
                 std::memory_order_relaxed
             )
    ) {
    }
}

void MetricsRegistry::audit_event_recorded()
    noexcept {
    audit_events_recorded_total_.fetch_add(
        1,
        std::memory_order_relaxed
    );
}

void MetricsRegistry::audit_event_failed()
    noexcept {
    audit_events_failed_total_.fetch_add(
        1,
        std::memory_order_relaxed
    );
}

void MetricsRegistry::auth_login_success()
    noexcept {
    auth_login_success_total_.fetch_add(
        1,
        std::memory_order_relaxed
    );
}

void MetricsRegistry::auth_login_failure()
    noexcept {
    auth_login_failure_total_.fetch_add(
        1,
        std::memory_order_relaxed
    );
}

void MetricsRegistry::auth_login_throttled()
    noexcept {
    auth_login_throttled_total_.fetch_add(
        1,
        std::memory_order_relaxed
    );
}

void MetricsRegistry::auth_refresh_reuse()
    noexcept {
    auth_refresh_reuse_total_.fetch_add(
        1,
        std::memory_order_relaxed
    );
}

MetricsSnapshot MetricsRegistry::snapshot()
    const noexcept {
    const auto uptime =
        std::chrono::duration_cast<
            std::chrono::seconds
        >(
            std::chrono::steady_clock::now()
            - started_at_
        );

    return MetricsSnapshot{
        static_cast<std::uint64_t>(
            uptime.count()
        ),
        http_requests_total_.load(
            std::memory_order_relaxed
        ),
        http_requests_in_flight_.load(
            std::memory_order_relaxed
        ),
        http_responses_2xx_.load(
            std::memory_order_relaxed
        ),
        http_responses_3xx_.load(
            std::memory_order_relaxed
        ),
        http_responses_4xx_.load(
            std::memory_order_relaxed
        ),
        http_responses_5xx_.load(
            std::memory_order_relaxed
        ),
        http_request_duration_microseconds_total_
            .load(
                std::memory_order_relaxed
            ),
        http_connections_active_.load(
            std::memory_order_relaxed
        ),
        http_connections_opened_total_.load(
            std::memory_order_relaxed
        ),
        audit_events_recorded_total_.load(
            std::memory_order_relaxed
        ),
        audit_events_failed_total_.load(
            std::memory_order_relaxed
        ),
        auth_login_success_total_.load(
            std::memory_order_relaxed
        ),
        auth_login_failure_total_.load(
            std::memory_order_relaxed
        ),
        auth_login_throttled_total_.load(
            std::memory_order_relaxed
        ),
        auth_refresh_reuse_total_.load(
            std::memory_order_relaxed
        )
    };
}

}  // namespace secure
