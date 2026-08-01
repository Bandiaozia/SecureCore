#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>

namespace secure {

struct MetricsSnapshot final {
    std::uint64_t uptime_seconds{0};

    std::uint64_t http_requests_total{0};

    std::uint64_t http_requests_in_flight{0};

    std::uint64_t http_responses_2xx{0};

    std::uint64_t http_responses_3xx{0};

    std::uint64_t http_responses_4xx{0};

    std::uint64_t http_responses_5xx{0};

    std::uint64_t
        http_request_duration_microseconds_total{0};

    std::uint64_t http_connections_active{0};

    std::uint64_t
        http_connections_opened_total{0};

    std::uint64_t
        audit_events_recorded_total{0};

    std::uint64_t
        audit_events_failed_total{0};
};

class MetricsRegistry final {
public:
    MetricsRegistry() noexcept;

    void request_started() noexcept;

    void request_finished() noexcept;

    void record_http_response(
        unsigned int status_code,
        std::chrono::microseconds elapsed
    ) noexcept;

    void connection_opened() noexcept;

    void connection_closed() noexcept;

    void audit_event_recorded() noexcept;

    void audit_event_failed() noexcept;

    [[nodiscard]]
    MetricsSnapshot snapshot()
        const noexcept;

private:
    const std::chrono::steady_clock::time_point
        started_at_;

    std::atomic_uint64_t
        http_requests_total_{0};

    std::atomic_uint64_t
        http_requests_in_flight_{0};

    std::atomic_uint64_t
        http_responses_2xx_{0};

    std::atomic_uint64_t
        http_responses_3xx_{0};

    std::atomic_uint64_t
        http_responses_4xx_{0};

    std::atomic_uint64_t
        http_responses_5xx_{0};

    std::atomic_uint64_t
        http_request_duration_microseconds_total_{0};

    std::atomic_uint64_t
        http_connections_active_{0};

    std::atomic_uint64_t
        http_connections_opened_total_{0};

    std::atomic_uint64_t
        audit_events_recorded_total_{0};

    std::atomic_uint64_t
        audit_events_failed_total_{0};
};

}  // namespace secure
