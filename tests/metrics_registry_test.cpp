#include "secure/observability/metrics_registry.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>

namespace {

void require(
    bool condition,
    const char* message
) {
    if (condition) {
        return;
    }

    std::cerr
        << "Metrics test failed: "
        << message
        << '\n';

    std::exit(EXIT_FAILURE);
}

}  // namespace

int main() {
    secure::MetricsRegistry metrics;

    metrics.connection_opened();
    metrics.connection_opened();
    metrics.connection_closed();

    metrics.request_started();
    metrics.request_started();
    metrics.request_finished();

    metrics.record_http_response(
        200,
        std::chrono::microseconds{1250}
    );

    metrics.record_http_response(
        404,
        std::chrono::microseconds{250}
    );

    metrics.record_http_response(
        503,
        std::chrono::microseconds{500}
    );

    metrics.audit_event_recorded();
    metrics.audit_event_recorded();
    metrics.audit_event_failed();

    metrics.auth_login_success();
    metrics.auth_login_failure();
    metrics.auth_login_failure();
    metrics.auth_login_throttled();
    metrics.auth_refresh_reuse();

    const auto snapshot =
        metrics.snapshot();

    require(
        snapshot.http_requests_total == 3,
        "request total"
    );

    require(
        snapshot.http_requests_in_flight == 1,
        "in-flight requests"
    );

    require(
        snapshot.http_responses_2xx == 1,
        "2xx total"
    );

    require(
        snapshot.http_responses_4xx == 1,
        "4xx total"
    );

    require(
        snapshot.http_responses_5xx == 1,
        "5xx total"
    );

    require(
        snapshot
            .http_request_duration_microseconds_total
            == 2000,
        "duration total"
    );

    require(
        snapshot.http_connections_active == 1,
        "active connections"
    );

    require(
        snapshot
            .http_connections_opened_total == 2,
        "opened connections"
    );

    require(
        snapshot.audit_events_recorded_total == 2,
        "audit events recorded"
    );

    require(
        snapshot.audit_events_failed_total == 1,
        "audit event failures"
    );

    require(
        snapshot.auth_login_success_total == 1,
        "login success total"
    );

    require(
        snapshot.auth_login_failure_total == 2,
        "login failure total"
    );

    require(
        snapshot.auth_login_throttled_total == 1,
        "login throttled total"
    );

    require(
        snapshot.auth_refresh_reuse_total == 1,
        "refresh reuse total"
    );

    std::cout
        << "Metrics tests passed\n";

    return EXIT_SUCCESS;
}
