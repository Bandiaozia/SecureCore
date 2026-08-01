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

    const auto snapshot =
        metrics.snapshot();

    require(
        snapshot.http_requests_total == 3,
        "request total"
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

    std::cout
        << "Metrics tests passed\n";

    return EXIT_SUCCESS;
}
