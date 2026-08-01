#include "secure/http/metrics_routes.hpp"

#include "secure/database/database.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/router.hpp"
#include "secure/observability/metrics_registry.hpp"
#include "secure/runtime/worker_pool.hpp"
#include "secure/runtime/service_state.hpp"

#include <iomanip>
#include <sstream>
#include <string>

#include <boost/beast/http.hpp>

namespace secure {

namespace http = boost::beast::http;

namespace {

HttpResponse metrics_handler(
    MetricsRegistry& metrics_registry,
    WorkerPool& worker_pool,
    Database& database,
    ServiceState& service_state,
    const HttpRequest& request
) {
    const MetricsSnapshot metrics =
        metrics_registry.snapshot();

    const WorkerPoolSnapshot workers =
        worker_pool.snapshot();

    const DatabasePoolSnapshot database_pool =
        database.pool_snapshot();

    const ServicePhase service_phase =
        service_state.phase();

    const double duration_seconds =
        static_cast<double>(
            metrics
                .http_request_duration_microseconds_total
        ) /
        1'000'000.0;

    std::ostringstream output;

    output
        << "# HELP securecore_up Whether SecureCore is running.\n"
        << "# TYPE securecore_up gauge\n"
        << "securecore_up "
        << (
            service_phase == ServicePhase::stopped
                ? 0
                : 1
        )
        << "\n"
        << "# HELP securecore_server_state Current server lifecycle state.\n"
        << "# TYPE securecore_server_state gauge\n"
        << "securecore_server_state{state=\"starting\"} "
        << (service_phase == ServicePhase::starting ? 1 : 0)
        << "\n"
        << "securecore_server_state{state=\"running\"} "
        << (service_phase == ServicePhase::running ? 1 : 0)
        << "\n"
        << "securecore_server_state{state=\"draining\"} "
        << (service_phase == ServicePhase::draining ? 1 : 0)
        << "\n"
        << "securecore_server_state{state=\"stopped\"} "
        << (service_phase == ServicePhase::stopped ? 1 : 0)
        << "\n"
        << "# HELP securecore_uptime_seconds Process uptime.\n"
        << "# TYPE securecore_uptime_seconds gauge\n"
        << "securecore_uptime_seconds "
        << metrics.uptime_seconds
        << "\n"
        << "# HELP securecore_http_requests_total Completed HTTP requests.\n"
        << "# TYPE securecore_http_requests_total counter\n"
        << "securecore_http_requests_total "
        << metrics.http_requests_total
        << "\n"
        << "# HELP securecore_http_requests_in_flight HTTP requests currently being processed or written.\n"
        << "# TYPE securecore_http_requests_in_flight gauge\n"
        << "securecore_http_requests_in_flight "
        << metrics.http_requests_in_flight
        << "\n"
        << "# HELP securecore_http_responses_total HTTP responses by status class.\n"
        << "# TYPE securecore_http_responses_total counter\n"
        << "securecore_http_responses_total{class=\"2xx\"} "
        << metrics.http_responses_2xx
        << "\n"
        << "securecore_http_responses_total{class=\"3xx\"} "
        << metrics.http_responses_3xx
        << "\n"
        << "securecore_http_responses_total{class=\"4xx\"} "
        << metrics.http_responses_4xx
        << "\n"
        << "securecore_http_responses_total{class=\"5xx\"} "
        << metrics.http_responses_5xx
        << "\n"
        << "# HELP securecore_http_request_duration_seconds_sum Cumulative request duration.\n"
        << "# TYPE securecore_http_request_duration_seconds_sum counter\n"
        << "securecore_http_request_duration_seconds_sum "
        << std::fixed
        << std::setprecision(6)
        << duration_seconds
        << "\n"
        << "# HELP securecore_http_request_duration_seconds_count Timed HTTP requests.\n"
        << "# TYPE securecore_http_request_duration_seconds_count counter\n"
        << "securecore_http_request_duration_seconds_count "
        << metrics.http_requests_total
        << "\n"
        << "# HELP securecore_http_connections_active Active HTTP connections.\n"
        << "# TYPE securecore_http_connections_active gauge\n"
        << "securecore_http_connections_active "
        << metrics.http_connections_active
        << "\n"
        << "# HELP securecore_http_connections_opened_total Opened HTTP connections.\n"
        << "# TYPE securecore_http_connections_opened_total counter\n"
        << "securecore_http_connections_opened_total "
        << metrics.http_connections_opened_total
        << "\n"
        << "# HELP securecore_worker_threads Worker thread count.\n"
        << "# TYPE securecore_worker_threads gauge\n"
        << "securecore_worker_threads "
        << workers.thread_count
        << "\n"
        << "# HELP securecore_worker_queue_capacity Worker queue capacity.\n"
        << "# TYPE securecore_worker_queue_capacity gauge\n"
        << "securecore_worker_queue_capacity "
        << workers.queue_capacity
        << "\n"
        << "# HELP securecore_worker_queue_size Queued worker tasks.\n"
        << "# TYPE securecore_worker_queue_size gauge\n"
        << "securecore_worker_queue_size "
        << workers.queued_tasks
        << "\n"
        << "# HELP securecore_worker_active_tasks Active worker tasks.\n"
        << "# TYPE securecore_worker_active_tasks gauge\n"
        << "securecore_worker_active_tasks "
        << workers.active_tasks
        << "\n"
        << "# HELP securecore_worker_completed_tasks_total Completed worker tasks.\n"
        << "# TYPE securecore_worker_completed_tasks_total counter\n"
        << "securecore_worker_completed_tasks_total "
        << workers.completed_tasks
        << "\n"
        << "# HELP securecore_worker_rejected_tasks_total Rejected worker submissions.\n"
        << "# TYPE securecore_worker_rejected_tasks_total counter\n"
        << "securecore_worker_rejected_tasks_total "
        << workers.rejected_tasks
        << "\n"
        << "# HELP securecore_database_pool_size Database connection pool size.\n"
        << "# TYPE securecore_database_pool_size gauge\n"
        << "securecore_database_pool_size "
        << database_pool.pool_size
        << "\n"
        << "# HELP securecore_database_connections_available Available database connections.\n"
        << "# TYPE securecore_database_connections_available gauge\n"
        << "securecore_database_connections_available "
        << database_pool.available_connections
        << "\n"
        << "# HELP securecore_database_connections_active Leased database connections.\n"
        << "# TYPE securecore_database_connections_active gauge\n"
        << "securecore_database_connections_active "
        << database_pool.active_connections
        << "\n"
        << "# HELP securecore_database_waiting_threads Threads waiting for a database connection.\n"
        << "# TYPE securecore_database_waiting_threads gauge\n"
        << "securecore_database_waiting_threads "
        << database_pool.waiting_threads
        << "\n"
        << "# HELP securecore_database_acquisitions_total Database connection acquisitions.\n"
        << "# TYPE securecore_database_acquisitions_total counter\n"
        << "securecore_database_acquisitions_total "
        << database_pool.acquisitions_total
        << "\n"
        << "# HELP securecore_database_acquire_timeouts_total Database connection acquisition timeouts.\n"
        << "# TYPE securecore_database_acquire_timeouts_total counter\n"
        << "securecore_database_acquire_timeouts_total "
        << database_pool.timeouts_total
        << "\n"
        << "# HELP securecore_audit_events_recorded_total Persisted security audit events.\n"
        << "# TYPE securecore_audit_events_recorded_total counter\n"
        << "securecore_audit_events_recorded_total "
        << metrics.audit_events_recorded_total
        << "\n"
        << "# HELP securecore_audit_events_failed_total Audit events that could not be persisted.\n"
        << "# TYPE securecore_audit_events_failed_total counter\n"
        << "securecore_audit_events_failed_total "
        << metrics.audit_events_failed_total
        << "\n"
        << "# HELP securecore_auth_login_success_total Successful login attempts.\n"
        << "# TYPE securecore_auth_login_success_total counter\n"
        << "securecore_auth_login_success_total "
        << metrics.auth_login_success_total
        << "\n"
        << "# HELP securecore_auth_login_failure_total Failed login attempts.\n"
        << "# TYPE securecore_auth_login_failure_total counter\n"
        << "securecore_auth_login_failure_total "
        << metrics.auth_login_failure_total
        << "\n"
        << "# HELP securecore_auth_login_throttled_total Login attempts rejected by abuse protection.\n"
        << "# TYPE securecore_auth_login_throttled_total counter\n"
        << "securecore_auth_login_throttled_total "
        << metrics.auth_login_throttled_total
        << "\n"
        << "# HELP securecore_auth_refresh_reuse_total Detected refresh-token reuse attempts.\n"
        << "# TYPE securecore_auth_refresh_reuse_total counter\n"
        << "securecore_auth_refresh_reuse_total "
        << metrics.auth_refresh_reuse_total
        << "\n";

    HttpResponse response{
        http::status::ok,
        request.version()
    };

    response.set(
        http::field::content_type,
        "text/plain; version=0.0.4; "
        "charset=utf-8"
    );

    response.body() = output.str();

    return response;
}

}  // namespace

void register_metrics_routes(
    Router& router,
    MetricsRegistry& metrics_registry,
    WorkerPool& worker_pool,
    Database& database,
    ServiceState& service_state
) {
    router.get(
        "/metrics",
        [
            &metrics_registry,
            &worker_pool,
            &database,
            &service_state
        ](
            const HttpRequest& request
        ) {
            return metrics_handler(
                metrics_registry,
                worker_pool,
                database,
                service_state,
                request
            );
        }
    );
}

}  // namespace secure
