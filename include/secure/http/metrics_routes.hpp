#pragma once

namespace secure {

class AdminService;
class Database;
class MetricsRegistry;
class Router;
class ServiceState;
class WorkerPool;

void register_metrics_routes(
    Router& router,
    MetricsRegistry& metrics_registry,
    WorkerPool& worker_pool,
    Database& database,
    ServiceState& service_state,
    AdminService& admin_service,
    bool require_authentication
);

}  // namespace secure
