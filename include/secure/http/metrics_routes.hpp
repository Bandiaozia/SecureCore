#pragma once

namespace secure {

class MetricsRegistry;
class Router;
class WorkerPool;

void register_metrics_routes(
    Router& router,
    MetricsRegistry& metrics_registry,
    WorkerPool& worker_pool
);

}  // namespace secure
