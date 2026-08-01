#pragma once

#include "secure/config/server_config.hpp"
#include "secure/database/database.hpp"
#include "secure/database/migration.hpp"
#include "secure/http/http_server.hpp"
#include "secure/http/middleware.hpp"
#include "secure/http/rate_limiter.hpp"
#include "secure/http/router.hpp"
#include "secure/log/logger.hpp"
#include "secure/observability/metrics_registry.hpp"
#include "secure/repository/audit_repository.hpp"
#include "secure/repository/auth_session_repository.hpp"
#include "secure/repository/user_repository.hpp"
#include "secure/runtime/service_state.hpp"
#include "secure/runtime/worker_pool.hpp"
#include "secure/security/auth_abuse_protector.hpp"
#include "secure/security/password_hasher.hpp"
#include "secure/security/token_service.hpp"
#include "secure/service/account_security_service.hpp"
#include "secure/service/audit_service.hpp"
#include "secure/service/admin_service.hpp"
#include "secure/service/auth_service.hpp"
#include "secure/service/user_service.hpp"

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl/context.hpp>

namespace secure {

class ServerApplication final {
public:
    explicit ServerApplication(
        ServerConfig config
    );

    int run();

private:
    void run_io_context();

    void stop();

    void run_shutdown_sequence();

    void join_shutdown_thread();

    ServerConfig config_;

    Logger logger_;

    MetricsRegistry metrics_registry_;

    ServiceState service_state_;

    Router router_;

    RateLimiter rate_limiter_;

    MiddlewarePipeline middleware_pipeline_;

    Database database_;

    MigrationRunner migration_runner_;

    UserRepository user_repository_;

    AuthSessionRepository
        auth_session_repository_;

    AuditRepository audit_repository_;

    PasswordHasher password_hasher_;

    TokenService token_service_;

    AuditService audit_service_;

    UserService user_service_;

    AuthAbuseProtector auth_abuse_protector_;

    AuthService auth_service_;

    AdminService admin_service_;

    AccountSecurityService
        account_security_service_;

    boost::asio::io_context io_context_;

    boost::asio::executor_work_guard<
        boost::asio::io_context::executor_type
    > io_work_guard_;

    std::unique_ptr<
        boost::asio::ssl::context
    > tls_context_;

    WorkerPool worker_pool_;

    boost::asio::signal_set signals_;

    HttpServer http_server_;

    std::atomic_bool stopping_{false};

    std::mutex shutdown_thread_mutex_;

    std::thread shutdown_thread_;
};

}  // namespace secure
