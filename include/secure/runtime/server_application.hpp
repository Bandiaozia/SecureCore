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
#include "secure/repository/auth_session_repository.hpp"
#include "secure/repository/user_repository.hpp"
#include "secure/runtime/worker_pool.hpp"
#include "secure/security/password_hasher.hpp"
#include "secure/security/token_service.hpp"
#include "secure/service/account_security_service.hpp"
#include "secure/service/admin_service.hpp"
#include "secure/service/auth_service.hpp"
#include "secure/service/user_service.hpp"

#include <atomic>

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

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

    ServerConfig config_;

    Logger logger_;

    MetricsRegistry metrics_registry_;

    Router router_;

    RateLimiter rate_limiter_;

    MiddlewarePipeline middleware_pipeline_;

    Database database_;

    MigrationRunner migration_runner_;

    UserRepository user_repository_;

    AuthSessionRepository
        auth_session_repository_;

    PasswordHasher password_hasher_;

    TokenService token_service_;

    UserService user_service_;

    AuthService auth_service_;

    AdminService admin_service_;

    AccountSecurityService
        account_security_service_;

    /*
     * io_context 必须比 WorkerPool 更早构造、
     * 更晚销毁。工作任务完成后会向它投递响应。
     */
    boost::asio::io_context io_context_;

    WorkerPool worker_pool_;

    boost::asio::signal_set signals_;

    HttpServer http_server_;

    std::atomic_bool stopping_{false};
};

}  // namespace secure
