#pragma once

#include "secure/config/server_config.hpp"
#include "secure/database/database.hpp"
#include "secure/database/migration.hpp"
#include "secure/http/http_server.hpp"
#include "secure/http/middleware.hpp"
#include "secure/http/rate_limiter.hpp"
#include "secure/http/router.hpp"
#include "secure/log/logger.hpp"
#include "secure/repository/user_repository.hpp"
#include "secure/security/password_hasher.hpp"
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

    Router router_;

    RateLimiter rate_limiter_;

    MiddlewarePipeline middleware_pipeline_;

    Database database_;

    MigrationRunner migration_runner_;

    UserRepository user_repository_;

    PasswordHasher password_hasher_;

    UserService user_service_;

    boost::asio::io_context io_context_;

    boost::asio::signal_set signals_;

    HttpServer http_server_;

    std::atomic_bool stopping_{false};
};

}  // namespace secure
