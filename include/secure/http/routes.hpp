#pragma once

namespace secure {

class AuthService;
class Database;
class Router;
class ServiceState;
class UserService;

void register_routes(
    Router& router,
    Database& database,
    ServiceState& service_state,
    UserService& user_service,
    AuthService& auth_service
);

}  // namespace secure
