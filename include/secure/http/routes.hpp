#pragma once

namespace secure {

class AuthService;
class Database;
class Router;
class UserService;

void register_routes(
    Router& router,
    Database& database,
    UserService& user_service,
    AuthService& auth_service
);

}  // namespace secure
