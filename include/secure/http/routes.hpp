#pragma once

namespace secure {

class Database;
class Router;
class UserService;

void register_routes(
    Router& router,
    Database& database,
    UserService& user_service
);

}  // namespace secure
