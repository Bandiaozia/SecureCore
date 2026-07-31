#pragma once

namespace secure {

class Database;
class Router;

void register_routes(
    Router& router,
    Database& database
);

}  // namespace secure
