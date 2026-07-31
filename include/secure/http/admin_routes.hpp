#pragma once

namespace secure {

class AdminService;
class Router;

void register_admin_routes(
    Router& router,
    AdminService& admin_service
);

}  // namespace secure
