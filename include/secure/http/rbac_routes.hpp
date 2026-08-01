#pragma once

namespace secure {

class AdminService;
class AuditService;
class Router;

void register_rbac_routes(
    Router& router,
    AdminService& admin_service,
    AuditService& audit_service
);

}  // namespace secure
