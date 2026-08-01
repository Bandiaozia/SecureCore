#pragma once

namespace secure {

class AdminService;
class AuditService;
class Router;

void register_audit_routes(
    Router& router,
    AdminService& admin_service,
    AuditService& audit_service
);

}  // namespace secure
