#pragma once

namespace secure {

class AccountSecurityService;
class AuditService;
class Router;

void register_account_routes(
    Router& router,
    AccountSecurityService&
        account_security_service,
    AuditService& audit_service
);

}  // namespace secure
