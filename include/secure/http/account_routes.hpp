#pragma once

namespace secure {

class AccountSecurityService;
class Router;

void register_account_routes(
    Router& router,
    AccountSecurityService&
        account_security_service
);

}  // namespace secure
