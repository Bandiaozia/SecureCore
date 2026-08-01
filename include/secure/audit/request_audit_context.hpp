#pragma once

#include <optional>
#include <string>

namespace secure {

struct RequestAuditContext final {
    std::string request_id;

    std::string client_ip;

    std::string user_agent;
};

class ScopedRequestAuditContext final {
public:
    explicit ScopedRequestAuditContext(
        RequestAuditContext context
    );

    ~ScopedRequestAuditContext();

    ScopedRequestAuditContext(
        const ScopedRequestAuditContext&
    ) = delete;

    ScopedRequestAuditContext& operator=(
        const ScopedRequestAuditContext&
    ) = delete;

private:
    std::optional<RequestAuditContext>
        previous_;
};

[[nodiscard]]
std::optional<RequestAuditContext>
current_request_audit_context();

}  // namespace secure
