#include "secure/audit/request_audit_context.hpp"

#include <optional>
#include <utility>

namespace secure {

namespace {

thread_local std::optional<RequestAuditContext>
    active_context;

}  // namespace

ScopedRequestAuditContext::
ScopedRequestAuditContext(
    RequestAuditContext context
)
    : previous_(active_context) {
    active_context = std::move(context);
}

ScopedRequestAuditContext::~ScopedRequestAuditContext() {
    active_context = std::move(previous_);
}

std::optional<RequestAuditContext>
current_request_audit_context() {
    return active_context;
}

}  // namespace secure
