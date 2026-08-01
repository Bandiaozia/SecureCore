#pragma once

#include "secure/http/http_types.hpp"

#include <string>
#include <string_view>

namespace secure {

[[nodiscard]]
std::string generate_request_id();

[[nodiscard]]
std::string resolve_request_id(
    const HttpRequest& request
);

void apply_request_id(
    HttpResponse& response,
    std::string_view request_id
);

}  // namespace secure
