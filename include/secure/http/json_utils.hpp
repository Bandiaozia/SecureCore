#pragma once

#include "secure/http/api_error.hpp"
#include "secure/http/http_types.hpp"

#include <string_view>

#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>

namespace secure {

using Json = nlohmann::json;

[[nodiscard]]
bool has_json_content_type(
    const HttpRequest& request
);

[[nodiscard]]
HttpResponse make_json_response(
    boost::beast::http::status status,
    const Json& body
);



}  // namespace secure
