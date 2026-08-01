#pragma once

#include "secure/http/http_types.hpp"

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/beast/http.hpp>

namespace secure {

struct ApiErrorDetail final {
    std::string field;
    std::string reason;
};

struct ApiError final {
    std::string code;
    std::string message;
    std::vector<ApiErrorDetail> details;
};

class ApiException final
    : public std::runtime_error {
public:
    ApiException(
        boost::beast::http::status status,
        ApiError error
    );

    [[nodiscard]]
    boost::beast::http::status status()
        const noexcept;

    [[nodiscard]]
    const ApiError& error() const noexcept;

private:
    boost::beast::http::status status_;
    ApiError error_;
};

[[nodiscard]]
std::string default_api_error_message(
    std::string_view code
);

[[nodiscard]]
HttpResponse make_api_error_response(
    boost::beast::http::status status,
    ApiError error
);

[[nodiscard]]
HttpResponse make_json_error(
    boost::beast::http::status status,
    std::string_view error_code
);

[[nodiscard]]
HttpResponse make_json_error(
    boost::beast::http::status status,
    std::string_view error_code,
    std::string_view message
);

[[nodiscard]]
HttpResponse make_validation_error(
    std::vector<ApiErrorDetail> details
);

void attach_request_id_to_api_error(
    HttpResponse& response,
    std::string_view request_id
);

}  // namespace secure
