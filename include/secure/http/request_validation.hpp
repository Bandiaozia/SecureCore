#pragma once

#include "secure/http/api_error.hpp"
#include "secure/http/http_types.hpp"
#include "secure/http/json_utils.hpp"
#include "secure/http/router.hpp"

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace secure {

[[nodiscard]]
Json parse_json_object(
    const HttpRequest& request
);

class JsonObjectValidator final {
public:
    explicit JsonObjectValidator(
        const Json& object
    );

    [[nodiscard]]
    std::optional<std::string>
    required_string(
        std::string_view field,
        std::size_t minimum_size = 0,
        std::size_t maximum_size =
            std::numeric_limits<
                std::size_t
            >::max()
    );

    [[nodiscard]]
    std::optional<bool> required_boolean(
        std::string_view field
    );

    void add_error(
        std::string_view field,
        std::string reason
    );

    void throw_if_invalid() const;

private:
    const Json& object_;
    std::vector<ApiErrorDetail> details_;
};

[[nodiscard]]
std::int64_t require_path_integer(
    const RouteParameters& parameters,
    std::string_view name,
    std::int64_t minimum = 1,
    std::int64_t maximum =
        std::numeric_limits<
            std::int64_t
        >::max()
);

[[nodiscard]]
std::int64_t query_integer_or_default(
    const HttpRequest& request,
    std::string_view name,
    std::int64_t default_value,
    std::int64_t minimum,
    std::int64_t maximum
);

[[nodiscard]]
bool valid_username_input(
    std::string_view username
);

[[nodiscard]]
bool valid_email_input(
    std::string_view email
);

[[nodiscard]]
bool valid_password_input(
    std::string_view password
) noexcept;

}  // namespace secure
