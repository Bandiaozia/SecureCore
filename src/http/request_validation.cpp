#include "secure/http/request_validation.hpp"

#include <charconv>
#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <boost/beast/http.hpp>

namespace secure {

namespace http = boost::beast::http;

namespace {

[[noreturn]]
void throw_api_error(
    http::status status,
    std::string code,
    std::string message
) {
    throw ApiException(
        status,
        ApiError{
            std::move(code),
            std::move(message),
            {}
        }
    );
}

std::string trim_copy(
    std::string_view value
) {
    const auto first =
        value.find_first_not_of(
            " \t\r\n"
        );

    if (
        first ==
        std::string_view::npos
    ) {
        return {};
    }

    const auto last =
        value.find_last_not_of(
            " \t\r\n"
        );

    return std::string(
        value.substr(
            first,
            last - first + 1
        )
    );
}

bool is_ascii_letter(
    char character
) {
    return (
        (
            character >= 'a' &&
            character <= 'z'
        ) ||
        (
            character >= 'A' &&
            character <= 'Z'
        )
    );
}

bool is_ascii_digit(
    char character
) {
    return (
        character >= '0' &&
        character <= '9'
    );
}

std::optional<std::int64_t>
parse_integer(
    std::string_view value,
    std::int64_t minimum,
    std::int64_t maximum
) {
    if (value.empty()) {
        return std::nullopt;
    }

    std::int64_t result = 0;

    const char* begin = value.data();
    const char* end = begin + value.size();

    const auto [position, error] =
        std::from_chars(
            begin,
            end,
            result
        );

    if (
        error != std::errc{} ||
        position != end ||
        result < minimum ||
        result > maximum
    ) {
        return std::nullopt;
    }

    return result;
}

std::string range_reason(
    std::size_t minimum_size,
    std::size_t maximum_size
) {
    if (minimum_size == 1) {
        return "must not be empty and must contain no more than " +
            std::to_string(maximum_size) +
            " bytes";
    }

    return "must contain between " +
        std::to_string(minimum_size) +
        " and " +
        std::to_string(maximum_size) +
        " bytes";
}

}  // namespace

Json parse_json_object(
    const HttpRequest& request
) {
    if (!has_json_content_type(request)) {
        throw_api_error(
            http::status::unsupported_media_type,
            "unsupported_media_type",
            default_api_error_message(
                "unsupported_media_type"
            )
        );
    }

    if (request.body().empty()) {
        throw_api_error(
            http::status::bad_request,
            "empty_body",
            default_api_error_message(
                "empty_body"
            )
        );
    }

    Json body;

    try {
        body = Json::parse(
            request.body()
        );
    } catch (const Json::parse_error&) {
        throw_api_error(
            http::status::bad_request,
            "invalid_json",
            default_api_error_message(
                "invalid_json"
            )
        );
    }

    if (!body.is_object()) {
        throw ApiException(
            http::status::unprocessable_entity,
            ApiError{
                "validation_failed",
                default_api_error_message(
                    "validation_failed"
                ),
                {
                    ApiErrorDetail{
                        "$",
                        "must be a JSON object"
                    }
                }
            }
        );
    }

    return body;
}

JsonObjectValidator::JsonObjectValidator(
    const Json& object
)
    : object_(object) {
}

std::optional<std::string>
JsonObjectValidator::required_string(
    std::string_view field,
    std::size_t minimum_size,
    std::size_t maximum_size
) {
    const std::string field_name(field);
    const auto iterator =
        object_.find(field_name);

    if (iterator == object_.end()) {
        add_error(
            field,
            "is required"
        );
        return std::nullopt;
    }

    if (!iterator->is_string()) {
        add_error(
            field,
            "must be a string"
        );
        return std::nullopt;
    }

    std::string value =
        iterator->get<std::string>();

    if (
        value.size() < minimum_size ||
        value.size() > maximum_size
    ) {
        add_error(
            field,
            range_reason(
                minimum_size,
                maximum_size
            )
        );
        return std::nullopt;
    }

    return value;
}

std::optional<bool>
JsonObjectValidator::required_boolean(
    std::string_view field
) {
    const std::string field_name(field);
    const auto iterator =
        object_.find(field_name);

    if (iterator == object_.end()) {
        add_error(
            field,
            "is required"
        );
        return std::nullopt;
    }

    if (!iterator->is_boolean()) {
        add_error(
            field,
            "must be a boolean"
        );
        return std::nullopt;
    }

    return iterator->get<bool>();
}

void JsonObjectValidator::add_error(
    std::string_view field,
    std::string reason
) {
    details_.push_back(
        ApiErrorDetail{
            std::string(field),
            std::move(reason)
        }
    );
}

void JsonObjectValidator::throw_if_invalid()
    const {
    if (details_.empty()) {
        return;
    }

    throw ApiException(
        http::status::unprocessable_entity,
        ApiError{
            "validation_failed",
            default_api_error_message(
                "validation_failed"
            ),
            details_
        }
    );
}

std::int64_t require_path_integer(
    const RouteParameters& parameters,
    std::string_view name,
    std::int64_t minimum,
    std::int64_t maximum
) {
    const auto iterator =
        parameters.find(
            std::string(name)
        );

    if (iterator != parameters.end()) {
        const auto parsed =
            parse_integer(
                iterator->second,
                minimum,
                maximum
            );

        if (parsed.has_value()) {
            return *parsed;
        }
    }

    throw ApiException(
        http::status::unprocessable_entity,
        ApiError{
            "validation_failed",
            default_api_error_message(
                "validation_failed"
            ),
            {
                ApiErrorDetail{
                    std::string(name),
                    "must be an integer between " +
                        std::to_string(minimum) +
                        " and " +
                        std::to_string(maximum)
                }
            }
        }
    );
}

std::int64_t query_integer_or_default(
    const HttpRequest& request,
    std::string_view name,
    std::int64_t default_value,
    std::int64_t minimum,
    std::int64_t maximum
) {
    const auto value =
        query_parameter(
            request.target(),
            name
        );

    if (!value.has_value()) {
        return default_value;
    }

    const auto parsed =
        parse_integer(
            *value,
            minimum,
            maximum
        );

    if (parsed.has_value()) {
        return *parsed;
    }

    throw ApiException(
        http::status::unprocessable_entity,
        ApiError{
            "validation_failed",
            default_api_error_message(
                "validation_failed"
            ),
            {
                ApiErrorDetail{
                    std::string(name),
                    "must be an integer between " +
                        std::to_string(minimum) +
                        " and " +
                        std::to_string(maximum)
                }
            }
        }
    );
}

bool valid_username_input(
    std::string_view username
) {
    const std::string normalized =
        trim_copy(username);

    if (
        normalized.size() < 3 ||
        normalized.size() > 32
    ) {
        return false;
    }

    for (const char character : normalized) {
        if (
            !is_ascii_letter(character) &&
            !is_ascii_digit(character) &&
            character != '_' &&
            character != '-'
        ) {
            return false;
        }
    }

    return true;
}

bool valid_email_input(
    std::string_view email
) {
    const std::string normalized =
        trim_copy(email);

    if (
        normalized.size() < 3 ||
        normalized.size() > 254
    ) {
        return false;
    }

    const auto at_position =
        normalized.find('@');

    if (
        at_position == std::string::npos ||
        at_position == 0 ||
        at_position + 1 >= normalized.size() ||
        normalized.find(
            '@',
            at_position + 1
        ) != std::string::npos ||
        at_position > 64
    ) {
        return false;
    }

    const auto dot_position =
        normalized.find(
            '.',
            at_position + 2
        );

    if (
        dot_position == std::string::npos ||
        dot_position + 1 >= normalized.size()
    ) {
        return false;
    }

    for (const char character : normalized) {
        const auto value =
            static_cast<unsigned char>(
                character
            );

        if (std::isspace(value) != 0) {
            return false;
        }
    }

    return true;
}

bool valid_password_input(
    std::string_view password
) noexcept {
    return (
        password.size() >= 8 &&
        password.size() <= 128
    );
}

}  // namespace secure
