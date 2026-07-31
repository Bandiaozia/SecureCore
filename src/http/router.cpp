#include "secure/http/router.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <unordered_set>
#include <utility>
#include <vector>

namespace secure {

namespace http = boost::beast::http;

namespace {

bool is_hex_digit(char value) {
    return (
        (value >= '0' && value <= '9') ||
        (value >= 'a' && value <= 'f') ||
        (value >= 'A' && value <= 'F')
    );
}

unsigned char hex_value(char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<unsigned char>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<unsigned char>(value - 'a' + 10);
    }
    return static_cast<unsigned char>(value - 'A' + 10);
}

std::optional<std::string> decode_component(
    std::string_view value,
    bool plus_as_space
) {
    std::string result;
    result.reserve(value.size());

    for (std::size_t index = 0; index < value.size(); ++index) {
        const char character = value[index];

        if (character == '%' ) {
            if (
                index + 2 >= value.size() ||
                !is_hex_digit(value[index + 1]) ||
                !is_hex_digit(value[index + 2])
            ) {
                return std::nullopt;
            }

            const auto decoded = static_cast<char>(
                (hex_value(value[index + 1]) << 4U) |
                hex_value(value[index + 2])
            );

            result.push_back(decoded);
            index += 2;
            continue;
        }

        if (plus_as_space && character == '+') {
            result.push_back(' ');
        } else {
            result.push_back(character);
        }
    }

    return result;
}

bool is_valid_parameter_name(std::string_view name) {
    if (name.empty()) {
        return false;
    }

    const auto first = static_cast<unsigned char>(name.front());
    if (
        std::isalpha(first) == 0 &&
        name.front() != '_'
    ) {
        return false;
    }

    for (const char character : name.substr(1)) {
        const auto value = static_cast<unsigned char>(character);
        if (
            std::isalnum(value) == 0 &&
            character != '_'
        ) {
            return false;
        }
    }

    return true;
}

}  // namespace

std::optional<std::string> query_parameter(
    boost::beast::string_view target,
    std::string_view name
) {
    const auto query_position = target.find('?');

    if (
        query_position == boost::beast::string_view::npos ||
        query_position + 1 >= target.size()
    ) {
        return std::nullopt;
    }

    const auto query = target.substr(query_position + 1);
    std::size_t start = 0;

    while (start <= query.size()) {
        const auto separator = query.find('&', start);
        const auto end = separator == boost::beast::string_view::npos
            ? query.size()
            : separator;
        const auto pair = query.substr(start, end - start);
        const auto equals = pair.find('=');
        const auto raw_key = pair.substr(0, equals);
        const auto raw_value = equals == boost::beast::string_view::npos
            ? boost::beast::string_view{}
            : pair.substr(equals + 1);

        const auto decoded_key = decode_component(
            std::string_view(raw_key.data(), raw_key.size()),
            true
        );

        if (decoded_key.has_value() && *decoded_key == name) {
            return decode_component(
                std::string_view(raw_value.data(), raw_value.size()),
                true
            );
        }

        if (separator == boost::beast::string_view::npos) {
            break;
        }

        start = separator + 1;
    }

    return std::nullopt;
}

void Router::add_route(
    http::verb method,
    std::string path,
    Handler handler
) {
    if (
        path.empty() ||
        path.front() != '/' ||
        path.find('?') != std::string::npos
    ) {
        throw std::invalid_argument(
            "Route path must be an absolute path without a query: " +
            path
        );
    }

    if (!handler) {
        throw std::invalid_argument(
            "Route handler must not be empty: " + path
        );
    }

    if (!is_pattern_path(path)) {
        auto& methods = exact_routes_[path];
        const auto [iterator, inserted] = methods.emplace(
            method_key(method),
            std::move(handler)
        );
        static_cast<void>(iterator);
        if (!inserted) {
            throw std::logic_error("Duplicate route: " + path);
        }
        return;
    }

    PatternRoute compiled = compile_pattern(std::move(path));

    auto iterator = std::find_if(
        pattern_routes_.begin(),
        pattern_routes_.end(),
        [&compiled](const PatternRoute& route) {
            return route.shape == compiled.shape;
        }
    );

    if (
        iterator != pattern_routes_.end() &&
        iterator->pattern != compiled.pattern
    ) {
        throw std::logic_error(
            "Conflicting route parameter names: " +
            iterator->pattern +
            " and " +
            compiled.pattern
        );
    }

    if (iterator == pattern_routes_.end()) {
        pattern_routes_.push_back(std::move(compiled));
        iterator = std::prev(pattern_routes_.end());
    }

    const auto [method_iterator, inserted] = iterator->methods.emplace(
        method_key(method),
        std::move(handler)
    );
    static_cast<void>(method_iterator);

    if (!inserted) {
        throw std::logic_error(
            "Duplicate route pattern: " + iterator->pattern
        );
    }

    std::stable_sort(
        pattern_routes_.begin(),
        pattern_routes_.end(),
        [](const PatternRoute& left, const PatternRoute& right) {
            return left.static_segment_count > right.static_segment_count;
        }
    );
}

void Router::add_route(
    http::verb method,
    std::string path,
    SimpleHandler handler
) {
    if (!handler) {
        throw std::invalid_argument(
            "Route handler must not be empty: " + path
        );
    }

    Handler adapted = [handler = std::move(handler)](
        const HttpRequest& request,
        const RouteParameters&
    ) {
        return handler(request);
    };

    add_route(method, std::move(path), std::move(adapted));
}

#define SECURECORE_DEFINE_ROUTE_METHOD(name, verb_value) \
void Router::name(std::string path, Handler handler) { \
    add_route(http::verb::verb_value, std::move(path), std::move(handler)); \
} \
void Router::name(std::string path, SimpleHandler handler) { \
    add_route(http::verb::verb_value, std::move(path), std::move(handler)); \
}

SECURECORE_DEFINE_ROUTE_METHOD(get, get)
SECURECORE_DEFINE_ROUTE_METHOD(post, post)
SECURECORE_DEFINE_ROUTE_METHOD(put, put)
SECURECORE_DEFINE_ROUTE_METHOD(patch, patch)
SECURECORE_DEFINE_ROUTE_METHOD(remove, delete_)

#undef SECURECORE_DEFINE_ROUTE_METHOD

HttpResponse Router::dispatch(const HttpRequest& request) const {
    const std::string path = path_from_target(request.target());

    if (path.empty() || path.front() != '/') {
        return make_error_response(
            request,
            http::status::bad_request,
            R"({"error":"bad_request"})"
        );
    }

    const auto exact = exact_routes_.find(path);
    if (exact != exact_routes_.end()) {
        const auto method = exact->second.find(method_key(request.method()));
        if (method == exact->second.end()) {
            HttpResponse response = make_error_response(
                request,
                http::status::method_not_allowed,
                R"({"error":"method_not_allowed"})"
            );
            response.set(http::field::allow, make_allow_header(exact->second));
            return response;
        }

        HttpResponse response = method->second(request, {});
        finalize_response(response, request);
        return response;
    }

    for (const PatternRoute& route : pattern_routes_) {
        RouteParameters parameters;
        if (!match_pattern(route, path, parameters)) {
            continue;
        }

        const auto method = route.methods.find(method_key(request.method()));
        if (method == route.methods.end()) {
            HttpResponse response = make_error_response(
                request,
                http::status::method_not_allowed,
                R"({"error":"method_not_allowed"})"
            );
            response.set(http::field::allow, make_allow_header(route.methods));
            return response;
        }

        HttpResponse response = method->second(request, parameters);
        finalize_response(response, request);
        return response;
    }

    return make_error_response(
        request,
        http::status::not_found,
        R"({"error":"not_found"})"
    );
}

int Router::method_key(http::verb method) noexcept {
    return static_cast<int>(method);
}

std::string Router::path_from_target(boost::beast::string_view target) {
    const auto query_position = target.find('?');
    const auto path_view = target.substr(0, query_position);
    return std::string(path_view.data(), path_view.size());
}

bool Router::is_pattern_path(std::string_view path) noexcept {
    return (
        path.find('{') != std::string_view::npos ||
        path.find('}') != std::string_view::npos
    );
}

std::vector<std::string> Router::split_path(std::string_view path) {
    std::vector<std::string> segments;

    if (path == "/") {
        return segments;
    }

    std::size_t start = 1;
    while (start <= path.size()) {
        const auto separator = path.find('/', start);
        if (separator == std::string_view::npos) {
            segments.emplace_back(path.substr(start));
            break;
        }

        segments.emplace_back(path.substr(start, separator - start));
        start = separator + 1;

        if (start == path.size()) {
            segments.emplace_back();
            break;
        }
    }

    return segments;
}

Router::PatternRoute Router::compile_pattern(std::string path) {
    PatternRoute route;
    route.pattern = std::move(path);

    const auto raw_segments = split_path(route.pattern);
    std::unordered_set<std::string> names;
    std::string shape;

    for (const std::string& segment : raw_segments) {
        RouteSegment compiled_segment;

        const bool begins_parameter = !segment.empty() && segment.front() == '{';
        const bool ends_parameter = !segment.empty() && segment.back() == '}';

        if (begins_parameter || ends_parameter) {
            if (
                !begins_parameter ||
                !ends_parameter ||
                segment.size() < 3 ||
                segment.find('{', 1) != std::string::npos ||
                segment.find('}') != segment.size() - 1
            ) {
                throw std::invalid_argument(
                    "Invalid route parameter segment in: " + route.pattern
                );
            }

            const std::string name = segment.substr(1, segment.size() - 2);
            if (!is_valid_parameter_name(name)) {
                throw std::invalid_argument(
                    "Invalid route parameter name in: " + route.pattern
                );
            }

            if (!names.insert(name).second) {
                throw std::invalid_argument(
                    "Duplicate route parameter name in: " + route.pattern
                );
            }

            compiled_segment.parameter = true;
            compiled_segment.value = name;
            shape += "/{}";
        } else {
            if (
                segment.find('{') != std::string::npos ||
                segment.find('}') != std::string::npos
            ) {
                throw std::invalid_argument(
                    "Invalid route pattern: " + route.pattern
                );
            }

            compiled_segment.value = segment;
            ++route.static_segment_count;
            shape += '/' + segment;
        }

        route.segments.push_back(std::move(compiled_segment));
    }

    route.shape = shape.empty() ? "/" : std::move(shape);
    return route;
}

bool Router::match_pattern(
    const PatternRoute& route,
    std::string_view path,
    RouteParameters& parameters
) {
    const auto path_segments = split_path(path);
    if (path_segments.size() != route.segments.size()) {
        return false;
    }

    for (std::size_t index = 0; index < route.segments.size(); ++index) {
        const RouteSegment& expected = route.segments[index];
        const std::string& actual = path_segments[index];

        if (!expected.parameter) {
            if (expected.value != actual) {
                return false;
            }
            continue;
        }

        if (actual.empty()) {
            return false;
        }

        const auto decoded = decode_component(actual, false);
        if (!decoded.has_value()) {
            return false;
        }

        parameters.emplace(expected.value, *decoded);
    }

    return true;
}

void Router::finalize_response(
    HttpResponse& response,
    const HttpRequest& request
) {
    response.version(request.version());

    if (response.find(http::field::server) == response.end()) {
        response.set(http::field::server, "SecureCore");
    }

    if (
        response.result() != http::status::no_content &&
        response.find(http::field::content_type) == response.end()
    ) {
        response.set(http::field::content_type, "application/json");
    }

    response.keep_alive(request.keep_alive());
    response.prepare_payload();
}

HttpResponse Router::make_error_response(
    const HttpRequest& request,
    http::status status,
    std::string body
) {
    HttpResponse response{status, request.version()};
    response.body() = std::move(body);
    finalize_response(response, request);
    return response;
}

std::string Router::make_allow_header(const MethodMap& methods) {
    std::vector<std::string> method_names;
    method_names.reserve(methods.size());

    for (const auto& [key, handler] : methods) {
        static_cast<void>(handler);
        const auto name = http::to_string(static_cast<http::verb>(key));
        method_names.emplace_back(name.data(), name.size());
    }

    std::sort(method_names.begin(), method_names.end());

    std::string result;
    for (std::size_t index = 0; index < method_names.size(); ++index) {
        if (index != 0) {
            result += ", ";
        }
        result += method_names[index];
    }

    return result;
}

}  // namespace secure
