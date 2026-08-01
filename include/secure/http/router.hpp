#pragma once

#include "secure/http/http_types.hpp"

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <boost/beast/core/string.hpp>
#include <boost/beast/http.hpp>

namespace secure {

using RouteParameters =
    std::unordered_map<std::string, std::string>;

[[nodiscard]]
std::optional<std::string> query_parameter(
    boost::beast::string_view target,
    std::string_view name
);

class Router final {
public:
    using Handler =
        std::function<
            HttpResponse(
                const HttpRequest&,
                const RouteParameters&
            )
        >;

    using SimpleHandler =
        std::function<
            HttpResponse(const HttpRequest&)
        >;

    void add_route(
        boost::beast::http::verb method,
        std::string path,
        Handler handler
    );

    void add_route(
        boost::beast::http::verb method,
        std::string path,
        SimpleHandler handler
    );

    void get(std::string path, Handler handler);
    void get(std::string path, SimpleHandler handler);
    void post(std::string path, Handler handler);
    void post(std::string path, SimpleHandler handler);
    void put(std::string path, Handler handler);
    void put(std::string path, SimpleHandler handler);
    void patch(std::string path, Handler handler);
    void patch(std::string path, SimpleHandler handler);
    void remove(std::string path, Handler handler);
    void remove(std::string path, SimpleHandler handler);

    [[nodiscard]]
    HttpResponse dispatch(
        const HttpRequest& request
    ) const;

private:
    struct RouteSegment final {
        bool parameter{false};
        std::string value;
    };

    using MethodMap =
        std::unordered_map<int, Handler>;

    struct PatternRoute final {
        std::string pattern;
        std::string shape;
        std::vector<RouteSegment> segments;
        std::size_t static_segment_count{0};
        MethodMap methods;
    };

    static int method_key(
        boost::beast::http::verb method
    ) noexcept;

    static std::string path_from_target(
        boost::beast::string_view target
    );

    static bool is_pattern_path(
        std::string_view path
    ) noexcept;

    static std::vector<std::string>
    split_path(std::string_view path);

    static PatternRoute compile_pattern(
        std::string path
    );

    static bool match_pattern(
        const PatternRoute& route,
        std::string_view path,
        RouteParameters& parameters
    );

    static void finalize_response(
        HttpResponse& response,
        const HttpRequest& request
    );

    static HttpResponse make_error_response(
        const HttpRequest& request,
        boost::beast::http::status status,
        std::string_view error_code
    );

    static std::string make_allow_header(
        const MethodMap& methods
    );

    std::unordered_map<std::string, MethodMap>
        exact_routes_;

    std::vector<PatternRoute>
        pattern_routes_;
};

}  // namespace secure
