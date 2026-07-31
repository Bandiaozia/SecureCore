#pragma once

#include "secure/http/http_types.hpp"

#include <functional>
#include <string>
#include <unordered_map>

#include <boost/beast/core/string.hpp>
#include <boost/beast/http.hpp>

namespace secure {

class Router final {
public:
    using Handler =
        std::function<
            HttpResponse(const HttpRequest&)
        >;

    void add_route(
        boost::beast::http::verb method,
        std::string path,
        Handler handler
    );

    void get(
        std::string path,
        Handler handler
    );

    void post(
        std::string path,
        Handler handler
    );

    [[nodiscard]]
    HttpResponse dispatch(
        const HttpRequest& request
    ) const;

private:
    using MethodMap =
        std::unordered_map<int, Handler>;

    static int method_key(
        boost::beast::http::verb method
    ) noexcept;

    static std::string path_from_target(
        boost::beast::string_view target
    );

    static void finalize_response(
        HttpResponse& response,
        const HttpRequest& request
    );

    static HttpResponse make_error_response(
        const HttpRequest& request,
        boost::beast::http::status status,
        std::string body
    );

    static std::string make_allow_header(
        const MethodMap& methods
    );

    std::unordered_map<
        std::string,
        MethodMap
    > routes_;
};

}  // namespace secure
