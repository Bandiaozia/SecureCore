#include "secure/http/router.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>
#include <vector>

namespace secure {

namespace http = boost::beast::http;

void Router::add_route(
    http::verb method,
    std::string path,
    Handler handler
) {
    if (
        path.empty() ||
        path.front() != '/'
    ) {
        throw std::invalid_argument(
            "Route path must begin with '/': " +
            path
        );
    }

    if (!handler) {
        throw std::invalid_argument(
            "Route handler must not be empty: " +
            path
        );
    }

    auto& methods = routes_[path];

    const auto [iterator, inserted] =
        methods.emplace(
            method_key(method),
            std::move(handler)
        );

    static_cast<void>(iterator);

    if (!inserted) {
        const auto method_name =
            http::to_string(method);

        throw std::logic_error(
            "Duplicate route: " +
            std::string(
                method_name.data(),
                method_name.size()
            ) +
            " " +
            path
        );
    }
}

void Router::get(
    std::string path,
    Handler handler
) {
    add_route(
        http::verb::get,
        std::move(path),
        std::move(handler)
    );
}

void Router::post(
    std::string path,
    Handler handler
) {
    add_route(
        http::verb::post,
        std::move(path),
        std::move(handler)
    );
}

HttpResponse Router::dispatch(
    const HttpRequest& request
) const {
    const std::string path =
        path_from_target(request.target());

    if (
        path.empty() ||
        path.front() != '/'
    ) {
        return make_error_response(
            request,
            http::status::bad_request,
            R"({"error":"bad_request"})"
        );
    }

    const auto path_iterator =
        routes_.find(path);

    if (path_iterator == routes_.end()) {
        return make_error_response(
            request,
            http::status::not_found,
            R"({"error":"not_found"})"
        );
    }

    const auto method_iterator =
        path_iterator->second.find(
            method_key(request.method())
        );

    if (
        method_iterator ==
        path_iterator->second.end()
    ) {
        HttpResponse response =
            make_error_response(
                request,
                http::status::method_not_allowed,
                R"({"error":"method_not_allowed"})"
            );

        response.set(
            http::field::allow,
            make_allow_header(
                path_iterator->second
            )
        );

        return response;
    }

    HttpResponse response =
        method_iterator->second(request);

    finalize_response(
        response,
        request
    );

    return response;
}

int Router::method_key(
    http::verb method
) noexcept {
    return static_cast<int>(method);
}

std::string Router::path_from_target(
    boost::beast::string_view target
) {
    const auto query_position =
        target.find('?');

    const auto path_view =
        target.substr(
            0,
            query_position
        );

    return std::string(
        path_view.data(),
        path_view.size()
    );
}

void Router::finalize_response(
    HttpResponse& response,
    const HttpRequest& request
) {
    response.version(request.version());

    if (
        response.find(http::field::server) ==
        response.end()
    ) {
        response.set(
            http::field::server,
            "SecureCore"
        );
    }

    if (
        response.find(http::field::content_type) ==
        response.end()
    ) {
        response.set(
            http::field::content_type,
            "application/json"
        );
    }

    response.keep_alive(
        request.keep_alive()
    );

    response.prepare_payload();
}

HttpResponse Router::make_error_response(
    const HttpRequest& request,
    http::status status,
    std::string body
) {
    HttpResponse response{
        status,
        request.version()
    };

    response.body() = std::move(body);

    finalize_response(
        response,
        request
    );

    return response;
}

std::string Router::make_allow_header(
    const MethodMap& methods
) {
    std::vector<std::string>
        method_names;

    method_names.reserve(
        methods.size()
    );

    for (const auto& [key, handler] : methods) {
        static_cast<void>(handler);

        const auto name =
            http::to_string(
                static_cast<http::verb>(key)
            );

        method_names.emplace_back(
            name.data(),
            name.size()
        );
    }

    std::sort(
        method_names.begin(),
        method_names.end()
    );

    std::string result;

    for (
        std::size_t index = 0;
        index < method_names.size();
        ++index
    ) {
        if (index != 0) {
            result += ", ";
        }

        result += method_names[index];
    }

    return result;
}

}  // namespace secure
