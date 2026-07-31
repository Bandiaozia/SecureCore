#include "secure/http/router.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

#include <boost/beast/http.hpp>

namespace {

namespace http = boost::beast::http;

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "router test failed: " << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

secure::HttpRequest make_request(
    http::verb method,
    std::string target
) {
    secure::HttpRequest request{method, std::move(target), 11};
    request.keep_alive(true);
    return request;
}

secure::HttpResponse text_response(
    http::status status,
    std::string body
) {
    secure::HttpResponse response{status, 11};
    response.body() = std::move(body);
    return response;
}

}  // namespace

int main() {
    secure::Router router;

    router.get(
        "/exact",
        [](const secure::HttpRequest&) {
            return text_response(http::status::ok, "exact");
        }
    );

    router.get(
        "/users/{id}",
        [](
            const secure::HttpRequest&,
            const secure::RouteParameters& parameters
        ) {
            return text_response(
                http::status::ok,
                parameters.at("id")
            );
        }
    );

    router.patch(
        "/users/{id}",
        [](
            const secure::HttpRequest&,
            const secure::RouteParameters& parameters
        ) {
            return text_response(
                http::status::ok,
                "patched:" + parameters.at("id")
            );
        }
    );

    const auto exact = router.dispatch(
        make_request(http::verb::get, "/exact?ignored=yes")
    );
    require(exact.result() == http::status::ok, "exact status");
    require(exact.body() == "exact", "exact body");

    const auto dynamic = router.dispatch(
        make_request(http::verb::get, "/users/42")
    );
    require(dynamic.result() == http::status::ok, "dynamic status");
    require(dynamic.body() == "42", "dynamic parameter");

    const auto patched = router.dispatch(
        make_request(http::verb::patch, "/users/42")
    );
    require(patched.result() == http::status::ok, "patch status");
    require(patched.body() == "patched:42", "patch body");

    const auto wrong_method = router.dispatch(
        make_request(http::verb::post, "/users/42")
    );
    require(
        wrong_method.result() == http::status::method_not_allowed,
        "method not allowed status"
    );
    require(
        wrong_method[http::field::allow] == "GET, PATCH",
        "allow header"
    );

    const auto missing = router.dispatch(
        make_request(http::verb::get, "/missing")
    );
    require(missing.result() == http::status::not_found, "not found");

    const auto limit = secure::query_parameter(
        "/users?limit=20&name=Alice+Smith",
        "limit"
    );
    require(limit.has_value() && *limit == "20", "query limit");

    const auto name = secure::query_parameter(
        "/users?limit=20&name=Alice+Smith",
        "name"
    );
    require(name.has_value() && *name == "Alice Smith", "query decode");

    std::cout << "router tests passed\n";
    return EXIT_SUCCESS;
}
