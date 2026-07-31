#include "secure/http/routes.hpp"

#include "secure/http/http_types.hpp"
#include "secure/http/router.hpp"

#include <boost/beast/http.hpp>

namespace secure {

namespace http = boost::beast::http;

void register_routes(
    Router& router
) {
    router.get(
        "/health",
        [](
            const HttpRequest& request
        ) {
            HttpResponse response{
                http::status::ok,
                request.version()
            };

            response.body() =
                R"({"status":"ok"})";

            return response;
        }
    );
}

}  // namespace secure
