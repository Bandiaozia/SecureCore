#include "fuzz_common.hpp"

#include "secure/http/http_types.hpp"
#include "secure/http/router.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

#include <boost/beast/core/string.hpp>
#include <boost/beast/http.hpp>

namespace {

secure::HttpResponse ok_response(
    const secure::HttpRequest&
) {
    secure::HttpResponse response;
    response.result(boost::beast::http::status::ok);
    response.body() = "{}";
    return response;
}

const secure::Router& test_router() {
    static const secure::Router router = [] {
        secure::Router value;
        value.get("/health", ok_response);
        value.get("/users/{id}", ok_response);
        value.post(
            "/users/{id}/sessions/{session}",
            ok_response
        );
        return value;
    }();

    return router;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(
    const std::uint8_t* data,
    std::size_t size
) {
    std::string target =
        secure::fuzz::input_string(data, size);

    if (target.empty() || target.front() != '/') {
        target.insert(target.begin(), '/');
    }

    try {
        secure::HttpRequest request;
        request.version(11);
        request.method(
            size == 0
                ? boost::beast::http::verb::get
                : static_cast<boost::beast::http::verb>(
                      data[0] % 10U + 1U
                  )
        );
        request.target(
            boost::beast::string_view(
                target.data(),
                target.size()
            )
        );

        static_cast<void>(test_router().dispatch(request));
    } catch (const std::exception&) {
    }

    return 0;
}
