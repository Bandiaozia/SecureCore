#pragma once

#include <boost/beast/http.hpp>

namespace secure {

using HttpRequest =
    boost::beast::http::request<
        boost::beast::http::string_body
    >;

using HttpResponse =
    boost::beast::http::response<
        boost::beast::http::string_body
    >;

}  // namespace secure
