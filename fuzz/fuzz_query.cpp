#include "fuzz_common.hpp"

#include "secure/http/router.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

#include <boost/beast/core/string.hpp>

extern "C" int LLVMFuzzerTestOneInput(
    const std::uint8_t* data,
    std::size_t size
) {
    const std::string target =
        secure::fuzz::input_string(data, size);

    const boost::beast::string_view view(
        target.data(),
        target.size()
    );

    static_cast<void>(secure::query_parameter(view, "a"));
    static_cast<void>(secure::query_parameter(view, "limit"));
    static_cast<void>(secure::query_parameter(view, ""));

    if (!target.empty()) {
        const std::size_t name_size =
            target.size() < 32 ? target.size() : 32;

        static_cast<void>(
            secure::query_parameter(
                view,
                std::string_view(target.data(), name_size)
            )
        );
    }

    return 0;
}
