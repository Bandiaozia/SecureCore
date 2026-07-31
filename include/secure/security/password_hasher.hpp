#pragma once

#include <string>
#include <string_view>

namespace secure {

class PasswordHasher final {
public:
    PasswordHasher();

    [[nodiscard]]
    std::string hash(
        std::string_view password
    ) const;

    [[nodiscard]]
    bool verify(
        std::string_view password,
        std::string_view encoded_hash
    ) const;
};

}  // namespace secure
