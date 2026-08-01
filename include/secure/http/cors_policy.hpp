#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace secure {

class CorsPolicy final {
public:
    CorsPolicy(
        std::vector<std::string> allowed_origins,
        bool allow_credentials,
        std::uint32_t max_age_seconds
    );

    [[nodiscard]]
    bool allows(
        std::string_view origin
    ) const;

    [[nodiscard]]
    bool wildcard() const noexcept;

    [[nodiscard]]
    bool allow_credentials() const noexcept;

    [[nodiscard]]
    std::uint32_t max_age_seconds()
        const noexcept;

    [[nodiscard]]
    const std::vector<std::string>&
    allowed_origins() const noexcept;

private:
    std::vector<std::string> allowed_origins_;

    bool wildcard_{false};

    bool allow_credentials_{false};

    std::uint32_t max_age_seconds_{600};
};

struct HstsPolicy final {
    bool enabled{true};

    std::uint32_t max_age_seconds{31536000};

    bool include_subdomains{true};

    bool preload{false};
};

}  // namespace secure
