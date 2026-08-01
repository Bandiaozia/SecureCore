#include "secure/http/cors_policy.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace secure {

namespace {

bool contains_space_or_control(
    std::string_view value
) {
    return std::any_of(
        value.begin(),
        value.end(),
        [](char character) {
            const auto byte =
                static_cast<unsigned char>(character);

            return std::isspace(byte) != 0 ||
                   byte < 0x20 ||
                   byte == 0x7f;
        }
    );
}

bool valid_exact_origin(
    std::string_view origin
) {
    if (
        origin.empty() ||
        contains_space_or_control(origin)
    ) {
        return false;
    }

    const std::string_view http_prefix = "http://";
    const std::string_view https_prefix = "https://";

    std::size_t authority_start = 0;

    if (origin.starts_with(http_prefix)) {
        authority_start = http_prefix.size();
    } else if (origin.starts_with(https_prefix)) {
        authority_start = https_prefix.size();
    } else {
        return false;
    }

    if (authority_start >= origin.size()) {
        return false;
    }

    const std::string_view authority = origin.substr(authority_start);

    if (
        authority.find('/') != std::string_view::npos ||
        authority.find('?') != std::string_view::npos ||
        authority.find('#') != std::string_view::npos ||
        authority.find('@') != std::string_view::npos
    ) {
        return false;
    }

    return !authority.empty();
}

}  // namespace

CorsPolicy::CorsPolicy(
    std::vector<std::string> allowed_origins,
    bool allow_credentials,
    std::uint32_t max_age_seconds
)
    : allowed_origins_(
          std::move(allowed_origins)
      ),
      allow_credentials_(allow_credentials),
      max_age_seconds_(max_age_seconds) {
    if (allowed_origins_.empty()) {
        throw std::invalid_argument(
            "CORS allowed origin list must not be empty"
        );
    }

    for (const std::string& origin : allowed_origins_) {
        if (origin == "*") {
            wildcard_ = true;
            continue;
        }

        if (!valid_exact_origin(origin)) {
            throw std::invalid_argument(
                "Invalid CORS origin: " + origin
            );
        }
    }

    if (wildcard_ && allowed_origins_.size() != 1) {
        throw std::invalid_argument(
            "CORS wildcard cannot be combined with exact origins"
        );
    }

    if (wildcard_ && allow_credentials_) {
        throw std::invalid_argument(
            "CORS credentials cannot be enabled with wildcard origin"
        );
    }

    std::sort(
        allowed_origins_.begin(),
        allowed_origins_.end()
    );

    const auto duplicate = std::adjacent_find(
        allowed_origins_.begin(),
        allowed_origins_.end()
    );

    if (duplicate != allowed_origins_.end()) {
        throw std::invalid_argument(
            "CORS allowed origins must not contain duplicates"
        );
    }
}

bool CorsPolicy::allows(
    std::string_view origin
) const {
    if (wildcard_) {
        return true;
    }

    return std::binary_search(
        allowed_origins_.begin(),
        allowed_origins_.end(),
        std::string(origin)
    );
}

bool CorsPolicy::wildcard() const noexcept {
    return wildcard_;
}

bool CorsPolicy::allow_credentials()
    const noexcept {
    return allow_credentials_;
}

std::uint32_t CorsPolicy::max_age_seconds()
    const noexcept {
    return max_age_seconds_;
}

const std::vector<std::string>&
CorsPolicy::allowed_origins() const noexcept {
    return allowed_origins_;
}

}  // namespace secure
