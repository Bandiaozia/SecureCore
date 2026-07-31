#include "secure/security/token_service.hpp"

#include <array>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

#include <sodium.h>

namespace secure {

namespace {

constexpr std::size_t token_random_bytes =
    32;

std::string encode_hex(
    const unsigned char* data,
    std::size_t size
) {
    std::string result(
        size * 2 + 1,
        '\0'
    );

    sodium_bin2hex(
        result.data(),
        result.size(),
        data,
        size
    );

    result.resize(size * 2);

    return result;
}

}  // namespace

TokenService::TokenService() {
    if (sodium_init() < 0) {
        throw std::runtime_error(
            "Failed to initialize libsodium "
            "for token service"
        );
    }
}

GeneratedToken
TokenService::generate_access_token()
    const {
    return generate_token(
        "sc_at_"
    );
}

GeneratedToken
TokenService::generate_refresh_token()
    const {
    return generate_token(
        "sc_rt_"
    );
}

std::string TokenService::hash_token(
    std::string_view token
) const {
    if (token.empty()) {
        throw std::invalid_argument(
            "Token must not be empty"
        );
    }

    std::array<
        unsigned char,
        crypto_generichash_BYTES
    > hash_bytes{};

    const int result =
        crypto_generichash(
            hash_bytes.data(),
            hash_bytes.size(),
            reinterpret_cast<
                const unsigned char*
            >(token.data()),
            static_cast<
                unsigned long long
            >(token.size()),
            nullptr,
            0
        );

    if (result != 0) {
        throw std::runtime_error(
            "Token hashing failed"
        );
    }

    return encode_hex(
        hash_bytes.data(),
        hash_bytes.size()
    );
}

GeneratedToken
TokenService::generate_token(
    std::string_view prefix
) const {
    std::array<
        unsigned char,
        token_random_bytes
    > random_bytes{};

    randombytes_buf(
        random_bytes.data(),
        random_bytes.size()
    );

    std::string token(prefix);

    token += encode_hex(
        random_bytes.data(),
        random_bytes.size()
    );

    return GeneratedToken{
        token,
        hash_token(token)
    };
}

}  // namespace secure
