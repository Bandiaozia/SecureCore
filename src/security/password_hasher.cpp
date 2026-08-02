#include "secure/security/password_hasher.hpp"

#include <array>
#include <stdexcept>
#include <string>

#include <sodium.h>

namespace secure {

PasswordHasher::PasswordHasher() {
    if (sodium_init() < 0) {
        throw std::runtime_error(
            "Failed to initialize libsodium"
        );
    }
}

std::string PasswordHasher::hash(
    std::string_view password
) const {
    if (password.empty()) {
        throw std::invalid_argument(
            "Password must not be empty"
        );
    }

    std::array<
        char,
        crypto_pwhash_STRBYTES
    > encoded_hash{};

    const int result =
        crypto_pwhash_str(
            encoded_hash.data(),
            password.data(),
            static_cast<
                unsigned long long
            >(password.size()),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        );

    if (result != 0) {
        throw std::runtime_error(
            "Password hashing failed"
        );
    }

    return std::string(
        encoded_hash.data()
    );
}

bool PasswordHasher::verify(
    std::string_view password,
    std::string_view encoded_hash
) const {
    if (
        password.empty() ||
        encoded_hash.empty()
    ) {
        return false;
    }

    /*
     * crypto_pwhash_str_verify() 要求哈希字符串
     * 以 '\0' 结尾，因此从 string_view 创建副本。
     */
    const std::string hash_text(
        encoded_hash
    );

    return (
        crypto_pwhash_str_verify(
            hash_text.c_str(),
            password.data(),
            static_cast<
                unsigned long long
            >(password.size())
        ) == 0
    );
}

bool PasswordHasher::needs_rehash(
    std::string_view encoded_hash
) const {
    if (encoded_hash.empty()) {
        return false;
    }

    const std::string hash_text(encoded_hash);
    const int result = crypto_pwhash_str_needs_rehash(
        hash_text.c_str(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE
    );

    if (result < 0) {
        throw std::runtime_error(
            "Password hash parameters could not be inspected"
        );
    }

    return result != 0;
}

}  // namespace secure
