#pragma once

#include "secure/model/user.hpp"

#include <stdexcept>
#include <string>
#include <string_view>

namespace secure {

class PasswordHasher;
class UserRepository;

enum class RegistrationErrorCode {
    invalid_username,
    invalid_email,
    weak_password,
    duplicate_user
};

[[nodiscard]]
std::string_view registration_error_name(
    RegistrationErrorCode code
) noexcept;

class RegistrationError final
    : public std::runtime_error {
public:
    RegistrationError(
        RegistrationErrorCode code,
        std::string message
    );

    [[nodiscard]]
    RegistrationErrorCode code()
        const noexcept;

private:
    RegistrationErrorCode code_;
};

class UserService final {
public:
    UserService(
        UserRepository& user_repository,
        PasswordHasher& password_hasher
    );

    [[nodiscard]]
    User register_user(
        std::string username,
        std::string email,
        std::string password
    );

private:
    UserRepository& user_repository_;

    PasswordHasher& password_hasher_;
};

}  // namespace secure
