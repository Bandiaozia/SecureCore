#include "secure/service/user_service.hpp"

#include "secure/repository/user_repository.hpp"
#include "secure/security/password_hasher.hpp"

#include <cctype>
#include <string>
#include <string_view>
#include <utility>

namespace secure {

namespace {

std::string trim_copy(
    std::string_view value
) {
    const auto first =
        value.find_first_not_of(
            " \t\r\n"
        );

    if (
        first ==
        std::string_view::npos
    ) {
        return {};
    }

    const auto last =
        value.find_last_not_of(
            " \t\r\n"
        );

    return std::string(
        value.substr(
            first,
            last - first + 1
        )
    );
}

bool is_ascii_letter(
    char character
) {
    return (
        (
            character >= 'a' &&
            character <= 'z'
        ) ||
        (
            character >= 'A' &&
            character <= 'Z'
        )
    );
}

bool is_ascii_digit(
    char character
) {
    return (
        character >= '0' &&
        character <= '9'
    );
}

bool is_valid_username(
    std::string_view username
) {
    if (
        username.size() < 3 ||
        username.size() > 32
    ) {
        return false;
    }

    for (
        const char character :
        username
    ) {
        if (
            !is_ascii_letter(character) &&
            !is_ascii_digit(character) &&
            character != '_' &&
            character != '-'
        ) {
            return false;
        }
    }

    return true;
}

bool is_valid_email(
    std::string_view email
) {
    if (
        email.size() < 3 ||
        email.size() > 254
    ) {
        return false;
    }

    const auto at_position =
        email.find('@');

    if (
        at_position ==
            std::string_view::npos ||
        at_position == 0 ||
        at_position + 1 >= email.size() ||
        email.find(
            '@',
            at_position + 1
        ) != std::string_view::npos
    ) {
        return false;
    }

    if (at_position > 64) {
        return false;
    }

    const auto dot_position =
        email.find(
            '.',
            at_position + 2
        );

    if (
        dot_position ==
            std::string_view::npos ||
        dot_position + 1 >= email.size()
    ) {
        return false;
    }

    for (
        const char character :
        email
    ) {
        const auto value =
            static_cast<unsigned char>(
                character
            );

        if (
            std::isspace(value) != 0
        ) {
            return false;
        }
    }

    return true;
}

std::string lowercase_ascii(
    std::string value
) {
    for (char& character : value) {
        const auto unsigned_character =
            static_cast<unsigned char>(
                character
            );

        character =
            static_cast<char>(
                std::tolower(
                    unsigned_character
                )
            );
    }

    return value;
}

bool is_valid_password(
    std::string_view password
) {
    /*
     * 当前第一版只限制长度。
     *
     * 不强制用户必须同时使用大写、小写、
     * 数字和特殊字符。
     */
    return (
        password.size() >= 8 &&
        password.size() <= 128
    );
}

}  // namespace

std::string_view registration_error_name(
    RegistrationErrorCode code
) noexcept {
    switch (code) {
    case RegistrationErrorCode::
        invalid_username:
        return "invalid_username";

    case RegistrationErrorCode::
        invalid_email:
        return "invalid_email";

    case RegistrationErrorCode::
        weak_password:
        return "weak_password";

    case RegistrationErrorCode::
        duplicate_user:
        return "duplicate_user";
    }

    return "registration_failed";
}

RegistrationError::RegistrationError(
    RegistrationErrorCode code,
    std::string message
)
    : std::runtime_error(
          std::move(message)
      ),
      code_(code) {
}

RegistrationErrorCode
RegistrationError::code()
    const noexcept {
    return code_;
}

UserService::UserService(
    UserRepository& user_repository,
    PasswordHasher& password_hasher
)
    : user_repository_(
          user_repository
      ),
      password_hasher_(
          password_hasher
      ) {
}

User UserService::register_user(
    std::string username,
    std::string email,
    std::string password
) {
    username = trim_copy(username);

    email = lowercase_ascii(
        trim_copy(email)
    );

    if (!is_valid_username(username)) {
        throw RegistrationError(
            RegistrationErrorCode::
                invalid_username,
            "Username must contain 3 to 32 "
            "ASCII letters, digits, '_' or '-'"
        );
    }

    if (!is_valid_email(email)) {
        throw RegistrationError(
            RegistrationErrorCode::
                invalid_email,
            "Email address is invalid"
        );
    }

    if (!is_valid_password(password)) {
        throw RegistrationError(
            RegistrationErrorCode::
                weak_password,
            "Password must contain between "
            "8 and 128 bytes"
        );
    }

    const std::string password_hash =
        password_hasher_.hash(
            password
        );

    try {
        return user_repository_.create(
            CreateUser{
                std::move(username),
                std::move(email),
                password_hash,
                "user"
            }
        );
    } catch (
        const DuplicateUserError&
    ) {
        throw RegistrationError(
            RegistrationErrorCode::
                duplicate_user,
            "Username or email already exists"
        );
    }
}

}  // namespace secure
