#include "secure/config/server_config.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

namespace secure {

namespace {

struct EnvironmentMapping final {
    std::string_view variable;
    std::string_view key;
};

constexpr std::array environment_mappings{
    EnvironmentMapping{
        "SECURECORE_ENVIRONMENT",
        "environment"
    },
    EnvironmentMapping{
        "SECURECORE_LISTEN_ADDRESS",
        "listen_address"
    },
    EnvironmentMapping{
        "SECURECORE_LISTEN_PORT",
        "listen_port"
    },
    EnvironmentMapping{
        "SECURECORE_LOG_FILE",
        "log_file"
    },
    EnvironmentMapping{
        "SECURECORE_DATABASE_PATH",
        "database_path"
    },
    EnvironmentMapping{
        "SECURECORE_DATABASE_POOL_SIZE",
        "database_pool_size"
    },
    EnvironmentMapping{
        "SECURECORE_DATABASE_ACQUIRE_TIMEOUT_MS",
        "database_acquire_timeout_ms"
    },
    EnvironmentMapping{
        "SECURECORE_IO_THREADS",
        "io_threads"
    },
    EnvironmentMapping{
        "SECURECORE_WORKER_THREADS",
        "worker_threads"
    },
    EnvironmentMapping{
        "SECURECORE_WORKER_QUEUE_CAPACITY",
        "worker_queue_capacity"
    },
    EnvironmentMapping{
        "SECURECORE_SHUTDOWN_GRACE_PERIOD_MS",
        "shutdown_grace_period_ms"
    },
    EnvironmentMapping{
        "SECURECORE_AUDIT_RETENTION_DAYS",
        "audit_retention_days"
    },
    EnvironmentMapping{
        "SECURECORE_METRICS_REQUIRE_AUTH",
        "metrics_require_auth"
    },
    EnvironmentMapping{
        "SECURECORE_AUTH_LOGIN_ACCOUNT_FAILURE_LIMIT",
        "auth_login_account_failure_limit"
    },
    EnvironmentMapping{
        "SECURECORE_AUTH_LOGIN_IP_FAILURE_LIMIT",
        "auth_login_ip_failure_limit"
    },
    EnvironmentMapping{
        "SECURECORE_AUTH_LOGIN_FAILURE_WINDOW_SECONDS",
        "auth_login_failure_window_seconds"
    },
    EnvironmentMapping{
        "SECURECORE_AUTH_LOGIN_LOCKOUT_SECONDS",
        "auth_login_lockout_seconds"
    },
    EnvironmentMapping{
        "SECURECORE_AUTH_LOGIN_MAX_LOCKOUT_SECONDS",
        "auth_login_max_lockout_seconds"
    },
    EnvironmentMapping{
        "SECURECORE_TLS_ENABLED",
        "tls_enabled"
    },
    EnvironmentMapping{
        "SECURECORE_TLS_CERTIFICATE_FILE",
        "tls_certificate_file"
    },
    EnvironmentMapping{
        "SECURECORE_TLS_PRIVATE_KEY_FILE",
        "tls_private_key_file"
    },
    EnvironmentMapping{
        "SECURECORE_TLS_HANDSHAKE_TIMEOUT_SECONDS",
        "tls_handshake_timeout_seconds"
    },
    EnvironmentMapping{
        "SECURECORE_TRUSTED_PROXY_CIDRS",
        "trusted_proxy_cidrs"
    },
    EnvironmentMapping{
        "SECURECORE_PROXY_FORWARDED_HEADER_MAX_BYTES",
        "proxy_forwarded_header_max_bytes"
    },
    EnvironmentMapping{
        "SECURECORE_CORS_ALLOWED_ORIGINS",
        "cors_allowed_origins"
    },
    EnvironmentMapping{
        "SECURECORE_CORS_ALLOW_CREDENTIALS",
        "cors_allow_credentials"
    },
    EnvironmentMapping{
        "SECURECORE_CORS_MAX_AGE_SECONDS",
        "cors_max_age_seconds"
    },
    EnvironmentMapping{
        "SECURECORE_HSTS_ENABLED",
        "hsts_enabled"
    },
    EnvironmentMapping{
        "SECURECORE_HSTS_MAX_AGE_SECONDS",
        "hsts_max_age_seconds"
    },
    EnvironmentMapping{
        "SECURECORE_HSTS_INCLUDE_SUBDOMAINS",
        "hsts_include_subdomains"
    },
    EnvironmentMapping{
        "SECURECORE_HSTS_PRELOAD",
        "hsts_preload"
    },
    EnvironmentMapping{
        "SECURECORE_HTTP_MAX_CONNECTIONS",
        "http_max_connections"
    },
    EnvironmentMapping{
        "SECURECORE_HTTP_RATE_LIMIT_REQUESTS",
        "http_rate_limit_requests"
    },
    EnvironmentMapping{
        "SECURECORE_HTTP_RATE_LIMIT_WINDOW_SECONDS",
        "http_rate_limit_window_seconds"
    },
    EnvironmentMapping{
        "SECURECORE_HTTP_MAX_HEADER_BYTES",
        "http_max_header_bytes"
    },
    EnvironmentMapping{
        "SECURECORE_HTTP_MAX_BODY_BYTES",
        "http_max_body_bytes"
    },
    EnvironmentMapping{
        "SECURECORE_HTTP_READ_TIMEOUT_SECONDS",
        "http_read_timeout_seconds"
    },
    EnvironmentMapping{
        "SECURECORE_HTTP_WRITE_TIMEOUT_SECONDS",
        "http_write_timeout_seconds"
    },
    EnvironmentMapping{
        "SECURECORE_HTTP_IDLE_TIMEOUT_SECONDS",
        "http_idle_timeout_seconds"
    }
};

std::string trim(
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

std::string lowercase(
    std::string value
) {
    for (char& character : value) {
        character = static_cast<char>(
            std::tolower(
                static_cast<unsigned char>(
                    character
                )
            )
        );
    }

    return value;
}

std::vector<std::string> parse_csv_list(
    const std::string& value,
    std::string_view key,
    std::string_view source,
    bool allow_none
) {
    const std::string normalized = lowercase(value);

    if (allow_none && normalized == "none") {
        return {};
    }

    std::vector<std::string> result;
    std::size_t start = 0;

    while (start <= value.size()) {
        const auto separator = value.find(',', start);
        const auto length =
            separator == std::string::npos
                ? value.size() - start
                : separator - start;

        std::string item = trim(
            std::string_view(value).substr(start, length)
        );

        if (item.empty()) {
            throw std::runtime_error(
                "Invalid " + std::string(key) +
                " from " + std::string(source) +
                ": list entries must not be empty"
            );
        }

        result.push_back(std::move(item));

        if (separator == std::string::npos) {
            break;
        }

        start = separator + 1;
    }

    return result;
}

void validate_proxy_cidr(
    const std::string& cidr
) {
    const auto separator = cidr.find('/');
    const std::string address_text =
        separator == std::string::npos
            ? cidr
            : cidr.substr(0, separator);

    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(
        address_text,
        error
    );

    if (error) {
        throw std::runtime_error(
            "Invalid trusted_proxy_cidrs entry: " + cidr
        );
    }

    if (separator == std::string::npos) {
        return;
    }

    const std::string prefix = cidr.substr(separator + 1);

    if (prefix.empty()) {
        throw std::runtime_error(
            "Invalid trusted_proxy_cidrs prefix: " + cidr
        );
    }

    const unsigned maximum = address.is_v4() ? 32U : 128U;

    if (
        !std::all_of(
            prefix.begin(),
            prefix.end(),
            [](char character) {
                return std::isdigit(
                    static_cast<unsigned char>(character)
                ) != 0;
            }
        )
    ) {
        throw std::runtime_error(
            "Invalid trusted_proxy_cidrs prefix: " + cidr
        );
    }

    unsigned long parsed = 0;

    try {
        parsed = std::stoul(prefix);
    } catch (const std::exception&) {
        throw std::runtime_error(
            "Invalid trusted_proxy_cidrs prefix: " + cidr
        );
    }

    if (parsed > maximum) {
        throw std::runtime_error(
            "Invalid trusted_proxy_cidrs prefix: " + cidr
        );
    }
}

bool valid_cors_origin(
    std::string_view origin
) {
    if (origin == "*") {
        return true;
    }

    if (
        origin.empty() ||
        origin.find_first_of(" \t\r\n") !=
            std::string_view::npos
    ) {
        return false;
    }

    std::size_t authority_start = 0;

    if (origin.starts_with("http://")) {
        authority_start = 7;
    } else if (origin.starts_with("https://")) {
        authority_start = 8;
    } else {
        return false;
    }

    if (authority_start >= origin.size()) {
        return false;
    }

    const auto authority = origin.substr(authority_start);

    return (
        authority.find('/') == std::string_view::npos &&
        authority.find('?') == std::string_view::npos &&
        authority.find('#') == std::string_view::npos &&
        authority.find('@') == std::string_view::npos
    );
}

std::uint64_t parse_unsigned(
    const std::string& value,
    std::string_view key,
    std::string_view source,
    std::uint64_t minimum,
    std::uint64_t maximum
) {
    std::uint64_t result = 0;

    const char* begin = value.data();
    const char* end = begin + value.size();

    const auto [position, error] =
        std::from_chars(
            begin,
            end,
            result
        );

    if (
        error != std::errc{} ||
        position != end ||
        result < minimum ||
        result > maximum
    ) {
        throw std::runtime_error(
            "Invalid " +
            std::string(key) +
            " from " +
            std::string(source) +
            ": expected an integer from " +
            std::to_string(minimum) +
            " through " +
            std::to_string(maximum)
        );
    }

    return result;
}

bool parse_boolean(
    const std::string& value,
    std::string_view key,
    std::string_view source
) {
    const std::string normalized =
        lowercase(value);

    if (
        normalized == "true" ||
        normalized == "1" ||
        normalized == "yes" ||
        normalized == "on"
    ) {
        return true;
    }

    if (
        normalized == "false" ||
        normalized == "0" ||
        normalized == "no" ||
        normalized == "off"
    ) {
        return false;
    }

    throw std::runtime_error(
        "Invalid " +
        std::string(key) +
        " from " +
        std::string(source) +
        ": expected true or false"
    );
}

bool is_loopback_address(
    std::string_view address
) {
    return (
        address == "127.0.0.1" ||
        address == "::1" ||
        address == "localhost"
    );
}

void ensure_parent_directory(
    const std::string& raw_path,
    std::string_view description
) {
    if (raw_path.empty()) {
        throw std::runtime_error(
            std::string(description) +
            " path must not be empty"
        );
    }

    const std::filesystem::path path(
        raw_path
    );

    std::error_code error;

    if (
        std::filesystem::exists(path, error) &&
        std::filesystem::is_directory(path, error)
    ) {
        throw std::runtime_error(
            std::string(description) +
            " path refers to a directory: " +
            raw_path
        );
    }

    if (error) {
        throw std::runtime_error(
            "Failed to inspect " +
            std::string(description) +
            " path: " +
            error.message()
        );
    }

    std::filesystem::path parent =
        path.parent_path();

    if (parent.empty()) {
        parent = ".";
    }

    error.clear();

    std::filesystem::create_directories(
        parent,
        error
    );

    if (error) {
        throw std::runtime_error(
            "Failed to create " +
            std::string(description) +
            " parent directory '" +
            parent.string() +
            "': " +
            error.message()
        );
    }

    error.clear();

    if (
        !std::filesystem::is_directory(
            parent,
            error
        ) ||
        error
    ) {
        throw std::runtime_error(
            std::string(description) +
            " parent is not a directory: " +
            parent.string()
        );
    }
}

void require_regular_file(
    const std::string& raw_path,
    std::string_view description,
    bool redact_path = false
) {
    if (raw_path.empty()) {
        throw std::runtime_error(
            std::string(description) +
            " path must not be empty"
        );
    }

    std::error_code error;

    const bool regular_file =
        std::filesystem::is_regular_file(
            raw_path,
            error
        );

    if (error || !regular_file) {
        throw std::runtime_error(
            std::string(description) +
            " does not exist or is not a "
            "regular file" +
            (
                redact_path
                    ? std::string{}
                    : ": " + raw_path
            )
        );
    }
}

void require_private_permissions(
    const std::string& raw_path
) {
    std::error_code error;

    const auto permissions =
        std::filesystem::status(
            raw_path,
            error
        ).permissions();

    if (error) {
        throw std::runtime_error(
            "Failed to inspect TLS private "
            "key permissions: " +
            error.message()
        );
    }

    using Permissions =
        std::filesystem::perms;

    constexpr Permissions unsafe =
        Permissions::group_read |
        Permissions::group_write |
        Permissions::group_exec |
        Permissions::others_read |
        Permissions::others_write |
        Permissions::others_exec;

    if (
        (permissions & unsafe) !=
        Permissions::none
    ) {
        throw std::runtime_error(
            "TLS private key permissions are "
            "too open. Restrict the file with "
            "chmod 600"
        );
    }
}

}  // namespace

ServerConfig ServerConfig::load_from_file(
    const std::string& path
) {
    std::ifstream input(path);

    if (!input.is_open()) {
        throw std::runtime_error(
            "Failed to open configuration file: " +
            path
        );
    }

    ServerConfig config;

    std::string raw_line;
    std::size_t line_number = 0;

    while (std::getline(input, raw_line)) {
        ++line_number;

        const std::string line = trim(raw_line);

        if (
            line.empty() ||
            line.front() == '#'
        ) {
            continue;
        }

        const auto separator = line.find('=');

        if (
            separator ==
            std::string::npos
        ) {
            throw std::runtime_error(
                "Missing '=' at configuration line " +
                std::to_string(line_number)
            );
        }

        const std::string key = trim(
            std::string_view(line).substr(
                0,
                separator
            )
        );

        const std::string value = trim(
            std::string_view(line).substr(
                separator + 1
            )
        );

        if (key.empty() || value.empty()) {
            throw std::runtime_error(
                "Empty key or value at "
                "configuration line " +
                std::to_string(line_number)
            );
        }

        config.apply_setting(
            key,
            value,
            "configuration line " +
                std::to_string(line_number)
        );
    }

    config.apply_environment_overrides();
    config.validate_common();

    return config;
}

void ServerConfig::apply_setting(
    std::string_view key,
    const std::string& value,
    std::string_view source
) {
    if (key == "environment") {
        environment_ = lowercase(value);
    } else if (key == "listen_address") {
        listen_address_ = value;
    } else if (key == "listen_port") {
        listen_port_ =
            static_cast<std::uint16_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    65535
                )
            );
    } else if (key == "log_file") {
        log_file_ = value;
    } else if (key == "database_path") {
        database_path_ = value;
    } else if (key == "database_pool_size") {
        database_pool_size_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    64
                )
            );
    } else if (
        key == "database_acquire_timeout_ms"
    ) {
        database_acquire_timeout_ms_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    60000
                )
            );
    } else if (key == "io_threads") {
        io_threads_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    64
                )
            );
    } else if (key == "worker_threads") {
        worker_threads_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    64
                )
            );
    } else if (
        key == "worker_queue_capacity"
    ) {
        worker_queue_capacity_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    1000000
                )
            );
    } else if (
        key == "shutdown_grace_period_ms"
    ) {
        shutdown_grace_period_ms_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    600000
                )
            );
    } else if (
        key == "audit_retention_days"
    ) {
        audit_retention_days_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    3650
                )
            );
    } else if (
        key == "metrics_require_auth"
    ) {
        metrics_require_auth_ = parse_boolean(
            value,
            key,
            source
        );
    } else if (
        key == "auth_login_account_failure_limit"
    ) {
        auth_login_account_failure_limit_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    1000
                )
            );
    } else if (
        key == "auth_login_ip_failure_limit"
    ) {
        auth_login_ip_failure_limit_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    100000
                )
            );
    } else if (
        key == "auth_login_failure_window_seconds"
    ) {
        auth_login_failure_window_seconds_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    86400
                )
            );
    } else if (
        key == "auth_login_lockout_seconds"
    ) {
        auth_login_lockout_seconds_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    86400
                )
            );
    } else if (
        key == "auth_login_max_lockout_seconds"
    ) {
        auth_login_max_lockout_seconds_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    604800
                )
            );
    } else if (key == "tls_enabled") {
        tls_enabled_ = parse_boolean(
            value,
            key,
            source
        );
    } else if (
        key == "tls_certificate_file"
    ) {
        tls_certificate_file_ = value;
    } else if (
        key == "tls_private_key_file"
    ) {
        tls_private_key_file_ = value;
    } else if (
        key ==
        "tls_handshake_timeout_seconds"
    ) {
        tls_handshake_timeout_seconds_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    300
                )
            );
    } else if (
        key == "trusted_proxy_cidrs"
    ) {
        trusted_proxy_cidrs_ = parse_csv_list(
            value,
            key,
            source,
            true
        );
    } else if (
        key == "proxy_forwarded_header_max_bytes"
    ) {
        proxy_forwarded_header_max_bytes_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    128,
                    65536
                )
            );
    } else if (
        key == "cors_allowed_origins"
    ) {
        cors_allowed_origins_ = parse_csv_list(
            value,
            key,
            source,
            false
        );
    } else if (
        key == "cors_allow_credentials"
    ) {
        cors_allow_credentials_ = parse_boolean(
            value,
            key,
            source
        );
    } else if (
        key == "cors_max_age_seconds"
    ) {
        cors_max_age_seconds_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    0,
                    86400
                )
            );
    } else if (
        key == "hsts_enabled"
    ) {
        hsts_enabled_ = parse_boolean(
            value,
            key,
            source
        );
    } else if (
        key == "hsts_max_age_seconds"
    ) {
        hsts_max_age_seconds_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    0,
                    63072000
                )
            );
    } else if (
        key == "hsts_include_subdomains"
    ) {
        hsts_include_subdomains_ = parse_boolean(
            value,
            key,
            source
        );
    } else if (
        key == "hsts_preload"
    ) {
        hsts_preload_ = parse_boolean(
            value,
            key,
            source
        );
    } else if (
        key == "http_max_connections"
    ) {
        http_max_connections_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    1000000
                )
            );
    } else if (
        key == "http_rate_limit_requests"
    ) {
        http_rate_limit_requests_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    0,
                    1000000
                )
            );
    } else if (
        key ==
        "http_rate_limit_window_seconds"
    ) {
        http_rate_limit_window_seconds_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    3600
                )
            );
    } else if (
        key == "http_max_header_bytes"
    ) {
        http_max_header_bytes_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1024,
                    1024ULL * 1024ULL
                )
            );
    } else if (
        key == "http_max_body_bytes"
    ) {
        http_max_body_bytes_ =
            parse_unsigned(
                value,
                key,
                source,
                1,
                1024ULL * 1024ULL * 1024ULL
            );
    } else if (
        key == "http_read_timeout_seconds"
    ) {
        http_read_timeout_seconds_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    3600
                )
            );
    } else if (
        key == "http_write_timeout_seconds"
    ) {
        http_write_timeout_seconds_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    3600
                )
            );
    } else if (
        key == "http_idle_timeout_seconds"
    ) {
        http_idle_timeout_seconds_ =
            static_cast<std::uint32_t>(
                parse_unsigned(
                    value,
                    key,
                    source,
                    1,
                    3600
                )
            );
    } else {
        throw std::runtime_error(
            "Unknown configuration key '" +
            std::string(key) +
            "' from " +
            std::string(source)
        );
    }
}

void ServerConfig::apply_environment_overrides() {
    for (
        const auto& mapping :
        environment_mappings
    ) {
        const char* raw_value = std::getenv(
            std::string(mapping.variable).c_str()
        );

        if (raw_value == nullptr) {
            continue;
        }

        const std::string value = trim(raw_value);

        if (value.empty()) {
            throw std::runtime_error(
                "Environment variable " +
                std::string(mapping.variable) +
                " must not be empty"
            );
        }

        apply_setting(
            mapping.key,
            value,
            "environment variable " +
                std::string(mapping.variable)
        );
    }
}

void ServerConfig::validate_common() const {
    if (
        environment_ != "development" &&
        environment_ != "test" &&
        environment_ != "production"
    ) {
        throw std::runtime_error(
            "Invalid environment: expected "
            "development, test, or production"
        );
    }

    if (listen_address_.empty()) {
        throw std::runtime_error(
            "listen_address must not be empty"
        );
    }

    if (log_file_.empty()) {
        throw std::runtime_error(
            "log_file must not be empty"
        );
    }

    if (database_path_.empty()) {
        throw std::runtime_error(
            "database_path must not be empty"
        );
    }

    if (
        auth_login_max_lockout_seconds_ <
        auth_login_lockout_seconds_
    ) {
        throw std::runtime_error(
            "auth_login_max_lockout_seconds must "
            "be greater than or equal to "
            "auth_login_lockout_seconds"
        );
    }

    for (const std::string& cidr : trusted_proxy_cidrs_) {
        validate_proxy_cidr(cidr);
    }

    if (cors_allowed_origins_.empty()) {
        throw std::runtime_error(
            "cors_allowed_origins must not be empty"
        );
    }

    bool wildcard_origin = false;

    for (const std::string& origin : cors_allowed_origins_) {
        if (!valid_cors_origin(origin)) {
            throw std::runtime_error(
                "Invalid cors_allowed_origins entry: " + origin
            );
        }

        if (origin == "*") {
            wildcard_origin = true;
        }
    }

    if (
        wildcard_origin &&
        cors_allowed_origins_.size() != 1
    ) {
        throw std::runtime_error(
            "CORS wildcard cannot be combined with exact origins"
        );
    }

    if (
        wildcard_origin &&
        cors_allow_credentials_
    ) {
        throw std::runtime_error(
            "cors_allow_credentials cannot be true when cors_allowed_origins=*"
        );
    }

    if (
        hsts_preload_ &&
        (
            !hsts_enabled_ ||
            !hsts_include_subdomains_ ||
            hsts_max_age_seconds_ < 31536000
        )
    ) {
        throw std::runtime_error(
            "hsts_preload requires HSTS enabled, includeSubDomains, and max-age of at least 31536000"
        );
    }
}

void ServerConfig::validate_for_server() const {
    validate_common();

    ensure_parent_directory(
        log_file_,
        "Log file"
    );

    ensure_parent_directory(
        database_path_,
        "Database"
    );

    if (tls_enabled_) {
        require_regular_file(
            tls_certificate_file_,
            "TLS certificate file"
        );

        require_regular_file(
            tls_private_key_file_,
            "TLS private key file",
            true
        );

        require_private_permissions(
            tls_private_key_file_
        );
    }

    if (environment_ == "production") {
        if (
            !tls_enabled_ &&
            !is_loopback_address(
                listen_address_
            )
        ) {
            throw std::runtime_error(
                "Production mode refuses "
                "unencrypted HTTP on a non-loopback "
                "listen address"
            );
        }

        if (http_rate_limit_requests_ == 0) {
            throw std::runtime_error(
                "Production mode requires HTTP "
                "rate limiting"
            );
        }

        if (
            cors_allowed_origins_.size() == 1 &&
            cors_allowed_origins_.front() == "*"
        ) {
            throw std::runtime_error(
                "Production mode requires an explicit CORS origin allowlist"
            );
        }
    }
}

void ServerConfig::validate_for_admin() const {
    validate_common();

    ensure_parent_directory(
        database_path_,
        "Database"
    );
}

std::string ServerConfig::redacted_summary()
    const {
    std::ostringstream result;

    result
        << "environment=" << environment_
        << ", listen=" << listen_address_
        << ':' << listen_port_
        << ", tls="
        << (tls_enabled_ ? "enabled" : "disabled")
        << ", database_pool_size="
        << database_pool_size_
        << ", database_acquire_timeout_ms="
        << database_acquire_timeout_ms_
        << ", io_threads=" << io_threads_
        << ", worker_threads=" << worker_threads_
        << ", worker_queue_capacity="
        << worker_queue_capacity_
        << ", shutdown_grace_period_ms="
        << shutdown_grace_period_ms_
        << ", audit_retention_days="
        << audit_retention_days_
        << ", metrics_auth="
        << (metrics_require_auth_ ? "required" : "public")
        << ", auth_login_limits="
        << auth_login_account_failure_limit_
        << "/account,"
        << auth_login_ip_failure_limit_
        << "/ip per "
        << auth_login_failure_window_seconds_
        << "s, lockout="
        << auth_login_lockout_seconds_
        << "-"
        << auth_login_max_lockout_seconds_
        << "s"
        << ", trusted_proxy_networks="
        << trusted_proxy_cidrs_.size()
        << ", forwarded_header_limit="
        << proxy_forwarded_header_max_bytes_
        << " bytes"
        << ", cors_origins="
        << (
            cors_allowed_origins_.size() == 1 &&
            cors_allowed_origins_.front() == "*"
                ? "wildcard"
                : std::to_string(cors_allowed_origins_.size())
          )
        << ", hsts="
        << (hsts_enabled_ ? "enabled" : "disabled")
        << ", max_connections="
        << http_max_connections_
        << ", rate_limit="
        << http_rate_limit_requests_
        << '/' << http_rate_limit_window_seconds_
        << "s";

    return result.str();
}

const std::string&
ServerConfig::environment() const noexcept {
    return environment_;
}

const std::string&
ServerConfig::listen_address()
    const noexcept {
    return listen_address_;
}

std::uint16_t
ServerConfig::listen_port()
    const noexcept {
    return listen_port_;
}

const std::string&
ServerConfig::log_file()
    const noexcept {
    return log_file_;
}

const std::string&
ServerConfig::database_path()
    const noexcept {
    return database_path_;
}

std::uint32_t
ServerConfig::database_pool_size()
    const noexcept {
    return database_pool_size_;
}

std::uint32_t
ServerConfig::database_acquire_timeout_ms()
    const noexcept {
    return database_acquire_timeout_ms_;
}

std::uint32_t
ServerConfig::io_threads()
    const noexcept {
    return io_threads_;
}

std::uint32_t
ServerConfig::worker_threads()
    const noexcept {
    return worker_threads_;
}

std::uint32_t
ServerConfig::worker_queue_capacity()
    const noexcept {
    return worker_queue_capacity_;
}

std::uint32_t
ServerConfig::shutdown_grace_period_ms()
    const noexcept {
    return shutdown_grace_period_ms_;
}

std::uint32_t
ServerConfig::audit_retention_days()
    const noexcept {
    return audit_retention_days_;
}

bool ServerConfig::metrics_require_auth()
    const noexcept {
    return metrics_require_auth_;
}

std::uint32_t
ServerConfig::auth_login_account_failure_limit()
    const noexcept {
    return auth_login_account_failure_limit_;
}

std::uint32_t
ServerConfig::auth_login_ip_failure_limit()
    const noexcept {
    return auth_login_ip_failure_limit_;
}

std::uint32_t
ServerConfig::auth_login_failure_window_seconds()
    const noexcept {
    return auth_login_failure_window_seconds_;
}

std::uint32_t
ServerConfig::auth_login_lockout_seconds()
    const noexcept {
    return auth_login_lockout_seconds_;
}

std::uint32_t
ServerConfig::auth_login_max_lockout_seconds()
    const noexcept {
    return auth_login_max_lockout_seconds_;
}

bool ServerConfig::tls_enabled()
    const noexcept {
    return tls_enabled_;
}

const std::string&
ServerConfig::tls_certificate_file()
    const noexcept {
    return tls_certificate_file_;
}

const std::string&
ServerConfig::tls_private_key_file()
    const noexcept {
    return tls_private_key_file_;
}

std::uint32_t
ServerConfig::tls_handshake_timeout_seconds()
    const noexcept {
    return tls_handshake_timeout_seconds_;
}

const std::vector<std::string>&
ServerConfig::trusted_proxy_cidrs()
    const noexcept {
    return trusted_proxy_cidrs_;
}

std::uint32_t
ServerConfig::proxy_forwarded_header_max_bytes()
    const noexcept {
    return proxy_forwarded_header_max_bytes_;
}

const std::vector<std::string>&
ServerConfig::cors_allowed_origins()
    const noexcept {
    return cors_allowed_origins_;
}

bool ServerConfig::cors_allow_credentials()
    const noexcept {
    return cors_allow_credentials_;
}

std::uint32_t ServerConfig::cors_max_age_seconds()
    const noexcept {
    return cors_max_age_seconds_;
}

bool ServerConfig::hsts_enabled()
    const noexcept {
    return hsts_enabled_;
}

std::uint32_t ServerConfig::hsts_max_age_seconds()
    const noexcept {
    return hsts_max_age_seconds_;
}

bool ServerConfig::hsts_include_subdomains()
    const noexcept {
    return hsts_include_subdomains_;
}

bool ServerConfig::hsts_preload()
    const noexcept {
    return hsts_preload_;
}

std::uint32_t
ServerConfig::http_max_connections()
    const noexcept {
    return http_max_connections_;
}

std::uint32_t
ServerConfig::http_rate_limit_requests()
    const noexcept {
    return http_rate_limit_requests_;
}

std::uint32_t
ServerConfig::http_rate_limit_window_seconds()
    const noexcept {
    return http_rate_limit_window_seconds_;
}

std::uint32_t
ServerConfig::http_max_header_bytes()
    const noexcept {
    return http_max_header_bytes_;
}

std::uint64_t
ServerConfig::http_max_body_bytes()
    const noexcept {
    return http_max_body_bytes_;
}

std::uint32_t
ServerConfig::http_read_timeout_seconds()
    const noexcept {
    return http_read_timeout_seconds_;
}

std::uint32_t
ServerConfig::http_write_timeout_seconds()
    const noexcept {
    return http_write_timeout_seconds_;
}

std::uint32_t
ServerConfig::http_idle_timeout_seconds()
    const noexcept {
    return http_idle_timeout_seconds_;
}

}  // namespace secure
