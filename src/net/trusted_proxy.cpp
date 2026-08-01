#include "secure/net/trusted_proxy.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/beast/core/string.hpp>
#include <boost/beast/http.hpp>
#include <boost/system/error_code.hpp>

namespace secure {

namespace beast = boost::beast;
namespace http = beast::http;

namespace {

constexpr std::size_t maximum_forwarded_hops = 64;

std::string trim_copy(
    std::string_view value
) {
    const auto first = value.find_first_not_of(
        " \t\r\n"
    );

    if (first == std::string_view::npos) {
        return {};
    }

    const auto last = value.find_last_not_of(
        " \t\r\n"
    );

    return std::string(
        value.substr(first, last - first + 1)
    );
}

std::string lowercase_copy(
    std::string_view value
) {
    std::string result(value);

    for (char& character : result) {
        character = static_cast<char>(
            std::tolower(
                static_cast<unsigned char>(character)
            )
        );
    }

    return result;
}

bool has_control_character(
    std::string_view value
) {
    return std::any_of(
        value.begin(),
        value.end(),
        [](char character) {
            const auto byte =
                static_cast<unsigned char>(character);

            return byte < 0x20 || byte == 0x7f;
        }
    );
}

std::vector<std::string> split_top_level(
    std::string_view value,
    char delimiter
) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    bool quoted = false;
    bool escaped = false;

    for (std::size_t index = 0; index < value.size(); ++index) {
        const char character = value[index];

        if (escaped) {
            escaped = false;
            continue;
        }

        if (quoted && character == '\\') {
            escaped = true;
            continue;
        }

        if (character == '"') {
            quoted = !quoted;
            continue;
        }

        if (!quoted && character == delimiter) {
            parts.push_back(
                trim_copy(value.substr(start, index - start))
            );
            start = index + 1;
        }
    }

    if (quoted || escaped) {
        throw ProxyHeaderError(
            "invalid_forwarded_header",
            "The proxy forwarding header contains an unterminated quoted value."
        );
    }

    parts.push_back(trim_copy(value.substr(start)));

    return parts;
}

std::string unquote(
    std::string value
) {
    if (value.empty() || value.front() != '"') {
        return value;
    }

    if (value.size() < 2 || value.back() != '"') {
        throw ProxyHeaderError(
            "invalid_forwarded_header",
            "The proxy forwarding header contains an invalid quoted value."
        );
    }

    std::string result;
    result.reserve(value.size() - 2);

    bool escaped = false;

    for (
        std::size_t index = 1;
        index + 1 < value.size();
        ++index
    ) {
        const char character = value[index];

        if (escaped) {
            if (character != '\\' && character != '"') {
                throw ProxyHeaderError(
                    "invalid_forwarded_header",
                    "The proxy forwarding header contains an invalid escape sequence."
                );
            }

            result.push_back(character);
            escaped = false;
            continue;
        }

        if (character == '\\') {
            escaped = true;
            continue;
        }

        if (character == '"') {
            throw ProxyHeaderError(
                "invalid_forwarded_header",
                "The proxy forwarding header contains an unescaped quote."
            );
        }

        result.push_back(character);
    }

    if (escaped) {
        throw ProxyHeaderError(
            "invalid_forwarded_header",
            "The proxy forwarding header contains an incomplete escape sequence."
        );
    }

    return result;
}

boost::asio::ip::address parse_ip_token(
    std::string raw_value
) {
    raw_value = trim_copy(raw_value);
    raw_value = unquote(std::move(raw_value));

    if (
        raw_value.empty() ||
        has_control_character(raw_value)
    ) {
        throw ProxyHeaderError(
            "invalid_forwarded_header",
            "The proxy forwarding header contains an invalid client address."
        );
    }

    const std::string normalized =
        lowercase_copy(raw_value);

    if (
        normalized == "unknown" ||
        normalized.front() == '_'
    ) {
        throw ProxyHeaderError(
            "invalid_forwarded_header",
            "Obfuscated or unknown forwarded client identifiers are not accepted."
        );
    }

    std::string address_text;

    if (raw_value.front() == '[') {
        const auto closing = raw_value.find(']');

        if (closing == std::string::npos) {
            throw ProxyHeaderError(
                "invalid_forwarded_header",
                "The forwarded IPv6 address is missing a closing bracket."
            );
        }

        address_text = raw_value.substr(1, closing - 1);

        if (closing + 1 < raw_value.size()) {
            if (raw_value[closing + 1] != ':') {
                throw ProxyHeaderError(
                    "invalid_forwarded_header",
                    "The forwarded IPv6 address has an invalid suffix."
                );
            }

            const std::string_view port =
                std::string_view(raw_value).substr(closing + 2);

            if (
                port.empty() ||
                !std::all_of(
                    port.begin(),
                    port.end(),
                    [](char character) {
                        return std::isdigit(
                            static_cast<unsigned char>(character)
                        ) != 0;
                    }
                )
            ) {
                throw ProxyHeaderError(
                    "invalid_forwarded_header",
                    "The forwarded address contains an invalid port."
                );
            }
        }
    } else {
        const auto first_colon = raw_value.find(':');
        const auto last_colon = raw_value.rfind(':');

        if (
            first_colon != std::string::npos &&
            first_colon == last_colon &&
            raw_value.find('.') != std::string::npos
        ) {
            const std::string_view port =
                std::string_view(raw_value).substr(first_colon + 1);

            if (
                port.empty() ||
                !std::all_of(
                    port.begin(),
                    port.end(),
                    [](char character) {
                        return std::isdigit(
                            static_cast<unsigned char>(character)
                        ) != 0;
                    }
                )
            ) {
                throw ProxyHeaderError(
                    "invalid_forwarded_header",
                    "The forwarded address contains an invalid port."
                );
            }

            address_text = raw_value.substr(0, first_colon);
        } else {
            address_text = raw_value;
        }
    }

    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(
        address_text,
        error
    );

    if (
        error ||
        address.is_unspecified() ||
        address.is_multicast()
    ) {
        throw ProxyHeaderError(
            "invalid_forwarded_header",
            "The proxy forwarding header contains an invalid client IP address."
        );
    }

    return address;
}

std::string header_value(
    const HttpRequest& request,
    beast::string_view name
) {
    std::optional<std::string> result;

    for (const auto& field : request) {
        if (!beast::iequals(field.name_string(), name)) {
            continue;
        }

        if (result.has_value()) {
            throw ProxyHeaderError(
                "invalid_forwarded_header",
                "Duplicate proxy forwarding headers are not accepted."
            );
        }

        const auto value = field.value();
        result = std::string(value.data(), value.size());
    }

    return result.value_or(std::string{});
}

struct ForwardedValues final {
    std::vector<boost::asio::ip::address> addresses;
    std::optional<std::string> scheme;
};

ForwardedValues parse_forwarded_header(
    std::string_view value
) {
    ForwardedValues result;

    for (const std::string& element : split_top_level(value, ',')) {
        if (element.empty()) {
            throw ProxyHeaderError(
                "invalid_forwarded_header",
                "The Forwarded header contains an empty element."
            );
        }

        bool found_for = false;

        for (const std::string& parameter : split_top_level(element, ';')) {
            if (parameter.empty()) {
                throw ProxyHeaderError(
                    "invalid_forwarded_header",
                    "The Forwarded header contains an empty parameter."
                );
            }

            const auto separator = parameter.find('=');

            if (
                separator == std::string::npos ||
                separator == 0 ||
                separator + 1 >= parameter.size()
            ) {
                throw ProxyHeaderError(
                    "invalid_forwarded_header",
                    "The Forwarded header contains an invalid parameter."
                );
            }

            const std::string name = lowercase_copy(
                trim_copy(
                    std::string_view(parameter).substr(0, separator)
                )
            );

            std::string parameter_value = trim_copy(
                std::string_view(parameter).substr(separator + 1)
            );

            if (name == "for") {
                if (found_for) {
                    throw ProxyHeaderError(
                        "invalid_forwarded_header",
                        "A Forwarded element contains more than one for parameter."
                    );
                }

                result.addresses.push_back(
                    parse_ip_token(std::move(parameter_value))
                );
                found_for = true;
            } else if (
                name == "proto" &&
                !result.scheme.has_value()
            ) {
                parameter_value = lowercase_copy(
                    unquote(std::move(parameter_value))
                );

                if (
                    parameter_value != "http" &&
                    parameter_value != "https"
                ) {
                    throw ProxyHeaderError(
                        "invalid_forwarded_header",
                        "The Forwarded proto parameter must be http or https."
                    );
                }

                result.scheme = std::move(parameter_value);
            }
        }

        if (!found_for) {
            throw ProxyHeaderError(
                "invalid_forwarded_header",
                "Every Forwarded element must include a for parameter."
            );
        }

        if (result.addresses.size() > maximum_forwarded_hops) {
            throw ProxyHeaderError(
                "invalid_forwarded_header",
                "The proxy forwarding chain contains too many hops."
            );
        }
    }

    return result;
}

std::vector<boost::asio::ip::address>
parse_x_forwarded_for(
    std::string_view value
) {
    std::vector<boost::asio::ip::address> addresses;

    for (std::string part : split_top_level(value, ',')) {
        if (part.empty()) {
            throw ProxyHeaderError(
                "invalid_forwarded_header",
                "X-Forwarded-For contains an empty address."
            );
        }

        addresses.push_back(
            parse_ip_token(std::move(part))
        );

        if (addresses.size() > maximum_forwarded_hops) {
            throw ProxyHeaderError(
                "invalid_forwarded_header",
                "The proxy forwarding chain contains too many hops."
            );
        }
    }

    return addresses;
}

std::optional<std::string> parse_forwarded_proto(
    std::string_view value
) {
    if (value.empty()) {
        return std::nullopt;
    }

    const auto parts = split_top_level(value, ',');

    if (parts.empty() || parts.front().empty()) {
        throw ProxyHeaderError(
            "invalid_forwarded_header",
            "X-Forwarded-Proto is empty."
        );
    }

    const std::string scheme = lowercase_copy(parts.front());

    if (scheme != "http" && scheme != "https") {
        throw ProxyHeaderError(
            "invalid_forwarded_header",
            "X-Forwarded-Proto must be http or https."
        );
    }

    return scheme;
}

}  // namespace

ProxyHeaderError::ProxyHeaderError(
    std::string code,
    std::string message
)
    : std::runtime_error(std::move(message)),
      code_(std::move(code)) {
}

const std::string& ProxyHeaderError::code()
    const noexcept {
    return code_;
}

TrustedProxyResolver::TrustedProxyResolver(
    std::vector<std::string> trusted_cidrs,
    std::size_t forwarded_header_max_bytes
)
    : forwarded_header_max_bytes_(
          forwarded_header_max_bytes
      ) {
    if (forwarded_header_max_bytes_ == 0) {
        throw std::invalid_argument(
            "Forwarded header byte limit must be positive"
        );
    }

    trusted_networks_.reserve(trusted_cidrs.size());

    for (std::string cidr : trusted_cidrs) {
        cidr = trim_copy(cidr);

        if (cidr.empty()) {
            throw std::invalid_argument(
                "Trusted proxy CIDR must not be empty"
            );
        }

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
            throw std::invalid_argument(
                "Invalid trusted proxy CIDR: " + cidr
            );
        }

        unsigned prefix = address.is_v4() ? 32U : 128U;

        if (separator != std::string::npos) {
            const std::string prefix_text = cidr.substr(separator + 1);

            if (
                prefix_text.empty() ||
                !std::all_of(
                    prefix_text.begin(),
                    prefix_text.end(),
                    [](char character) {
                        return std::isdigit(
                            static_cast<unsigned char>(character)
                        ) != 0;
                    }
                )
            ) {
                throw std::invalid_argument(
                    "Invalid trusted proxy CIDR prefix: " + cidr
                );
            }

            try {
                const unsigned long parsed = std::stoul(prefix_text);
                const unsigned maximum = address.is_v4() ? 32U : 128U;

                if (parsed > maximum) {
                    throw std::out_of_range("prefix");
                }

                prefix = static_cast<unsigned>(parsed);
            } catch (const std::exception&) {
                throw std::invalid_argument(
                    "Invalid trusted proxy CIDR prefix: " + cidr
                );
            }
        }

        trusted_networks_.push_back(
            Network{address, prefix}
        );
    }
}

ResolvedClient TrustedProxyResolver::resolve(
    std::string_view peer_ip,
    const HttpRequest& request,
    bool direct_tls
) const {
    boost::system::error_code peer_error;
    const auto peer_address = boost::asio::ip::make_address(
        std::string(peer_ip),
        peer_error
    );

    ResolvedClient result{
        peer_error
            ? std::string(peer_ip)
            : peer_address.to_string(),
        direct_tls,
        false
    };

    if (peer_error || !is_trusted(peer_ip)) {
        return result;
    }

    const std::string forwarded = header_value(
        request,
        "Forwarded"
    );
    const std::string x_forwarded_for = header_value(
        request,
        "X-Forwarded-For"
    );
    const std::string x_real_ip = header_value(
        request,
        "X-Real-IP"
    );
    const std::string x_forwarded_proto = header_value(
        request,
        "X-Forwarded-Proto"
    );

    const std::size_t forwarded_bytes =
        forwarded.size() +
        x_forwarded_for.size() +
        x_real_ip.size() +
        x_forwarded_proto.size();

    if (forwarded_bytes > forwarded_header_max_bytes_) {
        throw ProxyHeaderError(
            "forwarded_header_too_large",
            "Proxy forwarding headers exceed the configured size limit."
        );
    }

    std::vector<boost::asio::ip::address> chain;
    std::optional<std::string> scheme;

    if (!forwarded.empty()) {
        ForwardedValues values = parse_forwarded_header(forwarded);
        chain = std::move(values.addresses);
        scheme = std::move(values.scheme);
    } else if (!x_forwarded_for.empty()) {
        chain = parse_x_forwarded_for(x_forwarded_for);
    } else if (!x_real_ip.empty()) {
        chain.push_back(parse_ip_token(x_real_ip));
    }

    if (!scheme.has_value() && !x_forwarded_proto.empty()) {
        scheme = parse_forwarded_proto(x_forwarded_proto);
    }

    if (scheme.has_value()) {
        result.secure_transport = *scheme == "https";
        result.used_forwarded_headers = true;
    }

    if (chain.empty()) {
        return result;
    }

    boost::asio::ip::address current = peer_address;

    for (auto iterator = chain.rbegin(); iterator != chain.rend(); ++iterator) {
        const bool current_is_trusted = std::any_of(
            trusted_networks_.begin(),
            trusted_networks_.end(),
            [this, &current](const Network& network) {
                return contains(network, current);
            }
        );

        if (!current_is_trusted) {
            break;
        }

        current = *iterator;

        const bool candidate_is_trusted = std::any_of(
            trusted_networks_.begin(),
            trusted_networks_.end(),
            [this, &current](const Network& network) {
                return contains(network, current);
            }
        );

        if (!candidate_is_trusted) {
            break;
        }
    }

    result.client_ip = current.to_string();
    result.used_forwarded_headers = true;

    return result;
}

bool TrustedProxyResolver::is_trusted(
    std::string_view address_text
) const noexcept {
    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(
        std::string(address_text),
        error
    );

    if (error) {
        return false;
    }

    return std::any_of(
        trusted_networks_.begin(),
        trusted_networks_.end(),
        [this, &address](const Network& network) {
            return contains(network, address);
        }
    );
}

std::size_t TrustedProxyResolver::trusted_network_count()
    const noexcept {
    return trusted_networks_.size();
}

std::size_t TrustedProxyResolver::forwarded_header_max_bytes()
    const noexcept {
    return forwarded_header_max_bytes_;
}

bool TrustedProxyResolver::contains(
    const Network& network,
    const boost::asio::ip::address& address
) const noexcept {
    if (network.address.is_v4() != address.is_v4()) {
        return false;
    }

    if (address.is_v4()) {
        const std::uint32_t network_value =
            network.address.to_v4().to_uint();
        const std::uint32_t address_value =
            address.to_v4().to_uint();

        if (network.prefix_length == 0) {
            return true;
        }

        const std::uint32_t mask =
            network.prefix_length == 32
                ? 0xffffffffU
                : static_cast<std::uint32_t>(
                      0xffffffffU <<
                      (32U - network.prefix_length)
                  );

        return (network_value & mask) == (address_value & mask);
    }

    const auto network_bytes = network.address.to_v6().to_bytes();
    const auto address_bytes = address.to_v6().to_bytes();

    unsigned remaining = network.prefix_length;

    for (std::size_t index = 0; index < network_bytes.size(); ++index) {
        if (remaining == 0) {
            return true;
        }

        const unsigned bits = std::min(remaining, 8U);
        const std::uint8_t mask = static_cast<std::uint8_t>(
            0xffU << (8U - bits)
        );

        if (
            (network_bytes[index] & mask) !=
            (address_bytes[index] & mask)
        ) {
            return false;
        }

        remaining -= bits;
    }

    return true;
}

}  // namespace secure
