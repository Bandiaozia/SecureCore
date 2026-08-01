#pragma once

#include "secure/http/http_types.hpp"

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio/ip/address.hpp>

namespace secure {

struct ResolvedClient final {
    std::string client_ip;

    bool secure_transport{false};

    bool used_forwarded_headers{false};
};

class ProxyHeaderError final
    : public std::runtime_error {
public:
    ProxyHeaderError(
        std::string code,
        std::string message
    );

    [[nodiscard]]
    const std::string& code() const noexcept;

private:
    std::string code_;
};

class TrustedProxyResolver final {
public:
    TrustedProxyResolver(
        std::vector<std::string> trusted_cidrs,
        std::size_t forwarded_header_max_bytes
    );

    [[nodiscard]]
    ResolvedClient resolve(
        std::string_view peer_ip,
        const HttpRequest& request,
        bool direct_tls
    ) const;

    [[nodiscard]]
    bool is_trusted(
        std::string_view address
    ) const noexcept;

    [[nodiscard]]
    std::size_t trusted_network_count()
        const noexcept;

    [[nodiscard]]
    std::size_t forwarded_header_max_bytes()
        const noexcept;

private:
    struct Network final {
        boost::asio::ip::address address;
        unsigned prefix_length{0};
    };

    [[nodiscard]]
    bool contains(
        const Network& network,
        const boost::asio::ip::address& address
    ) const noexcept;

    std::vector<Network> trusted_networks_;

    std::size_t forwarded_header_max_bytes_{4096};
};

}  // namespace secure
