#pragma once

#include <array>
#include <cstddef>
#include <memory>

#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

namespace secure {

class ConnectionManager;

class TcpSession final
    : public std::enable_shared_from_this<TcpSession> {
public:
    TcpSession(
        boost::asio::ip::tcp::socket socket,
        ConnectionManager& connection_manager
    );

    void start();

    void stop();

private:
    void do_read();

    void do_write(std::size_t bytes_to_write);

    void handle_disconnect(
        const boost::system::error_code& error
    );

    boost::asio::ip::tcp::socket socket_;
    ConnectionManager& connection_manager_;

    std::array<char, 4096> buffer_{};

    bool stopped_{false};
};

}  // namespace secure
