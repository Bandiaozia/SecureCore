#pragma once

#include <cstdint>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace secure {

class TcpServer final {
public:
    TcpServer(
        boost::asio::io_context& io_context,
        std::uint16_t port
    );

    void start();
    void stop();

private:
    void do_accept();

    boost::asio::ip::tcp::acceptor acceptor_;
};

}  // namespace secure
