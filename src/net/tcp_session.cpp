#include "secure/net/tcp_session.hpp"

#include <iostream>
#include <utility>

#include <boost/asio/buffer.hpp>
#include <boost/asio/write.hpp>

namespace secure {

TcpSession::TcpSession(boost::asio::ip::tcp::socket socket)
    : socket_(std::move(socket)) {
}

void TcpSession::start() {
    std::cout << "Client connected.\n";
    do_read();
}

void TcpSession::do_read() {
    auto self = shared_from_this();

    socket_.async_read_some(
        boost::asio::buffer(buffer_),
        [self](
            const boost::system::error_code& error,
            std::size_t bytes_transferred
        ) {
            if (error) {
                std::cout << "Client disconnected.\n";
                return;
            }

            std::cout
                << "Received "
                << bytes_transferred
                << " bytes.\n";

            self->do_write(bytes_transferred);
        }
    );
}

void TcpSession::do_write(std::size_t bytes_to_write) {
    auto self = shared_from_this();

    boost::asio::async_write(
        socket_,
        boost::asio::buffer(buffer_.data(), bytes_to_write),
        [self](
            const boost::system::error_code& error,
            std::size_t
        ) {
            if (error) {
                std::cout << "Failed to write data.\n";
                return;
            }

            self->do_read();
        }
    );
}

}  // namespace secure
