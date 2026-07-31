#include "secure/net/tcp_session.hpp"

#include "secure/net/connection_manager.hpp"

#include <iostream>
#include <utility>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>

namespace secure {

TcpSession::TcpSession(
    boost::asio::ip::tcp::socket socket,
    ConnectionManager& connection_manager
)
    : socket_(std::move(socket)),
      connection_manager_(connection_manager) {
}

void TcpSession::start() {
    std::cout << "Client session started.\n";
    do_read();
}

void TcpSession::stop() {
    if (stopped_) {
        return;
    }

    stopped_ = true;

    boost::system::error_code ignored_error;

    socket_.cancel(ignored_error);

    socket_.shutdown(
        boost::asio::ip::tcp::socket::shutdown_both,
        ignored_error
    );

    socket_.close(ignored_error);
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
                self->handle_disconnect(error);
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
        boost::asio::buffer(
            buffer_.data(),
            bytes_to_write
        ),
        [self](
            const boost::system::error_code& error,
            std::size_t
        ) {
            if (error) {
                self->handle_disconnect(error);
                return;
            }

            self->do_read();
        }
    );
}

void TcpSession::handle_disconnect(
    const boost::system::error_code& error
) {
    if (
        error != boost::asio::error::eof &&
        error != boost::asio::error::operation_aborted
    ) {
        std::cerr
            << "Connection error: "
            << error.message()
            << '\n';
    }

    stop();

    connection_manager_.remove(
        shared_from_this()
    );

    std::cout
        << "Client disconnected. Active connections: "
        << connection_manager_.size()
        << '\n';
}

}  // namespace secure
