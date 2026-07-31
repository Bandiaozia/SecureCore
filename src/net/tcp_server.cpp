#include "secure/net/tcp_server.hpp"
#include <boost/asio/ip/address.hpp>
#include "secure/net/tcp_session.hpp"

#include <iostream>
#include <memory>
#include <utility>

namespace secure {

using boost::asio::ip::tcp;
TcpServer::TcpServer(
    boost::asio::io_context& io_context,
    const std::string& listen_address,
    std::uint16_t port
)
    : acceptor_(io_context) {
    const auto address =
        boost::asio::ip::make_address(
            listen_address
        );

    const tcp::endpoint endpoint(
        address,
        port
    );

    acceptor_.open(endpoint.protocol());

    acceptor_.set_option(
        tcp::acceptor::reuse_address(true)
    );

    acceptor_.bind(endpoint);

    acceptor_.listen(
        tcp::acceptor::max_listen_connections
    );

    std::cout
        << "TCP server configured on "
        << listen_address
        << ':'
        << port
        << ".\n";
}
void TcpServer::start() {
    std::cout << "TCP server started.\n";
    do_accept();
}

void TcpServer::stop() {
    boost::system::error_code error;

    acceptor_.close(error);

    if (error) {
        std::cerr
            << "Failed to close TCP acceptor: "
            << error.message()
            << '\n';
    }

    connection_manager_.stop_all();

    std::cout << "All client connections stopped.\n";
}

void TcpServer::do_accept() {
    acceptor_.async_accept(
        [this](
            const boost::system::error_code& error,
            tcp::socket socket
        ) {
            if (!error) {
                auto session =
                    std::make_shared<TcpSession>(
                        std::move(socket),
                        connection_manager_
                    );

                connection_manager_.start(session);

                std::cout
                    << "Active connections: "
                    << connection_manager_.size()
                    << '\n';
            } else if (acceptor_.is_open()) {
                std::cerr
                    << "Accept failed: "
                    << error.message()
                    << '\n';
            }

            if (acceptor_.is_open()) {
                do_accept();
            }
        }
    );
}

}  // namespace secure