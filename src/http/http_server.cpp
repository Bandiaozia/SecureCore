#include "secure/http/http_server.hpp"

#include "secure/http/http_session.hpp"
#include "secure/log/logger.hpp"

#include <memory>
#include <utility>

#include <boost/asio/ip/address.hpp>

namespace secure {

using boost::asio::ip::tcp;

HttpServer::HttpServer(
    boost::asio::io_context& io_context,
    const std::string& listen_address,
    std::uint16_t port,
    Logger& logger
)
    : logger_(logger),
      acceptor_(io_context) {
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

    logger_.info(
        "HTTP server configured on ",
        listen_address,
        ':',
        port,
        '.'
    );
}

void HttpServer::start() {
    logger_.info("HTTP server started.");
    do_accept();
}

void HttpServer::stop() {
    boost::system::error_code error;

    acceptor_.close(error);

    if (error) {
        logger_.error(
            "Failed to close HTTP acceptor: ",
            error.message()
        );
    }

    connection_manager_.stop_all();

    logger_.info(
        "All HTTP connections stopped."
    );
}

void HttpServer::do_accept() {
    acceptor_.async_accept(
        [this](
            const boost::system::error_code& error,
            tcp::socket socket
        ) {
            if (!error) {
                auto session =
                    std::make_shared<HttpSession>(
                        std::move(socket),
                        connection_manager_,
                        logger_
                    );

                connection_manager_.start(
                    session
                );

                logger_.info(
                    "Active HTTP connections: ",
                    connection_manager_.size()
                );
            } else if (acceptor_.is_open()) {
                logger_.error(
                    "HTTP accept failed: ",
                    error.message()
                );
            }

            if (acceptor_.is_open()) {
                do_accept();
            }
        }
    );
}

}  // namespace secure
