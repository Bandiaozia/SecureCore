#pragma once

#include <array>
#include <cstddef>
#include <memory>

#include <boost/asio/ip/tcp.hpp>

namespace secure {

class TcpSession final
    : public std::enable_shared_from_this<TcpSession> {
public:
    explicit TcpSession(boost::asio::ip::tcp::socket socket);

    void start();

private:
    void do_read();
    void do_write(std::size_t bytes_to_write);

    boost::asio::ip::tcp::socket socket_;
    std::array<char, 4096> buffer_{};
};

}  // namespace secure
