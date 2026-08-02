#include "secure/http/rate_limiter.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

}  // namespace

int main() {
    using namespace std::chrono_literals;

    try {
        secure::RateLimiter limiter(2, 60s, 2);

        require(limiter.check("192.0.2.1").allowed, "first client");
        require(limiter.check("192.0.2.2").allowed, "second client");
        require(limiter.check("192.0.2.3").allowed, "capacity eviction");

        require(limiter.check("192.0.2.3").allowed, "second request");
        require(!limiter.check("192.0.2.3").allowed, "request limit");

        bool rejected_zero_capacity = false;
        try {
            secure::RateLimiter invalid(1, 1s, 0);
        } catch (const std::invalid_argument&) {
            rejected_zero_capacity = true;
        }

        require(rejected_zero_capacity, "zero capacity rejection");
    } catch (const std::exception& error) {
        std::cerr << "Rate limiter test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "Rate limiter tests passed\n";
    return EXIT_SUCCESS;
}
