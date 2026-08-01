#include "secure/security/auth_abuse_protector.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>

namespace {

void require(
    bool condition,
    const char* message
) {
    if (condition) {
        return;
    }

    std::cerr
        << "Auth abuse protector test failed: "
        << message
        << '\n';

    std::exit(EXIT_FAILURE);
}

}  // namespace

int main() {
    using namespace std::chrono_literals;
    using Clock = secure::AuthAbuseProtector::Clock;

    secure::AuthAbuseProtector protector(
        secure::AuthAbuseConfig{
            3,
            5,
            60s,
            10s,
            40s
        }
    );

    const Clock::time_point started = Clock::now();

    require(
        protector.check(
            "Alice",
            "127.0.0.1",
            started
        ).allowed,
        "initial attempt"
    );

    require(
        protector.record_failure(
            "Alice",
            "127.0.0.1",
            started
        ).allowed,
        "first account failure"
    );

    require(
        protector.record_failure(
            "alice",
            "127.0.0.1",
            started + 1s
        ).allowed,
        "second account failure"
    );

    const auto first_lock =
        protector.record_failure(
            " ALICE ",
            "127.0.0.1",
            started + 2s
        );

    require(!first_lock.allowed, "account locked");
    require(first_lock.newly_locked, "new account lock");
    require(
        first_lock.retry_after_seconds == 10,
        "base lockout duration"
    );

    require(
        !protector.check(
            "alice",
            "203.0.113.5",
            started + 3s
        ).allowed,
        "account lock applies across IPs"
    );

    require(
        protector.check(
            "alice",
            "203.0.113.5",
            started + 12s
        ).allowed,
        "account lock expires"
    );

    require(
        protector.record_failure(
            "alice",
            "203.0.113.5",
            started + 13s
        ).allowed,
        "second-cycle failure one"
    );

    require(
        protector.record_failure(
            "alice",
            "203.0.113.6",
            started + 14s
        ).allowed,
        "second-cycle failure two"
    );

    const auto second_lock =
        protector.record_failure(
            "alice",
            "203.0.113.7",
            started + 15s
        );

    require(!second_lock.allowed, "second account lock");
    require(
        second_lock.retry_after_seconds == 20,
        "exponential account lockout"
    );

    protector.record_success(
        "alice",
        "203.0.113.7"
    );

    require(
        protector.check(
            "alice",
            "203.0.113.7",
            started + 16s
        ).allowed,
        "success clears account and IP state"
    );

    secure::AuthAbuseProtector ip_protector(
        secure::AuthAbuseConfig{
            100,
            3,
            60s,
            7s,
            28s
        }
    );

    require(
        ip_protector.record_failure(
            "one",
            "198.51.100.9",
            started
        ).allowed,
        "first IP failure"
    );

    require(
        ip_protector.record_failure(
            "two",
            "198.51.100.9",
            started + 1s
        ).allowed,
        "second IP failure"
    );

    const auto ip_lock =
        ip_protector.record_failure(
            "three",
            "198.51.100.9",
            started + 2s
        );

    require(!ip_lock.allowed, "IP locked");
    require(
        !ip_protector.check(
            "different-account",
            "198.51.100.9",
            started + 3s
        ).allowed,
        "IP lock applies across accounts"
    );

    require(
        ip_protector.check(
            "different-account",
            "198.51.100.9",
            started + 9s
        ).allowed,
        "IP lock expires"
    );

    require(
        ip_protector.tracked_accounts() >= 3,
        "account states tracked"
    );

    std::cout
        << "Authentication abuse protector tests passed\n";

    return EXIT_SUCCESS;
}
