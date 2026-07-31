#include "secure/log/logger.hpp"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace secure {

Logger::Logger(const std::string& file_path) {
    const std::filesystem::path path(file_path);

    if (path.has_parent_path()) {
        std::filesystem::create_directories(
            path.parent_path()
        );
    }

    file_.open(
        file_path,
        std::ios::out | std::ios::app
    );

    if (!file_.is_open()) {
        throw std::runtime_error(
            "Failed to open log file: " + file_path
        );
    }
}

void Logger::write(
    LogLevel level,
    const std::string& message
) {
    std::ostringstream line;

    line
        << '['
        << timestamp()
        << "] ["
        << level_name(level)
        << "] [thread "
        << std::this_thread::get_id()
        << "] "
        << message
        << '\n';

    const std::string output = line.str();

    std::scoped_lock lock(mutex_);

    if (level == LogLevel::error) {
        std::cerr << output;
        std::cerr.flush();
    } else {
        std::cout << output;
        std::cout.flush();
    }

    file_ << output;
    file_.flush();
}

std::string Logger::timestamp() {
    using namespace std::chrono;

    const auto now = system_clock::now();
    const auto milliseconds_part =
        duration_cast<milliseconds>(
            now.time_since_epoch()
        ) % 1000;

    const std::time_t time =
        system_clock::to_time_t(now);

    std::tm local_time{};

    localtime_r(
        &time,
        &local_time
    );

    std::ostringstream result;

    result
        << std::put_time(
            &local_time,
            "%Y-%m-%d %H:%M:%S"
        )
        << '.'
        << std::setw(3)
        << std::setfill('0')
        << milliseconds_part.count();

    return result.str();
}

std::string_view Logger::level_name(
    LogLevel level
) noexcept {
    switch (level) {
        case LogLevel::debug:
            return "DEBUG";

        case LogLevel::info:
            return "INFO";

        case LogLevel::warning:
            return "WARN";

        case LogLevel::error:
            return "ERROR";
    }

    return "UNKNOWN";
}

}  // namespace secure
