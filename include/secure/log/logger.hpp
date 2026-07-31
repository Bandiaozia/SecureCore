#pragma once

#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace secure {

enum class LogLevel {
    debug,
    info,
    warning,
    error
};

class Logger final {
public:
    explicit Logger(const std::string& file_path);

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    template <typename... Arguments>
    void debug(Arguments&&... arguments) {
        log(
            LogLevel::debug,
            std::forward<Arguments>(arguments)...
        );
    }

    template <typename... Arguments>
    void info(Arguments&&... arguments) {
        log(
            LogLevel::info,
            std::forward<Arguments>(arguments)...
        );
    }

    template <typename... Arguments>
    void warning(Arguments&&... arguments) {
        log(
            LogLevel::warning,
            std::forward<Arguments>(arguments)...
        );
    }

    template <typename... Arguments>
    void error(Arguments&&... arguments) {
        log(
            LogLevel::error,
            std::forward<Arguments>(arguments)...
        );
    }

private:
    template <typename... Arguments>
    void log(
        LogLevel level,
        Arguments&&... arguments
    ) {
        std::ostringstream message;

        (
            message
            << ...
            << std::forward<Arguments>(arguments)
        );

        write(level, message.str());
    }

    void write(
        LogLevel level,
        const std::string& message
    );

    static std::string timestamp();

    static std::string_view level_name(
        LogLevel level
    ) noexcept;

    std::mutex mutex_;
    std::ofstream file_;
};

}  // namespace secure
