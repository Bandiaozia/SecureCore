cmake_minimum_required(VERSION 3.22)

project(SecureCore LANGUAGES CXX)
find_package(Boost REQUIRED COMPONENTS system)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(SQLite3 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(
    SODIUM
    REQUIRED
    IMPORTED_TARGET
    libsodium
)

add_executable(
    secure-server
    apps/secure_server/main.cpp
    src/runtime/server_application.cpp
    src/config/server_config.cpp
    src/log/logger.cpp
    src/net/connection_manager.cpp
    src/http/http_server.cpp
    src/http/http_session.cpp
    src/http/router.cpp
    src/http/routes.cpp
    src/http/json_utils.cpp
    src/http/rate_limiter.cpp
    src/http/middleware.cpp
    src/database/database.cpp
    src/database/migration.cpp
    src/repository/user_repository.cpp
    src/security/password_hasher.cpp
    src/service/user_service.cpp
)

target_include_directories(
    secure-server
    PRIVATE
        include
)

target_link_libraries(
    secure-server
    PRIVATE
        Boost::system
        nlohmann_json::nlohmann_json
        Threads::Threads
)


target_compile_options(
    secure-server
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

target_link_libraries(
    secure-server
    PRIVATE SQLite::SQLite3
)

target_link_libraries(
    secure-server
    PRIVATE PkgConfig::SODIUM
)

include(CTest)

if(BUILD_TESTING)
    find_package(
        Python3
        REQUIRED
        COMPONENTS Interpreter
    )

    add_test(
        NAME securecore-http-smoke
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/http_smoke_test.py
            $<TARGET_FILE:secure-server>
    )

    set_tests_properties(
        securecore-http-smoke
        PROPERTIES
            TIMEOUT 30
    )
endif()