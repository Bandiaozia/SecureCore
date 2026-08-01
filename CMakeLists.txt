cmake_minimum_required(VERSION 3.22)

project(
    SecureCore
    LANGUAGES CXX
)

set(
    CMAKE_CXX_STANDARD
    20
)

set(
    CMAKE_CXX_STANDARD_REQUIRED
    ON
)

set(
    CMAKE_CXX_EXTENSIONS
    OFF
)

set(
    CMAKE_EXPORT_COMPILE_COMMANDS
    ON
)

find_package(
    Boost
    REQUIRED
    COMPONENTS system
)

find_package(
    nlohmann_json
    CONFIG
    REQUIRED
)

find_package(
    Threads
    REQUIRED
)

find_package(
    SQLite3
    REQUIRED
)

find_package(
    PkgConfig
    REQUIRED
)

pkg_check_modules(
    SODIUM
    REQUIRED
    IMPORTED_TARGET
    libsodium
)

set(
    SECURECORE_SOURCES

    src/runtime/server_application.cpp

    src/config/server_config.cpp

    src/log/logger.cpp

    src/net/connection_manager.cpp

    src/http/http_server.cpp
    src/http/http_session.cpp
    src/http/router.cpp
    src/http/routes.cpp
    src/http/admin_routes.cpp
    src/http/account_routes.cpp
    src/http/json_utils.cpp
    src/http/rate_limiter.cpp
    src/http/middleware.cpp

    src/database/database.cpp
    src/database/migration.cpp

    src/repository/user_repository.cpp
    src/repository/auth_session_repository.cpp

    src/security/token_service.cpp
    src/security/password_hasher.cpp

    src/service/user_service.cpp
    src/service/auth_service.cpp
    src/service/admin_service.cpp
    src/service/account_security_service.cpp
)

add_library(
    securecore
    STATIC
    ${SECURECORE_SOURCES}
)

target_include_directories(
    securecore
    PUBLIC
        include
)

target_link_libraries(
    securecore
    PUBLIC
        Boost::system
        nlohmann_json::nlohmann_json
        Threads::Threads
        SQLite::SQLite3
        PkgConfig::SODIUM
)

target_compile_options(
    securecore
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

add_executable(
    secure-server
    apps/secure_server/main.cpp
)

target_link_libraries(
    secure-server
    PRIVATE
        securecore
)

target_compile_options(
    secure-server
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

add_executable(
    secure-admin
    apps/secure_admin/main.cpp
)

target_link_libraries(
    secure-admin
    PRIVATE
        securecore
)

target_compile_options(
    secure-admin
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
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

    add_executable(
        securecore-router-test
        tests/router_test.cpp
    )

    target_link_libraries(
        securecore-router-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-router-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-router-unit
        COMMAND
            securecore-router-test
    )

endif()
