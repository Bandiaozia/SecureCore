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

include(
    cmake/SecurityTesting.cmake
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
    OpenSSL
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
    src/runtime/service_state.cpp
    src/runtime/worker_pool.cpp

    src/observability/metrics_registry.cpp

    src/audit/request_audit_context.cpp

    src/config/server_config.cpp

    src/log/logger.cpp

    src/net/connection_manager.cpp
    src/net/trusted_proxy.cpp

    src/http/http_server.cpp
    src/http/http_session.cpp
    src/http/tls_http_session.cpp
    src/http/router.cpp
    src/http/routes.cpp
    src/http/admin_routes.cpp
    src/http/account_routes.cpp
    src/http/audit_routes.cpp
    src/http/rbac_routes.cpp
    src/http/metrics_routes.cpp
    src/http/api_error.cpp
    src/http/json_utils.cpp
    src/http/request_id.cpp
    src/http/request_validation.cpp
    src/http/cors_policy.cpp
    src/http/rate_limiter.cpp
    src/http/middleware.cpp

    src/database/database.cpp
    src/database/transaction.cpp
    src/database/migration.cpp

    src/repository/user_repository.cpp
    src/repository/auth_session_repository.cpp
    src/repository/audit_repository.cpp
    src/repository/rbac_repository.cpp

    src/security/token_service.cpp
    src/security/password_hasher.cpp
    src/security/auth_abuse_protector.cpp

    src/service/user_service.cpp
    src/service/auth_service.cpp
    src/service/admin_service.cpp
    src/service/account_security_service.cpp
    src/service/audit_service.cpp
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
        OpenSSL::SSL
        OpenSSL::Crypto
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

    find_program(
        OPENSSL_EXECUTABLE
        NAMES openssl
        REQUIRED
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

    add_executable(
        securecore-worker-pool-test
        tests/worker_pool_test.cpp
    )

    target_link_libraries(
        securecore-worker-pool-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-worker-pool-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-worker-pool-unit
        COMMAND
            securecore-worker-pool-test
    )


    add_executable(
        securecore-metrics-test
        tests/metrics_registry_test.cpp
    )

    target_link_libraries(
        securecore-metrics-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-metrics-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-metrics-unit
        COMMAND
            securecore-metrics-test
    )



    add_executable(
        securecore-config-test
        tests/server_config_test.cpp
    )

    target_link_libraries(
        securecore-config-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-config-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-config-unit
        COMMAND
            securecore-config-test
    )

    add_executable(
        securecore-transaction-test
        tests/database_transaction_test.cpp
    )

    target_link_libraries(
        securecore-transaction-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-transaction-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-database-transaction-unit
        COMMAND
            securecore-transaction-test
    )

    add_executable(
        securecore-database-pool-test
        tests/database_connection_pool_test.cpp
    )

    target_link_libraries(
        securecore-database-pool-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-database-pool-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-database-pool-unit
        COMMAND
            securecore-database-pool-test
    )


    add_executable(
        securecore-graceful-shutdown-components-test
        tests/graceful_shutdown_components_test.cpp
    )

    target_link_libraries(
        securecore-graceful-shutdown-components-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-graceful-shutdown-components-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-graceful-shutdown-unit
        COMMAND
            securecore-graceful-shutdown-components-test
    )

    add_test(
        NAME securecore-graceful-shutdown-integration
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/graceful_shutdown_test.py
            $<TARGET_FILE:secure-server>
    )

    set_tests_properties(
        securecore-graceful-shutdown-integration
        PROPERTIES
            TIMEOUT 20
    )


    add_executable(
        securecore-api-validation-test
        tests/api_validation_test.cpp
    )

    target_link_libraries(
        securecore-api-validation-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-api-validation-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-api-validation-unit
        COMMAND
            securecore-api-validation-test
    )

    add_test(
        NAME securecore-api-validation-integration
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/api_validation_integration_test.py
            $<TARGET_FILE:secure-server>
    )

    set_tests_properties(
        securecore-api-validation-integration
        PROPERTIES
            TIMEOUT 30
    )

    add_executable(
        securecore-audit-test
        tests/audit_repository_test.cpp
    )

    target_link_libraries(
        securecore-audit-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-audit-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-audit-unit
        COMMAND
            securecore-audit-test
    )

    add_test(
        NAME securecore-audit-integration
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/audit_integration_test.py
            $<TARGET_FILE:secure-server>
            $<TARGET_FILE:secure-admin>
    )

    set_tests_properties(
        securecore-audit-integration
        PROPERTIES
            TIMEOUT 40
    )

    add_executable(
        securecore-auth-abuse-test
        tests/auth_abuse_protector_test.cpp
    )

    target_link_libraries(
        securecore-auth-abuse-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-auth-abuse-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-auth-abuse-unit
        COMMAND
            securecore-auth-abuse-test
    )

    add_test(
        NAME securecore-auth-abuse-integration
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/auth_abuse_integration_test.py
            $<TARGET_FILE:secure-server>
    )

    set_tests_properties(
        securecore-auth-abuse-integration
        PROPERTIES
            TIMEOUT 60
    )


    add_executable(
        securecore-rbac-test
        tests/rbac_repository_test.cpp
    )

    target_link_libraries(
        securecore-rbac-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-rbac-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-rbac-unit
        COMMAND
            securecore-rbac-test
    )

    add_test(
        NAME securecore-rbac-integration
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/rbac_integration_test.py
            $<TARGET_FILE:secure-server>
            $<TARGET_FILE:secure-admin>
    )

    set_tests_properties(
        securecore-rbac-integration
        PROPERTIES
            TIMEOUT 60
    )

    add_executable(
        securecore-proxy-security-test
        tests/proxy_security_test.cpp
    )

    target_link_libraries(
        securecore-proxy-security-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-proxy-security-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-proxy-security-unit
        COMMAND
            securecore-proxy-security-test
    )

    add_test(
        NAME securecore-proxy-security-integration
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/proxy_security_integration_test.py
            $<TARGET_FILE:secure-server>
    )

    set_tests_properties(
        securecore-proxy-security-integration
        PROPERTIES
            TIMEOUT 40
    )

    add_executable(
        securecore-security-parser-corpus-test
        tests/security_parser_corpus_test.cpp
    )

    target_link_libraries(
        securecore-security-parser-corpus-test
        PRIVATE
            securecore
    )

    target_compile_options(
        securecore-security-parser-corpus-test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    add_test(
        NAME securecore-security-parser-corpus
        COMMAND
            securecore-security-parser-corpus-test
    )

    add_test(
        NAME securecore-https-smoke
        COMMAND
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/https_smoke_test.py
            $<TARGET_FILE:secure-server>
            ${OPENSSL_EXECUTABLE}
    )

    set_tests_properties(
        securecore-https-smoke
        PROPERTIES
            TIMEOUT 30
    )

endif()

if(SECURECORE_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
