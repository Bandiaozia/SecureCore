cmake_minimum_required(VERSION 3.22)

project(SecureCore LANGUAGES CXX)
find_package(Boost REQUIRED COMPONENTS system)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(
    secure-server
    apps/secure_server/main.cpp
    src/runtime/server_application.cpp
    src/config/server_config.cpp
    src/log/logger.cpp
    src/net/connection_manager.cpp
    src/http/http_server.cpp
    src/http/http_session.cpp
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
)


target_compile_options(
    secure-server
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)