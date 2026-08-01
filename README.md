<div align="center">

# SecureCore

**A security-oriented server foundation built with modern C++20**

一个异步、安全、可测试的现代 C++ 服务端基础框架。

![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C)
![CI](https://github.com/Bandiaozia/SecureCore/actions/workflows/ci.yml/badge.svg)
![Security](https://github.com/Bandiaozia/SecureCore/actions/workflows/security.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/Bandiaozia/SecureCore)

</div>

## 项目简介

SecureCore 是一个使用 C++20 编写的服务端学习与实践项目。

项目基于 Boost.Asio 和 Boost.Beast，实现异步 HTTP/HTTPS 服务、
身份认证、细粒度 RBAC、审计日志、数据库连接池、优雅关闭以及完整的
Sanitizer、Fuzzer 和 CI 测试体系。

## 核心特性

- 异步 HTTP 与 HTTPS 服务
- 路由和中间件系统
- Argon2id 密码哈希
- Access Token 与 Refresh Token
- 细粒度 RBAC 权限控制
- SQLite 数据库和连接池
- 安全审计日志
- ASan、UBSan 和 TSan
- 6 个 libFuzzer 目标
- GitHub Actions 自动测试
- 可复现 Release 构建

## 快速开始

```bash
git clone https://github.com/Bandiaozia/SecureCore.git
cd SecureCore

cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Debug

cmake --build build -j4

ctest \
    --test-dir build \
    --output-on-failure
```

## 项目架构

```mermaid
flowchart LR
    Client[HTTP / HTTPS Client]
    Server[HTTP Server]
    Session[HTTP Session]
    Middleware[Middleware]
    Router[Router]
    Service[Service Layer]
    Repository[Repository Layer]
    DB[(SQLite)]

    Client --> Server
    Server --> Session
    Session --> Middleware
    Middleware --> Router
    Router --> Service
    Service --> Repository
    Repository --> DB
```

## 查看版本

```bash
./build/secure-server --version
./build/secure-admin --version
```
