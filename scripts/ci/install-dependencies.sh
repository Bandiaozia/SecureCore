#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
    build-essential \
    ccache \
    clang \
    cmake \
    file \
    g++ \
    gcc \
    jq \
    libboost-system-dev \
    libsodium-dev \
    libsqlite3-dev \
    libssl-dev \
    ninja-build \
    nlohmann-json3-dev \
    openssl \
    pkg-config \
    python3-yaml \
    ruby \
    shellcheck \
    util-linux

ccache --version
cmake --version
ninja --version
