FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive
ENV RUSTUP_HOME=/usr/local/rust/rustup \
    CARGO_HOME=/usr/local/rust/cargo \
    PATH=/usr/local/rust/cargo/bin:$PATH \
    RUST_VERSION=1.52.1 \
    SCCACHE_CACHE_SIZE=2G

RUN apt-get update

RUN apt-get install -yq \
    build-essential \
    libssl-dev \
    curl \
    pkg-config \
    clang-tools-11

RUN apt-get update && apt-get clean

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

RUN rustup target add wasm32-unknown-unknown

RUN cargo install sccache

ENV RUSTC_WRAPPER=/usr/local/rust/cargo/bin/sccache
