FROM rust:latest

ENV SCCACHE_CACHE_SIZE=2G

RUN apt-get update

RUN rustup target add wasm32-unknown-unknown

RUN cargo install sccache

ENV RUSTC_WRAPPER=$CARGO_HOME/bin/sccache

WORKDIR /usr/local/rust/project
