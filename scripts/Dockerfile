FROM rust:1.52.1

ENV SCCACHE_CACHE_SIZE=2G

RUN apt-get update

RUN cargo install sccache

ENV RUSTC_WRAPPER=$CARGO_HOME/bin/sccache

WORKDIR /usr/local/rust/project
