# This docker is used for deterministic wasm builds

# The version should be matching the version set in wasm/rust-toolchain.toml
FROM rust:1.54.0

WORKDIR /usr/local/rust/wasm

# The version should be matching the version set above
RUN rustup toolchain install 1.54.0 --component rustc cargo rust-std rust-docs rls rust-analysis
RUN rustup target add wasm32-unknown-unknown


# Tell anoma build.rs not to compile proto files inside the docker
ENV COMPILE_PROTO=false