# This docker is used for deterministic wasm builds

# The version should be matching the version set in wasm/rust-toolchain.toml
FROM rust:1.76.0-bullseye

WORKDIR /__w/namada/namada

# The version should be matching the version set above
RUN rustup toolchain install 1.76.0 --profile minimal
RUN rustup target add wasm32-unknown-unknown

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libudev-dev \
    && apt-get clean

# Download binaryen and extract wasm-opt
ADD https://github.com/WebAssembly/binaryen/releases/download/version_113/binaryen-version_113-x86_64-linux.tar.gz /tmp/binaryen.tar.gz
RUN tar -xf /tmp/binaryen.tar.gz
RUN mv binaryen-version_*/bin/wasm-opt /usr/local/bin
RUN rm -rf binaryen-version_*/ /tmp/binaryen.tar.gz
