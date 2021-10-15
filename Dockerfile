FROM ubuntu:20.04
WORKDIR /var/build
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    clang-tools-11 \
    curl \
    libssl-dev \
    pkg-config \
    && apt-get clean
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup toolchain install 1.54.0 --component \
    cargo \ 
    rls \
    rustc \
    rust-analysis \
    rust-docs \
    rust-std \
