FROM lukemathwalker/cargo-chef:latest-rust-1.61.0 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    clang-tools-11 \
    git \
    libssl-dev \
    pkg-config \
    && apt-get clean

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN make build-release

FROM golang:1.18.0 as tendermint-builder
WORKDIR /app

RUN git clone -b v0.1.1-abcipp --single-branch https://github.com/heliaxdev/tendermint.git && cd tendermint && make build

FROM debian:bullseye-slim AS runtime
ENV ANOMA_BASE_DIR=/.anoma 
ENV ANOMA_LOG_COLOR=false

RUN apt-get update && apt-get install libcurl4-openssl-dev -y && apt-get clean

RUN useradd --create-home namada
USER namada

COPY --from=builder --chmod=0755 /app/target/release/namada /usr/local/bin
COPY --from=builder --chmod=0755 /app/target/release/namadan /usr/local/bin
COPY --from=builder --chmod=0755 /app/target/release/namadaw /usr/local/bin
COPY --from=builder --chmod=0755 /app/target/release/namadac /usr/local/bin
COPY --from=tendermint-builder --chmod=0755 /app/tendermint/build/tendermint /usr/local/bin

EXPOSE 26656
EXPOSE 26660
EXPOSE 26659
EXPOSE 26657

ENTRYPOINT ["/usr/local/bin/namada"]
CMD ["--help"]