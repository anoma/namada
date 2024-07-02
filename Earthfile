VERSION 0.8

IMPORT github.com/earthly/lib/rust AS rust

install:
  FROM rust:1.78.0-bookworm
  RUN apt-get update -y
  RUN apt-get install -y protobuf-compiler 
  RUN apt-get install -y build-essential 
  RUN apt-get install -y clang-tools clang
  RUN apt-get install -y libudev-dev
  RUN apt-get install -y libssl-dev
  RUN apt-get install -y pkg-config
  RUN apt-get install -y gcc

  RUN rustup component add clippy rustfmt
  RUN rustup target add wasm32-unknown-unknown
  RUN rustup toolchain install nightly-2024-05-15 --component clippy,rustfmt

  # download masp artifacts
  RUN mkdir -p .masp-params
  RUN curl -o .masp-params/masp-spend.params -L https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-spend.params\?raw\=true
  RUN curl -o .masp-params/masp-output.params -L https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-output.params?raw=true
  RUN curl -o .masp-params/masp-convert.params -L https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-convert.params?raw=true

  # install rocksdb
  # GIT CLONE --branch v8.10.0 git@github.com:facebook/rocksdb.git rocksdb # v8.10.0 
  # RUN cd rocksdb && make shared_lib
  # RUN echo /rocksdb | tee /etc/ld.so.conf.d/rocksdb.conf
  # RUN ldconfig

  # download mold
  RUN curl -o mold.tar.gz -LO https://github.com/rui314/mold/releases/download/v2.32.0/mold-2.32.0-aarch64-linux.tar.gz
  RUN tar -xvzf mold.tar.gz

  # Call +INIT before copying the source file to avoid installing function depencies every time source code changes
  # This parametrization will be used in future calls to functions of the library
  DO rust+INIT --keep_fingerprints=true

  # SAVE ARTIFACT /rocksdb
  SAVE ARTIFACT /.masp-params

source:
  FROM +install
  COPY --keep-ts Cargo.toml Cargo.lock ./
  COPY --keep-ts --dir genesis crates proto examples wasm wasm_for_tests clippy.toml rustfmt.toml CHANGELOG.md ./

# lint runs cargo clippy on the source code
clippy:
  FROM +source

  DO rust+CARGO --args="+nightly-2024-05-15 clippy --all-targets --workspace --exclude namada_benchmarks -- -D warnings"
  DO rust+CARGO --args="+nightly-2024-05-15 clippy --all-targets --package namada_benchmarks -- -D warnings"

clippy-wasm:
  FROM +source

  DO rust+CARGO --args="+nightly-2024-05-15 clippy --manifest-path wasm/Cargo.toml --workspace -- -D warnings"

clippy-wasm-for-test:
  FROM +source
  
  DO rust+CARGO --args="+nightly-2024-05-15 clippy --manifest-path wasm/Cargo.toml --workspace -- -D warnings"

fmt:
  FROM +source
  DO rust+CARGO --args="+nightly-2024-05-15 fmt --all -- --check"

fmt-wasm:
  FROM +source

  DO rust+CARGO --args="+nightly-2024-05-15 fmt --manifest-path wasm/Cargo.toml --all --check"

build-wasm:
  FROM +source

  ENV RUSTFLAGS='-C link-arg=-s' 
  DO rust+CARGO --args="build --release --manifest-path wasm/Cargo.toml --target wasm32-unknown-unknown --target-dir target" --output="wasm32-unknown-unknown\/release\/[a-zA-Z_]+\.wasm"

build-wasm-for-test:
  FROM +source

  ENV RUSTFLAGS='-C link-arg=-s' 
  DO rust+CARGO --args="build --release --manifest-path wasm_for_tests/Cargo.toml --target wasm32-unknown-unknown --target-dir target" --output="wasm32-unknown-unknown\/release\/[a-zA-Z_]+\.wasm"

save-wasm-for-test:
  FROM +build-wasm-for-test
  RUN cp target/wasm32-unknown-unknown/release/*.wasm wasm_for_tests/
  SAVE ARTIFACT wasm_for_tests/

save-wasm:
  FROM +build-wasm
  RUN cp target/wasm32-unknown-unknown/release/*.wasm wasm/
  RUN python3 wasm/checksums.py
  SAVE ARTIFACT wasm/

build-release:
  FROM +source

  # ENV ROCKSDB_LIB_DIR="/rocksdb"
  ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=/mold-2.32.0-aarch64-linux/bin/mold"
  DO rust+CARGO --args="build --release --package namada_apps --manifest-path Cargo.toml --no-default-features --features jemalloc --features migrations" --output="release/[^/\.]+"

  SAVE ARTIFACT target

build-ci:
  FROM +source

  # ENV ROCKSDB_LIB_DIR="/rocksdb"
  ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=/mold-2.32.0-aarch64-linux/bin/mold"
  DO rust+CARGO --args="build --profile ci --package namada_apps --manifest-path Cargo.toml --no-default-features --features jemalloc --features migrations" --output="release/[^/\.]+"

  SAVE ARTIFACT target

build-debug:
  FROM +source

  # ENV ROCKSDB_LIB_DIR="/rocksdb"
  ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=/mold-2.32.0-aarch64-linux/bin/mold"
  DO rust+CARGO --args="build --package namada_apps --manifest-path Cargo.toml --no-default-features --features jemalloc --features migrations" --output="debug/[^/\.]+"
  
  SAVE ARTIFACT target

test-unit:
  FROM +source

  COPY +save-wasm/wasm/ wasm
  COPY +save-wasm-for-test/wasm_for_tests/ wasm_for_tests

  ARG filter=""

  DO rust+CARGO --args="+nightly-2024-05-15 test --lib $filter --features namada/testing -- --skip e2e --skip integration --skip pos_state_machine_test"

test-integration:
  FROM +source

  COPY +save-wasm/wasm/ wasm
  COPY +save-wasm-for-test/wasm_for_tests/ wasm_for_tests

  ARG filter=""

  ENV RUST_BACKTRACE=1
  ENV NAMADA_MASP_PARAMS_DIR=/.masp-params

  DO rust+CARGO --args="+nightly-2024-05-15 test --lib integration::$filter --features integration -- --test-threads=1"

test-e2e:
  FROM +source

  COPY +save-wasm/wasm/ wasm
  COPY +save-wasm-for-test/wasm_for_tests/ wasm_for_tests

  COPY --chmod 777 +build-hermes/target /usr/local/bin
  COPY --chmod 777 +download-gaia/gaiad /usr/local/bin
  COPY --chmod 777 +download-cometbft/cometbft /usr/local/bin
  COPY --chmod 777 +build-release/target /binaries

  RUN mv /usr/local/bin/release/hermes /usr/local/bin/

  ENV RUST_BACKTRACE=1
  ENV NAMADA_E2E_USE_PREBUILT_BINARIES=/binaries/release
  ENV NAMADA_E2E_DEBUG=false
  ENV NAMADA_MASP_PARAMS_DIR=/.masp-params
  ENV NAMADA_E2E_KEEP_TEMP=true
  ENV NAMADA_TM_STDOUT=false
  ENV NAMADA_LOG_COLOR=false
  ENV NAMADA_LOG=info

  ARG filter=""

  DO rust+CARGO --args="+nightly-2024-05-15 test --lib e2e::$filter -- --test-threads=1"

download-gaia:
  FROM +install

  ARG GAIA_VERSION="15.2.0"

  RUN curl -o gaiad -LO https://github.com/cosmos/gaia/releases/download/v${GAIA_VERSION}/gaiad-v${GAIA_VERSION}-linux-arm64

  SAVE ARTIFACT gaiad

download-cometbft:
  FROM +install

  ARG COMETBFT_VERSION="0.37.2"

  RUN curl -o cometbft.tar.gz -LO https://github.com/cometbft/cometbft/releases/download/v${COMETBFT_VERSION}/cometbft_${COMETBFT_VERSION}_linux_arm64.tar.gz
  RUN tar -xvzf cometbft.tar.gz

  SAVE ARTIFACT cometbft

build-hermes:
  FROM +source
  
  # tag or branch, no sha
  GIT CLONE --branch v1.8.2-namada-beta11 git@github.com:heliaxdev/hermes.git hermes

  ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=/mold-2.32.0-aarch64-linux/bin/mold"
  DO rust+CARGO --args="build --release --manifest-path hermes/Cargo.toml --bin hermes --target-dir target" --output="release/[^/\.]+"

  SAVE ARTIFACT target

benches:
  FROM +save-wasm
  FROM +save-wasm-for-test

  COPY +save-wasm/wasm/ wasm
  COPY +save-wasm-for-test/wasm_for_tests/ wasm_for_tests
  
  DO rust+CARGO --args="+nightly-2024-05-15 test --package namada_benchmarks --benches -- --nocapture"

lints:
  BUILD +clippy
  BUILD +clippy-wasm
  BUILD +clippy-wasm-for-test
  BUILD +fmt
  BUILD +fmt-wasm

builds-release:
  BUILD +build-wasm
  BUILD +build-release

tests:
  BUILD +test-unit
  BUILD +test-integration

tests-e2e-ledger:
  BUILD +test-e2e --filter="ledger_tests::"

tests-e2e-ibc:
  BUILD +test-e2e --filter="ibc_tests::"

tests-e2e-wallet:
  BUILD +test-e2e --filter="wallet_tests::"


# podman run --privileged -v satellite-cache:/tmp/earthly:rw -p 8372:8372 -e EARTHLY_TOKEN=o8eHRKiPfRg3a4vdfizLPBte9McGNBMjDnDTGECmMWhEhxtW9r4rKfHdyIrCX0Tw -e EARTHLY_ORG=heliax -e SATELLITE_NAME=local-satellite -e SATELLITE_HOST=earhtly.local earthly/satellite:v0.8.14
# podman machine stop ; podman machine set --cpus 16 --disk-size 128 --memory 32000 && podman machine start
# podman machine init --now --cpus 16 --disk-size 128 --memory 32000 
# earthly config global.container_frontend podman-shell