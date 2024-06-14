VERSION 0.8

IMPORT github.com/heliaxdev/earthly-lib/rust:5140492f2729571cebb7175ae56d54220bc939a4 AS rust

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
  RUN apt-get install -y parallel

  RUN rustup toolchain install 1.78.0-aarch64-unknown-linux-gnu --no-self-update --component clippy,rustfmt,rls,rust-analysis,rust-docs,rust-src
  RUN rustup toolchain install nightly-2024-05-15-aarch64-unknown-linux-gnu --no-self-update --component clippy,rustfmt,rls,rust-analysis,rust-docs,rust-src
  RUN rustup target add wasm32-unknown-unknown
  RUN rustup default 1.78.0-aarch64-unknown-linux-gnu

  # download masp artifacts
  RUN mkdir -p .masp-params
  RUN curl -o .masp-params/masp-spend.params -L https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-spend.params\?raw\=true
  RUN curl -o .masp-params/masp-output.params -L https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-output.params?raw=true
  RUN curl -o .masp-params/masp-convert.params -L https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-convert.params?raw=true

  # download cargo nextest
  RUN cargo install cargo-nextest --locked

  # install rocksdb
  # GIT CLONE --branch v8.10.0 git@github.com:facebook/rocksdb.git rocksdb # v8.10.0 
  # RUN cd rocksdb && make shared_lib
  # RUN echo /rocksdb | tee /etc/ld.so.conf.d/rocksdb.conf
  # RUN ldconfig

  # download mold
  RUN curl -o mold.tar.gz -LO https://github.com/rui314/mold/releases/download/v2.32.1/mold-2.32.1-aarch64-linux.tar.gz
  RUN tar --strip-components 2 -xvzf mold.tar.gz mold-2.32.1-aarch64-linux/bin/mold

  # Call +INIT before copying the source file to avoid installing function depencies every time source code changes
  # This parametrization will be used in future calls to functions of the library
  DO rust+INIT --keep_fingerprints=true

  # SAVE ARTIFACT /rocksdb
  SAVE ARTIFACT /.masp-params
  SAVE ARTIFACT /mold

source:
  FROM +install
  COPY --keep-ts Cargo.toml Cargo.lock clippy.toml rustfmt.toml CHANGELOG.md rust-toolchain.toml ./
  COPY --keep-ts --dir genesis crates proto examples wasm wasm_for_tests ./

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

  COPY --chmod 777 +download-wasm-opt/wasm-opt wasm-opt
  RUN parallel ./wasm-opt -Oz -o {} {} ::: wasm_for_tests/*.wasm

  SAVE ARTIFACT wasm_for_tests/

save-wasm:
  FROM +build-wasm
  RUN cp target/wasm32-unknown-unknown/release/*.wasm wasm/
  
  COPY --chmod 777 +download-wasm-opt/wasm-opt wasm-opt
  RUN parallel ./wasm-opt -Oz -o {} {} ::: wasm/*.wasm

  RUN python3 wasm/checksums.py
  SAVE ARTIFACT wasm/

build-release:
  FROM +source

  COPY --chmod 777 +install/mold mold

  # ENV ROCKSDB_LIB_DIR="/rocksdb"
  ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=/mold"
  DO rust+CARGO --args="build --release --package namada_apps --manifest-path Cargo.toml --no-default-features --features jemalloc --features migrations" --output="release/[^/\.]+"

  SAVE ARTIFACT target

build-debug:
  FROM +source

  COPY --chmod 777 +install/mold mold

  # ENV ROCKSDB_LIB_DIR="/rocksdb"
  ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=/mold"
  DO rust+CARGO --args="build --package namada_apps --manifest-path Cargo.toml --no-default-features --features jemalloc --features migrations" --output="debug/[^/\.]+"
  
  SAVE ARTIFACT target

test-unit:
  FROM +source

  COPY +save-wasm/wasm/ wasm
  COPY +save-wasm-for-test/wasm_for_tests/ wasm_for_tests


  DO rust+NEXTEST_UNIT --nightly="nightly-2024-05-15"

test-wasm:
  FROM +source

  COPY +save-wasm-for-test/wasm_for_tests/ wasm_for_tests

  ENV RUST_BACKTRACE=1
  ENV CARGO_TERM_COLOR=always

  DO rust+CARGO --args"+nightly-2024-05-15 nextest run --manifest-path wasm/Cargo.toml"

test-integration:
  FROM +source

  COPY +save-wasm/wasm/ wasm
  COPY +save-wasm-for-test/wasm_for_tests/ wasm_for_tests

  ENV RUST_BACKTRACE=1
  ENV NAMADA_MASP_PARAMS_DIR=/.masp-params
  ENV CARGO_TERM_COLOR=always

  DO rust+NEXTEST_INTEGRATION --nightly="nightly-2024-05-15"

test-e2e:
  FROM +source

  ARG --required filter

  COPY --chmod 777 +build-release/target /binaries

  COPY +save-wasm/wasm/ wasm
  COPY +save-wasm-for-test/wasm_for_tests/ wasm_for_tests

  COPY --chmod 777 +build-hermes/target /usr/local/bin
  COPY --chmod 777 +download-gaia/gaiad /usr/local/bin
  COPY --chmod 777 +download-cometbft/cometbft /usr/local/bin

  RUN mv /usr/local/bin/release/hermes /usr/local/bin/

  ENV RUST_BACKTRACE=1
  ENV NAMADA_E2E_USE_PREBUILT_BINARIES=/binaries/release
  ENV NAMADA_E2E_DEBUG=false
  ENV NAMADA_MASP_PARAMS_DIR=/.masp-params
  ENV NAMADA_E2E_KEEP_TEMP=true
  ENV NAMADA_TM_STDOUT=false
  ENV NAMADA_LOG_COLOR=false
  ENV NAMADA_LOG=info
  ENV CARGO_TERM_COLOR=always

  DO rust+NEXTEST_E2E --nightly="nightly-2024-05-15" --filter="$filter"

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

download-wasm-opt:
  FROM +install

  ARG WASM_OPT_VERSION="117"

  RUN curl -o binaryen.tar.gz -LO https://github.com/WebAssembly/binaryen/releases/download/version_${WASM_OPT_VERSION}/binaryen-version_${WASM_OPT_VERSION}-aarch64-linux.tar.gz
  RUN tar --strip-components 2 -xvzf binaryen.tar.gz binaryen-version_${WASM_OPT_VERSION}/bin/wasm-opt

  SAVE ARTIFACT wasm-opt

build-hermes:
  FROM +source

  COPY --chmod 777 +install/mold mold
  
  # tag or branch, no sha
  GIT CLONE --branch v1.8.2-namada-beta11 git@github.com:heliaxdev/hermes.git hermes

  ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=/mold"
  DO rust+CARGO --args="build --release --manifest-path hermes/Cargo.toml --bin hermes --target-dir target" --output="release/[^/\.]+"

  SAVE ARTIFACT target

benches:
  FROM +source

  COPY +save-wasm/wasm/ wasm
  COPY +save-wasm-for-test/wasm_for_tests/ wasm_for_tests
  
  DO rust+CARGO --args="+nightly-2024-05-15 test --package namada_benchmarks --benches -- --nocapture"

check-default-features:
  FROM +source

  DO rust+CARGO --args="check --manifest-path wasm/Cargo.toml --workspace --target wasm32-unknown-unknown"
  DO rust+CARGO --args="check --manifest-path wasm_for_tests/Cargo.toml --workspace --target wasm32-unknown-unknown"

  DO rust+CARGO --args="check --package namada --target wasm32-unknown-unknown --no-default-features --features namada-sdk"
  DO rust+CARGO --args="check --package namada_sdk --all-features"

check-package:
  FROM +source

  ARG package=""

  DO rust+CARGO --args="+nightly-2024-05-15 check -Z unstable-options --tests --package $package"

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
  BUILD +test-wasm

tests-e2e-ledger:
  BUILD +test-e2e --filter="ledger_tests::"

tests-e2e-ibc:
  BUILD +test-e2e --filter="ibc_tests::"

tests-e2e-wallet:
  BUILD +test-e2e --filter="wallet_tests::"

tests-e2e-ibc-ledger:
  BUILD +test-e2e --filter="ibc_tests::run_ledger_ibc"

tests-e2e-ibc-gaia:
  BUILD +test-e2e --filter="ibc_tests::ibc_namada_gaia"

tests-e2e-ibc-ledger-pgf:
  BUILD +test-e2e --filter="ibc_tests::pgf_over_ibc_with_hermes"

tests-e2e-ibc-ledger-inflation:
  BUILD +test-e2e --filter="ibc_tests::proposal_ibc_token_inflation"

tests-e2e-ibc-ledger-rate-limit:
  BUILD +test-e2e --filter="ibc_tests::ibc_rate_limit"

check-namada:
  FROM +install

  FOR package IN "namada" "namada_account" "namada_apps" "namada_apps_lib" "namada_benchmarks" "namada_core" "namada_encoding_spec" "namada_ethereum_bridge" "namada_events" "namada_gas" "namada_governance" "namada_ibc" "namada_light_sdk" "namada_macros" "namada_merkle_tree" "namada_parameters" "namada_proof_of_stake" "namada_replay_protection" "namada_node" "namada_sdk" "namada_shielded_token" "namada_state" "namada_storage" "namada_test_utils" "namada_tests" "namada_token" "namada_trans_token" "namada_tx" "namada_tx_env" "namada_tx_prelude" "namada_vm_env" "namada_vote_ext" "namada_vp_env" "namada_vp_prelude"
    BUILD +check-package --package="${package}"
  END

  BUILD +check-default-features