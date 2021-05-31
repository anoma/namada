package = Anoma

# env = OPENSSL_INCLUDE_DIR="/usr/local/opt/openssl/include"
cargo = $(env) cargo
rustup = $(env) rustup
debug-env = RUST_BACKTRACE=1 RUST_LOG=$(package)=debug
debug-cargo = $(env) $(debug-env) cargo
# Nightly build is currently used for rustfmt and clippy.
# NOTE On change also update `RUSTFMT_TOOLCHAIN` in `apps/build.rs`.
nightly = nightly-2021-03-09

# Transitive dependency of wasmer. It's safe to ignore as we don't use cranelift compiler. It should disseaper once the wasmer library updates its dependencies
audit-ignores := RUSTSEC-2021-0067
# Transitive dependency warning from tendermint-rpc
audit-ignores += RUSTSEC-2021-0064
# Transitive dependency warning from tendermint-rpc
audit-ignores += RUSTSEC-2020-0016

build:
	$(cargo) build

build-release:
	$(cargo) build --release

clippy:
	$(cargo) +$(nightly) clippy

clippy-check:
	$(cargo) +$(nightly) clippy -- -D warnings

install:
	# Warning: built in debug mode for now
	$(cargo) install --path ./apps --debug

run-ledger:
	# runs the node
	$(cargo) run --bin anoman -- run-ledger

run-gossip:
	# runs the node gossip node
	$(cargo) run --bin anoman -- run-gossip

reset-ledger:
	# runs the node
	$(cargo) run --bin anoman -- reset-ledger

audit:
	$(cargo) audit --deny warnings $(foreach ignore,$(audit-ignores), --ignore $(ignore))

test:
	$(cargo) test

test-debug:
	$(debug-cargo) test -- --nocapture

fmt:
	$(cargo) +$(nightly) fmt --all

fmt-check:
	$(cargo) +$(nightly) fmt --all -- --check

watch:
	$(cargo) watch

clean:
	$(cargo) clean

build-doc:
	$(cargo) doc --no-deps
	make -C tech-specs build

doc:
	# build and opens the docs in browser
	$(cargo) doc --open

# Build the validity predicate and transaction wasm from templates
build-wasm-scripts:
	make -C vps/vp_template && \
	make -C vps/vp_token && \
	make -C vps/vp_user && \
	make -C txs/tx_template && \
	make -C txs/tx_transfer && \
	make -C txs/tx_from_intent && \
	make -C txs/tx_update_vp && \
	make -C matchmaker_template && \
	make -C filter_template

clean-wasm-scripts:
	make -C vps/vp_template clean && \
	make -C vps/vp_token clean && \
	make -C vps/vp_user clean && \
	make -C txs/tx_template clean && \
	make -C txs/tx_transfer clean && \
	make -C txs/tx_from_intent clean && \
	make -C txs/tx_update_vp clean && \
	make -C matchmaker_template clean && \
	make -C filter_template clean

dev-deps:
	$(rustup) toolchain install $(nightly)
	$(rustup) target add wasm32-unknown-unknown
	$(rustup) component add rustfmt clippy --toolchain $(nightly)
	$(cargo) install cargo-watch

.PHONY : build build-release clippy install run-anoma run-gossip test test-debug fmt watch clean doc build-wasm-scripts dev-deps
