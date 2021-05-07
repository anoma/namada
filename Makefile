package = Anoma

# env = OPENSSL_INCLUDE_DIR="/usr/local/opt/openssl/include"
cargo = $(env) cargo
rustup = $(env) rustup
debug-env = RUST_BACKTRACE=1 RUST_LOG=$(package)=debug
debug-cargo = $(env) $(debug-env) cargo
# nightly build is currently used for rustfmt
nightly = nightly-2021-03-09

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
	$(cargo) install --path ./ --debug

run-ledger:
	# runs the node node
	$(cargo) run --bin anoman -- run-ledger

run-gossip:
	# runs the node gossip node
	$(cargo) run --bin anoman -- run-gossip

reset-ledger:
	# runs the node node
	$(cargo) run --bin anoman -- reset-ledger

audit:
	$(cargo) audit

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
	make -C matchmaker_template && \
	make -C filter_template


dev-deps:
	$(rustup) toolchain install $(nightly)
	$(rustup) component add rustfmt clippy --toolchain $(nightly)

.PHONY : build build-release clippy install run-anoma run-gossip test test-debug fmt watch clean doc build-wasm-scripts dev-deps
