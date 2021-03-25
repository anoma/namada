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
	$(cargo) clippy

install:
	# Warning: built in debug mode for now
	$(cargo) install --path ./ --debug

run-anoma:
	# runs the node daemon
	$(cargo) run --bin anomad -- run-anoma
run-gossip:
	# runs the node gossip daemon
	$(cargo) run --bin anomad -- run-gossip

test:
	$(cargo) test

test-debug:
	$(debug-cargo) test -- --nocapture

fmt:
	$(cargo) +$(nightly) fmt

watch:
	$(cargo) watch

clean:
	$(cargo) clean

doc:
	# build and opens the docs in browser
	$(cargo) doc --open

# Build the validity predicate and transaction wasm from templates
build-wasm-scripts:
	make -C ../vp_template && \
	make -C ../tx_template

dev-deps:
	$(rustup) toolchain install $(nightly)
	$(rustup) component add rustfmt --toolchain $(nightly)

.PHONY : build build-release clippy install run-anoma run-gossip test test-debug fmt watch clean doc build-wasm-scripts dev-deps
