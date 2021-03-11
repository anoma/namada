package = Anoma

# env = OPENSSL_INCLUDE_DIR="/usr/local/opt/openssl/include"
cargo = $(env) cargo
debug-env = RUST_BACKTRACE=1 RUST_LOG=$(package)=debug
debug-cargo = $(env) $(debug-env) cargo

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
run-orderbook:
	# runs the node orderbook daemon
	$(cargo) run --bin anomad -- run-orderbook

test:
	$(cargo) test

test-debug:
	$(debug-cargo) test -- --nocapture

fmt:
	$(cargo) fmt

watch:
	$(cargo) watch

clean:
	$(cargo) clean

doc:
	# build and opens the docs in browser
	$(cargo) doc --open

.PHONY : build build-release run install test test-debug fmt watch dev-deps clean doc
