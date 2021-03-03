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

run:
	# runs the node daemon
	$(cargo) run --bin anomad -- run

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

# Build the validity predicate and transaction wasm from templates
build-wasm-scripts:
	make -C ../vp_template && \
	make -C ../tx_template

.PHONY : build build-release clippy install run test test-debug fmt watch clean doc build-wasm-scripts
