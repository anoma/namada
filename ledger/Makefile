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

dev-deps:
	$(cargo) install clippy
	$(cargo) install rustfmt

clean:
	$(cargo) clean

.PHONY : build build-release run install test test-debug fmt watch dev-deps clean
