package = anoma

cargo := $(env) cargo
rustup := $(env) rustup
debug-env := RUST_BACKTRACE=1 RUST_LOG=$(package)=debug
debug-cargo := $(env) $(debug-env) cargo
# Nightly build is currently used for rustfmt and clippy.
# NOTE On change also update `RUSTFMT_TOOLCHAIN` in `apps/build.rs`.
nightly := nightly-2021-03-09

# Paths for all the wasm sources
tx_wasms := $(dir $(wildcard txs/*/.))
vp_wasms := $(dir $(wildcard vps/*/.))	
wasms := $(tx_wasms) $(vp_wasms) matchmaker_template filter_template

build:
	$(cargo) build

build-release:
	$(cargo) build --release

clippy-wasm = $(cargo) +$(nightly) clippy --manifest-path $(wasm)/Cargo.toml
clippy:
	$(cargo) +$(nightly) clippy && \
	$(foreach wasm,$(wasms),$(clippy-wasm) && ) true

clippy-check-wasm = $(cargo) +$(nightly) clippy --manifest-path $(wasm)/Cargo.toml -- -D warnings
clippy-check:
	$(cargo) +$(nightly) clippy -- -D warnings && \
	$(foreach wasm,$(wasms),$(clippy-check-wasm) && ) true

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
	$(cargo) audit

test-wasm = $(cargo) test --manifest-path $(wasm)/Cargo.toml
test:
	$(cargo) test && \
	$(foreach wasm,$(wasms),$(test-wasm) && ) true

test-debug:
	$(debug-cargo) test -- --nocapture

fmt-wasm = $(cargo) +$(nightly) fmt --manifest-path $(wasm)/Cargo.toml
fmt:
	$(cargo) +$(nightly) fmt --all && \
	$(foreach wasm,$(wasms),$(fmt-wasm) && ) true

fmt-check-wasm = $(cargo) +$(nightly) fmt --manifest-path $(wasm)/Cargo.toml -- --check
fmt-check:
	$(cargo) +$(nightly) fmt --all -- --check && \
	$(foreach wasm,$(wasms),$(fmt-check-wasm) && ) true

watch:
	$(cargo) watch

clean:
	$(cargo) clean

doc:
	# build and opens the docs in browser
	$(cargo) doc --open

# Build the validity predicate, transactions, matchmaker and matchmaker filter wasm
build-wasm = make -C $(wasm)
build-wasm-scripts:
	$(foreach wasm,$(wasms),$(build-wasm) && ) true

dev-deps:
	$(rustup) toolchain install $(nightly)
	$(rustup) component add rustfmt clippy --toolchain $(nightly)
	$(cargo) install cargo-watch

.PHONY : build build-release clippy install run-anoma run-gossip test test-debug fmt watch clean doc build-wasm-scripts dev-deps
