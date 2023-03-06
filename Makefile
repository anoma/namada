package = namada

cargo := $(env) cargo
rustup := $(env) rustup
debug-env := RUST_BACKTRACE=1 RUST_LOG=$(package)=debug
debug-cargo := $(env) $(debug-env) cargo
# Nightly build is currently used for rustfmt and clippy.
nightly := $(shell cat rust-nightly-version)

# Path to the wasm source for the provided txs and VPs
wasms := wasm/wasm_source
wasms_for_tests := wasm_for_tests/wasm_source
# Paths for all the wasm templates
wasm_templates := wasm/tx_template wasm/vp_template

# TODO upgrade libp2p
audit-ignores += RUSTSEC-2021-0076

build:
	$(cargo) build

build-test:
	$(cargo) +$(nightly) build --tests -Z unstable-options

build-release:
	NAMADA_DEV=false $(cargo) build --release --package namada_apps --manifest-path Cargo.toml

install-release:
	NAMADA_DEV=false $(cargo) install --path ./apps --locked

check-release:
	NAMADA_DEV=false $(cargo) check --release --package namada_apps

package: build-release
	scripts/make-package.sh

check-wasm = $(cargo) check --target wasm32-unknown-unknown --manifest-path $(wasm)/Cargo.toml
check:
	$(cargo) check && \
	make -C $(wasms) check && \
	make -C $(wasms_for_tests) check && \
	$(foreach wasm,$(wasm_templates),$(check-wasm) && ) true

check-abcipp:
	$(cargo) +$(nightly) check \
		--workspace \
		--exclude namada_tests \
		--exclude namada_benchmarks \
		--all-targets \
		--no-default-features \
		--features "abcipp ibc-mocks-abcipp testing" \
		-Z unstable-options

check-mainnet:
	$(cargo) check --workspace --features "mainnet"

clippy-wasm = $(cargo) +$(nightly) clippy --manifest-path $(wasm)/Cargo.toml --all-targets -- -D warnings

clippy:
	NAMADA_DEV=false $(cargo) +$(nightly) clippy --all-targets -- -D warnings && \
	make -C $(wasms) clippy && \
	make -C $(wasms_for_tests) clippy && \
	$(foreach wasm,$(wasm_templates),$(clippy-wasm) && ) true

clippy-abcipp:
	NAMADA_DEV=false $(cargo) +$(nightly) clippy --all-targets \
		--manifest-path ./apps/Cargo.toml \
		--no-default-features \
		--features "std testing abcipp" && \
	$(cargo) +$(nightly) clippy --all-targets \
		--manifest-path ./proof_of_stake/Cargo.toml \
		--features "testing" && \
	$(cargo) +$(nightly) clippy --all-targets \
		--manifest-path ./shared/Cargo.toml \
		--no-default-features \
		--features "testing wasm-runtime abcipp ibc-mocks-abcipp ferveo-tpke" && \
	$(cargo) +$(nightly) clippy \
		--all-targets \
		--manifest-path ./vm_env/Cargo.toml \
		--no-default-features && \
	make -C $(wasms) clippy && \
	$(foreach wasm,$(wasm_templates),$(clippy-wasm) && ) true

clippy-mainnet:
	$(cargo) +$(nightly) clippy --all-targets --features "mainnet" -- -D warnings

clippy-fix:
	$(cargo) +$(nightly) clippy --fix -Z unstable-options --all-targets --allow-dirty --allow-staged

install: tendermint
	NAMADA_DEV=false $(cargo) install --path ./apps --locked

tendermint:
	./scripts/get_tendermint.sh

run-ledger:
	# runs the node
	$(cargo) run --bin namadan -- ledger run

run-gossip:
	# runs the node gossip node
	$(cargo) run --bin namadan -- gossip run

reset-ledger:
	# runs the node
	$(cargo) run --bin namadan -- ledger reset

audit:
	$(cargo) audit $(foreach ignore,$(audit-ignores), --ignore $(ignore))

test: test-unit test-e2e test-wasm

# NOTE: `unstable-options` are used twice for all unit tests - 1st to compile 
# with allowing to use unstable features in test, 2nd to run with `report-time`
test-unit-coverage:
	$(cargo) +$(nightly) llvm-cov --output-dir target \
		--features namada/testing \
		--html \
		-Z unstable-options \
		-- --skip e2e -Z unstable-options --report-time

test-e2e:
	RUST_BACKTRACE=1 $(cargo) test e2e \
		-Z unstable-options \
		-- \
		--test-threads=1 \
		-Z unstable-options --report-time

test-unit-abcipp:
	$(cargo) test \
		--manifest-path ./apps/Cargo.toml \
		--no-default-features \
		--features "testing std abcipp" \
		-Z unstable-options \
		$(TEST_FILTER) -- \
		-Z unstable-options --report-time && \
	$(cargo) test \
		--manifest-path \
		./proof_of_stake/Cargo.toml \
		--features "testing" \
		-Z unstable-options \
		$(TEST_FILTER) -- \
		-Z unstable-options --report-time && \
	$(cargo) test \
		--manifest-path ./shared/Cargo.toml \
		--no-default-features \
		--features "testing wasm-runtime abcipp ibc-mocks-abcipp" \
		-Z unstable-options \
		$(TEST_FILTER) -- \
		-Z unstable-options --report-time && \
	$(cargo) test \
		--manifest-path ./vm_env/Cargo.toml \
		--no-default-features \
		--features "abcipp" \
		-Z unstable-options \
		$(TEST_FILTER) -- \
		-Z unstable-options --report-time

test-unit:
	$(cargo) +$(nightly) test \
		$(TEST_FILTER) \
		-Z unstable-options \
		-- --skip e2e \
		-Z unstable-options --report-time

test-unit-mainnet:
	$(cargo) +$(nightly) test \
		--features "mainnet" \
		$(TEST_FILTER) \
		-Z unstable-options \
		-- --skip e2e \
		-Z unstable-options --report-time

test-unit-debug:
	$(debug-cargo) +$(nightly) test \
		$(TEST_FILTER) -- \
		-Z unstable-options \
		-- --skip e2e \
		--nocapture \
		-Z unstable-options --report-time

test-wasm:
	make -C $(wasms) test

test-wasm-template = $(cargo) test \
	--manifest-path $(wasm)/Cargo.toml \
		-- \
		-Z unstable-options --report-time
test-wasm-templates:
	$(foreach wasm,$(wasm_templates),$(test-wasm-template) && ) true

test-debug:
	$(debug-cargo) test \
		-Z unstable-options \
		-- \
		--nocapture \
		-Z unstable-options --report-time

fmt-wasm = $(cargo) +$(nightly) fmt --manifest-path $(wasm)/Cargo.toml
fmt:
	$(cargo) +$(nightly) fmt --all && \
	make -C $(wasms) fmt && \
	$(foreach wasm,$(wasm_templates),$(fmt-wasm) && ) true

fmt-check-wasm = $(cargo) +$(nightly) fmt --manifest-path $(wasm)/Cargo.toml -- --check
fmt-check:
	$(cargo) +$(nightly) fmt --all -- --check && \
	make -C $(wasms) fmt-check && \
	$(foreach wasm,$(wasm_templates),$(fmt-check-wasm) && ) true

watch:
	$(cargo) watch

clean:
	$(cargo) clean

bench:
	$(cargo) +$(nightly) bench -Z unstable-options

build-doc:
	$(cargo) doc --no-deps

doc:
	# build and opens the docs in browser
	$(cargo) doc --open

build-wasm-image-docker:
	docker build -t namada-wasm - < docker/namada-wasm/Dockerfile

build-wasm-scripts-docker: build-wasm-image-docker
	docker run --rm -v ${PWD}:/__w/namada/namada namada-wasm make build-wasm-scripts

debug-wasm-scripts-docker: build-wasm-image-docker
	docker run --rm -v ${PWD}:/usr/local/rust/wasm namada-wasm make debug-wasm-scripts

# Build the validity predicate and transactions wasm
build-wasm-scripts:
	rm wasm/*.wasm || true
	make -C $(wasms)
	make opt-wasm
	make checksum-wasm

# Debug build the validity predicate and transactions wasm
debug-wasm-scripts:
	rm wasm/*.wasm || true
	make -C $(wasms) debug
	make opt-wasm
	make checksum-wasm

# need python
checksum-wasm:
	python3 wasm/checksums.py

# this command needs wasm-opt installed
opt-wasm:
	@for file in $(shell ls wasm/*.wasm); do wasm-opt -Oz -o $${file} $${file}; done

clean-wasm-scripts:
	make -C $(wasms) clean

dev-deps:
	$(rustup) toolchain install $(nightly)
	$(rustup) target add wasm32-unknown-unknown
	$(rustup) component add rustfmt clippy miri --toolchain $(nightly)
	$(cargo) install cargo-watch unclog

test-miri:
	$(cargo) +$(nightly) miri setup
	$(cargo) +$(nightly) clean
	MIRIFLAGS="-Zmiri-disable-isolation" $(cargo) +$(nightly) miri test


.PHONY : build check build-release clippy install run-ledger run-gossip reset-ledger test test-debug fmt watch clean build-doc doc build-wasm-scripts-docker debug-wasm-scripts-docker build-wasm-scripts debug-wasm-scripts clean-wasm-scripts dev-deps test-miri test-unit test-unit-abcipp clippy-abcipp bench-gas
