cargo := $(env) cargo
rustup := $(env) rustup
# Nightly build is currently used for rustfmt and clippy.
nightly := $(shell cat ../../rust-nightly-version)

# All the wasms that can be built from this source, switched via Cargo features
# Wasms can be added via the Cargo.toml `[features]` list.
wasms := tx_bond
wasms += tx_bridge_pool
wasms += tx_change_validator_commission
wasms += tx_change_consensus_key
wasms += tx_change_validator_metadata
wasms += tx_claim_rewards
wasms += tx_deactivate_validator
wasms += tx_ibc
wasms += tx_init_account
wasms += tx_init_proposal
wasms += tx_become_validator
wasms += tx_redelegate
wasms += tx_reactivate_validator
wasms += tx_reveal_pk
wasms += tx_transfer
wasms += tx_unbond
wasms += tx_unjail_validator
wasms += tx_update_account
wasms += tx_vote_proposal
wasms += tx_withdraw
wasms += tx_update_steward_commission
wasms += tx_resign_steward
wasms += vp_implicit
wasms += vp_user

# Build all wasms in release mode
all: $(wasms)

# Build all wasms in debug mode
debug:
	$(foreach wasm,$(wasms),make debug_$(wasm) && ) true

# `cargo check` all wasms
check:
	$(foreach wasm,$(wasms),make check_$(wasm) && ) true

# `cargo test` all wasms
test:
	$(foreach wasm,$(wasms),make test_$(wasm) && ) true

# `cargo clippy` all wasms
clippy:
	$(foreach wasm,$(wasms),make clippy_$(wasm) && ) true

clippy-fix:
	$(cargo) +$(nightly) clippy --fix -Z unstable-options --all-targets --allow-dirty --allow-staged

fmt:
	$(cargo) +$(nightly) fmt --all

fmt-check:
	$(cargo) +$(nightly) fmt --all -- --check

# Build a selected wasm
# Linker flag "-s" for stripping (https://github.com/rust-lang/cargo/issues/3483#issuecomment-431209957)
$(wasms): %:
	RUSTFLAGS='-C link-arg=-s' $(cargo) build --release --target wasm32-unknown-unknown --target-dir 'target' --features $@ && \
	cp "./target/wasm32-unknown-unknown/release/namada_wasm.wasm" ../$@.wasm

# Build a selected wasm in debug mode
$(patsubst %,debug_%,$(wasms)): debug_%:
	RUSTFLAGS='-C link-arg=-s' $(cargo) build --target wasm32-unknown-unknown --target-dir 'target' --features $* && \
	cp "./target/wasm32-unknown-unknown/debug/namada_wasm.wasm" ../$*.wasm

# `cargo check` one of the wasms, e.g. `make check_tx_transfer`
$(patsubst %,check_%,$(wasms)): check_%:
	$(cargo) check --target wasm32-unknown-unknown --features $*

# `cargo test` one of the wasms, e.g. `make test_tx_transfer`
$(patsubst %,test_%,$(wasms)): test_%:
	$(cargo) +$(nightly) test --features $* \
		-- \
		-Z unstable-options --report-time

# `cargo watch` one of the wasms, e.g. `make watch_tx_transfer`
$(patsubst %,watch_%,$(wasms)): watch_%:
	$(cargo) watch --features $*

# `cargo clippy` one of the wasms, e.g. `make clippy_tx_transfer`
$(patsubst %,clippy_%,$(wasms)): clippy_%:
	$(cargo) +$(nightly) clippy --all-targets --features $* -- -D warnings

clean-wasm = rm ../$(wasm).*.wasm
clean:
	$(foreach wasm,$(wasms),$(clean-wasm) && ) true

deps:
	$(rustup) target add wasm32-unknown-unknown

.PHONY : all debug check test clippy fmt fmt-check clean deps
