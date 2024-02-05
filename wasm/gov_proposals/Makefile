cargo := $(env) cargo

build:
	RUSTFLAGS='-C link-arg=-s' $(cargo) build --release --target wasm32-unknown-unknown --target-dir 'target' --features param_change_gov_proposal && \
    cp "./target/wasm32-unknown-unknown/release/gov_proposals.wasm" ../param-change-gov-proposal.wasm
