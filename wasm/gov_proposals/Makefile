cargo := $(env) cargo

build:
	RUSTFLAGS='-C link-arg=-s' $(cargo) build --release --target wasm32-unknown-unknown --target-dir 'target' --features init_inflation_pos_and_pgf && \
    cp "./target/wasm32-unknown-unknown/release/gov_proposals.wasm" ../init_inflation_pos_and_pgf.wasm
