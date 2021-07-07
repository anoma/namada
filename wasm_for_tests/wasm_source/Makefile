cargo = $(env) cargo
rustup = $(env) rustup

# All the wasms that can be built from this source, switched via Cargo features
# Wasms can be added via the Cargo.toml `[features]` list.
wasms := tx_memory_limit
wasms += tx_no_op
wasms += tx_read_storage_key
wasms += vp_always_false
wasms += vp_always_true
wasms += vp_eval
wasms += vp_memory_limit
wasms += vp_read_storage_key


all: $(wasms)

# Build a selected wasm
$(wasms): %:
	$(cargo) build --release --target wasm32-unknown-unknown --features $@ && \
	cp "./target/wasm32-unknown-unknown/release/anoma_wasm_for_tests.wasm" ../$@.wasm

# `cargo check` one of the wasms, e.g. `make check_tx_no_op`
$(patsubst %,check_%,$(wasms)): check_%:
	$(cargo) check --target wasm32-unknown-unknown --features $*

# `cargo watch` one of the wasms, e.g. `make watch_tx_no_op`
$(patsubst %,watch_%,$(wasms)): watch_%:
	$(cargo) watch --features $*

clean-wasm = rm ../$(wasm).wasm
clean:
	$(foreach wasm,$(wasms),$(clean-wasm) && ) true

deps:
	$(rustup) target add wasm32-unknown-unknown

.PHONY : all clean deps
