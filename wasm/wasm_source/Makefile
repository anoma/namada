cargo = $(env) cargo
rustup = $(env) rustup

# All the wasms that can be built from this source, switched via Cargo features
# Wasms can be added via the Cargo.toml `[features]` list.
wasms := tx_from_intent
wasms += tx_transfer
wasms += tx_update_vp
wasms += vp_token
wasms += vp_user

all: $(wasms)

# Build a selected wasm
$(wasms): %:
	$(cargo) build --release --target wasm32-unknown-unknown --features $@ && \
	cp "./target/wasm32-unknown-unknown/release/anoma_wasm.wasm" ../$@.wasm

# `cargo check` one of the wasms, e.g. `make check_tx_transfer`
$(patsubst %,check_%,$(wasms)): check_%:
	$(cargo) check --target wasm32-unknown-unknown --features $*

# `cargo watch` one of the wasms, e.g. `make watch_tx_transfer`
$(patsubst %,watch_%,$(wasms)): watch_%:
	$(cargo) watch --features $*

clean-wasm = rm ../$(wasm).wasm
clean:
	$(foreach wasm,$(wasms),$(clean-wasm) && ) true

deps:
	$(rustup) target add wasm32-unknown-unknown

.PHONY : all clean deps
