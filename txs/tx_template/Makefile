cargo = $(env) cargo
rustup = $(env) rustup
wasm = tx.wasm

build-release:
	$(cargo) build --release && \
	cp "./target/wasm32-unknown-unknown/release/tx_template.wasm" $(wasm)

build:
	$(cargo) build

clippy:
	$(cargo) clippy

fmt:
	$(cargo) fmt

watch:
	$(cargo) watch

clean:
	$(cargo) clean && if [ -e $(wasm) ]; then rm $(wasm); fi

deps:
	$(rustup) target add wasm32-unknown-unknown

.PHONY : build-release build clippy fmt watch clean deps
