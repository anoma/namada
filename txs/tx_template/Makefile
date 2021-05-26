cargo = $(env) cargo
rustup = $(env) rustup

build-release:
	$(cargo) build --release --target wasm32-unknown-unknown && \
	cp "./target/wasm32-unknown-unknown/release/tx_template.wasm" tx.wasm

build:
	$(cargo) build --target wasm32-unknown-unknown

watch:
	$(cargo) watch

clean:
	$(cargo) clean

deps:
	$(rustup) target add wasm32-unknown-unknown

.PHONY : build-release build watch clean deps
