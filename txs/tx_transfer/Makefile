cargo = $(env) cargo
rustup = $(env) rustup
wasm = tx.wasm

build-release:
	$(cargo) build --release --target wasm32-unknown-unknown && \
	cp "./target/wasm32-unknown-unknown/release/tx_transfer.wasm" $(wasm)

build:
	$(cargo) build --target wasm32-unknown-unknown

watch:
	$(cargo) watch

clean:
	$(cargo) clean && if [ -e $(wasm) ]; then rm $(wasm); fi

deps:
	$(rustup) target add wasm32-unknown-unknown

.PHONY : build-release build watch clean deps
