cargo = $(env) cargo
rustup = $(env) rustup

build-release:
	$(cargo) build --release && \
	cp "./target/wasm32-unknown-unknown/release/filter.wasm" filter.wasm

build:
	$(cargo) build

clippy:
	$(cargo) clippy

fmt:
	$(cargo) fmt

watch:
	$(cargo) watch

clean:
	$(cargo) clean

deps:
	$(rustup) target add wasm32-unknown-unknown

.PHONY : build-release build clippy fmt watch clean deps
