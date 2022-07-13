FROM ghcr.io/james-chf/devchain-container:sha-8e60590
COPY target/x86_64-unknown-linux-gnu/small/anoma /usr/local/bin
COPY target/x86_64-unknown-linux-gnu/small/anomac /usr/local/bin
COPY target/x86_64-unknown-linux-gnu/small/anoman /usr/local/bin
COPY target/x86_64-unknown-linux-gnu/small/anomaw /usr/local/bin
COPY wasm_for_tests/tx_log.wasm wasm_for_tests/tx_log.wasm