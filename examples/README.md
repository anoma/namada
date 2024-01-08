# Examples
This directory contains examples and additional tooling to help in the
development of Namada. The currently provided examples are listed below:
## `generate-txs`
This utility serves to randomly generate Namada transaction test vectors
offline. These test vectors are useful for ensuring compatibility with hardware
wallets. This example is included in the Namada repository in order to ensure
that the test vector generation logic is maintained and remains up to date with
the latest changes in transaction formats.
### Usage
This example is run as follows:
```
cargo run --example generate-txs -- <vectors.json> <debugs.txt>
```
where `<vectors.json>` is the path where the JSON test vectors will be stored
and `<debugs.txt>` is where rust `Debug` representations oof this data will be
stored.
