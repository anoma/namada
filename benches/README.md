# Benchmarks

The benchmarks are built with [criterion.rs](https://bheisler.github.io/criterion.rs/book).

To enable tracing logs, run with e.g. `RUST_LOG=debug`.

To ensure that the benches can run successfully without performing measurement, you can run `make test-benches` from the workspace run.

To test a selected bench can run successfully on a single run, use can use e.g.:

```shell
cargo test --bench native_vps
```

To benchmark a selected bench with a minimum sample size use e.g.:

```shell
cargo bench --bench whitelisted_txs -- --sample-size 10
```
