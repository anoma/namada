# Benchmarks

The benchmarks are built with [criterion.rs](https://bheisler.github.io/criterion.rs/book).

Measurements are taken on the elapsed wall-time.

The benchmarks only focus on successful transactions and vps: in case of failure, the bench function shall panic to avoid timing incomplete execution paths.

In addition, this crate also contains benchmarks for `WrapperTx` (`namada_apps_lib::tx::wrapper::WrapperTx`) validation and `host_env` (`namada_vm::host_env`) exposed functions that define the gas constants of `gas` (`namada_apps_lib::gas`).

For more realistic results these benchmarks should be run on all the combination of supported OS/architecture.

## Testing & running

To enable tracing logs, run with e.g. `RUST_LOG=debug`.

To ensure that the benches can run successfully without performing measurement, you can run `make test-benches` from the workspace run.

To test a selected bench can run successfully on a single run, use can use e.g.:

```shell
cargo test --bench native_vps
```

To benchmark a selected bench with a minimum sample size use e.g.:

```shell
cargo bench --bench native_vps -- --sample-size 10
```
