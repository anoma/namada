# Fuzz testing

- Uses [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) which depends on LLVM libFuzzer
- When ran, a target generates arbitrary input setup for the test. This can be structured data with derived or manually implemented [`trait Arbitrary`](https://crates.io/crates/arbitrary)
- To ensure that the fuzzer explored all interesting branches fuzz testing is used together with code coverage reports

## How to run

- Install
  - `cargo install cargo-fuzz` - the runner
  - `cargo install rustfilt` - symbol demangler which makes coverage reports easier to read
- Run e.g. `make fuzz-txs-mempool` (uses nightly)
- If there is any crash, the fuzzer has found an issue. Read the stack trace for details. It will also print instructions on how to re-run the same case.
- When there are no panics you'll see it printing statistics. E.g. `cov: 26771 ft: 111572 corp: 2688/1423Kb lim: 2369 exec/s: 39 rss: 647Mb L: 2232/2335 MS: 5`
- The important stat you'll want to look watch is the very first one - `cov` - "Total number of code blocks or edges covered by executing the current corpus." (more details at <https://llvm.org/docs/LibFuzzer.html#output>)
- After the number in `cov` seems to have settled and is no longer increasing, the fuzzer has most likely explored all possible branches. We're going to check that next with coverage.
- To generate raw coverage data, run e.g. `cargo +$(cat rust-nightly-version) fuzz coverage txs_mempool --dev`. This will create `fuzz/coverage/txs_mempool/coverage.profdata` (the path gets printed at the end).
- To turn the raw coverage data into a report:
  - Find the system root for the nightly toolchain with `rustc +$(cat rust-nightly-version) --print sysroot`
    - Use `llvm-cov` installed with this toolchain in `lib/rustlib/x86_64-unknown-linux-gnu/bin/` sub-dir of the sysroot
    - The path to `llvm-cov` has to be the one provided by nightly toolchain. Using an unmatched version (e.g. a system-wide installation) will likely make it fail with: "Failed to load coverage: unsupported instrumentation profile format version"
  - Provide the path to the built target, e.g. `target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/debug/txs_mempool`
  - `--ignore-filename-regex` is used to avoid getting coverage for dependencies
  - The full command is e.g.:

  ```bash
  /home/ubuntu/.rustup/toolchains/nightly-2024-05-15-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov \
    show \
    target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/debug/txs_mempool \
    --format=html \
    --ignore-filename-regex="(/rustc|\.cargo)" \
    -Xdemangler=rustfilt \
    -instr-profile=fuzz/coverage/txs_mempool/coverage.profdata \
    > index.html
  ```

  - Open the `index.html` in the browser. It's usually quite large and can take a while to fully load be searchable (you can also extend `--ignore-filename-regex` with paths that you're not interested in to trim it down). Red code means that the fuzzer didn't reach the colored lines. Otherwise, the second column from the left indicates a number of times a given line has been covered.
  - If some code that should be fuzzed isn't covered, you may need to add conditional compilation. Refer to [Side notes](#side-notes) below.

## Side notes

- `#[cfg(fuzzing)]` may be used to turn off certain code paths - for example:
  - to make a tx signature verification always pass as an arbitrary tx is never going to have a valid signature
  - to make a tx fee check pass even when the source doesn't have sufficient balance
  - to make a tx fee check pass with an invalid token address
- In release build, fuzzer compilation of the `namada_node` crate requires crazy amount of memory (ran out on 64GB machine). To get around it, we're only using debug build (corresponds `--dev` flag for `cargo fuzz`), but this build is still configured with `opt-level=3` so there should be no perceivable slowdown.
