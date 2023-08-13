# MASP proofs for tests

This directory contains pre-built MASP transaction proofs used to speed-up integration tests.

```shell
# Run the tests with the saved proofs from here.
make test-integration

# Delete old proofs, run the tests and save the new proofs.
make test-integration-save-proofs
```
