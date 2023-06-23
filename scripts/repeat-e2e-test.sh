#!/bin/sh
# Run an e2e test at most n times, exit at first failure.
# This can be handy for testing of non-deterministic issues that are tricky to
# reproduce.
#
# The first arg is the max number of repetitions and second is the exact name 
# of the test.
#
# Usage example:
# $ scripts/repeat-e2e-test.sh 10 e2e::ledger_tests::run_ledger
#
# Adapted from https://gitlab.com/tezos/tezos/-/blob/master/tests_python/scripts/repeat_test.sh

NUM=$1
TEST=$2
# Thanks internet https://stackoverflow.com/a/4774063/3210255
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
NIGHTLY=$(cat "$SCRIPTPATH"/../rust-nightly-version)

for i in $(seq 1 "$NUM")
do
    echo "Execution $i/$NUM"
    if ! RUST_BACKTRACE=1 NAMADA_E2E_KEEP_TEMP=true NAMADA_E2E_DEBUG=true cargo "+$NIGHTLY" test "$TEST" -- --exact --test-threads=1 --nocapture; then
        exit 1
    fi
done
exit 0


