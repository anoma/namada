import json
import os
import subprocess
import sys
import time

TESTS = [
    "integration::ledger_tests::change_validator_metadata",
    "integration::ledger_tests::implicit_account_reveal_pk",
    "integration::ledger_tests::invalid_transactions",
    "integration::ledger_tests::ledger_txs_and_queries",
    "integration::ledger_tests::pgf_governance_proposal",
    "integration::ledger_tests::pgf_steward_change_commission",
    "integration::ledger_tests::pos_rewards",
    "integration::ledger_tests::proposal_submission",
    "integration::ledger_tests::test_bond_queries",
    "integration::masp::cross_epoch_unshield",
    "integration::masp::dynamic_assets",
    "integration::masp::masp_incentives",
    "integration::masp::masp_pinned_txs",
    "integration::masp::masp_txs_and_queries",
    "integration::masp::multiple_unfetched_txs_same_block",
    "integration::masp::spend_unconverted_asset_type",
    "integration::masp::wrapper_fee_unshielding",
    "integration::masp::wrapper_fee_unshielding_out_of_gas",
]

NIGHTLY_VERSION = open("rust-nightly-version", "r").read().strip()
CARGO_TEST_COMMAND = "RUST_BACKTRACE=1 cargo +{} test --lib {} --features integration -Z unstable-options -- --test-threads=1 --exact -Z unstable-options --report-time"

test_results = {}
has_failures = False

for task in TESTS:
    try:
        command = CARGO_TEST_COMMAND.format(NIGHTLY_VERSION, task)
        start = time.time()
        subprocess.check_call(command, shell=True, stdout=sys.stdout, stderr=subprocess.STDOUT)
        end = time.time()
        test_results[task] = {
            'status': 'ok',
            'time': round(end - start, 2),
            'command': command
        }
    except:
        test_results[task] = {
            'status': 'fail',
            'time': -1,
            'command': command
        }
        has_failures = True
        continue

for test_name in test_results.keys():
    test_status = test_results[test_name]['status']
    time = test_results[test_name]['time']
    print("- Test {} ({}s) -> status: {}".format(test_name, time, test_status))
    if test_results[test_name]['status'] != 'ok':
        test_command = test_results[test_name]['command']
        print("     Run locally with: {}".format(test_command))

if has_failures:
    exit(1)