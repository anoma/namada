#!/bin/sh
# depends on cargo-release 0.24.4, git 2.24.0 or later, unclog 0.5.0
set -e

if [ -z "$1" ]; then
  echo "please specify a version to release"
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)

if [ "$REPO_ROOT" != "$PWD" ]; then
  echo "please run from repository root"
  exit 1
fi

VERSION="$1"
TAG_NAME="v$1"

# start from a clean build
git clean -fxd

# update the main workspace crate versions (1 commit)
HASH_BEFORE=$(git rev-parse HEAD)
cargo release --execute $VERSION
HASH_AFTER=$(git rev-parse HEAD)

# update the wasm crate versions (2 fixups)
cd $REPO_ROOT/wasm
cargo update -w
git add Cargo.lock
git commit --fixup=$HASH_AFTER
cargo release --execute $VERSION

# update the wasm_for_tests crate version, and rebuild them (3 fixups)
cd $REPO_ROOT/wasm_for_tests/wasm_source
cargo update -w
git add Cargo.lock
git commit --fixup=$HASH_AFTER
cargo release --execute $VERSION
make all
git add ../*.wasm
git commit --fixup=$HASH_AFTER

# build the wasm checksums (1 fixup)
cd $REPO_ROOT
make build-wasm-scripts-docker
git add wasm/checksums.json
git commit --fixup=$HASH_AFTER

# update the changelog (1 fixup)
unclog release $TAG_NAME
unclog build > CHANGELOG.md
git add .changelog CHANGELOG.md
git commit --fixup=$HASH_AFTER

# show the user the result
git rebase --interactive --autosquash --keep-base $HASH_BEFORE

echo "final $TAG_NAME commit ready for testing"
