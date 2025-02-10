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

# update the apps crate versions (1 commit)
HASH_BEFORE=$(git rev-parse HEAD)
cd $REPO_ROOT/crates/apps
cargo release version --execute $VERSION
git commit -am "Namada $VERSION"
HASH_AFTER=$(git rev-parse HEAD)

# update the changelog
cd $REPO_ROOT
unclog release $TAG_NAME
unclog build > CHANGELOG.md
git add .changelog CHANGELOG.md
git commit --message "Changelog: Release apps $VERSION"

# show the user the result
git rebase --interactive --autosquash --keep-base $HASH_BEFORE

echo "final $TAG_NAME commit ready for testing"

