#!/usr/bin/env bash

set -Eo pipefail

HERMES_MAJORMINOR="1.7"
HERMES_PATCH="4"
HERMES_SUFFIX="-namada-beta7"

HERMES_REPO="https://github.com/heliaxdev/hermes"

HERMES_VERSION="${HERMES_MAJORMINOR}.${HERMES_PATCH}${HERMES_SUFFIX}"

TARGET_PATH="/usr/local/bin"
TMP_PATH="/tmp"

error_exit()
{
    echo "Error: $1" >&2
    exit 1
}

read -r SYSTEM MACHINE <<< "$(uname -s -m)"

if [[ $SYSTEM = "Darwin" ]]; then
  SYSTEM="apple-darwin"
else
  SYSTEM="unknown-linux-gnu"
fi

ARCH="x86_64"
if [[ $MACHINE = "aarch64" ]] || [[ $MACHINE = "arm64" ]]; then
  ARCH="aarch64"
fi

RELEASE_URL=${HERMES_REPO}/releases/download/v${HERMES_VERSION}/hermes-v${HERMES_VERSION}-${ARCH}-${SYSTEM}.tar.gz
echo "$RELEASE_URL"

curl -LsSfo "$TMP_PATH"/hermes.tar.gz "$RELEASE_URL" || error_exit "hermes release download failed"

cd $TARGET_PATH
sudo tar -xvzf $TMP_PATH/hermes.tar.gz hermes || error_exit "hermes release extraction failed"
