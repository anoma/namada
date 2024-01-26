#!/usr/bin/env bash

set -Eo pipefail

# an examplary download-url
# https://github.com/tendermint/tendermint/releases/download/v0.34.13/tendermint_0.34.13_linux_amd64.tar.gz
# https://github.com/heliaxdev/tendermint/releases/download/v0.1.1-abcipp/tendermint_0.1.0-abcipp_darwin_amd64.tar.gz
TM_MAJORMINOR="0.37"
TM_PATCH="1"
TM_SUFFIX=""
TM_REPO="https://github.com/cometbft/cometbft"

TM_VERSION="${TM_MAJORMINOR}.${TM_PATCH}${TM_SUFFIX}"

TARGET_PATH="/usr/local/bin"
TMP_PATH="/tmp"

error_exit()
{
    echo "Error: $1" >&2
    exit 1
}

# check for existence
TM_EXECUTABLE=$(which cometbft)
if [ -x "$TM_EXECUTABLE" ]; then
  TM_EXISTS_VER=$(${TM_EXECUTABLE} version)
fi

if [[ $TM_EXISTS_VER == "${TM_MAJORMINOR}" ]]; then
  echo "tendermint already exists in your current PATH with a sufficient version = $TM_EXISTS_VER"
  echo "tendermint is located at = $(which cometbft)"
  exit
fi

read -r SYSTEM MACHINE <<< "$(uname -s -m)"

ARCH="amd64"
if [[ $MACHINE = "aarch64" ]] || [[ $MACHINE = "arm64" ]]; then
  ARCH="arm64"
fi

RELEASE_URL="${TM_REPO}/releases/download/v${TM_VERSION}/cometbft_${TM_VERSION}_$(echo "${SYSTEM}" | tr '[:upper:]' '[:lower:]')_${ARCH}.tar.gz"
echo "$RELEASE_URL"

curl -LsSfo "$TMP_PATH"/cometbft.tar.gz "$RELEASE_URL" || error_exit "tendermint release download failed"

cd $TARGET_PATH
sudo tar -xvzf $TMP_PATH/cometbft.tar.gz tendermint || error_exit "tendermint release extraction failed"
