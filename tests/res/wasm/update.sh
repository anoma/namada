#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# build the vp_template wasm using docker
docker run --rm -v ${PWD/../../..}:/usr/local/rust/project anoma-wasm make -C wasm/vps/vp_template

# copy the built wasm into here
cp $SCRIPTPATH/../../../wasm/vps/vp_template/vp.wasm $SCRIPTPATH/vp_template.wasm