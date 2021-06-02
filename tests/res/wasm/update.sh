#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

make -C $SCRIPTPATH/../../../vps/vp_template
cp $SCRIPTPATH/../../../vps/vp_template/vp.wasm $SCRIPTPATH/vp_template.wasm