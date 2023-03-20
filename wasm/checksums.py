import json
import glob
import hashlib
import os
import sys

gas = json.load(open("wasm/gas.json"))
checksums = {}

for wasm in sorted(glob.glob("wasm/*.wasm")):
    basename = os.path.basename(wasm)
    file_name = (
        os.path.splitext(basename)[0]
        if wasm.count(".") == 1
        else os.path.splitext(basename)[0].split(".")[0]
    )
    file_key = "{}.wasm".format(file_name)
    checksums[file_key] = "{}.{}.wasm".format(
        file_name, hashlib.sha256(open(wasm, "rb").read()).hexdigest()
    )

    # Check gas in whitelist
    if file_key not in gas:
        print("{} doesn't have an associated gas cost in gas.json".format(file_key))
        sys.exit(1)

    os.rename(wasm, "wasm/{}".format(checksums[file_key]))

# Prune unused gas entries if needed (in case of a tx/vp removal)
for k in list(gas.keys()):
    if k not in checksums:
        del gas[k]

json.dump(gas, open("wasm/gas.json", "w"), indent=4, sort_keys=True)

updated_wasms = list(checksums.values())

for wasm in sorted(glob.glob("wasm/*.wasm")):
    basename = os.path.basename(wasm)
    if basename not in updated_wasms:
        os.remove(wasm)

json.dump(checksums, open("wasm/checksums.json", "w"), indent=4, sort_keys=True)
