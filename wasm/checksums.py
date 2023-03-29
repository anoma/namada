import json
import glob
import hashlib
import os

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
    extended_file_name = "{}.{}.wasm".format(
        file_name, hashlib.sha256(open(wasm, "rb").read()).hexdigest()
    )
    checksums[file_key] = {"hash": extended_file_name, "gas": str(gas[file_key])}

    os.rename(wasm, "wasm/{}".format(checksums[file_key]["hash"]))

updated_wasms = [value["hash"] for value in checksums.values()]

for wasm in sorted(glob.glob("wasm/*.wasm")):
    basename = os.path.basename(wasm)
    if basename not in updated_wasms:
        os.remove(wasm)

json.dump(checksums, open("wasm/checksums.json", "w"), indent=4, sort_keys=True)
