import json
import glob
import hashlib
import os

gas = json.load(open("wasm/gas.json"))
checksums = {}
updated_wasms = []

for wasm in sorted(glob.glob("wasm/*.wasm")):
    basename = os.path.basename(wasm)
    file_name = (
        os.path.splitext(basename)[0]
        if wasm.count(".") == 1
        else os.path.splitext(basename)[0].split(".")[0]
    )
    file_key = "{}.wasm".format(file_name)
    file_hash = hashlib.sha256(open(wasm, "rb").read()).hexdigest()
    checksums[file_key] = {"hash": file_hash, "gas": str(gas[file_key])}

    extended_file_name = "{}.{}.wasm".format(
        file_name, hashlib.sha256(open(wasm, "rb").read()).hexdigest()
    )
    os.rename(wasm, "wasm/{}".format(extended_file_name))
    updated_wasms.append(extended_file_name)

for wasm in sorted(glob.glob("wasm/*.wasm")):
    basename = os.path.basename(wasm)
    if basename not in updated_wasms:
        os.remove(wasm)

json.dump(checksums, open("wasm/checksums.json", "w"), indent=4, sort_keys=True)
