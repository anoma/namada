import json
import glob
import hashlib
import os

CURRENT_FOLDER = os.path.dirname(os.path.realpath(__file__))
WASM_EXTENSION = ".wasm"
WASM_FOLDER = "{}/../wasm".format(CURRENT_FOLDER)
CHECKSUM_FILE_PATH = "{}/checksums.json".format(WASM_FOLDER)


checksums = {}
for wasm in sorted(glob.glob("{}/*.opt.wasm".format(WASM_FOLDER))):
    basename = os.path.basename(wasm)
    file_name = os.path.splitext(basename)[0] if wasm.count(
        ".") == 1 else os.path.splitext(basename)[0].split('.')[0]
    checksums["{}{}".format(file_name, WASM_EXTENSION)] = "{}.{}.wasm".format(
        file_name, hashlib.sha256(open(wasm, "rb").read()).hexdigest())
    
    os.rename(wasm, 'wasm/{}'.format(checksums["{}{}".format(file_name, WASM_EXTENSION)]))

updated_wasms = list(checksums.values())

for wasm in sorted(glob.glob("{}/*.wasm".format(WASM_FOLDER))):
    basename = os.path.basename(wasm)
    if not basename in updated_wasms:
        os.remove(wasm)

with open(CHECKSUM_FILE_PATH, 'w+') as f:
    json.dump(checksums, f, indent=4, sort_keys=True)
