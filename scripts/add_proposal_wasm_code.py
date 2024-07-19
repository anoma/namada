import json
import argparse

parser = argparse.ArgumentParser(description='Bingbong')
parser.add_argument('--proposal-path', type=str, help='Path to the proposal json file')
parser.add_argument('--wasm-path', type=str, help='Path to the wasm code to attach as proposal data')

args = parser.parse_args()

wasm_path = args.wasm_path
with open(wasm_path, 'rb') as f:
    wasm_bytes = list(f.read())

proposal_path = args.proposal_path.strip().replace(" ", "")

print("Proposal path: ", proposal_path)
with open(proposal_path, 'r') as f:
    proposal = json.load(f)

proposal['data'] = wasm_bytes
new_proposal_path = proposal_path.replace(".json", "_edited.json")
with open(new_proposal_path, 'w') as f:
    json.dump(proposal, f)

print(f"Add wasm to {proposal_path}")