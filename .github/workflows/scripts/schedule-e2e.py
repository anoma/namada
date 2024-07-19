import json
import os
import subprocess
import sys

N_OF_MACHINES = int(os.environ.get("N_OF_MACHINES", 5))
CURRENT_MACHINE_INDEX = int(os.environ.get("INDEX", 1))

NIGHTLY_VERSION = open("rust-nightly-version", "r").read().strip()

E2E_FILE = ".github/workflows/scripts/e2e.json"
CARGO_TEST_COMMAND = "cargo +{} nextest run -E '{}' --test-threads 1 --no-fail-fast"

MACHINES = [{'tasks': [], 'time': [], 'total_time': 0} for _ in range(N_OF_MACHINES)]

def find_freer_machine():
    minimum_work = 60 * 60 * 24 # 1 day in seconds
    minimum_work_machine_index = -1
    for index, machine in enumerate(MACHINES):
        if machine['total_time'] < minimum_work:
            minimum_work_machine_index = index
            minimum_work = machine['total_time']
    return minimum_work_machine_index

e2e_list = json.load(open(E2E_FILE, "r"))
sorted_task = dict(sorted(e2e_list.items(), key=lambda item: item[1], reverse=True))

for task in sorted_task.items():
    machine_index = find_freer_machine()
    MACHINES[machine_index]['total_time'] += task[1]
    MACHINES[machine_index]['tasks'].append({
        'name': task[0],
        'time': task[1]
    })

tasks = MACHINES[CURRENT_MACHINE_INDEX]['tasks']

test_filter = ' + '.join(['test(={})'.format(task['name']) for task in tasks ])

command = CARGO_TEST_COMMAND.format(NIGHTLY_VERSION, test_filter)
subprocess.check_call(command, shell=True, stdout=sys.stdout, stderr=subprocess.STDOUT)