import json
import os
import subprocess
import sys

N_OF_MACHINES = 2

E2E_FILE = ".github/workflows/scripts/e2e.json"
CARGO_TEST_COMMAND = "cargo test {} -- --test-threads=1 --nocapture"

MACHINES = [{'tasks': [], 'total_time': 0} for _ in range(N_OF_MACHINES)]

CURRENT_MACHINE_INDEX = int(os.environ.get("INDEX", 1))

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
    MACHINES[machine_index]['tasks'].append(task[0])

for index, machine in enumerate(MACHINES):
    print("Machine {}: {} tasks for a total of {}s".format(index, len(machine['tasks']), machine['total_time']))
    for test in machine['tasks']:
        cargo = CARGO_TEST_COMMAND.format(test)
        print("   - {}".format(cargo))

tasks = MACHINES[CURRENT_MACHINE_INDEX]['tasks']

for test_name in tasks:
    try:
        command = CARGO_TEST_COMMAND.format(test_name)
        subprocess.check_call(command, shell=True, stdout=sys.stdout, stderr=subprocess.STDOUT)
    except:
        print("TEST FAILED: {}".format(test_name))
        print("run locally with: {}".format(command))
        break
