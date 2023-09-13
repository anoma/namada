import sys

if len(sys.argv) != 3:
    print("Usage: python script.py CHAIN_ID_A CHAIN_ID_B")
    sys.exit(1)

CHAIN_ID_A = sys.argv[1]
CHAIN_ID_B = sys.argv[2]

config_content = """
[global]
log_level = 'info'

[mode]

[mode.clients]
enabled = true
refresh = true
misbehaviour = true

[mode.connections]
enabled = false

[mode.channels]
enabled = false

[mode.packets]
enabled = true
clear_interval = 10
clear_on_start = false
tx_confirmation = true

[telemetry]
enabled = false
host = '127.0.0.1'
port = 3001

[[chains]]
id = 'local.21dbb046494e45859ec2af32'
type = 'namada'
rpc_addr = 'http://127.0.0.1:26657'
grpc_addr = 'http://127.0.0.1:9090'
event_source = { mode = 'push', url = 'ws://127.0.0.1:26657/websocket', batch_delay = '500ms' }
account_prefix = ''
key_name = 'relayer'
store_prefix = 'ibc'
gas_price = { price = 0.001, denom = 'nam' }

[[chains]]
id = 'local.c494d99978173902e92aafca'
type = 'namada'
rpc_addr = 'http://127.0.0.1:27657'
grpc_addr = 'http://127.0.0.1:9090'
event_source = { mode = 'push', url = 'ws://127.0.0.1:28657/websocket', batch_delay = '500ms' }
account_prefix = ''
key_name = 'relayer'
store_prefix = 'ibc'
gas_price = { price = 0.001, denom = 'nam' }
"""

# Write the configuration to the file
with open('config.toml', 'w') as config_file:
    config_file.write(config_content)

print("Configuration written to config.toml")