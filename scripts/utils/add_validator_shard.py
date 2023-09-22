#!/usr/bin/env python3
import sys
import toml

validator_config = toml.load(sys.argv[1])

# Delete any section containing "validator.validator"
for key in list(validator_config.keys()):
    if 'validator.validator' in key:
        del validator_config[key]


alias = next(iter(validator_config['validator'].items()))[0]

validator_config['validator'][alias]['tokens'] = 6714000000
validator_config['validator'][alias]['non_staked_balance'] = 1000000000000
validator_config['validator'][alias]['validator_vp'] = 'vp_validator'
validator_config['validator'][alias]['staking_reward_vp'] = 'vp_validator'
validator_config['validator'][alias]['commission_rate'] = "0.05"
validator_config['validator'][alias]['max_commission_rate_change'] = "0.01"

network_config = toml.load(sys.argv[2])

if not network_config.get("validator"):
    network_config['validator'] = {}
network_config["validator"] |= validator_config["validator"]

print(toml.dumps(network_config))
