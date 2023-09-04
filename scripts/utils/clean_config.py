
import sys
import toml

# Load the TOML file
with open(sys.argv[1], 'r') as file:
    data = toml.load(file)

# Function to remove sections and keys with "validator.validator" in their names
def remove_validator_sections_and_keys(data):
    new_data = {}
    for key, value in data.items():
        if isinstance(value, dict):
            if not key.startswith('validator'):
                new_data[key] = remove_validator_sections_and_keys(value)
        elif not (key.startswith('validator.validator') or key.endswith('.public_key')):
            new_data[key] = value
    return new_data

# Remove validator sections and keys
data = remove_validator_sections_and_keys(data)

# Save the modified data back to the TOML file
with open(sys.argv[1], 'w') as file:
    toml.dump(data, file)
