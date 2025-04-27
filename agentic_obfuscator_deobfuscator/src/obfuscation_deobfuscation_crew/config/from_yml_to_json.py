import yaml
import json

with open("obfuscation_techniques.yaml", "r") as yaml_file:
    data = yaml.safe_load(yaml_file)

with open("obfuscation_techniques.json", "w") as json_file:
    json.dump(data, json_file, indent=2)
