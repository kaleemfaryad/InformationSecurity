import json

def load_rules(filename="rules.json"):
    with open(filename, "r") as file:
        return json.load(file)
