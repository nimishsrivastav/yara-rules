#!/usr/bin/env python3

import yara
import os

# Directory containing YARA rule files
rules_dir = 'rules/'

# Directory containing binary files
binaries_dir = 'samples/binaries/'

# Compile all YARA rules from the rules directory
rules = {}
for file_name in os.listdir(rules_dir):
    if file_name.endswith('.yar') or file_name.endswith('.yara'):
        rule_path = os.path.join(rules_dir, file_name)
        rule_name = os.path.splitext(file_name)[0]
        rules[rule_name] = yara.compile(filepath=rule_path)

# Function to scan a single binary file with all compiled rules
def scan_file(file_path):
    matches = {}
    with open(file_path, 'rb') as f:
        binary_data = f.read()
        for rule_name, rule in rules.items():
            match = rule.match(data=binary_data)
            if match:
                matches[rule_name] = match
    return matches

# Scan all files in the binaries directory
results = {}
for file_name in os.listdir(binaries_dir):
    file_path = os.path.join(binaries_dir, file_name)
    matches = scan_file(file_path)
    if matches:
        results[file_name] = matches

# Print the results
for file_name, matches in results.items():
    print(f'File: {file_name}')
    for rule_name, match in matches.items():
        print(f'  Rule: {rule_name}')
        for m in match:
            print(f'    Match: {m}')
