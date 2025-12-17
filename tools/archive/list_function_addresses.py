#!/usr/bin/env python3
"""List function addresses from the known functions database in hex format."""

import json
import os

# Load the database
db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                        'reports', 'data', 'd2_known_functions.json')

with open(db_path, 'r') as f:
    data = json.load(f)

print("D2 Known Functions - Addresses for Ghidra Renaming")
print("=" * 60)

for func in data['functions']:
    addr = func['absolute_address']
    name = f"{func['module']}_{func['name']}"
    hex_addr = f"0x{addr:08X}"
    fun_name = f"FUN_{addr:08x}"
    print(f"{name:45} | {hex_addr} | {fun_name}")

print("\n" + "=" * 60)
print(f"Total functions: {len(data['functions'])}")
