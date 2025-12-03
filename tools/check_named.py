#!/usr/bin/env python3
"""Check named function matching."""

import json

with open('data/function_index/LoD/1.09d/D2Client.dll.json') as f:
    d109d = json.load(f)
with open('data/function_index/LoD/1.10/D2Client.dll.json') as f:
    d110 = json.load(f)

# Get named functions
named_109d = {}
for f in d109d['functions']:
    name = f.get('name')
    if name and not name.startswith('FUN_'):
        named_109d[name] = f

named_110 = {}
for f in d110['functions']:
    name = f.get('name')
    if name and not name.startswith('FUN_'):
        named_110[name] = f

print(f'Named functions in 1.09d: {len(named_109d)}')
print(f'Named functions in 1.10: {len(named_110)}')

# Find common names
common_names = set(named_109d.keys()) & set(named_110.keys())
print(f'Common named functions: {len(common_names)}')

# Check if common names have matching indexes
matching_indexes = 0
different_indexes = 0
diff_examples = []

for name in common_names:
    f1 = named_109d[name]
    f2 = named_110[name]
    
    # Check if any index matches
    found_match = False
    for m in ['STR', 'API', 'MNE', 'CFG']:
        v1 = f1.get('indexes', {}).get(m)
        v2 = f2.get('indexes', {}).get(m)
        if v1 and v2 and v1 == v2:
            found_match = True
            break
    
    if found_match:
        matching_indexes += 1
    else:
        different_indexes += 1
        if len(diff_examples) < 10:
            diff_examples.append((name, f1, f2))

print(f'\nSame name + matching index: {matching_indexes}')
print(f'Same name + different indexes: {different_indexes}')

if diff_examples:
    print(f'\nExamples of same name but different code:')
    for name, f1, f2 in diff_examples:
        print(f'  {name}')
        print(f'    1.09d: {f1["rva"]} size={f1.get("size")}')
        print(f'    1.10:  {f2["rva"]} size={f2.get("size")}')
