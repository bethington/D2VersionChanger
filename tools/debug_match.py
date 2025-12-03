#!/usr/bin/env python3
"""Debug specific function matching."""

import json
from pathlib import Path

# Load two specific exports
with open('data/function_index/LoD/1.09d/D2Client.dll.json') as f:
    d109d = json.load(f)
with open('data/function_index/LoD/1.10/D2Client.dll.json') as f:
    d110 = json.load(f)

# Find the function at 0x1F50 in 1.10 (should match 1.09d 0x1F10)
f110 = None
for f in d110['functions']:
    if f['rva'] == '0x1F50':
        f110 = f
        break

if f110:
    print('1.10 function at 0x1F50:')
    print(f'  Primary: {f110["index_method"]} = {f110.get("index", "")[:50]}')
    print(f'  Indexes:')
    for m, v in f110.get('indexes', {}).items():
        print(f'    {m}: {v[:50] if v else "None"}...')

# Find the matching function in 1.09d
for f in d109d['functions']:
    if f['rva'] == '0x1F10':
        print('\n1.09d function at 0x1F10:')
        print(f'  Primary: {f["index_method"]} = {f.get("index", "")[:50]}')
        print(f'  Indexes:')
        for m, v in f.get('indexes', {}).items():
            print(f'    {m}: {v[:50] if v else "None"}...')
        
        # Check for matching indexes
        print('\nIndex comparison:')
        for m in ['STR', 'API', 'MNE', 'CFG', 'PRO']:
            v110 = f110.get('indexes', {}).get(m)
            v109d = f.get('indexes', {}).get(m)
            match = v110 == v109d if v110 and v109d else False
            print(f'  {m}: {"MATCH" if match else "NO MATCH"} - 1.09d={str(v109d)[:30] if v109d else "None"}, 1.10={str(v110)[:30] if v110 else "None"}')
        break

print('\n' + '='*70)
print('Checking a MNE->CFG partial match case')
print('='*70)

# Find 0x51D0 in 1.10 which has primary=MNE but matches on CFG
for f in d110['functions']:
    if f['rva'] == '0x51D0':
        print(f'\n1.10 function at 0x51D0:')
        print(f'  Primary: {f["index_method"]}')
        cfg_hash = f.get('indexes', {}).get('CFG')
        print(f'  CFG hash: {cfg_hash}')
        
        # Find this CFG hash in 1.09d
        for f2 in d109d['functions']:
            if f2.get('indexes', {}).get('CFG') == cfg_hash:
                print(f'\n  Found CFG match in 1.09d at {f2["rva"]}:')
                print(f'    Primary: {f2["index_method"]}')
                print(f'    Name: {f2.get("name", "FUN_")}')
                print(f'    Size: 1.09d={f2.get("size")}, 1.10={f.get("size")}')
                break
        break
