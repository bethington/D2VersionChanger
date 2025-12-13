#!/usr/bin/env python3
"""Search for COLLISION_TrySetUnitCollisionMask across versions."""
import json

# Search for COLLISION functions or the specific address
for ver in ['1.07', '1.08', '1.09', '1.09b', '1.09d', '1.10', '1.11', '1.11b']:
    try:
        data = json.load(open(f'data/function_index/LoD/{ver}/D2Common.dll.json'))
        for f in data['functions']:
            name = f.get('name', '')
            addr = f.get('address', '')
            # Match by name pattern or specific 1.10 address
            if 'COLLISION' in name.upper() or 'TrySet' in name or addr == '0x6FD44FF0':
                size = f.get('size')
                calls = f.get('api_calls', [])[:4]
                print(f'{ver}: {addr} - {name} (size {size})')
                print(f'    calls: {calls}')
    except FileNotFoundError:
        pass

# Also check for ValidateRegionWithAlternative since that's what we were analyzing
print("\n" + "="*60)
print("ValidateRegionWithAlternative across versions:")
print("="*60)
for ver in ['1.07', '1.08', '1.09', '1.09b', '1.09d', '1.10']:
    try:
        data = json.load(open(f'data/function_index/LoD/{ver}/D2Common.dll.json'))
        for f in data['functions']:
            if f.get('name') == 'ValidateRegionWithAlternative':
                print(f'{ver}: {f.get("address")} (size {f.get("size")})')
                print(f'    calls: {f.get("api_calls", [])}')
    except FileNotFoundError:
        pass
