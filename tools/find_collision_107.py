#!/usr/bin/env python3
"""
Find the 1.07 match for COLLISION_TrySetUnitCollisionMask (1.10 @ 0x6FD44FF0).

Known info:
- 1.10 address: 0x6FD44FF0
- 1.10 size: 454
- 1.10 calls: ClearMapCellFlagRadius, Ordinal_10035, ApplyTileAttributePattern (x2)
"""
import json

# Load 1.10 data for reference
data_110 = json.load(open('data/function_index/LoD/1.10/D2Common.dll.json'))
target_110 = [f for f in data_110['functions'] if f.get('address') == '0x6FD44FF0'][0]

print("Target function in 1.10:")
print(f"  Address: 0x6FD44FF0")
print(f"  Name: COLLISION_TrySetUnitCollisionMask (user provided)")
print(f"  Size: {target_110.get('size')}")
print(f"  Calls: {target_110.get('api_calls')}")

# Load 1.07 data
data_107 = json.load(open('data/function_index/LoD/1.07/D2Common.dll.json'))

print("\n" + "="*70)
print("Searching 1.07 for matching function...")
print("="*70)

# Find functions in 1.07 that call both ClearMapCellFlagRadius AND ApplyTileAttributePattern
candidates = []
for f in data_107['functions']:
    calls = f.get('api_calls', [])
    if 'ClearMapCellFlagRadius' in calls and 'ApplyTileAttributePattern' in calls:
        candidates.append(f)

print(f"\nFound {len(candidates)} functions calling both ClearMapCellFlagRadius AND ApplyTileAttributePattern:")
print()

for f in sorted(candidates, key=lambda x: x.get('size', 0), reverse=True):
    addr = f.get('address')
    name = f.get('name')
    size = f.get('size')
    calls = f.get('api_calls', [])
    
    # Calculate size ratio to 1.10 target (454)
    size_ratio = min(size, 454) / max(size, 454) if size else 0
    
    print(f"{addr}: {name}")
    print(f"    Size: {size} ({size_ratio:.1%} match to 1.10)")
    print(f"    Calls: {calls}")
    print()

# Best candidate by size match
print("="*70)
print("BEST CANDIDATE (by size proximity to 454):")
print("="*70)
best = min(candidates, key=lambda x: abs(x.get('size', 0) - 454))
print(f"  1.07: {best.get('address')} - {best.get('name')}")
print(f"  Size: {best.get('size')} vs 1.10 size 454")
print(f"  Calls: {best.get('api_calls')}")
