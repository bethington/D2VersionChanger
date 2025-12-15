import json
from registry_loader import quick_load_dll

# Load D2Common.dll data from split functions_v2 files
dll_data = quick_load_dll("D2Common.dll")
d2common = dll_data["functions"]

# Find named functions that exist in both 1.09d and 1.10
print("Named functions matched across 1.09d → 1.10 boundary:")
print("=" * 60)

count = 0
for f in d2common:
    versions = f.get('versions', {})
    if 'LoD/1.09d' in versions and 'LoD/1.10' in versions:
        name = f.get('name')
        if name and not name.startswith('FUN_'):
            addr_09d = versions['LoD/1.09d'].get('address')
            addr_110 = versions['LoD/1.10'].get('address')
            count += 1
            if count <= 10:
                print(f'  {name}')
                print(f'    1.09d: {addr_09d}')
                print(f'    1.10: {addr_110}')

print()
print(f"Total named functions matched: {count}")

# Also count all matches
all_matched = sum(1 for f in d2common if 'LoD/1.09d' in f.get('versions', {}) and 'LoD/1.10' in f.get('versions', {}))
print(f"Total functions matched (including unnamed): {all_matched}")
