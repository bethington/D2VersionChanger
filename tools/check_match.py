import json
from registry_loader import quick_load_dll

# Load D2Common.dll data from split functions_v2 files
dll_data = quick_load_dll("D2Common.dll")
d2common_funcs = dll_data["functions"]
print(f"Registry has {len(d2common_funcs)} D2Common.dll functions")

# Find function with 1.10 @ 0x6FD44FF0
target_addr = "0x6fd44ff0"  # lowercase for comparison
for func in d2common_funcs:
    versions = func.get("versions", {})
    lod110 = versions.get("LoD/1.10", {})
    addr_110 = lod110.get("address", "") if lod110 else ""

    if addr_110.lower() == target_addr:
        name = func.get("name", "unnamed")
        func_id = func.get("id", "?")
        print(f"\nFound function: {name}")
        print(f"  ID: {func_id}")
        print(f"  Versions tracked ({len(versions)}): {sorted(versions.keys())}")

        lod107 = versions.get("LoD/1.07", {})
        print(
            f"\n  1.07: {lod107.get('address') if lod107 else 'NOT IN REGISTRY'} (name: {lod107.get('name', 'N/A') if lod107 else 'N/A'})"
        )
        print(f"  1.10: {lod110.get('address')} (name: {lod110.get('name', 'N/A')})")

        # Check if 0x6FD638E0 (ValidateRegionWithAlternative 1.07 address) is in this function
        expected_107 = "0x6fd638e0"
        if lod107 and lod107.get("address", "").lower() == expected_107:
            print(
                f"\n  ✓ CONFIRMED: 1.10 @ 0x6FD44FF0 matches 1.07 @ 0x6FD638E0 (ValidateRegionWithAlternative)"
            )
        elif lod107:
            print(f"\n  ✗ Different 1.07 address than expected (0x6FD638E0)")
        else:
            print(f"\n  ✗ 1.07 version not in registry for this function")
        break
else:
    print(f"No function found with 1.10 @ {target_addr}")

    # Debug: look for the function in any version
    print("\nSearching for ValidateRegionWithAlternative by name...")
    for func in d2common_funcs:
        if "ValidateRegion" in func.get("name", ""):
            print(
                f"  Found: {func.get('name')} - versions: {sorted(func.get('versions', {}).keys())}"
            )
