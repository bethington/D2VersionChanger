#!/usr/bin/env python3
"""Check signature matching for ValidateRegionWithAlternative."""

import json

# 1.09d signature
data_09d = json.load(open("data/function_index/LoD/1.09d/D2Common.dll.json"))
func_09d = [f for f in data_09d["functions"] if f.get("address") == "0x6FD438F0"][0]
print("1.09d ValidateRegionWithAlternative:")
print("  signature:", func_09d.get("signature"))

# 1.10 candidate
data_110 = json.load(open("data/function_index/LoD/1.10/D2Common.dll.json"))
func_110 = [f for f in data_110["functions"] if f.get("address") == "0x6FD44FF0"][0]
print()
print("1.10 FUN_6fd44ff0:")
print("  signature:", func_110.get("signature"))

# Find ALL 9-parameter functions in 1.10
print()
print("All functions in 1.10 with 8+ parameters:")
for f in data_110["functions"]:
    sig = f.get("signature", "")
    if sig:
        # Count params
        params = sig.count("param")
        if params >= 8:
            name = f.get("name")
            addr = f.get("address")
            print(f"  {name} @ {addr}: {params} params")
            print(f"    sig: {sig[:100]}")
            print()
