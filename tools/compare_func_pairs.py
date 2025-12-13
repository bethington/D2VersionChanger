#!/usr/bin/env python3
"""Compare function pairs between versions."""
import json


def count_params(sig):
    if not sig or "(" not in sig:
        return 0
    return sig.count("param")


# 1.09d
data_09d = json.load(open("data/function_index/LoD/1.09d/D2Common.dll.json"))
qrca = [
    f for f in data_09d["functions"] if f.get("name") == "QueryRoomCellAttributePattern"
][0]
vrwa = [
    f for f in data_09d["functions"] if f.get("name") == "ValidateRegionWithAlternative"
][0]

print("1.09d:")
print(
    f'QueryRoomCellAttributePattern: size={qrca["size"]}, params={count_params(qrca.get("signature",""))}'
)
print(f'  signature: {qrca.get("signature","")}')
print(
    f'ValidateRegionWithAlternative: size={vrwa["size"]}, params={count_params(vrwa.get("signature",""))}'
)
print(f'  signature: {vrwa.get("signature","")}')

# 1.10
data_110 = json.load(open("data/function_index/LoD/1.10/D2Common.dll.json"))
ord_10132 = [f for f in data_110["functions"] if f.get("name") == "Ordinal_10132"][0]
fun_6fd44ff0 = [f for f in data_110["functions"] if f.get("address") == "0x6FD44FF0"][0]

print()
print("1.10:")
print(
    f'Ordinal_10132: size={ord_10132["size"]}, params={count_params(ord_10132.get("signature",""))}'
)
print(f'  signature: {ord_10132.get("signature","")}')
print(
    f'FUN_6fd44ff0: size={fun_6fd44ff0["size"]}, params={count_params(fun_6fd44ff0.get("signature",""))}'
)
print(f'  signature: {fun_6fd44ff0.get("signature","")}')

print()
print("PROPOSED MAPPING:")
print(f"  QueryRoomCellAttributePattern (444) -> FUN_6fd44ff0 (454) = 97.8% size match")
print(
    f"  ValidateRegionWithAlternative (536) -> Ordinal_10132 (579) = 92.6% size match"
)
