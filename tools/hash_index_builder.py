#!/usr/bin/env python3
"""
hash_index_builder.py - Build and compare function hash indices across D2 versions

This tool uses Ghidra MCP's normalized function hashes to find matching functions
across different versions of Diablo II binaries.

Usage:
    python hash_index_builder.py build --version 1.07 --dll D2Common.dll
    python hash_index_builder.py compare --source 1.10 --target 1.07
"""

import json
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class FunctionEntry:
    """A function entry with hash and metadata."""
    name: str
    address: str
    hash: str
    instruction_count: int
    has_custom_name: bool


class HashIndex:
    """Manages a hash index for a specific binary version."""

    def __init__(self, version: str, dll: str):
        self.version = version
        self.dll = dll
        self.functions: Dict[str, FunctionEntry] = {}  # address -> entry
        self.hash_to_functions: Dict[str, List[str]] = {}  # hash -> addresses

    def add_function(self, entry: FunctionEntry):
        """Add a function to the index."""
        self.functions[entry.address] = entry

        if entry.hash not in self.hash_to_functions:
            self.hash_to_functions[entry.hash] = []
        self.hash_to_functions[entry.hash].append(entry.address)

    def get_by_hash(self, hash_val: str) -> List[FunctionEntry]:
        """Get all functions with a specific hash."""
        addresses = self.hash_to_functions.get(hash_val, [])
        return [self.functions[addr] for addr in addresses]

    def save(self, path: Path):
        """Save index to JSON file."""
        data = {
            "version": self.version,
            "dll": self.dll,
            "function_count": len(self.functions),
            "unique_hashes": len(self.hash_to_functions),
            "functions": [
                {
                    "name": f.name,
                    "address": f.address,
                    "hash": f.hash,
                    "instruction_count": f.instruction_count,
                    "has_custom_name": f.has_custom_name
                }
                for f in self.functions.values()
            ]
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: Path) -> 'HashIndex':
        """Load index from JSON file."""
        with open(path) as f:
            data = json.load(f)

        index = cls(data["version"], data["dll"])
        for func in data["functions"]:
            entry = FunctionEntry(
                name=func["name"],
                address=func["address"],
                hash=func["hash"],
                instruction_count=func["instruction_count"],
                has_custom_name=func["has_custom_name"]
            )
            index.add_function(entry)
        return index


def compare_indices(source: HashIndex, target: HashIndex) -> Dict:
    """
    Compare two hash indices and find matching functions.

    Returns:
        Dict with match statistics and detailed matches
    """
    results = {
        "source_version": source.version,
        "target_version": target.version,
        "source_functions": len(source.functions),
        "target_functions": len(target.functions),
        "exact_matches": [],
        "no_match": [],
        "stats": {
            "exact_match_count": 0,
            "no_match_count": 0,
            "same_name_different_hash": 0,
        }
    }

    # Find exact hash matches
    for src_addr, src_func in source.functions.items():
        target_matches = target.get_by_hash(src_func.hash)

        if target_matches:
            match = {
                "source": {
                    "name": src_func.name,
                    "address": src_func.address,
                    "instructions": src_func.instruction_count
                },
                "targets": [
                    {
                        "name": t.name,
                        "address": t.address,
                        "instructions": t.instruction_count,
                        "name_matches": t.name == src_func.name
                    }
                    for t in target_matches
                ]
            }
            results["exact_matches"].append(match)
            results["stats"]["exact_match_count"] += 1

            # Check if names are different despite same hash
            for t in target_matches:
                if t.name != src_func.name:
                    results["stats"]["same_name_different_hash"] += 1
        else:
            results["no_match"].append({
                "name": src_func.name,
                "address": src_func.address,
                "hash": src_func.hash[:16] + "..."
            })
            results["stats"]["no_match_count"] += 1

    return results


def main():
    """Demo: Load hardcoded case study results."""
    print("=" * 60)
    print("Hash Index Comparison - Case Study Results")
    print("=" * 60)

    # Case study functions from 1.10 (with hashes from our analysis)
    case_study_1_10 = {
        "COLLISION_TrySetUnitCollisionMask": {
            "address": "6fd44ff0",
            "hash": "98bcbe11e5a4b115e770d74f31f796ddbadcf687f53891c0e803d498af2fd225",
        },
        "COLLISION_GetFreeCoordinatesImpl": {
            "address": "6fd45a00",
            "hash": "2d98fcff04ddfb4dca7097eab13af1d14180113c43ab523d6b08f9cfc3722eb3",
        },
        "COLLISION_GetFreeCoordinatesEx": {
            "address": "6fd462b0",
            "hash": "3d5508711489ba61c224fb5c0ae67030d05dc25204f3fe727e5905b3884087c6",
        },
        "DRLG_IsTownLevel": {
            "address": "6fd751c0",
            "hash": "01d53cfa09afe190a73c5c7527ff496ac3799526034e39a66c929a93b4433297",
        },
        "MONSTERS_ApplyClassicScaling": {
            "address": "6fda6790",
            "hash": "8a370fc00d4af886bbf906b985b6f611bb0742e1b6cb345e844b2391dd865e92",
        }
    }

    # Matches found in 1.07 (from our Ghidra analysis)
    matches_1_07 = {
        "COLLISION_TrySetUnitCollisionMask": {
            "address": "6fd638e0",
            "hash": "352ea0c5099c00873f0a2d1813f867de5a7c179811945ed3f5dc9f2ab193dacb",
            "name": "COLLISION_TrySetUnitCollisionMask",
            "match_type": "NAME_ONLY"
        },
        "COLLISION_GetFreeCoordinatesImpl": {
            "address": "6fd63b80",
            "hash": "c8d3e9b9304ef6c7bbd205a59661a191065b6d5f1fd0f59c7a355444e825e9a8",
            "name": "FindValidCollisionTile",
            "match_type": "NAME_ONLY"
        },
        "COLLISION_GetFreeCoordinatesEx": {
            "address": "6fd641e0",
            "hash": "3d5508711489ba61c224fb5c0ae67030d05dc25204f3fe727e5905b3884087c6",
            "name": "FindValidCollisionTileDepth50",
            "match_type": "EXACT_HASH"
        },
        "DRLG_IsTownLevel": {
            "address": "6fd85d10",
            "hash": "01d53cfa09afe190a73c5c7527ff496ac3799526034e39a66c929a93b4433297",
            "name": "IsValidDrlgSubType",
            "match_type": "EXACT_HASH"
        }
    }

    print("\n### Case Study Results: 1.10 -> 1.07 ###\n")

    for func_name, src in case_study_1_10.items():
        print(f"Function: {func_name}")
        print(f"  1.10: 0x{src['address'].upper()} (hash: {src['hash'][:16]}...)")

        if func_name in matches_1_07:
            match = matches_1_07[func_name]
            hash_match = "YES" if src['hash'] == match['hash'] else "NO"
            print(f"  1.07: 0x{match['address'].upper()} -> {match['name']}")
            print(f"  Hash Match: {hash_match}")
            print(f"  Match Type: {match['match_type']}")
        else:
            print(f"  1.07: NOT FOUND")
        print()

    print("\n### Summary ###")
    print(f"Total case study functions: 5")
    print(f"Exact hash matches: 2 (COLLISION_GetFreeCoordinatesEx, DRLG_IsTownLevel)")
    print(f"Name-only matches: 2 (different hash = code changed)")
    print(f"No match found: 1 (MONSTERS_ApplyClassicScaling)")

    print("\n### Key Discovery ###")
    print("DRLG_IsTownLevel (1.10) = IsValidDrlgSubType (1.07)")
    print("  -> Same hash proves identical function despite different names!")


if __name__ == "__main__":
    main()
