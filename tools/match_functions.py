#!/usr/bin/env python3
"""
Tier 1 Hash-Based Function Matching

Matches functions between adjacent versions using hash comparison.
Updates prev_match and next_match fields in the new function format.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from collections import defaultdict

# Version ordering - adjacent versions for matching
VERSION_ORDER = {
    "Classic": [
        "1.00", "1.01", "1.02", "1.03", "1.04b", "1.04c",
        "1.05", "1.05b", "1.06", "1.06b", "1.08", "1.09", "1.09b"
    ],
    "LoD": [
        "1.07", "1.08", "1.09", "1.09b", "1.09d", "1.10",
        "1.11", "1.11b", "1.12a", "1.13c", "1.13d",
        "1.14a", "1.14b", "1.14c", "1.14d", "PD2"
    ]
}

# Hash priority for matching (higher = better)
HASH_PRIORITY = ["API", "MNE", "CFG", "CAL", "PRO", "STR", "APS"]


@dataclass
class Match:
    """Represents a function match between versions."""
    address: str
    name: str
    confidence: float
    method: str  # Which hash method matched


def build_hash_index(functions: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """
    Build an index from hash values to function addresses.

    Returns: {hash_type: {hash_value: address}}
    """
    index = defaultdict(dict)

    for address, func_data in functions.items():
        hashes = func_data.get("hashes", {})
        for hash_type, hash_value in hashes.items():
            if hash_value:
                index[hash_type][hash_value] = address

    return index


def find_match(
    func_data: Dict[str, Any],
    target_hash_index: Dict[str, Dict[str, str]],
    target_functions: Dict[str, Any]
) -> Optional[Match]:
    """
    Find a matching function in the target version using hash comparison.

    Uses hash priority to find the best match.
    """
    hashes = func_data.get("hashes", {})

    for hash_type in HASH_PRIORITY:
        hash_value = hashes.get(hash_type)
        if not hash_value:
            continue

        # Look up in target index
        target_address = target_hash_index.get(hash_type, {}).get(hash_value)
        if target_address:
            target_func = target_functions.get(target_address, {})
            return Match(
                address=target_address,
                name=target_func.get("name", ""),
                confidence=0.95,  # High confidence for hash match
                method=hash_type
            )

    return None


def match_versions(
    source_data: Dict[str, Any],
    target_data: Dict[str, Any],
    direction: str  # "next" or "prev"
) -> Tuple[int, int]:
    """
    Match functions between two adjacent versions.

    Updates the source_data in place with match information.
    Returns (matched_count, total_count).
    """
    source_functions = source_data.get("functions", {})
    target_functions = target_data.get("functions", {})

    if not source_functions or not target_functions:
        return 0, len(source_functions)

    # Build hash index for target
    target_hash_index = build_hash_index(target_functions)

    target_version = target_data.get("version", "")
    matched = 0

    for address, func_data in source_functions.items():
        match = find_match(func_data, target_hash_index, target_functions)

        if match:
            match_key = f"{direction}_match"
            func_data[match_key] = {
                "version": target_version,
                "address": match.address,
                "name": match.name,
                "confidence": match.confidence,
                "method": match.method
            }
            matched += 1

    return matched, len(source_functions)


def process_binary(binary_dir: Path) -> Dict[str, Any]:
    """
    Process all versions of a binary, matching adjacent versions.
    """
    stats = {
        "binary": binary_dir.name,
        "versions_processed": 0,
        "total_functions": 0,
        "total_matches": 0,
        "version_pairs": []
    }

    # Load all version files
    version_files = {}
    for json_file in sorted(binary_dir.glob("*.json")):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                game_type = data.get("game_type", "")
                version = data.get("version", "")
                key = f"{game_type}_{version}"
                version_files[key] = {
                    "path": json_file,
                    "data": data,
                    "game_type": game_type,
                    "version": version
                }
        except Exception as e:
            print(f"    ERROR loading {json_file}: {e}")

    # Process each game type separately
    for game_type, versions in VERSION_ORDER.items():
        # Get files for this game type in version order
        ordered_files = []
        for version in versions:
            key = f"{game_type}_{version}"
            if key in version_files:
                ordered_files.append(version_files[key])

        if len(ordered_files) < 2:
            continue

        # Match adjacent versions
        for i in range(len(ordered_files)):
            current = ordered_files[i]
            current_data = current["data"]
            current_version = current["version"]

            # Match to next version
            if i + 1 < len(ordered_files):
                next_file = ordered_files[i + 1]
                next_data = next_file["data"]
                next_version = next_file["version"]

                matched, total = match_versions(current_data, next_data, "next")
                stats["total_matches"] += matched
                stats["version_pairs"].append({
                    "from": current_version,
                    "to": next_version,
                    "direction": "next",
                    "matched": matched,
                    "total": total
                })

            # Match to previous version
            if i > 0:
                prev_file = ordered_files[i - 1]
                prev_data = prev_file["data"]
                prev_version = prev_file["version"]

                matched, total = match_versions(current_data, prev_data, "prev")
                stats["total_matches"] += matched
                stats["version_pairs"].append({
                    "from": current_version,
                    "to": prev_version,
                    "direction": "prev",
                    "matched": matched,
                    "total": total
                })

            stats["versions_processed"] += 1
            stats["total_functions"] += len(current_data.get("functions", {}))

            # Save updated file
            with open(current["path"], 'w', encoding='utf-8') as f:
                json.dump(current_data, f, indent=2)

    return stats


def main():
    base_dir = Path(__file__).parent.parent
    functions_dir = base_dir / "data" / "functions"

    print("=" * 70)
    print("TIER 1 HASH-BASED FUNCTION MATCHING")
    print("=" * 70)
    print(f"Functions directory: {functions_dir}")
    print(f"Hash priority: {' > '.join(HASH_PRIORITY)}")
    print()

    # Process all binaries
    total_stats = {
        "binaries_processed": 0,
        "total_functions": 0,
        "total_matches": 0
    }

    for binary_dir in sorted(functions_dir.iterdir()):
        if not binary_dir.is_dir():
            continue

        print(f"Processing {binary_dir.name}...")
        stats = process_binary(binary_dir)

        total_stats["binaries_processed"] += 1
        total_stats["total_functions"] += stats["total_functions"]
        total_stats["total_matches"] += stats["total_matches"]

        if stats["version_pairs"]:
            # Show summary for this binary
            next_matches = sum(p["matched"] for p in stats["version_pairs"] if p["direction"] == "next")
            prev_matches = sum(p["matched"] for p in stats["version_pairs"] if p["direction"] == "prev")
            print(f"  Versions: {stats['versions_processed']}, Next matches: {next_matches}, Prev matches: {prev_matches}")

    print()
    print("=" * 70)
    print("MATCHING COMPLETE")
    print("=" * 70)
    print(f"Binaries processed: {total_stats['binaries_processed']}")
    print(f"Total functions:    {total_stats['total_functions']}")
    print(f"Total matches:      {total_stats['total_matches']}")

    if total_stats["total_functions"] > 0:
        match_rate = (total_stats["total_matches"] / (total_stats["total_functions"] * 2)) * 100
        print(f"Match rate:         {match_rate:.1f}%")


if __name__ == "__main__":
    main()
