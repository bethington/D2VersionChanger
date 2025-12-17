#!/usr/bin/env python3
"""
Convert existing Ghidra exports to new per-binary per-version format.

New format:
- data/functions/{binary}/{game_type}_{version}.json
- Functions indexed by address (not array)
- "indexes" renamed to "hashes"
- prev_match/next_match fields for version chain links
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional

# Version ordering for matching
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


def convert_function(func_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a single function to new format."""
    # Rename indexes to hashes
    hashes = func_data.get("indexes", {})

    # Build new function entry
    new_func = {
        "name": func_data.get("name", ""),
        "display_name": func_data.get("display_name", ""),
        "original_name": func_data.get("original_name", ""),
        "has_custom_name": func_data.get("has_human_name", False),
        "rva": func_data.get("rva", ""),
        "size": func_data.get("size", 0),
        "signature": func_data.get("signature", ""),
        "calling_convention": func_data.get("calling_convention", ""),
        "return_type": func_data.get("return_type", ""),

        # Rename indexes to hashes
        "hashes": {
            "API": hashes.get("API"),
            "MNE": hashes.get("MNE"),
            "CFG": hashes.get("CFG"),
            "STR": hashes.get("STR"),
            "CAL": hashes.get("CAL"),
            "PRO": hashes.get("PRO"),
            "EXP": hashes.get("EXP"),
            "CON": hashes.get("CON"),
            "APS": hashes.get("APS"),
        },

        # Metrics
        "instruction_count": func_data.get("instruction_count", 0),
        "basic_block_count": func_data.get("basic_block_count", 0),
        "loop_count": func_data.get("loop_count", 0),
        "param_count": func_data.get("param_count", 0),
        "local_var_count": func_data.get("local_var_count", 0),

        # References
        "parameters": func_data.get("parameters", []),
        "callees": func_data.get("callees", []),
        "callers": func_data.get("callers", []),
        "strings": func_data.get("strings", []),
        "api_calls": func_data.get("api_calls", []),

        # Documentation
        "comment": func_data.get("comment", ""),
        "tags": func_data.get("tags", []),

        # Version chain links (populated by matching phase)
        "prev_match": None,
        "next_match": None
    }

    # Remove null hashes to save space
    new_func["hashes"] = {k: v for k, v in new_func["hashes"].items() if v}

    return new_func


def convert_file(input_path: Path, output_dir: Path) -> Optional[Dict[str, Any]]:
    """Convert a single Ghidra export file to new format."""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"  ERROR reading {input_path}: {e}")
        return None

    binary_name = data.get("program_name", input_path.stem)
    game_type = data.get("game_type", "Unknown")
    version = data.get("version", "Unknown")

    # Create output directory for this binary
    binary_dir = output_dir / binary_name
    binary_dir.mkdir(parents=True, exist_ok=True)

    # Build new format
    new_data = {
        "binary": binary_name,
        "game_type": game_type,
        "version": version,
        "image_base": data.get("image_base", ""),
        "total_functions": len(data.get("functions", [])),
        "source_file": str(input_path),
        "functions": {}
    }

    # Convert functions, indexed by address
    for func in data.get("functions", []):
        address = func.get("address", "")
        if address:
            new_data["functions"][address] = convert_function(func)

    # Write output file
    output_file = binary_dir / f"{game_type}_{version}.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(new_data, f, indent=2)

    return {
        "binary": binary_name,
        "game_type": game_type,
        "version": version,
        "function_count": len(new_data["functions"]),
        "output_file": str(output_file)
    }


def main():
    base_dir = Path(__file__).parent.parent
    input_dir = base_dir / "data" / "function_index"
    output_dir = base_dir / "data" / "functions"

    print("=" * 70)
    print("CONVERTING TO NEW FUNCTION FORMAT")
    print("=" * 70)
    print(f"Input:  {input_dir}")
    print(f"Output: {output_dir}")
    print()

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Track statistics
    stats = {
        "files_processed": 0,
        "files_failed": 0,
        "total_functions": 0,
        "binaries": set()
    }

    # Process all game types and versions
    for game_type in ["LoD", "Classic"]:
        game_dir = input_dir / game_type
        if not game_dir.exists():
            continue

        print(f"\nProcessing {game_type}...")

        for version_dir in sorted(game_dir.iterdir()):
            if not version_dir.is_dir():
                continue

            version = version_dir.name
            print(f"  Version {version}:")

            for json_file in sorted(version_dir.glob("*.json")):
                result = convert_file(json_file, output_dir)

                if result:
                    stats["files_processed"] += 1
                    stats["total_functions"] += result["function_count"]
                    stats["binaries"].add(result["binary"])
                    print(f"    {result['binary']}: {result['function_count']} functions")
                else:
                    stats["files_failed"] += 1

    print()
    print("=" * 70)
    print("CONVERSION COMPLETE")
    print("=" * 70)
    print(f"Files processed: {stats['files_processed']}")
    print(f"Files failed:    {stats['files_failed']}")
    print(f"Total functions: {stats['total_functions']}")
    print(f"Unique binaries: {len(stats['binaries'])}")
    print()
    print("Binaries converted:")
    for binary in sorted(stats["binaries"]):
        print(f"  - {binary}")


if __name__ == "__main__":
    main()
