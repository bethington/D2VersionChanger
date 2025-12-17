#!/usr/bin/env python3
"""
Generate function_registry.json - Complete function morphology data for all DLLs.

This creates a unified JSON file containing:
- All matched functions across all DLLs
- Their addresses in each version
- Match tier and confidence
- Ghidra names and signatures where available

Usage:
    python tools/generate_registry.py
    python tools/generate_registry.py --output reports/function_registry.json
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict


def load_state_file(path: Path) -> dict:
    """Load a matching state JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def generate_registry(cache_dir: Path, output_path: Path):
    """Generate the complete function registry."""

    matches_dir = cache_dir / "matches"

    if not matches_dir.exists():
        print(f"Error: Cache directory not found: {matches_dir}")
        return

    # Find all state files
    state_files = list(matches_dir.glob("*_state.json"))

    if not state_files:
        print("Error: No matching state files found")
        return

    print(f"Found {len(state_files)} DLL state files")

    # Build registry
    registry = {
        "generated": datetime.now().isoformat(),
        "format_version": "1.0",
        "statistics": {
            "total_dlls": 0,
            "total_functions": 0,
            "total_named": 0,
            "by_tier": defaultdict(int),
        },
        "dlls": {}
    }

    tier_names = {
        1: "Export Name",
        2: "Exact Bytes",
        3: "Prologue + Size",
        4: "Call Graph"
    }

    for state_file in sorted(state_files):
        dll_name = state_file.stem.replace("_state", "")
        print(f"  Processing {dll_name}...")

        state = load_state_file(state_file)
        matched = state.get('matched', {})

        if not matched:
            print(f"    No matched functions, skipping")
            continue

        # Get all versions from the matches
        all_versions = set()
        for match in matched.values():
            all_versions.update(match.get('addresses', {}).keys())

        dll_data = {
            "function_count": len(matched),
            "versions": sorted(all_versions),
            "functions": {}
        }

        named_count = 0

        for func_id, match in matched.items():
            # Get display name
            name = match.get('ghidra_name') or match.get('export_name') or func_id

            # Check if named
            is_named = False
            if name and name != func_id:
                if not name.startswith('FUN_') and not name.startswith('Ordinal_'):
                    is_named = True
                    named_count += 1

            tier = match.get('match_tier', 0)
            registry['statistics']['by_tier'][tier] += 1

            func_entry = {
                "name": name,
                "addresses": match.get('addresses', {}),
                "tier": tier,
                "confidence": match.get('confidence', 0),
            }

            # Add optional fields if present
            if match.get('export_name'):
                func_entry['export_name'] = match['export_name']

            if match.get('ghidra_signature'):
                func_entry['signature'] = match['ghidra_signature']

            if match.get('ordinal'):
                func_entry['ordinal'] = match['ordinal']

            dll_data['functions'][func_id] = func_entry

        dll_data['named_count'] = named_count
        registry['dlls'][dll_name] = dll_data
        registry['statistics']['total_dlls'] += 1
        registry['statistics']['total_functions'] += len(matched)
        registry['statistics']['total_named'] += named_count

        print(f"    {len(matched)} functions, {named_count} named")

    # Convert defaultdict to regular dict for JSON
    registry['statistics']['by_tier'] = dict(registry['statistics']['by_tier'])

    # Add tier summary
    tier_summary = {}
    for tier, count in sorted(registry['statistics']['by_tier'].items()):
        tier_summary[f"tier_{tier}"] = {
            "name": tier_names.get(tier, "Unknown"),
            "count": count,
            "percent": round(count / max(registry['statistics']['total_functions'], 1) * 100, 1)
        }
    registry['statistics']['tier_summary'] = tier_summary

    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(registry, f, indent=2)

    file_size = output_path.stat().st_size
    print(f"\nRegistry generated: {output_path}")
    print(f"File size: {file_size / 1024 / 1024:.2f} MB")
    print(f"\nSummary:")
    print(f"  DLLs: {registry['statistics']['total_dlls']}")
    print(f"  Total functions: {registry['statistics']['total_functions']}")
    print(f"  Named functions: {registry['statistics']['total_named']}")
    print(f"\nBy Tier:")
    for tier_key, tier_info in tier_summary.items():
        print(f"  {tier_info['name']}: {tier_info['count']} ({tier_info['percent']}%)")


def main():
    parser = argparse.ArgumentParser(description="Generate function_registry.json")
    parser.add_argument("--cache", type=str, default="cache", help="Cache directory")
    parser.add_argument("--output", "-o", type=str, default="reports/function_registry.json",
                        help="Output file path")
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    cache_dir = project_root / args.cache
    output_path = project_root / args.output

    generate_registry(cache_dir, output_path)


if __name__ == "__main__":
    main()
