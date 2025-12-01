#!/usr/bin/env python3
"""
Export function data to CSV format for external tools.

Creates CSV files with function addresses across versions, suitable for:
- Spreadsheet analysis
- External reverse engineering tools
- Database import

Usage:
    python tools/export_csv.py --dll D2Client.dll
    python tools/export_csv.py --all
    python tools/export_csv.py --dll D2Client.dll --output reports/D2Client_functions.csv
"""

import csv
import json
import argparse
from pathlib import Path
from typing import List, Optional


def load_state_file(path: Path) -> dict:
    """Load a matching state JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def export_dll_csv(dll_name: str, cache_dir: Path, output_path: Path, versions_filter: Optional[List[str]] = None):
    """Export a single DLL's function data to CSV."""

    state_path = cache_dir / "matches" / f"{dll_name}_state.json"

    if not state_path.exists():
        print(f"Error: State file not found: {state_path}")
        return False

    state = load_state_file(state_path)
    matched = state.get('matched', {})

    if not matched:
        print(f"No matched functions for {dll_name}")
        return False

    # Gather all versions
    all_versions = set()
    for match in matched.values():
        all_versions.update(match.get('addresses', {}).keys())

    all_versions = sorted(all_versions)

    # Apply version filter if provided
    if versions_filter:
        all_versions = [v for v in all_versions if v in versions_filter]

    # Build CSV headers
    headers = ['function_id', 'name', 'tier', 'confidence', 'export_name', 'signature']
    headers.extend(all_versions)

    # Build rows
    rows = []
    for func_id, match in sorted(matched.items()):
        name = match.get('ghidra_name') or match.get('export_name') or func_id

        row = {
            'function_id': func_id,
            'name': name,
            'tier': match.get('match_tier', 0),
            'confidence': round(match.get('confidence', 0), 2),
            'export_name': match.get('export_name', ''),
            'signature': match.get('ghidra_signature', ''),
        }

        # Add version addresses
        addresses = match.get('addresses', {})
        for version in all_versions:
            row[version] = addresses.get(version, '')

        rows.append(row)

    # Write CSV
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    file_size = output_path.stat().st_size
    print(f"Exported {len(rows)} functions to {output_path} ({file_size / 1024:.1f} KB)")
    return True


def export_all_csvs(cache_dir: Path, output_dir: Path, versions_filter: Optional[List[str]] = None):
    """Export all DLLs to CSV files."""

    matches_dir = cache_dir / "matches"

    if not matches_dir.exists():
        print(f"Error: Cache directory not found: {matches_dir}")
        return

    state_files = list(matches_dir.glob("*_state.json"))

    if not state_files:
        print("Error: No matching state files found")
        return

    print(f"Exporting {len(state_files)} DLLs to CSV...")

    for state_file in sorted(state_files):
        dll_name = state_file.stem.replace("_state", "")
        output_path = output_dir / f"{dll_name}.csv"
        export_dll_csv(dll_name, cache_dir, output_path, versions_filter)


def export_summary_csv(cache_dir: Path, output_path: Path):
    """Export a summary CSV with one row per DLL."""

    matches_dir = cache_dir / "matches"

    if not matches_dir.exists():
        print(f"Error: Cache directory not found: {matches_dir}")
        return

    state_files = list(matches_dir.glob("*_state.json"))

    headers = ['dll_name', 'total_functions', 'named_functions', 'tier_1', 'tier_2', 'tier_3', 'tier_4', 'versions']
    rows = []

    for state_file in sorted(state_files):
        dll_name = state_file.stem.replace("_state", "")
        state = load_state_file(state_file)
        matched = state.get('matched', {})

        if not matched:
            continue

        # Count tiers
        tier_counts = {1: 0, 2: 0, 3: 0, 4: 0}
        named_count = 0
        all_versions = set()

        for match in matched.values():
            tier = match.get('match_tier', 0)
            if tier in tier_counts:
                tier_counts[tier] += 1

            name = match.get('ghidra_name') or match.get('export_name')
            if name and not name.startswith('FUN_') and not name.startswith('Ordinal_'):
                named_count += 1

            all_versions.update(match.get('addresses', {}).keys())

        rows.append({
            'dll_name': dll_name,
            'total_functions': len(matched),
            'named_functions': named_count,
            'tier_1': tier_counts[1],
            'tier_2': tier_counts[2],
            'tier_3': tier_counts[3],
            'tier_4': tier_counts[4],
            'versions': len(all_versions)
        })

    # Write CSV
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Exported summary to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Export function data to CSV")
    parser.add_argument("--dll", type=str, help="DLL name to export")
    parser.add_argument("--all", action="store_true", help="Export all DLLs")
    parser.add_argument("--summary", action="store_true", help="Export summary CSV")
    parser.add_argument("--cache", type=str, default="cache", help="Cache directory")
    parser.add_argument("--output", "-o", type=str, help="Output file/directory path")
    parser.add_argument("--versions", type=str, nargs="+", help="Filter to specific versions")
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    cache_dir = project_root / args.cache

    if args.summary:
        output_path = Path(args.output) if args.output else project_root / "reports" / "function_summary.csv"
        export_summary_csv(cache_dir, output_path)
    elif args.all:
        output_dir = Path(args.output) if args.output else project_root / "reports" / "csv"
        export_all_csvs(cache_dir, output_dir, args.versions)
    elif args.dll:
        output_path = Path(args.output) if args.output else project_root / "reports" / "csv" / f"{args.dll}.csv"
        export_dll_csv(args.dll, cache_dir, output_path, args.versions)
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python tools/export_csv.py --dll D2Client.dll")
        print("  python tools/export_csv.py --all")
        print("  python tools/export_csv.py --summary")


if __name__ == "__main__":
    main()
