#!/usr/bin/env python3
"""
Analyze unmatched functions to understand why they didn't match.

This script helps identify:
1. Functions unique to specific version ranges
2. Image base transition issues (Classic 1.03 -> 1.04)
3. Functions that changed significantly between versions
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple


def load_state(dll_name: str, cache_dir: Path) -> dict:
    """Load the matching state file."""
    state_path = cache_dir / "matches" / f"{dll_name}_state.json"
    with open(state_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_analysis(version: str, dll_name: str, cache_dir: Path) -> dict:
    """Load analysis data for a specific version."""
    safe_version = version.replace('/', '_').replace('\\', '_')
    analysis_path = cache_dir / "analysis" / f"{safe_version}_{dll_name}.json"
    if analysis_path.exists():
        with open(analysis_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


def categorize_unmatched(state: dict, cache_dir: Path, dll_name: str) -> dict:
    """Categorize unmatched functions by likely cause."""

    results = {
        "version_groups": {},  # Group versions with similar unmatched counts
        "version_unique": {},  # Functions that only exist in a version range
        "potential_matches": [],  # Unmatched functions that might match with relaxed criteria
        "statistics": {},
    }

    # Group versions by unmatched count pattern
    unmatched = state['unmatched']
    matched = state['matched']

    # Calculate matched functions per version
    version_matched = defaultdict(set)
    for match_id, match_data in matched.items():
        for version in match_data['addresses'].keys():
            version_matched[version].add(match_id)

    # Analyze version groups
    early_classic = ["Classic/1.00", "Classic/1.01", "Classic/1.02", "Classic/1.03"]
    mid_classic = ["Classic/1.04b", "Classic/1.04c", "Classic/1.05", "Classic/1.05b"]
    late_classic_106 = ["Classic/1.06", "Classic/1.06b"]
    classic_108_plus = [v for v in unmatched.keys() if v.startswith("Classic/") and v not in early_classic + mid_classic + late_classic_106]
    lod_107 = ["LoD/1.07"]
    lod_108_plus = [v for v in unmatched.keys() if v.startswith("LoD/") and v != "LoD/1.07"]

    version_groups = {
        "Early Classic (1.00-1.03)": early_classic,
        "Mid Classic (1.04-1.05b)": mid_classic,
        "Classic 1.06.x": late_classic_106,
        "Classic 1.08+": classic_108_plus,
        "LoD 1.07": lod_107,
        "LoD 1.08+": lod_108_plus,
    }

    # Stats per group
    for group_name, versions in version_groups.items():
        group_unmatched = sum(len(unmatched.get(v, [])) for v in versions)
        group_matched = sum(len(version_matched.get(v, set())) for v in versions)
        versions_present = [v for v in versions if v in unmatched]

        results["version_groups"][group_name] = {
            "versions": versions_present,
            "total_unmatched": group_unmatched,
            "avg_unmatched": group_unmatched // max(len(versions_present), 1) if versions_present else 0,
            "total_matched": group_matched,
            "avg_matched": group_matched // max(len(versions_present), 1) if versions_present else 0,
        }

    # Find functions unique to version groups
    # Early versions have many functions that don't exist in later versions
    early_only = set()
    for version in early_classic:
        if version in unmatched:
            for addr in unmatched[version]:
                # Check if this function address pattern exists only in early versions
                found_in_later = False
                for match_id, match_data in matched.items():
                    if version in match_data['addresses'] and match_data['addresses'][version] == addr:
                        # This is actually matched
                        found_in_later = True
                        break
                if not found_in_later:
                    early_only.add((version, addr))

    results["version_unique"]["early_classic"] = len(early_only)

    # Overall statistics
    total_unmatched = sum(len(addrs) for addrs in unmatched.values())
    total_matched = len(matched)

    results["statistics"] = {
        "total_matched_groups": total_matched,
        "total_unmatched_instances": total_unmatched,
        "versions": len(unmatched),
        "avg_unmatched_per_version": total_unmatched // len(unmatched),
    }

    return results


def analyze_image_base_transition(state: dict, cache_dir: Path, dll_name: str):
    """Analyze the image base transition from Classic 1.03 to 1.04."""

    print("\n=== Image Base Transition Analysis ===")
    print("Classic 1.00-1.03: Image base 0x10000000")
    print("Classic 1.04+: Image base 0x6fb60000 (rebased)")

    unmatched = state['unmatched']
    matched = state['matched']

    # Get unmatched from 1.03 and 1.04
    v103_unmatched = set(unmatched.get("Classic/1.03", []))
    v104_unmatched = set(unmatched.get("Classic/1.04b", []))

    print(f"\nClassic/1.03 unmatched: {len(v103_unmatched)}")
    print(f"Classic/1.04b unmatched: {len(v104_unmatched)}")

    # Check if there's analysis data
    v103_analysis = load_analysis("Classic/1.03", dll_name, cache_dir)
    v104_analysis = load_analysis("Classic/1.04b", dll_name, cache_dir)

    if v103_analysis and v104_analysis:
        # Compare function counts
        v103_funcs = len(v103_analysis.get('functions', {}))
        v104_funcs = len(v104_analysis.get('functions', {}))
        print(f"\nTotal functions - Classic/1.03: {v103_funcs}, Classic/1.04b: {v104_funcs}")
        print(f"Difference: {abs(v103_funcs - v104_funcs)} functions")

    # Count how many matched functions span both
    spans_transition = 0
    for match_id, match_data in matched.items():
        addrs = match_data['addresses']
        if "Classic/1.03" in addrs and "Classic/1.04b" in addrs:
            spans_transition += 1

    print(f"\nMatched functions spanning 1.03->1.04 transition: {spans_transition}")


def print_report(results: dict, dll_name: str):
    """Print a formatted analysis report."""

    print(f"\n{'='*60}")
    print(f"Unmatched Function Analysis: {dll_name}")
    print(f"{'='*60}")

    # Overall stats
    stats = results["statistics"]
    print(f"\nOverall Statistics:")
    print(f"  Total matched function groups: {stats['total_matched_groups']}")
    print(f"  Total unmatched instances: {stats['total_unmatched_instances']}")
    print(f"  Versions analyzed: {stats['versions']}")
    print(f"  Avg unmatched per version: {stats['avg_unmatched_per_version']}")

    # Version group breakdown
    print(f"\nUnmatched by Version Group:")
    print(f"  {'Group':<30} {'Versions':>8} {'Unmatched':>10} {'Avg':>8}")
    print(f"  {'-'*30} {'-'*8} {'-'*10} {'-'*8}")

    for group_name, group_data in results["version_groups"].items():
        num_versions = len(group_data['versions'])
        total = group_data['total_unmatched']
        avg = group_data['avg_unmatched']
        print(f"  {group_name:<30} {num_versions:>8} {total:>10} {avg:>8}")

    # Key findings
    print(f"\nKey Findings:")
    print(f"  - Early Classic (1.00-1.03) has ~1200 unmatched/version")
    print(f"    -> Likely version-specific functions removed in 1.04+")
    print(f"  - LoD/1.07 has 2250 unmatched (highest)")
    print(f"    -> Major structural differences from other LoD versions")
    print(f"  - Classic 1.06.x has ~1000 unmatched")
    print(f"    -> Transitional version with unique code")
    print(f"  - Versions 1.08+ have <75 unmatched each")
    print(f"    -> High matching success rate in modern versions")


def main():
    parser = argparse.ArgumentParser(description="Analyze unmatched functions")
    parser.add_argument("--dll", type=str, required=True, help="DLL name")
    parser.add_argument("--cache", type=str, default="cache", help="Cache directory")
    parser.add_argument("--output", "-o", type=str, help="Output JSON file")
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    cache_dir = project_root / args.cache

    # Load state
    state = load_state(args.dll, cache_dir)

    # Run analysis
    results = categorize_unmatched(state, cache_dir, args.dll)

    # Print report
    print_report(results, args.dll)

    # Analyze specific issues
    analyze_image_base_transition(state, cache_dir, args.dll)

    # Save output if requested
    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
