#!/usr/bin/env python3
"""
Deep analysis of unmatched functions to understand WHY they don't match.

This script examines:
1. Which versions have the most unique (unmatched) functions
2. Whether unmatched functions exist in multiple versions but failed to match
3. Function size distribution of unmatched vs matched
4. Whether unmatched functions are truly unique or just failed matching
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


def analyze_unmatched_deeply(state: dict, cache_dir: Path, dll_name: str):
    """Perform deep analysis of unmatched functions."""

    matched = state['matched']
    unmatched = state['unmatched']

    print(f"\n{'='*70}")
    print(f"DEEP UNMATCHED ANALYSIS: {dll_name}")
    print(f"{'='*70}")

    # 1. Get function counts per version (matched + unmatched)
    print(f"\n## 1. Function Counts by Version")
    print(f"{'Version':<25} {'Total':>8} {'Matched':>8} {'Unmatched':>10} {'Match%':>8}")
    print("-" * 65)

    version_stats = {}
    for version in sorted(unmatched.keys()):
        # Count matched functions in this version
        matched_count = sum(1 for m in matched.values() if version in m['addresses'])
        unmatched_count = len(unmatched[version])
        total = matched_count + unmatched_count
        match_pct = (matched_count / total * 100) if total > 0 else 0

        version_stats[version] = {
            'total': total,
            'matched': matched_count,
            'unmatched': unmatched_count,
            'match_pct': match_pct
        }

        print(f"{version:<25} {total:>8} {matched_count:>8} {unmatched_count:>10} {match_pct:>7.1f}%")

    # 2. Analyze which versions share unmatched functions
    print(f"\n## 2. Unmatched Function Overlap Analysis")
    print("Checking if unmatched functions from one version exist in others...")

    # Load analysis data for versions with high unmatched counts
    high_unmatched_versions = [v for v, s in version_stats.items() if s['unmatched'] > 500]

    for version in high_unmatched_versions[:3]:  # Analyze top 3
        analysis = load_analysis(version, dll_name, cache_dir)
        if not analysis:
            print(f"\n  {version}: No analysis data available")
            continue

        print(f"\n  ### {version} ({version_stats[version]['unmatched']} unmatched)")

        # Get unmatched addresses for this version
        unmatched_addrs = set(unmatched[version])

        # Get function info for unmatched
        functions = analysis.get('functions', {})

        # Analyze sizes of unmatched functions
        unmatched_sizes = []
        tiny_funcs = 0  # < 16 bytes
        small_funcs = 0  # 16-64 bytes
        medium_funcs = 0  # 64-256 bytes
        large_funcs = 0  # > 256 bytes

        for addr in unmatched_addrs:
            if addr in functions:
                size = functions[addr].get('size', 0)
                unmatched_sizes.append(size)
                if size < 16:
                    tiny_funcs += 1
                elif size < 64:
                    small_funcs += 1
                elif size < 256:
                    medium_funcs += 1
                else:
                    large_funcs += 1

        if unmatched_sizes:
            avg_size = sum(unmatched_sizes) / len(unmatched_sizes)
            print(f"    Function size distribution:")
            print(f"      Tiny (<16 bytes):    {tiny_funcs:>5} ({tiny_funcs/len(unmatched_sizes)*100:.1f}%)")
            print(f"      Small (16-64 bytes): {small_funcs:>5} ({small_funcs/len(unmatched_sizes)*100:.1f}%)")
            print(f"      Medium (64-256):     {medium_funcs:>5} ({medium_funcs/len(unmatched_sizes)*100:.1f}%)")
            print(f"      Large (>256 bytes):  {large_funcs:>5} ({large_funcs/len(unmatched_sizes)*100:.1f}%)")
            print(f"    Average size: {avg_size:.1f} bytes")

    # 3. Compare matched vs unmatched function sizes across all versions
    print(f"\n## 3. Matched vs Unmatched Size Comparison")

    all_matched_sizes = []
    all_unmatched_sizes = []

    for version in list(unmatched.keys())[:5]:  # Sample 5 versions
        analysis = load_analysis(version, dll_name, cache_dir)
        if not analysis:
            continue

        functions = analysis.get('functions', {})
        unmatched_addrs = set(unmatched[version])

        for addr, func_info in functions.items():
            size = func_info.get('size', 0)
            if addr in unmatched_addrs:
                all_unmatched_sizes.append(size)
            else:
                all_matched_sizes.append(size)

    if all_matched_sizes and all_unmatched_sizes:
        print(f"  Matched functions:   avg={sum(all_matched_sizes)/len(all_matched_sizes):.1f} bytes, count={len(all_matched_sizes)}")
        print(f"  Unmatched functions: avg={sum(all_unmatched_sizes)/len(all_unmatched_sizes):.1f} bytes, count={len(all_unmatched_sizes)}")

        # Count tiny functions
        matched_tiny = sum(1 for s in all_matched_sizes if s < 16)
        unmatched_tiny = sum(1 for s in all_unmatched_sizes if s < 16)
        print(f"\n  Tiny functions (<16 bytes):")
        print(f"    Matched:   {matched_tiny} ({matched_tiny/len(all_matched_sizes)*100:.1f}%)")
        print(f"    Unmatched: {unmatched_tiny} ({unmatched_tiny/len(all_unmatched_sizes)*100:.1f}%)")

    # 4. Analyze version-exclusive functions
    print(f"\n## 4. Version-Exclusive Functions")
    print("Functions that exist ONLY in specific version ranges...")

    # Group versions
    version_groups = {
        'Early Classic (1.00-1.03)': [v for v in unmatched.keys() if 'Classic' in v and any(x in v for x in ['1.00', '1.01', '1.02', '1.03'])],
        'Mid Classic (1.04-1.06b)': [v for v in unmatched.keys() if 'Classic' in v and any(x in v for x in ['1.04', '1.05', '1.06'])],
        'Late Classic (1.08+)': [v for v in unmatched.keys() if 'Classic' in v and any(x in v for x in ['1.08', '1.09', '1.10', '1.11', '1.12', '1.13', '1.14'])],
        'LoD 1.07 Only': [v for v in unmatched.keys() if v == 'LoD/1.07'],
        'LoD 1.08+': [v for v in unmatched.keys() if 'LoD' in v and v != 'LoD/1.07'],
    }

    # Find functions that only appear in certain version groups
    for group_name, versions in version_groups.items():
        if not versions:
            continue

        # Count functions that are matched and span this group
        group_only_matches = 0
        for match_id, match_data in matched.items():
            addrs = match_data['addresses']
            in_group = any(v in addrs for v in versions)
            outside_group = any(v in addrs for v in unmatched.keys() if v not in versions)
            if in_group and not outside_group:
                group_only_matches += 1

        print(f"  {group_name}: {group_only_matches} functions exist ONLY in this group")

    # 5. Signature analysis - why didn't prologue matching work?
    print(f"\n## 5. Prologue Pattern Analysis")
    print("Examining why prologue matching failed for some functions...")

    # Sample an unmatched-heavy version
    sample_version = 'Classic/1.00' if 'Classic/1.00' in unmatched else list(unmatched.keys())[0]
    analysis = load_analysis(sample_version, dll_name, cache_dir)

    if analysis:
        functions = analysis.get('functions', {})
        signatures = analysis.get('signatures', {})
        unmatched_addrs = set(unmatched[sample_version])

        # Collect prologue patterns
        prologue_counts = defaultdict(int)
        for addr in unmatched_addrs:
            if addr in signatures:
                sig = signatures[addr]
                prologue = sig.get('prologue', 'unknown')[:16]  # First 16 chars
                prologue_counts[prologue] += 1

        print(f"\n  Top prologue patterns in unmatched functions ({sample_version}):")
        for prologue, count in sorted(prologue_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"    {prologue}: {count} functions")

    # 6. Summary and recommendations
    print(f"\n## 6. Summary & Recommendations")
    print("-" * 50)

    total_unmatched = sum(len(addrs) for addrs in unmatched.values())
    total_matched = len(matched)

    print(f"  Total matched function groups: {total_matched}")
    print(f"  Total unmatched instances: {total_unmatched}")

    # Identify the main issues
    issues = []

    # Check for tiny function problem
    if all_unmatched_sizes:
        tiny_pct = sum(1 for s in all_unmatched_sizes if s < 16) / len(all_unmatched_sizes) * 100
        if tiny_pct > 30:
            issues.append(f"  - {tiny_pct:.0f}% of unmatched are tiny (<16 bytes) - too small for reliable matching")

    # Check for version-specific code
    early_unmatched = sum(version_stats[v]['unmatched'] for v in version_stats if '1.00' in v or '1.01' in v or '1.02' in v or '1.03' in v)
    if early_unmatched > 3000:
        issues.append(f"  - {early_unmatched} unmatched in early Classic - likely removed/rewritten code")

    lod107_unmatched = version_stats.get('LoD/1.07', {}).get('unmatched', 0)
    if lod107_unmatched > 1000:
        issues.append(f"  - {lod107_unmatched} unmatched in LoD/1.07 - unique first-LoD code")

    if issues:
        print("\n  Key findings:")
        for issue in issues:
            print(issue)

    print("\n  Recommendations:")
    print("  1. Unmatched functions in early Classic are version-specific - this is expected")
    print("  2. Tiny functions (<16 bytes) lack sufficient context for matching")
    print("  3. Consider analyzing early Classic separately as a distinct codebase")
    print("  4. LoD/1.07 should be treated as a transitional version")


def main():
    parser = argparse.ArgumentParser(description="Deep analysis of unmatched functions")
    parser.add_argument("--dll", type=str, default="D2Client.dll", help="DLL name")
    parser.add_argument("--cache", type=str, default="cache", help="Cache directory")
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    cache_dir = project_root / args.cache

    state = load_state(args.dll, cache_dir)
    analyze_unmatched_deeply(state, cache_dir, args.dll)


if __name__ == "__main__":
    main()
