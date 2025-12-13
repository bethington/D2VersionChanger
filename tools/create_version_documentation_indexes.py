#!/usr/bin/env python3
"""
Create version-specific documentation indexes.
Generates comprehensive indexes for each Diablo 2 LoD version with:
- Cross-version function mappings
- What's new/changed/removed between versions
- Module-specific change summaries
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

REPORTS_PATH = Path("reports")
FUNCTION_INDEX_PATH = Path("data/function_index")

LOD_VERSIONS = ["1.07", "1.08", "1.09", "1.09b", "1.09d", "1.10", "1.11", "1.11b", "1.12a", "1.13c", "1.13d"]
MODULES = ["D2Game", "D2Client", "D2Common", "D2Win", "Storm", "Fog"]


def load_unified_index() -> Dict:
    """Load unified function index."""
    index_file = REPORTS_PATH / "unified_function_index.json"
    with open(index_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_version_functions(version: str) -> Dict[str, Set[str]]:
    """Load all functions for a specific version from unified index."""
    unified = load_unified_index()

    version_functions = defaultdict(set)

    # Extract functions present in this version
    for module_name, module_data in unified.get("modules", {}).items():
        for func in module_data.get("functions", []):
            addresses = func.get("addresses", {})
            if version in addresses:
                version_functions[module_name].add(func["name"])

    return version_functions


def get_version_index(version: int) -> int:
    """Get the index position of a version in the version list."""
    return LOD_VERSIONS.index(version) if version in LOD_VERSIONS else -1


def generate_version_profile(version: str, unified: Dict) -> Dict:
    """Generate comprehensive profile for a version."""
    profile = {
        "version": version,
        "release_date": get_version_release_date(version),
        "major_changes": get_major_changes_for_version(version),
        "modules": {},
        "statistics": {
            "total_functions": 0,
            "named_functions": 0,
            "unique_functions": 0,
            "functions_from_previous": 0,
            "functions_new": 0,
            "functions_removed": 0,
        }
    }

    # Get functions for this version
    current_version_funcs = load_version_functions(version)

    # Get functions for previous version (if exists)
    prev_version = get_previous_version(version)
    prev_version_funcs = load_version_functions(prev_version) if prev_version else {}

    # Analyze each module
    for module in MODULES:
        current = current_version_funcs.get(module, set())
        previous = prev_version_funcs.get(module, set())

        new_funcs = current - previous
        removed_funcs = previous - current
        stable_funcs = current & previous

        profile["modules"][module] = {
            "total_functions": len(current),
            "named_functions": count_named_in_set(current, unified, module),
            "unique_functions": len(new_funcs),
            "stable_functions": len(stable_funcs),
            "removed_functions": len(removed_funcs),
            "top_new_functions": sorted(list(new_funcs))[:10],
        }

        profile["statistics"]["total_functions"] += len(current)
        profile["statistics"]["named_functions"] += count_named_in_set(current, unified, module)
        profile["statistics"]["unique_functions"] += len(new_funcs)
        profile["statistics"]["functions_from_previous"] += len(stable_funcs)
        profile["statistics"]["functions_removed"] += len(removed_funcs)

        if not prev_version_funcs:
            profile["statistics"]["functions_new"] += len(current)

    return profile


def generate_version_comparison(version1: str, version2: str, unified: Dict) -> Dict:
    """Generate comparison between two versions."""
    v1_funcs = load_version_functions(version1)
    v2_funcs = load_version_functions(version2)

    comparison = {
        "from_version": version1,
        "to_version": version2,
        "modules": {},
        "summary": {
            "total_new_functions": 0,
            "total_removed_functions": 0,
            "total_stable_functions": 0,
            "total_modified_functions": 0,
        }
    }

    for module in MODULES:
        v1_set = v1_funcs.get(module, set())
        v2_set = v2_funcs.get(module, set())

        new_funcs = v2_set - v1_set
        removed_funcs = v1_set - v2_set
        stable_funcs = v1_set & v2_set

        comparison["modules"][module] = {
            "new_functions": {
                "count": len(new_funcs),
                "examples": sorted(list(new_funcs))[:5],
            },
            "removed_functions": {
                "count": len(removed_funcs),
                "examples": sorted(list(removed_funcs))[:5],
            },
            "stable_functions": len(stable_funcs),
            "stability_ratio": len(stable_funcs) / len(v1_set) if len(v1_set) > 0 else 0,
        }

        comparison["summary"]["total_new_functions"] += len(new_funcs)
        comparison["summary"]["total_removed_functions"] += len(removed_funcs)
        comparison["summary"]["total_stable_functions"] += len(stable_funcs)

    return comparison


def count_named_in_set(func_set: Set[str], unified: Dict, module: str) -> int:
    """Count named functions in a set."""
    count = 0
    module_data = unified.get("modules", {}).get(module, {})

    for func in module_data.get("functions", []):
        if func.get("name") in func_set and func.get("has_human_name"):
            count += 1

    return count


def get_previous_version(version: str) -> str:
    """Get the previous version in the version list."""
    try:
        idx = LOD_VERSIONS.index(version)
        return LOD_VERSIONS[idx - 1] if idx > 0 else None
    except (ValueError, IndexError):
        return None


def get_version_release_date(version: str) -> str:
    """Get estimated release date for a version."""
    release_dates = {
        "1.07": "2000-06-27",
        "1.08": "2001-03-13",
        "1.09": "2001-07-10",
        "1.09b": "2001-10-11",
        "1.09d": "2002-05-03",
        "1.10": "2003-10-27",
        "1.11": "2003-11-04",
        "1.11b": "2004-01-06",
        "1.12a": "2005-12-29",
        "1.13c": "2010-11-04",
        "1.13d": "2011-12-21",
    }
    return release_dates.get(version, "Unknown")


def get_major_changes_for_version(version: str) -> List[str]:
    """Get major changes for a version."""
    major_changes = {
        "1.07": ["Initial release", "Base D2 classic content"],
        "1.08": ["Bug fixes", "Balance adjustments"],
        "1.09": ["Lord of Destruction expansion content", "New areas, monsters, items", "Runes and jewels system"],
        "1.09b": ["Balance patches"],
        "1.09d": ["Final pre-patch adjustments"],
        "1.10": ["Major balance overhaul", "Immunities refactored", "More ubering support"],
        "1.11": ["Experience and monster balance", "Synergies added", "Ladder resets"],
        "1.11b": ["Bug fixes"],
        "1.12a": ["Ladder reset", "Minor adjustments"],
        "1.13c": ["Final patch with PvP improvements"],
        "1.13d": ["Final patch", "Security and bug fixes"],
    }
    return major_changes.get(version, ["Unknown changes"])


def generate_version_timeline() -> Dict:
    """Generate timeline of all versions."""
    timeline = {
        "title": "Diablo 2 LoD Version Timeline",
        "versions": []
    }

    for version in LOD_VERSIONS:
        timeline["versions"].append({
            "version": version,
            "release_date": get_version_release_date(version),
            "major_changes": get_major_changes_for_version(version),
        })

    return timeline


def main():
    """Main execution."""
    print("=" * 70)
    print("Creating Version-Specific Documentation Indexes")
    print("=" * 70)

    # Load unified index
    print("\nLoading unified function index...")
    unified = load_unified_index()

    # Generate version profiles
    print("\nGenerating version profiles...")
    version_profiles = {}
    for version in LOD_VERSIONS:
        print(f"  {version}...", end=" ", flush=True)
        profile = generate_version_profile(version, unified)
        version_profiles[version] = profile
        print(f"({profile['statistics']['total_functions']} functions)")

    # Save version profiles
    profiles_file = REPORTS_PATH / "version_profiles.json"
    with open(profiles_file, 'w', encoding='utf-8') as f:
        json.dump(version_profiles, f, indent=2)
    print(f"\nSaved version profiles to {profiles_file}")

    # Generate version comparisons
    print("\nGenerating version comparisons...")
    version_comparisons = {}
    for i in range(len(LOD_VERSIONS) - 1):
        v1 = LOD_VERSIONS[i]
        v2 = LOD_VERSIONS[i + 1]
        comparison_key = f"{v1}_to_{v2}"
        print(f"  {v1} -> {v2}...", end=" ", flush=True)
        comparison = generate_version_comparison(v1, v2, unified)
        version_comparisons[comparison_key] = comparison
        new_count = comparison["summary"]["total_new_functions"]
        removed_count = comparison["summary"]["total_removed_functions"]
        print(f"({new_count} new, {removed_count} removed)")

    # Save version comparisons
    comparisons_file = REPORTS_PATH / "version_comparisons.json"
    with open(comparisons_file, 'w', encoding='utf-8') as f:
        json.dump(version_comparisons, f, indent=2)
    print(f"\nSaved version comparisons to {comparisons_file}")

    # Generate timeline
    print("\nGenerating version timeline...")
    timeline = generate_version_timeline()
    timeline_file = REPORTS_PATH / "version_timeline.json"
    with open(timeline_file, 'w', encoding='utf-8') as f:
        json.dump(timeline, f, indent=2)
    print(f"Saved timeline to {timeline_file}")

    # Print summary
    print("\n" + "=" * 70)
    print("VERSION DOCUMENTATION INDEXES COMPLETE")
    print("=" * 70)

    print("\nVersion Profiles:")
    print("-" * 70)
    print(f"{'Version':<10} {'Total':<8} {'Named':<8} {'New':<8} {'Removed':<8}")
    print("-" * 70)
    for version in LOD_VERSIONS:
        stats = version_profiles[version]["statistics"]
        print(f"{version:<10} {stats['total_functions']:<8} {stats['named_functions']:<8} {stats['unique_functions']:<8} {stats['functions_removed']:<8}")

    print("\nMajor Version Transitions:")
    print("-" * 70)
    for i in range(len(LOD_VERSIONS) - 1):
        v1 = LOD_VERSIONS[i]
        v2 = LOD_VERSIONS[i + 1]
        key = f"{v1}_to_{v2}"
        comp = version_comparisons[key]
        new = comp["summary"]["total_new_functions"]
        removed = comp["summary"]["total_removed_functions"]
        stable = comp["summary"]["total_stable_functions"]
        pct_change = ((new - removed) / stable * 100) if stable > 0 else 0
        print(f"{v1} -> {v2}: {new:4} new, {removed:4} removed, {pct_change:5.1f}% change")

    print("\n" + "=" * 70)
    print("Files Generated:")
    print("-" * 70)
    print(f"  - {profiles_file}")
    print(f"  - {comparisons_file}")
    print(f"  - {timeline_file}")


if __name__ == "__main__":
    main()
