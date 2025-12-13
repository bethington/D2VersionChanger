#!/usr/bin/env python3
"""
Build unified function index covering all LoD versions.
Creates a master index showing all functions across all versions with consistency info.
"""

import json
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict

FUNCTION_INDEX_PATH = Path("data/function_index")
REPORTS_PATH = Path("reports")

MODULES = ["D2Game", "D2Client", "D2Common", "D2Win", "Storm", "Fog"]
LOD_VERSIONS = ["1.07", "1.08", "1.09", "1.09b", "1.09d", "1.10", "1.11", "1.11b", "1.12a", "1.13c", "1.13d"]


def load_module_version(module: str, version: str) -> Dict:
    """Load function index for a module and version."""
    file_path = FUNCTION_INDEX_PATH / "LoD" / version / f"{module}.dll.json"
    if not file_path.exists():
        return {}

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {module} {version}: {e}")
        return {}


def build_unified_index() -> Dict:
    """Build unified index across all versions and modules."""
    print("="*70)
    print("Building Unified Function Index")
    print("="*70)

    unified = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "versions": LOD_VERSIONS,
        "modules": {},
        "summary": {
            "total_unique_functions": 0,
            "total_named_functions": 0,
            "modules_summary": {}
        }
    }

    # Build index for each module
    for module in MODULES:
        print(f"\nProcessing {module}...")
        module_index = _build_module_index(module)
        unified["modules"][module] = module_index
        unified["summary"]["modules_summary"][module] = {
            "total_unique_functions": len(module_index["functions"]),
            "total_named_functions": sum(
                1 for f in module_index["functions"] if f.get("has_human_name", False)
            ),
            "consistency_distribution": _calculate_consistency_distribution(module_index["functions"])
        }

    # Calculate totals
    for module in unified["modules"]:
        unified["summary"]["total_unique_functions"] += unified["summary"]["modules_summary"][module]["total_unique_functions"]
        unified["summary"]["total_named_functions"] += unified["summary"]["modules_summary"][module]["total_named_functions"]

    return unified


def _build_module_index(module: str) -> Dict:
    """Build unified index for a single module."""
    module_index = {
        "module_name": module,
        "versions": LOD_VERSIONS,
        "functions": [],
        "by_consistency": defaultdict(list)
    }

    # Track all unique functions across all versions
    all_functions = {}  # name -> {versions: set, addresses: {version: address}, ...}

    # Load all versions
    version_data = {}
    for version in LOD_VERSIONS:
        data = load_module_version(module, version)
        if data and "functions" in data:
            version_data[version] = data

    # Collect all unique functions
    for version, data in version_data.items():
        for func in data.get("functions", []):
            func_name = func.get("name")
            if not func_name:
                continue

            if func_name not in all_functions:
                all_functions[func_name] = {
                    "name": func_name,
                    "has_human_name": func.get("has_human_name", False),
                    "versions": set(),
                    "addresses": {},
                    "index_methods": set(),
                    "first_seen_version": version,
                }

            all_functions[func_name]["versions"].add(version)
            all_functions[func_name]["addresses"][version] = func.get("address")

            # Track index methods
            indexes = func.get("indexes", {})
            for method, value in indexes.items():
                if value:
                    all_functions[func_name]["index_methods"].add(method)

    # Convert to list and add consistency info
    for func_name, func_info in sorted(all_functions.items()):
        consistency = len(func_info["versions"])
        func_entry = {
            "name": func_name,
            "consistency_level": consistency,
            "versions_count": consistency,
            "has_human_name": func_info["has_human_name"],
            "versions": sorted(list(func_info["versions"])),
            "addresses": func_info["addresses"],
            "index_methods": sorted(list(func_info["index_methods"])),
            "first_seen_version": func_info["first_seen_version"],
        }

        module_index["functions"].append(func_entry)

        # Also add to consistency bucket
        if consistency not in module_index["by_consistency"]:
            module_index["by_consistency"][consistency] = []
        module_index["by_consistency"][consistency].append(func_name)

    return module_index


def _calculate_consistency_distribution(functions: List[Dict]) -> Dict:
    """Calculate distribution of functions by consistency level."""
    distribution = defaultdict(int)
    for func in functions:
        consistency = func.get("consistency_level", 0)
        distribution[consistency] += 1

    return dict(sorted(distribution.items(), reverse=True))


def generate_quick_reference(unified: Dict) -> Dict:
    """Generate quick reference guide."""
    reference = {
        "timestamp": unified["timestamp"],
        "statistics": {
            "versions": len(unified["versions"]),
            "modules": len(unified["modules"]),
            "total_unique_functions": unified["summary"]["total_unique_functions"],
            "total_named_functions": unified["summary"]["total_named_functions"],
        },
        "by_module": {},
        "most_consistent": {},
        "least_consistent": {}
    }

    # Module statistics
    for module in unified["modules"]:
        module_data = unified["modules"][module]
        named_count = sum(1 for f in module_data["functions"] if f.get("has_human_name"))

        reference["by_module"][module] = {
            "total_functions": len(module_data["functions"]),
            "named_functions": named_count,
            "consistency_distribution": module_data.get("consistency_distribution", {})
        }

        # Find most consistent
        all_11_version = [f for f in module_data["functions"] if f["consistency_level"] == 11]
        reference["most_consistent"][module] = {
            "functions_in_all_versions": len(all_11_version),
            "sample": [f["name"] for f in all_11_version[:5]]
        }

        # Find least consistent
        single_version = [f for f in module_data["functions"] if f["consistency_level"] == 1]
        reference["least_consistent"][module] = {
            "version_specific_functions": len(single_version),
            "sample": [f["name"] for f in single_version[:5]]
        }

    return reference


def main():
    """Main execution."""
    REPORTS_PATH.mkdir(exist_ok=True)

    # Build unified index
    unified = build_unified_index()

    # Save unified index
    index_file = REPORTS_PATH / "unified_function_index.json"
    with open(index_file, 'w', encoding='utf-8') as f:
        json.dump(unified, f, indent=2)
    print(f"\nSaved unified index to {index_file}")

    # Generate quick reference
    reference = generate_quick_reference(unified)

    # Save quick reference
    ref_file = REPORTS_PATH / "unified_function_index_quick_reference.json"
    with open(ref_file, 'w', encoding='utf-8') as f:
        json.dump(reference, f, indent=2)
    print(f"Saved quick reference to {ref_file}")

    # Print summary
    print("\n" + "="*70)
    print("UNIFIED INDEX SUMMARY")
    print("="*70)
    print(f"Total Unique Functions: {unified['summary']['total_unique_functions']:,}")
    print(f"Total Named Functions: {unified['summary']['total_named_functions']:,}")
    print(f"Versions Analyzed: {len(LOD_VERSIONS)}")
    print(f"Modules: {len(MODULES)}\n")

    print("Module Breakdown:")
    print("-"*70)
    for module in MODULES:
        mod_sum = unified["summary"]["modules_summary"][module]
        total = mod_sum["total_unique_functions"]
        named = mod_sum["total_named_functions"]
        print(f"{module:12} | {total:5} total | {named:5} named | {mod_sum['consistency_distribution']}")

    print("\n" + "="*70)
    print("Most Consistent Functions (All 11 Versions)")
    print("="*70)
    for module in MODULES:
        most_consistent = reference["most_consistent"][module]
        count = most_consistent["functions_in_all_versions"]
        print(f"{module:12} | {count:3} functions")
        if most_consistent["sample"]:
            for name in most_consistent["sample"]:
                print(f"              - {name}")


if __name__ == "__main__":
    main()
