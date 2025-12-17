#!/usr/bin/env python3
"""
Generate comprehensive 1.10 cross-version function mappings for all modules.
Maps 1.10 functions to their addresses in all other LoD versions.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict

# Base paths
FUNCTION_INDEX_PATH = Path("data/function_index")
REPORTS_PATH = Path("reports")

# Target modules for mapping
MODULES = ["D2Game", "D2Client", "D2Common", "D2Win", "Storm", "Fog"]

# All LoD versions
LOD_VERSIONS = ["1.07", "1.08", "1.09", "1.09b", "1.09d", "1.10", "1.11", "1.11b", "1.12a", "1.13c", "1.13d"]


def load_module_version(module: str, version: str) -> Dict:
    """Load function index for a specific module and version."""
    file_path = FUNCTION_INDEX_PATH / "LoD" / version / f"{module}.dll.json"
    if not file_path.exists():
        return {}

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data
    except Exception as e:
        print(f"Error loading {module} {version}: {e}")
        return {}


def extract_human_named_functions(data: Dict) -> Dict[str, Dict]:
    """Extract functions with human-readable names from function index."""
    if not data or "functions" not in data:
        return {}

    result = {}
    for func in data.get("functions", []):
        if func.get("has_human_name", False):
            name = func.get("name")
            if name and not name.startswith("FUN_") and not name.startswith("Ordinal_"):
                result[name] = {
                    "address": func.get("address"),
                    "size": func.get("size"),
                    "api_index": func.get("indexes", {}).get("API"),
                    "mne_index": func.get("indexes", {}).get("MNE"),
                    "cfg_index": func.get("indexes", {}).get("CFG"),
                    "pro_index": func.get("indexes", {}).get("PRO"),
                }
    return result


def find_function_in_version(target_name: str, target_func: Dict, version_data: Dict) -> Tuple[str, Dict, str]:
    """Find a function in another version using name and index matching."""
    if not version_data or "functions" not in version_data:
        return None, None, "version_not_found"

    # First try: exact name match
    for func in version_data.get("functions", []):
        if func.get("name") == target_name:
            return func.get("address"), func, "name_match"

    # Second try: API index match (most reliable)
    target_api = target_func.get("api_index")
    if target_api:
        for func in version_data.get("functions", []):
            if func.get("indexes", {}).get("API") == target_api:
                return func.get("address"), func, "api_match"

    # Third try: MNE index match
    target_mne = target_func.get("mne_index")
    if target_mne:
        for func in version_data.get("functions", []):
            if func.get("indexes", {}).get("MNE") == target_mne:
                return func.get("address"), func, "mne_match"

    # Fourth try: CFG index match
    target_cfg = target_func.get("cfg_index")
    if target_cfg:
        for func in version_data.get("functions", []):
            if func.get("indexes", {}).get("CFG") == target_cfg:
                return func.get("address"), func, "cfg_match"

    return None, None, "no_match"


def generate_module_mapping(module: str) -> Dict:
    """Generate comprehensive 1.10 to all-versions mapping for a module."""
    print(f"\nGenerating mapping for {module}...")

    # Load 1.10 functions as baseline
    v110_data = load_module_version(module, "1.10")
    v110_functions = extract_human_named_functions(v110_data)

    print(f"  Found {len(v110_functions)} human-named functions in 1.10")

    # Load all other versions
    version_data = {}
    for version in LOD_VERSIONS:
        if version != "1.10":
            version_data[version] = load_module_version(module, version)

    # Map each 1.10 function to other versions
    mapping = {
        "module": module,
        "baseline_version": "1.10",
        "baseline_function_count": len(v110_functions),
        "all_versions": LOD_VERSIONS,
        "functions": [],
        "summary": {
            "all_versions": 0,
            "10_versions": 0,
            "9_versions": 0,
            "8_versions": 0,
            "7_or_fewer": 0,
        }
    }

    for func_name in sorted(v110_functions.keys()):
        v110_func = v110_functions[func_name]
        v110_addr = v110_func["address"]

        version_matches = {
            "1.10": {
                "address": v110_addr,
                "match_type": "baseline",
            }
        }

        # Search in all other versions
        for version in LOD_VERSIONS:
            if version == "1.10":
                continue

            vdata = version_data[version]
            addr, matched_func, match_type = find_function_in_version(func_name, v110_func, vdata)

            if addr:
                version_matches[version] = {
                    "address": addr,
                    "match_type": match_type,
                }

        # Count consistency
        consistency = len(version_matches) - 1  # Exclude 1.10 (baseline)
        consistency_bucket = "all_versions" if consistency == 10 else \
                            "10_versions" if consistency == 10 else \
                            "9_versions" if consistency == 9 else \
                            "8_versions" if consistency == 8 else \
                            "7_or_fewer"

        if consistency == 10:
            consistency_bucket = "all_versions"
        elif consistency == 9:
            consistency_bucket = "9_versions"
        elif consistency == 8:
            consistency_bucket = "8_versions"
        else:
            consistency_bucket = "7_or_fewer"

        mapping["summary"][consistency_bucket] += 1

        mapping["functions"].append({
            "name": func_name,
            "consistency_level": consistency,
            "versions_found": len(version_matches),
            "version_addresses": version_matches,
        })

    return mapping


def main():
    """Generate mappings for all modules."""
    print("="*60)
    print("Generating 1.10 Cross-Version Function Mappings")
    print("="*60)

    # Ensure reports directory exists
    REPORTS_PATH.mkdir(exist_ok=True)

    all_mappings = {}

    # Generate mapping for each module
    for module in MODULES:
        mapping = generate_module_mapping(module)
        all_mappings[module] = mapping

        # Save individual module mapping
        output_file = REPORTS_PATH / f"1_10_{module.lower()}_complete_mapping.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(mapping, f, indent=2)

        print(f"  Saved to {output_file}")
        print(f"  Summary: {mapping['summary']}")

    # Generate comprehensive summary
    comprehensive_summary = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "baseline_version": "1.10",
        "all_versions": LOD_VERSIONS,
        "modules": {}
    }

    for module, mapping in all_mappings.items():
        comprehensive_summary["modules"][module] = {
            "total_functions": mapping["baseline_function_count"],
            "consistency_summary": mapping["summary"],
            "functions_in_all_versions": len([f for f in mapping["functions"] if f["consistency_level"] == 10]),
            "functions_in_9_versions": len([f for f in mapping["functions"] if f["consistency_level"] == 9]),
            "functions_in_8_versions": len([f for f in mapping["functions"] if f["consistency_level"] == 8]),
        }

    # Save comprehensive summary
    summary_file = REPORTS_PATH / "1_10_comprehensive_mapping_summary.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(comprehensive_summary, f, indent=2)

    print("\n" + "="*60)
    print(f"Comprehensive summary saved to {summary_file}")
    print("="*60)

    # Print summary table
    print("\nCross-Version Function Coverage Summary:")
    print("-" * 60)
    for module in MODULES:
        mapping = all_mappings[module]
        total = mapping["baseline_function_count"]
        all_vers = mapping["summary"]["all_versions"]
        pct = (all_vers / total * 100) if total > 0 else 0
        print(f"{module:12} | Total: {total:4d} | All 11 versions: {all_vers:4d} ({pct:5.1f}%)")
    print("-" * 60)


if __name__ == "__main__":
    main()
