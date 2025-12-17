#!/usr/bin/env python3
"""
Analyze 1.10 function stability across versions.
Generates metrics on function consistency and identifies best cross-version anchors.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple

REPORTS_PATH = Path("reports")


def analyze_stability():
    """Analyze function stability across all modules."""
    print("="*70)
    print("Analyzing 1.10 Function Stability Across LoD Versions")
    print("="*70)

    # Load comprehensive summary
    summary_file = REPORTS_PATH / "1_10_comprehensive_mapping_summary.json"
    with open(summary_file, 'r', encoding='utf-8') as f:
        summary = json.load(f)

    # Collect stability data for all modules
    modules = summary["modules"]
    stability_report = {
        "timestamp": summary["timestamp"],
        "baseline_version": "1.10",
        "all_versions": summary["all_versions"],
        "module_analysis": {},
        "cross_module_analysis": {
            "total_functions_across_modules": 0,
            "most_stable_module": "",
            "least_stable_module": "",
            "average_stability": 0.0,
        }
    }

    total_funcs = 0
    total_all_versions = 0
    all_modules_stability = {}

    for module in sorted(modules.keys()):
        module_data = modules[module]
        total = module_data["total_functions"]
        all_vers = module_data["functions_in_all_versions"]
        stability_pct = (all_vers / total * 100) if total > 0 else 0

        total_funcs += total
        total_all_versions += all_vers
        all_modules_stability[module] = stability_pct

        stability_report["module_analysis"][module] = {
            "total_functions": total,
            "functions_in_all_versions": all_vers,
            "consistency_percentage": round(stability_pct, 1),
            "functions_by_consistency": {
                "all_11_versions": module_data.get("functions_in_all_versions", 0),
                "9_versions": module_data.get("functions_in_9_versions", 0),
                "8_versions": module_data.get("functions_in_8_versions", 0),
            }
        }

    # Calculate cross-module metrics
    avg_stability = sum(all_modules_stability.values()) / len(all_modules_stability) if all_modules_stability else 0
    most_stable = max(all_modules_stability.items(), key=lambda x: x[1])
    least_stable = min(all_modules_stability.items(), key=lambda x: x[1])

    stability_report["cross_module_analysis"] = {
        "total_functions_across_all_modules": total_funcs,
        "total_functions_present_in_all_versions": total_all_versions,
        "average_cross_version_stability": round(avg_stability, 1),
        "most_stable_module": {
            "name": most_stable[0],
            "stability_percentage": round(most_stable[1], 1),
        },
        "least_stable_module": {
            "name": least_stable[0],
            "stability_percentage": round(least_stable[1], 1),
        },
        "module_ranking": [
            {
                "rank": i+1,
                "module": module,
                "stability_percentage": round(stability, 1),
            }
            for i, (module, stability) in enumerate(sorted(all_modules_stability.items(), key=lambda x: x[1], reverse=True))
        ]
    }

    # Save stability analysis
    output_file = REPORTS_PATH / "1_10_stability_analysis.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(stability_report, f, indent=2)

    print(f"\nSaved stability analysis to {output_file}")

    # Print summary table
    print("\n" + "="*70)
    print("MODULE STABILITY RANKING")
    print("-"*70)
    print(f"{'Rank':<6} {'Module':<12} {'Total':>6} {'All 11 Vers':>12} {'Stability':>12}")
    print("-"*70)

    for rank, (module, stability) in enumerate(sorted(all_modules_stability.items(), key=lambda x: x[1], reverse=True), 1):
        module_info = modules[module]
        total = module_info["total_functions"]
        all_vers = module_info["functions_in_all_versions"]
        print(f"{rank:<6} {module:<12} {total:>6} {all_vers:>12} {stability:>11.1f}%")

    print("-"*70)
    print(f"{'TOTAL':<18} {total_funcs:>6} {total_all_versions:>12} {(total_all_versions/total_funcs*100):>11.1f}%")
    print("="*70)

    # Generate recommendations
    print("\nKEY INSIGHTS:")
    print("-"*70)
    print(f"1. Most Stable Module: {most_stable[0]} ({most_stable[1]:.1f}%)")
    print(f"   - Best choice for cross-version anchoring")
    print(f"\n2. Least Stable Module: {least_stable[0]} ({least_stable[1]:.1f}%)")
    print(f"   - More version-specific variations to account for")
    print(f"\n3. Cross-Module Average: {avg_stability:.1f}%")
    print(f"   - Overall {total_all_versions:,} out of {total_funcs:,} functions")
    print(f"   - {((total_funcs - total_all_versions) / total_funcs * 100):.1f}% are version-specific")
    print("-"*70)

    return stability_report


def generate_anchor_recommendations():
    """Generate recommendations for best functions to use as cross-version anchors."""
    print("\n" + "="*70)
    print("CROSS-VERSION ANCHOR RECOMMENDATIONS")
    print("="*70)

    # Load detailed mappings
    mappings = {}
    for module in ["D2Game", "D2Client", "D2Common", "D2Win", "Storm", "Fog"]:
        mapping_file = REPORTS_PATH / f"1_10_{module.lower()}_complete_mapping.json"
        with open(mapping_file, 'r', encoding='utf-8') as f:
            mappings[module] = json.load(f)

    # Find best anchor functions
    anchor_report = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "purpose": "Identify stable functions for use as cross-version anchors",
        "anchors_by_module": {}
    }

    for module in sorted(mappings.keys()):
        mapping = mappings[module]
        functions = mapping["functions"]

        # Get functions found in all 11 versions
        all_version_funcs = [f for f in functions if f["consistency_level"] == 10]

        # Sort by name for consistency
        all_version_funcs = sorted(all_version_funcs, key=lambda x: x["name"])

        anchor_report["anchors_by_module"][module] = {
            "total_all_version_anchors": len(all_version_funcs),
            "functions": [
                {
                    "name": f["name"],
                    "versions_found": f["versions_found"],
                    "v110_address": f["version_addresses"]["1.10"]["address"],
                    "sample_addresses": {
                        "v107": f["version_addresses"].get("1.07", {}).get("address"),
                        "v109d": f["version_addresses"].get("1.09d", {}).get("address"),
                        "v111": f["version_addresses"].get("1.11", {}).get("address"),
                        "v113d": f["version_addresses"].get("1.13d", {}).get("address"),
                    }
                }
                for f in all_version_funcs[:10]  # Show first 10
            ]
        }

    # Save anchor recommendations
    output_file = REPORTS_PATH / "1_10_anchor_recommendations.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(anchor_report, f, indent=2)

    print(f"\nSaved anchor recommendations to {output_file}")

    # Print summary
    print("\nRECOMMENDED ANCHORS (by module):")
    print("-"*70)
    for module in sorted(anchor_report["anchors_by_module"].keys()):
        module_anchors = anchor_report["anchors_by_module"][module]
        count = module_anchors["total_all_version_anchors"]
        print(f"{module:12} | {count:3d} functions present in all 11 versions")
    print("-"*70)


def main():
    """Run complete stability analysis."""
    REPORTS_PATH.mkdir(exist_ok=True)

    # Analyze stability
    analyze_stability()

    # Generate anchor recommendations
    generate_anchor_recommendations()

    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70)


if __name__ == "__main__":
    main()
