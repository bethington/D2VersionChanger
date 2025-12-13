#!/usr/bin/env python3
"""
Analyze 582 all-version functions for renaming and documentation strategy.
Extracts function signatures, categories, and recommends optimal naming.
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

REPORTS_PATH = Path("reports")
FUNCTION_INDEX_PATH = Path("data/function_index")

# Function categories based on naming patterns
FUNCTION_CATEGORIES = {
    "Memory Management": ["Alloc", "Free", "Create", "Delete", "Pool", "Memory"],
    "String Operations": ["Str", "String", "Sprintf", "Printf", "Copy", "Compare"],
    "Bit Operations": ["Bit", "Flag", "Clear", "Set", "Shift", "Mask"],
    "Math Operations": ["Math", "Calc", "Add", "Sub", "Mul", "Div", "Max", "Min"],
    "Data Structures": ["List", "Array", "Table", "Hash", "Tree", "Queue", "Stack"],
    "Game Logic": ["Unit", "Monster", "Item", "Quest", "Event", "Game", "World"],
    "Graphics/Rendering": ["Draw", "Sprite", "Cel", "Palette", "Graphics", "Image", "Render"],
    "UI/Windows": ["Ctrl", "Dialog", "Window", "Button", "Menu", "Text", "Label"],
    "File I/O": ["File", "Read", "Write", "Load", "Save", "Open", "Close"],
    "Network": ["Net", "Socket", "Packet", "Send", "Recv", "Protocol"],
    "Threading": ["Lock", "Mutex", "Thread", "Wait", "Signal", "Sync"],
}


def load_unified_index() -> Dict:
    """Load the unified function index."""
    index_file = REPORTS_PATH / "unified_function_index.json"
    if not index_file.exists():
        print("Error: unified_function_index.json not found")
        return {}

    with open(index_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_all_version_functions(unified: Dict) -> List[Dict]:
    """Extract all functions present in all 11 versions."""
    all_version_funcs = []

    for module_name, module_data in unified.get("modules", {}).items():
        for func in module_data.get("functions", []):
            if func.get("consistency_level") == 11:  # All 11 versions
                func["module"] = module_name
                all_version_funcs.append(func)

    return sorted(all_version_funcs, key=lambda x: x["name"])


def categorize_function(func_name: str) -> Tuple[str, int]:
    """Categorize a function based on its name. Returns (category, confidence)."""
    name_upper = func_name.upper()

    for category, keywords in FUNCTION_CATEGORIES.items():
        for keyword in keywords:
            if keyword.upper() in name_upper:
                return category, 1 if len(keyword) > 4 else 0

    return "Utility", 0


def analyze_function_signature(func: Dict) -> Dict:
    """Analyze function signature from multiple versions."""
    analysis = {
        "name": func.get("name"),
        "module": func.get("module"),
        "category": "Unknown",
        "confidence": 0,
        "index_methods": func.get("index_methods", []),
        "versions_with_data": []
    }

    # Categorize
    category, conf = categorize_function(func["name"])
    analysis["category"] = category
    analysis["confidence"] = conf

    return analysis


def calculate_renaming_priority(func: Dict, analysis: Dict) -> int:
    """Calculate renaming priority (higher = more important to rename)."""
    priority = 0

    # Named functions get high priority
    if func.get("has_human_name"):
        priority += 10

    # Functions with multiple index methods are reliable
    num_indexes = len(analysis.get("index_methods", []))
    priority += min(num_indexes, 3)

    # Core utilities get high priority
    if analysis["category"] in ["Memory Management", "String Operations", "Bit Operations"]:
        priority += 5

    return priority


def generate_renaming_report(all_version_funcs: List[Dict]) -> Dict:
    """Generate comprehensive renaming strategy report."""
    report = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "total_all_version_functions": len(all_version_funcs),
        "by_category": defaultdict(list),
        "by_module": defaultdict(list),
        "by_priority": [],
        "analysis": []
    }

    # Analyze each function
    for func in all_version_funcs:
        analysis = analyze_function_signature(func)
        priority = calculate_renaming_priority(func, analysis)

        analysis["priority"] = priority
        report["analysis"].append(analysis)

        # Group by category
        category = analysis["category"]
        report["by_category"][category].append({
            "name": func["name"],
            "module": func["module"],
            "priority": priority
        })

        # Group by module
        module = func["module"]
        report["by_module"][module].append({
            "name": func["name"],
            "category": category,
            "priority": priority
        })

    # Sort by priority
    report["by_priority"] = sorted(
        [{"name": a["name"], "module": a["module"], "category": a["category"], "priority": a["priority"]}
         for a in report["analysis"]],
        key=lambda x: x["priority"],
        reverse=True
    )

    # Convert defaultdicts to regular dicts for JSON serialization
    report["by_category"] = dict(report["by_category"])
    report["by_module"] = dict(report["by_module"])

    # Add category summaries
    report["category_summary"] = {
        cat: len(funcs) for cat, funcs in report["by_category"].items()
    }

    # Add module summaries
    report["module_summary"] = {
        mod: len(funcs) for mod, funcs in report["by_module"].items()
    }

    return report


def generate_priority_tiers(report: Dict) -> Dict:
    """Generate tiered priorities for renaming phases."""
    tiers = {
        "tier_1_critical": [],  # Priority >= 15
        "tier_2_high": [],      # Priority 10-14
        "tier_3_medium": [],    # Priority 5-9
        "tier_4_low": [],       # Priority 1-4
        "tier_5_utility": [],   # Priority 0
    }

    for item in report["by_priority"]:
        priority = item["priority"]
        if priority >= 15:
            tiers["tier_1_critical"].append(item)
        elif priority >= 10:
            tiers["tier_2_high"].append(item)
        elif priority >= 5:
            tiers["tier_3_medium"].append(item)
        elif priority >= 1:
            tiers["tier_4_low"].append(item)
        else:
            tiers["tier_5_utility"].append(item)

    tiers["summary"] = {
        "tier_1_critical": len(tiers["tier_1_critical"]),
        "tier_2_high": len(tiers["tier_2_high"]),
        "tier_3_medium": len(tiers["tier_3_medium"]),
        "tier_4_low": len(tiers["tier_4_low"]),
        "tier_5_utility": len(tiers["tier_5_utility"]),
    }

    return tiers


def generate_module_strategies(report: Dict) -> Dict:
    """Generate module-specific renaming strategies."""
    strategies = {}

    for module, funcs in report["by_module"].items():
        # Sort by priority
        sorted_funcs = sorted(funcs, key=lambda x: x["priority"], reverse=True)

        strategies[module] = {
            "total_functions": len(funcs),
            "top_priority": sorted_funcs[:10],
            "by_category": defaultdict(list),
            "recommended_first_pass": len([f for f in sorted_funcs if f["priority"] >= 10])
        }

        # Group by category
        for func in sorted_funcs:
            strategies[module]["by_category"][func["category"]].append(func["name"])

        # Convert to regular dict
        strategies[module]["by_category"] = dict(strategies[module]["by_category"])

    return strategies


def main():
    """Main analysis."""
    print("="*70)
    print("Analyzing 582 All-Version Functions")
    print("="*70)

    # Load unified index
    unified = load_unified_index()
    if not unified:
        return

    # Extract all-version functions
    print("\nExtracting all-version functions...")
    all_version_funcs = extract_all_version_functions(unified)
    print(f"Found {len(all_version_funcs)} functions present in all 11 versions")

    # Generate renaming report
    print("\nGenerating renaming strategy report...")
    report = generate_renaming_report(all_version_funcs)

    # Generate priority tiers
    print("Calculating priority tiers...")
    tiers = generate_priority_tiers(report)

    # Generate module strategies
    print("Creating module-specific strategies...")
    strategies = generate_module_strategies(report)

    # Save reports
    print("\nSaving reports...")

    # Save main analysis
    analysis_file = REPORTS_PATH / "all_version_functions_analysis.json"
    with open(analysis_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(f"  Saved analysis to {analysis_file}")

    # Save priority tiers
    tiers_file = REPORTS_PATH / "renaming_priority_tiers.json"
    with open(tiers_file, 'w', encoding='utf-8') as f:
        json.dump(tiers, f, indent=2)
    print(f"  Saved priority tiers to {tiers_file}")

    # Save module strategies
    strategies_file = REPORTS_PATH / "module_renaming_strategies.json"
    with open(strategies_file, 'w', encoding='utf-8') as f:
        json.dump(strategies, f, indent=2)
    print(f"  Saved module strategies to {strategies_file}")

    # Print summary
    print("\n" + "="*70)
    print("ALL-VERSION FUNCTION ANALYSIS SUMMARY")
    print("="*70)
    print(f"\nTotal Functions: {len(all_version_funcs)}")
    print(f"Modules: {len(report['module_summary'])}")

    print("\nFunctions by Category:")
    print("-"*70)
    for category in sorted(report["category_summary"].keys()):
        count = report["category_summary"][category]
        pct = (count / len(all_version_funcs)) * 100
        print(f"  {category:25} {count:3} functions ({pct:5.1f}%)")

    print("\nFunctions by Module:")
    print("-"*70)
    for module in sorted(report["module_summary"].keys()):
        count = report["module_summary"][module]
        pct = (count / len(all_version_funcs)) * 100
        print(f"  {module:15} {count:3} functions ({pct:5.1f}%)")

    print("\nRenaming Priority Tiers:")
    print("-"*70)
    print(f"  Tier 1 (Critical):  {tiers['summary']['tier_1_critical']:3} functions")
    print(f"  Tier 2 (High):      {tiers['summary']['tier_2_high']:3} functions")
    print(f"  Tier 3 (Medium):    {tiers['summary']['tier_3_medium']:3} functions")
    print(f"  Tier 4 (Low):       {tiers['summary']['tier_4_low']:3} functions")
    print(f"  Tier 5 (Utility):   {tiers['summary']['tier_5_utility']:3} functions")

    print("\nTop 10 Priority Functions:")
    print("-"*70)
    for i, func in enumerate(report["by_priority"][:10], 1):
        print(f"  {i:2}. {func['name']:40} ({func['category']}, Priority: {func['priority']})")

    print("\nModule Focus Areas (Top 3 per module):")
    print("-"*70)
    for module in sorted(strategies.keys()):
        strat = strategies[module]
        print(f"\n  {module}:")
        for func in strat["top_priority"][:3]:
            print(f"    - {func['name']} ({func['category']})")

    print("\n" + "="*70)
    print("RENAMING CAMPAIGN READY")
    print("="*70)
    print(f"\nRecommended first pass: {sum(t for k, t in tiers['summary'].items() if 'tier_1' in k or 'tier_2' in k)} functions")
    print(f"  (Tier 1 + Tier 2 = highest impact functions)")


if __name__ == "__main__":
    main()
