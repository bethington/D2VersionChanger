#!/usr/bin/env python3
"""
Create detailed per-module API profiles with dependency analysis and usage patterns.
Generates comprehensive documentation of each module's API surface area.
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

REPORTS_PATH = Path("reports")

MODULES = ["D2Game", "D2Client", "D2Common", "D2Win", "Storm", "Fog"]

MODULE_DESCRIPTIONS = {
    "D2Game": {
        "title": "Game Engine Module",
        "purpose": "Core game logic, monster behavior, item management, quest system",
        "responsibility": "Primary game mechanics and state management",
        "stability": "HIGH - Core engine code",
        "dependencies": ["D2Common", "Storm"],
        "primary_categories": ["Game Logic", "Memory Management"],
    },
    "D2Client": {
        "title": "Client/UI Module",
        "purpose": "User interface, screen rendering, input handling, game display",
        "responsibility": "Display layer and user interaction",
        "stability": "HIGH - Most stable module (225 all-version functions)",
        "dependencies": ["D2Common", "D2Win", "Fog"],
        "primary_categories": ["UI/Windows", "Graphics/Rendering"],
    },
    "D2Common": {
        "title": "Common Utilities Module",
        "purpose": "Shared utilities, data structures, memory management, string operations",
        "responsibility": "Foundation layer - shared by all modules",
        "stability": "CRITICAL - Used by all other modules",
        "dependencies": ["Storm"],
        "primary_categories": ["Memory Management", "String Operations", "Bit Operations"],
    },
    "D2Win": {
        "title": "Window Management Module",
        "purpose": "Windows API wrapper, window creation, message handling, event routing",
        "responsibility": "Low-level window system abstraction",
        "stability": "HIGH - System interface layer",
        "dependencies": ["D2Common"],
        "primary_categories": ["UI/Windows"],
    },
    "Storm": {
        "title": "Blizzard Engine Core",
        "purpose": "System library, file I/O, memory allocation, threading, networking",
        "responsibility": "Low-level system operations and hardware abstraction",
        "stability": "CRITICAL - Foundation for all modules",
        "dependencies": [],
        "primary_categories": ["File I/O", "Memory Management", "Threading", "Network"],
    },
    "Fog": {
        "title": "Graphics Rendering Engine",
        "purpose": "Sprite rendering, palette management, animation, visual effects",
        "responsibility": "Graphics rendering layer",
        "stability": "MEDIUM - Implementation varies across versions",
        "dependencies": ["D2Common", "Storm"],
        "primary_categories": ["Graphics/Rendering"],
    },
}


def load_api_data() -> Tuple[Dict, Dict, Dict]:
    """Load API reference and related data."""
    with open(REPORTS_PATH / "api_reference_summary.json", 'r', encoding='utf-8') as f:
        api_summary = json.load(f)

    with open(REPORTS_PATH / "function_signature_analysis.json", 'r', encoding='utf-8') as f:
        signatures = json.load(f)

    with open(REPORTS_PATH / "calling_convention_analysis.json", 'r', encoding='utf-8') as f:
        conventions = json.load(f)

    return api_summary, signatures, conventions


def analyze_module_api(module_name: str, api_summary: Dict) -> Dict:
    """Analyze comprehensive API profile for a module."""
    if module_name not in api_summary.get("modules", {}):
        return None

    module_data = api_summary["modules"][module_name]
    module_desc = MODULE_DESCRIPTIONS.get(module_name, {})

    profile = {
        "module": module_name,
        "title": module_desc.get("title", module_name),
        "purpose": module_desc.get("purpose", "Unknown"),
        "responsibility": module_desc.get("responsibility", "Unknown"),
        "stability": module_desc.get("stability", "UNKNOWN"),
        "dependencies": module_desc.get("dependencies", []),
        "api_statistics": {
            "total_functions": module_data.get("total_functions", 0),
            "by_category": module_data.get("category_summary", {}),
            "complexity_distribution": {},
            "confidence_distribution": {},
        },
        "interface_tiers": {
            "public": [],  # Well-documented, stable
            "internal": [],  # Used internally
            "deprecated": [],  # Unused or marked for removal
        },
        "recommendations": [],
    }

    # Analyze complexity distribution
    complexity_counts = defaultdict(int)
    confidence_counts = defaultdict(int)

    for func in module_data.get("interface", []):
        complexity = func.get("complexity", 1)
        if complexity <= 2:
            complexity_counts["trivial"] += 1
        elif complexity <= 4:
            complexity_counts["simple"] += 1
        elif complexity <= 6:
            complexity_counts["moderate"] += 1
        else:
            complexity_counts["complex"] += 1

        confidence = func.get("confidence", 0.5)
        if confidence >= 0.8:
            confidence_counts["high"] += 1
            profile["interface_tiers"]["public"].append(func["name"])
        elif confidence >= 0.5:
            confidence_counts["medium"] += 1
            profile["interface_tiers"]["internal"].append(func["name"])
        else:
            confidence_counts["low"] += 1
            profile["interface_tiers"]["deprecated"].append(func["name"])

    profile["api_statistics"]["complexity_distribution"] = dict(complexity_counts)
    profile["api_statistics"]["confidence_distribution"] = dict(confidence_counts)

    # Generate recommendations
    profile["recommendations"] = generate_module_recommendations(profile)

    return profile


def generate_module_recommendations(profile: Dict) -> List[str]:
    """Generate recommendations for a module."""
    recs = []

    total_funcs = profile["api_statistics"]["total_functions"]
    public_funcs = len(profile["interface_tiers"]["public"])
    internal_funcs = len(profile["interface_tiers"]["internal"])

    if public_funcs < total_funcs * 0.2:
        recs.append(
            f"Only {public_funcs}/{total_funcs} functions have high confidence - "
            "recommend validating calling conventions against actual assembly"
        )

    if internal_funcs > total_funcs * 0.8:
        recs.append(
            "Most functions have medium confidence - validate parameter types "
            "and return types from Ghidra decompilation"
        )

    complexity = profile["api_statistics"]["complexity_distribution"]
    if complexity.get("complex", 0) > 0:
        recs.append(
            f"{complexity.get('complex', 0)} complex functions detected - "
            "prioritize for detailed analysis"
        )

    if profile["stability"] == "CRITICAL":
        recs.append("CRITICAL module - prioritize for comprehensive testing and validation")

    if profile["dependencies"]:
        recs.append(
            f"This module depends on: {', '.join(profile['dependencies'])} - "
            "ensure those are documented first"
        )

    recs.append("Export function signatures from Ghidra for type validation")
    recs.append("Create Ghidra script to verify inferred calling conventions")

    return recs


def generate_module_profile_markdown(profile: Dict) -> str:
    """Generate Markdown documentation for a module profile."""
    md = f"""# {profile['title']} ({profile['module']})

## Module Overview

**Purpose:** {profile['purpose']}

**Responsibility:** {profile['responsibility']}

**Stability Level:** {profile['stability']}

**Dependencies:** {', '.join(profile['dependencies']) if profile['dependencies'] else 'None (independent)'}

---

## API Statistics

| Metric | Value |
|--------|-------|
| Total Functions | {profile['api_statistics']['total_functions']} |
| Primary Categories | {len(profile['api_statistics']['by_category'])} |

### Functions by Category

"""

    for category, data in sorted(
        profile["api_statistics"]["by_category"].items(),
        key=lambda x: x[1]["count"],
        reverse=True,
    ):
        md += f"- **{category}** ({data['count']} functions) - {data['description']}\n"

    md += f"""

### Complexity Distribution

| Complexity | Count |
|------------|-------|
"""

    for level, count in sorted(
        profile["api_statistics"]["complexity_distribution"].items(),
        key=lambda x: x[1],
        reverse=True,
    ):
        pct = (count / profile["api_statistics"]["total_functions"]) * 100
        md += f"| {level.capitalize()} | {count} ({pct:.1f}%) |\n"

    md += f"""
### Confidence Distribution

| Confidence | Count | Functions |
|------------|-------|-----------|
"""

    conf = profile["api_statistics"]["confidence_distribution"]
    total = profile["api_statistics"]["total_functions"]

    md += f"| High (>= 0.8) | {conf.get('high', 0)} ({conf.get('high', 0)/total*100:.1f}%) | Public API |\n"
    md += f"| Medium (0.5-0.79) | {conf.get('medium', 0)} ({conf.get('medium', 0)/total*100:.1f}%) | Internal API |\n"
    md += f"| Low (< 0.5) | {conf.get('low', 0)} ({conf.get('low', 0)/total*100:.1f}%) | Deprecated |\n"

    md += """
---

## Interface Tiers

### Public API (High Confidence)

Functions well-validated and recommended for cross-version use.

"""

    public = profile["interface_tiers"]["public"]
    if public:
        for func in sorted(public)[:10]:
            md += f"- `{func}`\n"
        if len(public) > 10:
            md += f"- ... and {len(public) - 10} more\n"
    else:
        md += "- None (requires validation)\n"

    md += f"""
**Total:** {len(public)} functions

### Internal API (Medium Confidence)

Functions with estimated signatures, recommend validation before use.

"""

    internal = profile["interface_tiers"]["internal"]
    if internal:
        for func in sorted(internal)[:10]:
            md += f"- `{func}`\n"
        if len(internal) > 10:
            md += f"- ... and {len(internal) - 10} more\n"
    else:
        md += "- None\n"

    md += f"""
**Total:** {len(internal)} functions

### Deprecated/Low Confidence

Functions with low confidence scores, require verification.

"""

    deprecated = profile["interface_tiers"]["deprecated"]
    if deprecated:
        for func in sorted(deprecated):
            md += f"- `{func}`\n"
    else:
        md += "- None\n"

    md += f"""
**Total:** {len(deprecated)} functions

---

## Recommendations

"""

    for i, rec in enumerate(profile["recommendations"], 1):
        md += f"{i}. {rec}\n"

    md += """
---

## Integration Points

### Upstream Dependencies

Functions from other modules that this module uses.

### Downstream Dependents

Other modules that depend on this module's functions.

---

## Next Steps

1. Validate exported signatures from Ghidra
2. Create per-function test cases
3. Document integration points
4. Generate version-specific profiles
5. Create API change summary between versions

"""

    return md


def main():
    """Main execution."""
    print("=" * 70)
    print("Creating Per-Module API Profiles")
    print("=" * 70)

    # Load data
    print("\nLoading API data...")
    api_summary, signatures, conventions = load_api_data()
    print(f"Loaded API data for {len(api_summary.get('modules', {}))} modules")

    # Analyze each module
    print("\nGenerating module profiles...")
    module_profiles = {}
    for module in MODULES:
        print(f"  {module}...", end=" ", flush=True)
        profile = analyze_module_api(module, api_summary)
        if profile:
            module_profiles[module] = profile
            print("OK")
        else:
            print("SKIP")

    # Save comprehensive profile
    profiles_file = REPORTS_PATH / "module_api_profiles.json"
    with open(profiles_file, 'w', encoding='utf-8') as f:
        json.dump(module_profiles, f, indent=2)
    print(f"\nSaved module profiles to {profiles_file}")

    # Generate per-module Markdown
    print("\nGenerating module profile documentation...")
    for module, profile in module_profiles.items():
        md_file = REPORTS_PATH / f"MODULE_PROFILE_{module}.md"
        md_content = generate_module_profile_markdown(profile)
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        print(f"  Saved {md_file.name}")

    # Print summary
    print("\n" + "=" * 70)
    print("MODULE API PROFILE GENERATION SUMMARY")
    print("=" * 70)

    for module in sorted(module_profiles.keys()):
        profile = module_profiles[module]
        total = profile["api_statistics"]["total_functions"]
        public = len(profile["interface_tiers"]["public"])
        internal = len(profile["interface_tiers"]["internal"])

        print(f"\n{module}:")
        print(f"  Total Functions: {total}")
        print(f"  Public API: {public} ({public/total*100:.1f}%)")
        print(f"  Internal API: {internal} ({internal/total*100:.1f}%)")
        print(f"  Stability: {profile['stability']}")

    print("\n" + "=" * 70)
    print("MODULE API PROFILES COMPLETE")
    print("=" * 70)
    print(f"\nGenerated profiles for {len(module_profiles)} modules")
    print(f"Total documented functions: {sum(p['api_statistics']['total_functions'] for p in module_profiles.values())}")


if __name__ == "__main__":
    main()
