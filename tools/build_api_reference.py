#!/usr/bin/env python3
"""
Build comprehensive API reference documentation for all-version Diablo 2 functions.
Creates formal API documentation with signatures, descriptions, and usage examples.
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

REPORTS_PATH = Path("reports")

# API category descriptions
API_CATEGORIES = {
    "Memory Management": {
        "description": "Functions for allocating, freeing, and managing memory",
        "importance": "CRITICAL",
    },
    "String Operations": {
        "description": "Functions for string manipulation and formatting",
        "importance": "CRITICAL",
    },
    "Bit Operations": {
        "description": "Functions for bit manipulation and flag handling",
        "importance": "HIGH",
    },
    "Game Logic": {
        "description": "Core game logic and mechanics functions",
        "importance": "HIGH",
    },
    "Math Operations": {
        "description": "Mathematical calculations and numeric operations",
        "importance": "MEDIUM",
    },
    "Data Structures": {
        "description": "Data structure manipulation and management",
        "importance": "MEDIUM",
    },
    "File I/O": {
        "description": "File reading, writing, and management",
        "importance": "MEDIUM",
    },
    "Graphics/Rendering": {
        "description": "Graphics rendering and visual effects",
        "importance": "MEDIUM",
    },
    "UI/Windows": {
        "description": "User interface and window management",
        "importance": "MEDIUM",
    },
    "Network": {
        "description": "Network communication and protocols",
        "importance": "LOW",
    },
    "Threading": {
        "description": "Thread management and synchronization",
        "importance": "LOW",
    },
    "Utility": {
        "description": "General utility and helper functions",
        "importance": "MEDIUM",
    },
}


def load_all_data() -> Tuple[Dict, Dict, Dict]:
    """Load all necessary data files."""
    with open(REPORTS_PATH / "function_signature_analysis.json", 'r', encoding='utf-8') as f:
        signatures = json.load(f)

    with open(REPORTS_PATH / "calling_convention_analysis.json", 'r', encoding='utf-8') as f:
        conventions = json.load(f)

    with open(REPORTS_PATH / "all_version_functions_analysis.json", 'r', encoding='utf-8') as f:
        analysis = json.load(f)

    return signatures, conventions, analysis


def generate_function_signature_string(func_name: str, ret_type: str, param_count: int, cc: str) -> str:
    """Generate a C-style function signature string."""
    # Generate parameter names based on count
    param_names = []
    if param_count >= 1:
        param_names.append("arg1")
    if param_count >= 2:
        param_names.append("arg2")
    if param_count >= 3:
        param_names.append("arg3")
    if param_count >= 4:
        param_names.append("...")

    params_str = ", ".join(param_names) if param_names else "void"
    return f"{ret_type} {cc} {func_name}({params_str});"


def get_function_documentation(func_name: str, category: str) -> str:
    """Generate documentation for a function."""
    doc = ""

    # Category-based description
    if category in ["Memory Management", "String Operations", "Bit Operations"]:
        doc = f"Core {category.lower()} function. Essential for correct program operation."
    elif category == "Game Logic":
        doc = "Game logic function. Important for game behavior and mechanics."
    elif category == "Utility":
        doc = "Utility helper function. Used for various helper operations."
    else:
        doc = f"{category} function. Part of the {category.lower()} subsystem."

    return doc


def build_module_api(module_name: str, signatures: Dict, conventions: Dict, analysis: Dict) -> Dict:
    """Build API reference for a single module."""
    api = {
        "module": module_name,
        "total_functions": 0,
        "functions_by_category": defaultdict(list),
        "category_summary": {},
        "interface": [],
    }

    sig_list = signatures.get("signatures", [])
    conv_list = conventions.get("conventions_analyzed", [])

    # Create lookup maps
    sig_map = {sig["name"]: sig for sig in sig_list if sig["module"] == module_name}
    conv_map = {conv["name"]: conv for conv in conv_list if conv["module"] == module_name}

    # Process each function in this module
    for func_name, sig_data in sig_map.items():
        conv_data = conv_map.get(func_name, {})
        category = sig_data.get("category", "Utility")

        func_entry = {
            "name": func_name,
            "category": category,
            "signature": generate_function_signature_string(
                func_name,
                sig_data.get("signature", {}).get("return_type", "int"),
                sig_data.get("signature", {}).get("parameter_count", 1),
                conv_data.get("calling_convention", "__cdecl"),
            ),
            "return_type": sig_data.get("signature", {}).get("return_type", "int"),
            "parameters": sig_data.get("signature", {}).get("parameter_count", 1),
            "calling_convention": conv_data.get("calling_convention", "__cdecl"),
            "confidence": conv_data.get("confidence", 0.5),
            "complexity": sig_data.get("complexity", {}).get("estimated_score", 1),
            "description": get_function_documentation(func_name, category),
            "notes": conv_data.get("analysis_notes", []),
        }

        api["functions_by_category"][category].append(func_entry)
        api["interface"].append(func_entry)

    # Convert defaultdict to regular dict
    api["functions_by_category"] = dict(api["functions_by_category"])

    # Generate category summary
    for category, functions in api["functions_by_category"].items():
        api["category_summary"][category] = {
            "count": len(functions),
            "description": API_CATEGORIES.get(category, {}).get("description", ""),
            "importance": API_CATEGORIES.get(category, {}).get("importance", "MEDIUM"),
        }

    api["total_functions"] = len(api["interface"])

    return api


def generate_api_markdown(module_api: Dict) -> str:
    """Generate Markdown documentation for a module API."""
    md = f"""# {module_api['module']} API Reference

## Overview

Module: **{module_api['module']}**
Total Functions: **{module_api['total_functions']}**

### Categories

"""

    for category, summary in module_api["category_summary"].items():
        md += f"- **{category}** ({summary['count']} functions) - {summary['description']}\n"

    md += "\n## API Functions\n\n"

    # Sort by category
    for category in sorted(module_api["functions_by_category"].keys()):
        md += f"### {category}\n\n"

        for func in sorted(module_api["functions_by_category"][category], key=lambda x: x["name"]):
            md += f"#### `{func['name']}`\n\n"
            md += f"```c\n{func['signature']}\n```\n\n"
            md += f"**Description:** {func['description']}\n\n"
            md += f"- **Return Type:** `{func['return_type']}`\n"
            md += f"- **Parameters:** {func['parameters']}\n"
            md += f"- **Calling Convention:** `{func['calling_convention']}`\n"
            md += f"- **Complexity:** {func['complexity']}/10\n"
            md += f"- **Confidence:** {func['confidence']:.0%}\n"

            if func["notes"]:
                md += "\n**Notes:**\n"
                for note in func["notes"]:
                    md += f"- {note}\n"

            md += "\n---\n\n"

    return md


def generate_api_summary() -> Dict:
    """Generate summary of all API information."""
    signatures, conventions, analysis = load_all_data()

    summary = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "total_functions": len(signatures.get("signatures", [])),
        "modules": {},
        "statistics": {
            "by_category": {},
            "by_calling_convention": {},
        },
        "recommendations": [],
    }

    # Build API for each module
    for module in ["D2Game", "D2Client", "D2Common", "D2Win", "Storm", "Fog"]:
        print(f"  Building API for {module}...", end=" ", flush=True)
        module_api = build_module_api(module, signatures, conventions, analysis)
        summary["modules"][module] = module_api
        print(f"({module_api['total_functions']} functions)")

    # Generate statistics
    for module_api in summary["modules"].values():
        for func in module_api["interface"]:
            category = func["category"]
            summary["statistics"]["by_category"][category] = (
                summary["statistics"]["by_category"].get(category, 0) + 1
            )

            cc = func["calling_convention"]
            summary["statistics"]["by_calling_convention"][cc] = (
                summary["statistics"]["by_calling_convention"].get(cc, 0) + 1
            )

    # Add recommendations
    summary["recommendations"].append(
        "API is based on 572 all-version functions present in all 11 LoD versions"
    )
    summary["recommendations"].append(
        "Calling conventions inferred from function names - validate against actual assembly"
    )
    summary["recommendations"].append(
        "Parameter types estimated - use Ghidra to extract actual types"
    )
    summary["recommendations"].append(
        "This represents the core stable API that remains consistent across versions"
    )

    return summary


def main():
    """Main execution."""
    print("=" * 70)
    print("Building API Reference Documentation")
    print("=" * 70)

    # Load data
    print("\nLoading signature and convention data...")
    signatures, conventions, analysis = load_all_data()
    print(f"Loaded {len(signatures.get('signatures', []))} function signatures")

    # Generate API summary
    print("\nGenerating API reference...")
    api_summary = generate_api_summary()

    # Save summary
    summary_file = REPORTS_PATH / "api_reference_summary.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(api_summary, f, indent=2)
    print(f"Saved API summary to {summary_file}")

    # Generate per-module Markdown
    print("\nGenerating module documentation...")
    for module, module_api in api_summary["modules"].items():
        md_file = REPORTS_PATH / f"API_{module}.md"
        md_content = generate_api_markdown(module_api)
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        print(f"  Saved {md_file.name}")

    # Print summary
    print("\n" + "=" * 70)
    print("API REFERENCE GENERATION SUMMARY")
    print("=" * 70)

    print(f"\nTotal Functions Documented: {api_summary['total_functions']}")

    print("\nFunctions by Category:")
    print("-" * 70)
    for category, count in sorted(
        api_summary["statistics"]["by_category"].items(),
        key=lambda x: x[1],
        reverse=True,
    ):
        pct = (count / api_summary['total_functions']) * 100
        print(f"  {category:25} {count:3} functions ({pct:5.1f}%)")

    print("\nFunctions by Module:")
    print("-" * 70)
    for module in sorted(api_summary["modules"].keys()):
        count = api_summary["modules"][module]["total_functions"]
        pct = (count / api_summary['total_functions']) * 100
        print(f"  {module:15} {count:3} functions ({pct:5.1f}%)")

    print("\nCalling Convention Distribution:")
    print("-" * 70)
    for cc, count in sorted(
        api_summary["statistics"]["by_calling_convention"].items(),
        key=lambda x: x[1],
        reverse=True,
    ):
        pct = (count / api_summary['total_functions']) * 100
        print(f"  {cc:15} {count:3} functions ({pct:5.1f}%)")

    print("\nRecommendations:")
    print("-" * 70)
    for rec in api_summary["recommendations"]:
        print(f"  - {rec}")

    print("\n" + "=" * 70)
    print("API REFERENCE COMPLETE")
    print("=" * 70)
    print(f"\nGenerated {len(api_summary['modules'])} module API documents")
    print(f"Total documentation: {sum(m['total_functions'] for m in api_summary['modules'].values())} function signatures")


if __name__ == "__main__":
    main()
