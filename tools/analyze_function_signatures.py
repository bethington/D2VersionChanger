#!/usr/bin/env python3
"""
Analyze function signatures and types for the 572 all-version functions.
Extracts calling conventions, parameter counts, return types, and complexity metrics.
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

REPORTS_PATH = Path("reports")
FUNCTION_INDEX_PATH = Path("data/function_index")

# Common calling conventions observed in x86 binaries
CALLING_CONVENTIONS = {
    "__cdecl": "C declaration (stack-based parameters, caller cleans)",
    "__stdcall": "Standard call (stack-based parameters, callee cleans)",
    "__fastcall": "Fast call (registers for first 2 params, then stack)",
    "__thiscall": "This call (C++ member functions, this in ECX)",
    "__d2call": "Custom D2 calling convention",
}

# Common return types inferred from function patterns
RETURN_TYPE_HINTS = {
    "Init": ("void", 0.8),
    "Create": ("void *", 0.7),
    "Alloc": ("void *", 0.9),
    "Free": ("void", 0.9),
    "Get": ("int", 0.6),
    "Set": ("void", 0.8),
    "Find": ("void *", 0.7),
    "Is": ("int", 0.8),
    "Check": ("int", 0.7),
    "Calc": ("int", 0.6),
    "Count": ("int", 0.8),
}

# Common parameter patterns by function category
PARAMETER_PATTERNS = {
    "Memory Management": ["ptr", "size", "count"],
    "String Operations": ["str", "src", "dst", "len"],
    "Bit Operations": ["value", "mask", "bit"],
    "Game Logic": ["unit", "item", "monster", "level"],
    "Math Operations": ["x", "y", "value", "result"],
    "File I/O": ["file", "path", "buffer", "size"],
}


def load_unified_index() -> Dict:
    """Load unified function index."""
    index_file = REPORTS_PATH / "unified_function_index.json"
    with open(index_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_all_version_functions() -> List[Dict]:
    """Load all-version functions analysis."""
    analysis_file = REPORTS_PATH / "all_version_functions_analysis.json"
    with open(analysis_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data.get("analysis", [])


def estimate_parameter_count(func_name: str, category: str) -> int:
    """Estimate parameter count based on function name and category."""
    name_upper = func_name.upper()

    # Common patterns
    if "Create" in name_upper or "Alloc" in name_upper:
        return 2  # Usually size/count + context
    elif "Copy" in name_upper or "Compare" in name_upper:
        return 3  # src, dst, size
    elif "Init" in name_upper:
        return 1  # Usually just object pointer
    elif "Find" in name_upper or "Search" in name_upper:
        return 2  # Data and search key
    elif "Set" in name_upper:
        return 2  # Object and value
    elif "Get" in name_upper or "Is" in name_upper:
        return 1  # Query object
    elif category == "Math Operations":
        return 2  # Two operands
    elif category == "String Operations":
        return 3  # src, dst, size
    else:
        return 1  # Default: single parameter


def estimate_return_type(func_name: str, category: str) -> Tuple[str, float]:
    """Estimate return type with confidence score."""
    for pattern, (ret_type, confidence) in RETURN_TYPE_HINTS.items():
        if pattern in func_name:
            return ret_type, confidence

    # Category-based defaults
    if category == "Memory Management":
        if "Free" in func_name or "Delete" in func_name:
            return "void", 0.8
        else:
            return "void *", 0.7
    elif category in ["Game Logic", "Graphics/Rendering", "UI/Windows"]:
        return "void", 0.6
    else:
        return "int", 0.5


def estimate_complexity_from_name(func_name: str) -> int:
    """Estimate complexity (1-10) from function name."""
    score = 1

    name_upper = func_name.upper()

    # Add points for complexity indicators
    complexity_indicators = {
        "Process": 2,
        "Calculate": 2,
        "Generate": 2,
        "Parse": 2,
        "Encode": 1,
        "Decode": 1,
        "Compress": 2,
        "Decompress": 2,
        "Validate": 1,
        "Convert": 1,
    }

    for indicator, points in complexity_indicators.items():
        if indicator.upper() in name_upper:
            score += points

    # Subtract for simplicity indicators
    simplicity_indicators = {
        "Get": -1,
        "Set": -1,
        "Init": 0,
        "Free": 0,
    }

    for indicator, points in simplicity_indicators.items():
        if indicator.upper() in name_upper:
            score += points

    return max(1, min(10, score))


def infer_string_references(func_name: str) -> List[str]:
    """Infer likely string references based on function name."""
    references = []

    # Pattern-based inference
    if "Error" in func_name:
        references.append("error message or error code string")
    if "Message" in func_name or "Msg" in func_name:
        references.append("message string")
    if "Path" in func_name or "File" in func_name:
        references.append("file path string")
    if "Name" in func_name:
        references.append("name string")
    if "Log" in func_name or "Debug" in func_name:
        references.append("debug/log string")
    if "Format" in func_name or "Sprintf" in func_name:
        references.append("format string")

    return references


def infer_api_calls(func_name: str, category: str) -> List[str]:
    """Infer likely external API calls based on function characteristics."""
    api_calls = []

    # Category-based API inference
    if category == "File I/O":
        api_calls.extend(["CreateFileA/W", "ReadFile", "WriteFile", "CloseHandle"])
    elif category == "Network":
        api_calls.extend(["socket", "send", "recv", "connect"])
    elif category == "Threading":
        api_calls.extend(["CreateThread", "WaitForSingleObject", "SetEvent"])
    elif category == "Graphics/Rendering":
        api_calls.extend(["DirectDraw or GDI calls", "Sprite rendering"])

    # Name-based API inference
    name_upper = func_name.upper()
    if "ALLOC" in name_upper or "MALLOC" in name_upper:
        api_calls.append("malloc/HeapAlloc")
    if "FREE" in name_upper:
        api_calls.append("free/HeapFree")
    if "MEMCPY" in name_upper or "COPY" in name_upper:
        api_calls.append("memcpy/RtlCopyMemory")

    return api_calls


def analyze_function_signature(func: Dict) -> Dict:
    """Analyze a single function's signature."""
    func_name = func.get("name", "Unknown")
    category = func.get("category", "Unknown")
    module = func.get("module", "Unknown")

    return_type, return_confidence = estimate_return_type(func_name, category)
    param_count = estimate_parameter_count(func_name, category)
    complexity = estimate_complexity_from_name(func_name)

    return {
        "name": func_name,
        "module": module,
        "category": category,
        "signature": {
            "return_type": return_type,
            "return_type_confidence": return_confidence,
            "parameter_count": param_count,
            "calling_convention": "__cdecl",  # Most common default
            "calling_convention_confidence": 0.5,
        },
        "complexity": {
            "estimated_score": complexity,
            "scale": "1-10 (1=trivial, 10=very complex)",
        },
        "likely_references": {
            "string_references": infer_string_references(func_name),
            "api_calls": infer_api_calls(func_name, category),
        },
        "analysis_confidence": 0.6,
    }


def generate_signature_report(all_version_funcs: List[Dict]) -> Dict:
    """Generate comprehensive signature analysis report."""
    report = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "total_functions": len(all_version_funcs),
        "signatures": [],
        "statistics": {
            "return_types": defaultdict(int),
            "parameter_counts": defaultdict(int),
            "complexity_distribution": defaultdict(int),
            "calling_conventions": defaultdict(int),
        },
        "summaries": {
            "by_module": {},
            "by_category": {},
        }
    }

    # Analyze each function
    for func in all_version_funcs:
        sig_analysis = analyze_function_signature(func)
        report["signatures"].append(sig_analysis)

        # Update statistics
        ret_type = sig_analysis["signature"]["return_type"]
        report["statistics"]["return_types"][ret_type] += 1

        param_count = sig_analysis["signature"]["parameter_count"]
        report["statistics"]["parameter_counts"][f"{param_count}_params"] += 1

        complexity = sig_analysis["complexity"]["estimated_score"]
        complexity_level = "trivial" if complexity <= 2 else "simple" if complexity <= 4 else "moderate" if complexity <= 6 else "complex" if complexity <= 8 else "very_complex"
        report["statistics"]["complexity_distribution"][complexity_level] += 1

        calling_conv = sig_analysis["signature"]["calling_convention"]
        report["statistics"]["calling_conventions"][calling_conv] += 1

    # Convert defaultdicts to regular dicts for JSON serialization
    report["statistics"]["return_types"] = dict(report["statistics"]["return_types"])
    report["statistics"]["parameter_counts"] = dict(report["statistics"]["parameter_counts"])
    report["statistics"]["complexity_distribution"] = dict(report["statistics"]["complexity_distribution"])
    report["statistics"]["calling_conventions"] = dict(report["statistics"]["calling_conventions"])

    # Module summaries
    by_module = defaultdict(lambda: {"count": 0, "avg_complexity": 0, "common_return_types": {}})
    for sig in report["signatures"]:
        module = sig["module"]
        by_module[module]["count"] += 1
        by_module[module]["avg_complexity"] += sig["complexity"]["estimated_score"]
        ret_type = sig["signature"]["return_type"]
        by_module[module]["common_return_types"][ret_type] = by_module[module]["common_return_types"].get(ret_type, 0) + 1

    # Calculate averages
    for module, data in by_module.items():
        if data["count"] > 0:
            data["avg_complexity"] = data["avg_complexity"] / data["count"]
        report["summaries"]["by_module"][module] = data

    # Category summaries
    by_category = defaultdict(lambda: {"count": 0, "avg_complexity": 0})
    for sig in report["signatures"]:
        category = sig["category"]
        by_category[category]["count"] += 1
        by_category[category]["avg_complexity"] += sig["complexity"]["estimated_score"]

    for category, data in by_category.items():
        if data["count"] > 0:
            data["avg_complexity"] = data["avg_complexity"] / data["count"]
        report["summaries"]["by_category"][category] = data

    return report


def generate_signature_guide() -> str:
    """Generate a guide document for signature analysis."""
    guide = """# Function Signature Analysis Guide

## Overview
This guide explains the function signature analysis for the 572 all-version Diablo 2 functions.

## Analysis Methodology

### 1. Return Type Inference
Return types are inferred from function names using pattern matching:

- **void**: Functions that don't return meaningful values (Init, Free, Set, etc.)
- **void\\***: Functions that allocate/create objects (Create, Alloc, Find, etc.)
- **int**: Functions that query or calculate values (Get, Is, Check, Calc, etc.)

**Confidence Scoring:**
- Pattern match found: 0.8-0.9 confidence
- Category-based inference: 0.6-0.7 confidence
- Default inference: 0.5 confidence

### 2. Parameter Count Estimation
Parameter counts are estimated based on function name and category:

- **1 parameter**: Simple query/operation (Get, Is, Init)
- **2 parameters**: Binary operation (Set, Compare, Find)
- **3 parameters**: Complex operation (Copy, Find with criteria)
- **4+ parameters**: Rare, typically specialized functions

### 3. Calling Convention
Most functions use **__cdecl** (C declaration):
- Parameters passed on stack, right-to-left
- Caller cleans up stack
- Most common for Windows C libraries

Some functions may use:
- **__stdcall**: Windows API functions
- **__fastcall**: Performance-critical functions
- **__thiscall**: C++ member functions (rare in D2)

### 4. Complexity Estimation
Complexity scored 1-10 based on function name indicators:

**Trivial (1-2):** Get, Set, Init, Free
**Simple (3-4):** Find, Check, Convert
**Moderate (5-6):** Calculate, Process, Validate
**Complex (7-8):** Generate, Encode, Decode, Parse
**Very Complex (9-10):** Compress, Decompress, Multiple steps

### 5. String and API References
- **String References**: Inferred from function name (Error, Message, Path, etc.)
- **API Calls**: Inferred from category (File I/O, Network, Threading, etc.)

## Limitations

These analyses are **estimations** based on function names and categories. Actual implementation details require:
1. Decompilation in Ghidra
2. Assembly inspection
3. Cross-reference analysis
4. Type information extraction

## Next Steps

For production use:
1. Validate signatures against actual decompiled code
2. Extract exact parameter names from stack analysis
3. Document calling convention from assembly patterns
4. Create Ghidra scripts to extract this automatically

## Use Cases

1. **API Documentation**: Generate API reference from signatures
2. **Type Safety**: Identify potential calling convention mismatches
3. **Complexity Analysis**: Prioritize functions for detailed analysis
4. **Refactoring**: Understand function boundaries and responsibilities

"""
    return guide


def main():
    """Main analysis execution."""
    print("=" * 70)
    print("Analyzing Function Signatures and Types")
    print("=" * 70)

    # Load data
    print("\nLoading function data...")
    all_version_funcs = load_all_version_functions()
    print(f"Loaded {len(all_version_funcs)} all-version functions")

    # Generate signature report
    print("\nAnalyzing function signatures...")
    report = generate_signature_report(all_version_funcs)

    # Save report
    report_file = REPORTS_PATH / "function_signature_analysis.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(f"Saved signature analysis to {report_file}")

    # Save guide
    guide_file = REPORTS_PATH / "FUNCTION_SIGNATURE_GUIDE.md"
    with open(guide_file, 'w', encoding='utf-8') as f:
        f.write(generate_signature_guide())
    print(f"Saved signature guide to {guide_file}")

    # Print summary
    print("\n" + "=" * 70)
    print("FUNCTION SIGNATURE ANALYSIS SUMMARY")
    print("=" * 70)

    print(f"\nTotal Functions Analyzed: {len(all_version_funcs)}")

    print("\nReturn Type Distribution:")
    print("-" * 70)
    for ret_type, count in sorted(report["statistics"]["return_types"].items(), key=lambda x: x[1], reverse=True):
        pct = (count / len(all_version_funcs)) * 100
        print(f"  {ret_type:15} {count:3} functions ({pct:5.1f}%)")

    print("\nParameter Count Distribution:")
    print("-" * 70)
    for param_count, count in sorted(report["statistics"]["parameter_counts"].items(), key=lambda x: x[1], reverse=True):
        pct = (count / len(all_version_funcs)) * 100
        print(f"  {param_count:15} {count:3} functions ({pct:5.1f}%)")

    print("\nComplexity Distribution:")
    print("-" * 70)
    for complexity, count in sorted(report["statistics"]["complexity_distribution"].items(), key=lambda x: x[1], reverse=True):
        pct = (count / len(all_version_funcs)) * 100
        print(f"  {complexity:15} {count:3} functions ({pct:5.1f}%)")

    print("\nAverage Complexity by Module:")
    print("-" * 70)
    for module in sorted(report["summaries"]["by_module"].keys()):
        data = report["summaries"]["by_module"][module]
        print(f"  {module:15} {data['count']:3} functions, avg complexity: {data['avg_complexity']:.1f}")

    print("\nAverage Complexity by Category:")
    print("-" * 70)
    for category in sorted(report["summaries"]["by_category"].keys()):
        data = report["summaries"]["by_category"][category]
        print(f"  {category:25} {data['count']:3} functions, avg complexity: {data['avg_complexity']:.1f}")

    print("\n" + "=" * 70)
    print("SIGNATURE ANALYSIS COMPLETE")
    print("=" * 70)
    print(f"\nReports generated:")
    print(f"  - {report_file}")
    print(f"  - {guide_file}")


if __name__ == "__main__":
    main()
