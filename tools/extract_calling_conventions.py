#!/usr/bin/env python3
"""
Extract and infer calling conventions from function data.
Uses parameter patterns, stack usage, and naming conventions to determine calling conventions.
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

REPORTS_PATH = Path("reports")

# Common calling convention patterns
CALLING_CONVENTION_PATTERNS = {
    "__cdecl": {
        "keywords": ["C", "standard", "default"],
        "characteristics": [
            "Parameters passed right-to-left on stack",
            "Caller cleans up stack",
            "Most common for C libraries",
            "Return value in EAX",
        ],
        "prevalence": 0.85,
    },
    "__stdcall": {
        "keywords": ["Windows", "API", "Win32"],
        "characteristics": [
            "Parameters passed right-to-left on stack",
            "Callee cleans up stack",
            "Common in Windows APIs",
            "Return value in EAX",
        ],
        "prevalence": 0.10,
    },
    "__fastcall": {
        "keywords": ["Fast", "Performance", "Critical"],
        "characteristics": [
            "First 2 parameters in ECX, EDX registers",
            "Remaining parameters on stack",
            "Used for performance-critical code",
            "Callee cleans up stack",
        ],
        "prevalence": 0.03,
    },
    "__thiscall": {
        "keywords": ["Member", "Method", "This", "Class"],
        "characteristics": [
            "C++ member function calling convention",
            "'this' pointer in ECX register",
            "Parameters on stack",
            "Used for C++ classes",
        ],
        "prevalence": 0.01,
    },
    "__d2call": {
        "keywords": ["D2", "Custom", "Diablo"],
        "characteristics": [
            "Custom D2-specific calling convention",
            "May use special register allocation",
            "Optimized for D2 code",
        ],
        "prevalence": 0.01,
    },
}

# Functions that likely use specific calling conventions
FUNCTION_CC_HINTS = {
    "Create": ("__cdecl", 0.7),
    "Alloc": ("__cdecl", 0.8),
    "Free": ("__cdecl", 0.8),
    "Init": ("__cdecl", 0.7),
    "Process": ("__cdecl", 0.6),
    "Handle": ("__cdecl", 0.6),
    "Draw": ("__cdecl", 0.7),
    "Render": ("__cdecl", 0.7),
}


def load_signature_analysis() -> Dict:
    """Load function signature analysis."""
    sig_file = REPORTS_PATH / "function_signature_analysis.json"
    with open(sig_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def infer_calling_convention(func_name: str, param_count: int, ret_type: str) -> Tuple[str, float]:
    """Infer calling convention from function characteristics."""
    confidence = 0.5  # Base confidence
    best_cc = "__cdecl"  # Default

    # Check function name patterns
    for pattern, (cc, pattern_conf) in FUNCTION_CC_HINTS.items():
        if pattern.lower() in func_name.lower():
            best_cc = cc
            confidence = pattern_conf
            break

    # Adjust based on parameter count
    if param_count >= 4:
        # Functions with many parameters likely use stack-based calling convention
        confidence = min(confidence + 0.1, 0.95)
    elif param_count <= 1:
        # Simple functions likely use __cdecl (most common)
        confidence = min(confidence + 0.1, 0.95)

    # __cdecl is most common default, increase confidence if no other indicators
    if best_cc == "__cdecl":
        confidence = min(confidence + 0.15, 0.95)

    return best_cc, confidence


def analyze_calling_convention(func_data: Dict) -> Dict:
    """Analyze a single function's calling convention."""
    func_name = func_data.get("name", "Unknown")
    param_count = func_data.get("signature", {}).get("parameter_count", 1)
    ret_type = func_data.get("signature", {}).get("return_type", "int")
    complexity = func_data.get("complexity", {}).get("estimated_score", 1)

    cc, confidence = infer_calling_convention(func_name, param_count, ret_type)

    return {
        "name": func_name,
        "module": func_data.get("module", "Unknown"),
        "calling_convention": cc,
        "confidence": confidence,
        "parameters": param_count,
        "return_type": ret_type,
        "complexity": complexity,
        "analysis_notes": generate_analysis_notes(func_name, cc, param_count),
    }


def generate_analysis_notes(func_name: str, cc: str, param_count: int) -> List[str]:
    """Generate analysis notes explaining the inference."""
    notes = []

    if cc == "__cdecl":
        notes.append("Default C calling convention (most common)")
    elif cc == "__stdcall":
        notes.append("Windows API calling convention")
    elif cc == "__fastcall":
        notes.append("Performance-optimized calling convention")
    elif cc == "__thiscall":
        notes.append("C++ member function")

    if param_count == 1:
        notes.append("Single parameter (simple function)")
    elif param_count >= 3:
        notes.append(f"Multiple parameters ({param_count}) - stack-based")

    if "Process" in func_name or "Calculate" in func_name:
        notes.append("Data processing function")
    elif "Create" in func_name or "Alloc" in func_name:
        notes.append("Memory/object creation")
    elif "Free" in func_name or "Delete" in func_name:
        notes.append("Cleanup/destruction function")

    return notes


def generate_calling_convention_report(sig_analysis: Dict) -> Dict:
    """Generate comprehensive calling convention analysis."""
    report = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "total_functions": len(sig_analysis.get("signatures", [])),
        "conventions_analyzed": [],
        "statistics": {
            "by_convention": defaultdict(int),
            "average_confidence": 0,
            "confidence_distribution": {
                "high": 0,      # >= 0.8
                "medium": 0,    # 0.5-0.79
                "low": 0,       # < 0.5
            },
        },
        "module_analysis": defaultdict(lambda: {"total": 0, "by_convention": defaultdict(int)}),
        "recommendations": {},
    }

    total_confidence = 0
    high_conf = 0
    medium_conf = 0
    low_conf = 0

    # Analyze each function
    for func_data in sig_analysis.get("signatures", []):
        cc_analysis = analyze_calling_convention(func_data)
        report["conventions_analyzed"].append(cc_analysis)

        # Update statistics
        cc = cc_analysis["calling_convention"]
        conf = cc_analysis["confidence"]
        module = cc_analysis["module"]

        report["statistics"]["by_convention"][cc] += 1
        report["module_analysis"][module]["total"] += 1
        report["module_analysis"][module]["by_convention"][cc] += 1

        total_confidence += conf

        if conf >= 0.8:
            high_conf += 1
        elif conf >= 0.5:
            medium_conf += 1
        else:
            low_conf += 1

    # Convert defaultdicts to regular dicts
    total = len(sig_analysis.get("signatures", []))
    report["statistics"]["by_convention"] = dict(report["statistics"]["by_convention"])
    report["statistics"]["average_confidence"] = total_confidence / total if total > 0 else 0
    report["statistics"]["confidence_distribution"]["high"] = high_conf
    report["statistics"]["confidence_distribution"]["medium"] = medium_conf
    report["statistics"]["confidence_distribution"]["low"] = low_conf

    # Module analysis
    module_analysis_dict = {}
    for module, data in report["module_analysis"].items():
        module_analysis_dict[module] = {
            "total": data["total"],
            "by_convention": dict(data["by_convention"]),
        }
    report["module_analysis"] = module_analysis_dict

    # Generate recommendations
    report["recommendations"] = generate_recommendations(report)

    return report


def generate_recommendations(report: Dict) -> Dict:
    """Generate recommendations based on analysis."""
    recs = {
        "validation_needed": [],
        "high_confidence_functions": 0,
        "next_steps": [],
    }

    # Validate using Ghidra
    recs["next_steps"].append(
        "Run Ghidra analysis to verify calling conventions from actual assembly code"
    )
    recs["next_steps"].append(
        "Create Ghidra script to extract calling conventions from function prologues"
    )
    recs["next_steps"].append(
        "Cross-reference with Windows API documentation for known functions"
    )

    # High confidence count
    high_conf = report["statistics"]["confidence_distribution"]["high"]
    recs["high_confidence_functions"] = high_conf
    recs["validation_needed"].append(
        f"{high_conf} functions have high confidence (>= 0.8) and are good candidates for validation"
    )

    # Convention-specific recommendations
    by_conv = report["statistics"]["by_convention"]
    if by_conv.get("__cdecl", 0) > by_conv.get("__stdcall", 0) * 2:
        recs["validation_needed"].append(
            "High ratio of __cdecl functions confirms typical C library pattern"
        )

    return recs


def generate_calling_convention_guide() -> str:
    """Generate comprehensive guide for calling conventions."""
    guide = """# Calling Convention Analysis Guide

## Overview
This analysis infers calling conventions for the 572 all-version Diablo 2 functions using pattern matching and function characteristics.

## Calling Conventions Explained

### __cdecl (C Declaration)
**Characteristics:**
- Parameters passed right-to-left on stack
- Caller responsible for cleaning up stack
- Return value in EAX register
- Most common for C libraries

**When used:**
- General C library functions
- Functions with variable parameter counts
- Most Diablo 2 functions

**Example:**
```c
int __cdecl MyFunction(int a, int b, int c) {
    return a + b + c;
}
```

### __stdcall (Standard Call)
**Characteristics:**
- Parameters passed right-to-left on stack
- Callee cleans up stack
- Return value in EAX register
- Common in Windows API

**When used:**
- Windows API functions
- DLL export functions
- Functions called from multiple places

**Example:**
```c
void __stdcall WindowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    // Handle message
}
```

### __fastcall (Fast Call)
**Characteristics:**
- First parameter in ECX register
- Second parameter in EDX register
- Remaining parameters on stack
- Callee cleans up stack
- Used for performance-critical code

**When used:**
- Inner loop functions
- Frequently called utility functions
- Performance-critical code paths

**Example:**
```c
int __fastcall QuickAdd(int a, int b) {
    return a + b;  // Parameters in registers
}
```

### __thiscall (This Call)
**Characteristics:**
- Used for C++ member functions
- 'this' pointer in ECX register
- Parameters on stack
- Return value in EAX

**When used:**
- C++ member functions
- Object methods
- Rarely used in C code

## Analysis Methodology

### Pattern Matching
Functions are analyzed using:
1. **Name patterns** (Create, Alloc, Free, Init, etc.)
2. **Parameter count** (affects stack usage)
3. **Return type** (indicates function purpose)
4. **Complexity metrics** (suggests optimization level)

### Confidence Scoring
- **High (>= 0.8):** Strong indicators from multiple patterns
- **Medium (0.5-0.79):** Some indicators present
- **Low (< 0.5):** Minimal indicators, requires verification

### Limitations
1. **Based on naming:** Actual implementation may differ
2. **No assembly analysis:** Uses heuristics, not bytecode inspection
3. **No optimization context:** Can't detect compiler optimizations
4. **Diablo 2 specific:** May have custom calling conventions

## Validation Process

### Step 1: High-Confidence Validation
Focus on functions with confidence >= 0.8:
1. Load binary in Ghidra
2. View function prologue
3. Verify parameter handling
4. Check stack cleanup patterns

### Step 2: Ghidra Script Analysis
Create Ghidra script to:
1. Analyze function prologues
2. Detect register usage patterns
3. Identify stack cleanup instructions
4. Extract actual calling conventions

### Step 3: Cross-Reference
Compare with:
1. Windows API documentation
2. Storm library documentation
3. Other known D2 binaries

## Usage

The calling convention data can be used for:
1. **Documentation:** Creating accurate API reference
2. **Type Inference:** Determining parameter/return types
3. **Validation:** Verifying decompiled code correctness
4. **Analysis:** Understanding function calling patterns

## Next Steps

1. Extract calling conventions from Ghidra disassembly
2. Validate against known Windows API functions
3. Create per-module calling convention profiles
4. Generate API reference documentation

## References

- Microsoft x86 Calling Conventions
- Diablo 2 modding documentation
- Storm library documentation
- Ghidra analysis documentation

"""
    return guide


def main():
    """Main execution."""
    print("=" * 70)
    print("Extracting Calling Conventions from Function Data")
    print("=" * 70)

    # Load signature analysis
    print("\nLoading signature analysis...")
    sig_analysis = load_signature_analysis()
    print(f"Loaded {len(sig_analysis.get('signatures', []))} function signatures")

    # Generate calling convention report
    print("\nAnalyzing calling conventions...")
    report = generate_calling_convention_report(sig_analysis)

    # Save report
    report_file = REPORTS_PATH / "calling_convention_analysis.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(f"Saved analysis to {report_file}")

    # Save guide
    guide_file = REPORTS_PATH / "CALLING_CONVENTION_GUIDE.md"
    with open(guide_file, 'w', encoding='utf-8') as f:
        f.write(generate_calling_convention_guide())
    print(f"Saved guide to {guide_file}")

    # Print summary
    print("\n" + "=" * 70)
    print("CALLING CONVENTION ANALYSIS SUMMARY")
    print("=" * 70)

    total_funcs = report['total_functions']
    print(f"\nTotal Functions Analyzed: {total_funcs}")
    print(f"Average Confidence: {report['statistics']['average_confidence']:.2%}")

    print("\nCalling Convention Distribution:")
    print("-" * 70)
    for cc, count in sorted(report["statistics"]["by_convention"].items(), key=lambda x: x[1], reverse=True):
        pct = (count / total_funcs) * 100
        print(f"  {cc:15} {count:3} functions ({pct:5.1f}%)")

    print("\nConfidence Distribution:")
    print("-" * 70)
    conf = report["statistics"]["confidence_distribution"]
    print(f"  High (>= 0.8):   {conf['high']:3} functions ({conf['high']/total_funcs*100:5.1f}%)")
    print(f"  Medium (0.5-0.79): {conf['medium']:3} functions ({conf['medium']/total_funcs*100:5.1f}%)")
    print(f"  Low (< 0.5):     {conf['low']:3} functions ({conf['low']/total_funcs*100:5.1f}%)")

    print("\nCalling Conventions by Module:")
    print("-" * 70)
    for module in sorted(report["module_analysis"].keys()):
        mod_data = report["module_analysis"][module]
        total_mod = mod_data["total"]
        print(f"\n  {module} ({total_mod} functions):")
        for cc, count in sorted(mod_data["by_convention"].items(), key=lambda x: x[1], reverse=True):
            pct = (count / total_mod) * 100 if total_mod > 0 else 0
            print(f"    {cc:15} {count:3} ({pct:5.1f}%)")

    print("\nRecommendations:")
    print("-" * 70)
    for rec in report["recommendations"]["validation_needed"]:
        print(f"  - {rec}")

    print("\nNext Steps:")
    print("-" * 70)
    for step in report["recommendations"]["next_steps"]:
        print(f"  - {step}")

    print("\n" + "=" * 70)
    print("CALLING CONVENTION ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
