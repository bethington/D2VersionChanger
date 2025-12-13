# Calling Convention Analysis Guide

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

