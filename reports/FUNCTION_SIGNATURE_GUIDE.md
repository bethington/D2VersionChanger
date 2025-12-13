# Function Signature Analysis Guide

## Overview
This guide explains the function signature analysis for the 572 all-version Diablo 2 functions.

## Analysis Methodology

### 1. Return Type Inference
Return types are inferred from function names using pattern matching:

- **void**: Functions that don't return meaningful values (Init, Free, Set, etc.)
- **void\***: Functions that allocate/create objects (Create, Alloc, Find, etc.)
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

