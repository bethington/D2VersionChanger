# Common Utilities Module (D2Common)

## Module Overview

**Purpose:** Shared utilities, data structures, memory management, string operations

**Responsibility:** Foundation layer - shared by all modules

**Stability Level:** CRITICAL - Used by all other modules

**Dependencies:** Storm

---

## API Statistics

| Metric | Value |
|--------|-------|
| Total Functions | 93 |
| Primary Categories | 8 |

### Functions by Category

- **Utility** (27 functions) - General utility and helper functions
- **Bit Operations** (23 functions) - Functions for bit manipulation and flag handling
- **Game Logic** (15 functions) - Core game logic and mechanics functions
- **Memory Management** (8 functions) - Functions for allocating, freeing, and managing memory
- **String Operations** (8 functions) - Functions for string manipulation and formatting
- **Data Structures** (5 functions) - Data structure manipulation and management
- **File I/O** (4 functions) - File reading, writing, and management
- **Math Operations** (3 functions) - Mathematical calculations and numeric operations


### Complexity Distribution

| Complexity | Count |
|------------|-------|
| Trivial | 93 (100.0%) |

### Confidence Distribution

| Confidence | Count | Functions |
|------------|-------|-----------|
| High (>= 0.8) | 10 (10.8%) | Public API |
| Medium (0.5-0.79) | 83 (89.2%) | Internal API |
| Low (< 0.5) | 0 (0.0%) | Deprecated |

---

## Interface Tiers

### Public API (High Confidence)

Functions well-validated and recommended for cross-version use.

- `AllocPoolMemoryTracked`
- `CreatePoolObject`
- `FreePoolMemory`
- `FreePoolMemoryTracked`
- `FreeTrackedPoolAllocation`
- `InitRngSeed`
- `InitTimerState`
- `SetUnitAllocatedFlag`
- `__nh_malloc`
- `_malloc`

**Total:** 10 functions

### Internal API (Medium Confidence)

Functions with estimated signatures, recommend validation before use.

- `AndDwordValue`
- `ApplyTileAttributePattern`
- `BinarySearchTable`
- `ClearBitFlags`
- `ClearBitInArray`
- `ClearField0x20`
- `ClearImageDimensions`
- `ClearMapCellFlagRadius`
- `CompareStringsIgnoreCase`
- `ComputeLinearIndex`
- ... and 73 more

**Total:** 83 functions

### Deprecated/Low Confidence

Functions with low confidence scores, require verification.

- None

**Total:** 0 functions

---

## Recommendations

1. Only 10/93 functions have high confidence - recommend validating calling conventions against actual assembly
2. Most functions have medium confidence - validate parameter types and return types from Ghidra decompilation
3. This module depends on: Storm - ensure those are documented first
4. Export function signatures from Ghidra for type validation
5. Create Ghidra script to verify inferred calling conventions

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

