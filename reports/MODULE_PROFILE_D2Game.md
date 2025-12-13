# Game Engine Module (D2Game)

## Module Overview

**Purpose:** Core game logic, monster behavior, item management, quest system

**Responsibility:** Primary game mechanics and state management

**Stability Level:** HIGH - Core engine code

**Dependencies:** D2Common, Storm

---

## API Statistics

| Metric | Value |
|--------|-------|
| Total Functions | 84 |
| Primary Categories | 8 |

### Functions by Category

- **Utility** (48 functions) - General utility and helper functions
- **Bit Operations** (9 functions) - Functions for bit manipulation and flag handling
- **Game Logic** (9 functions) - Core game logic and mechanics functions
- **Memory Management** (6 functions) - Functions for allocating, freeing, and managing memory
- **Math Operations** (5 functions) - Mathematical calculations and numeric operations
- **String Operations** (4 functions) - Functions for string manipulation and formatting
- **Data Structures** (2 functions) - Data structure manipulation and management
- **File I/O** (1 functions) - File reading, writing, and management


### Complexity Distribution

| Complexity | Count |
|------------|-------|
| Trivial | 84 (100.0%) |

### Confidence Distribution

| Confidence | Count | Functions |
|------------|-------|-----------|
| High (>= 0.8) | 8 (9.5%) | Public API |
| Medium (0.5-0.79) | 76 (90.5%) | Internal API |
| Low (< 0.5) | 0 (0.0%) | Deprecated |

---

## Interface Tiers

### Public API (High Confidence)

Functions well-validated and recommended for cross-version use.

- `CreatePoolObject`
- `FreePoolMemory`
- `FreeTrackedPoolAllocation`
- `InitRngSeed`
- `InitTimerState`
- `SMemFree`
- `__nh_malloc`
- `_malloc`

**Total:** 8 functions

### Internal API (Medium Confidence)

Functions with estimated signatures, recommend validation before use.

- `ClearBitInArray`
- `ClearField0x20`
- `ClearImageDimensions`
- `ExtractAndClearValue`
- `FUN_6fd23263`
- `FUN_6fd23386`
- `FUN_6fd23482`
- `GetItemDataByCode`
- `GetItemRandSeed`
- `GetParsedItemCountPtr`
- ... and 66 more

**Total:** 76 functions

### Deprecated/Low Confidence

Functions with low confidence scores, require verification.

- None

**Total:** 0 functions

---

## Recommendations

1. Only 8/84 functions have high confidence - recommend validating calling conventions against actual assembly
2. Most functions have medium confidence - validate parameter types and return types from Ghidra decompilation
3. This module depends on: D2Common, Storm - ensure those are documented first
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

