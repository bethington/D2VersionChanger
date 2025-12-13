# Graphics Rendering Engine (Fog)

## Module Overview

**Purpose:** Sprite rendering, palette management, animation, visual effects

**Responsibility:** Graphics rendering layer

**Stability Level:** MEDIUM - Implementation varies across versions

**Dependencies:** D2Common, Storm

---

## API Statistics

| Metric | Value |
|--------|-------|
| Total Functions | 60 |
| Primary Categories | 8 |

### Functions by Category

- **Utility** (22 functions) - General utility and helper functions
- **Bit Operations** (9 functions) - Functions for bit manipulation and flag handling
- **File I/O** (8 functions) - File reading, writing, and management
- **Memory Management** (8 functions) - Functions for allocating, freeing, and managing memory
- **String Operations** (7 functions) - Functions for string manipulation and formatting
- **Math Operations** (3 functions) - Mathematical calculations and numeric operations
- **Network** (2 functions) - Network communication and protocols
- **Data Structures** (1 functions) - Data structure manipulation and management


### Complexity Distribution

| Complexity | Count |
|------------|-------|
| Trivial | 60 (100.0%) |

### Confidence Distribution

| Confidence | Count | Functions |
|------------|-------|-----------|
| High (>= 0.8) | 11 (18.3%) | Public API |
| Medium (0.5-0.79) | 49 (81.7%) | Internal API |
| Low (< 0.5) | 0 (0.0%) | Deprecated |

---

## Interface Tiers

### Public API (High Confidence)

Functions well-validated and recommended for cross-version use.

- `CloseHandleWrapper`
- `CreateFileWrapper`
- `CreateStormThread`
- `CreateTcpConnection`
- `IffCreate`
- `InitializeLogManager`
- `SMemAlloc`
- `SMemFree`
- `SetAsyncFileHandle`
- `__nh_malloc`
- ... and 1 more

**Total:** 11 functions

### Internal API (Medium Confidence)

Functions with estimated signatures, recommend validation before use.

- `AtomicExchange64`
- `AtomicRead64`
- `ClearBitInArray`
- `CompareStringsIgnoreCase`
- `EncodeVarInt2Byte`
- `EnterCriticalSectionWrapper`
- `GetCosineFromTable`
- `GetField0x110`
- `GetField880`
- `GetFogStatePtr`
- ... and 39 more

**Total:** 49 functions

### Deprecated/Low Confidence

Functions with low confidence scores, require verification.

- None

**Total:** 0 functions

---

## Recommendations

1. Only 11/60 functions have high confidence - recommend validating calling conventions against actual assembly
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

