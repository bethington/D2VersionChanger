# Client/UI Module (D2Client)

## Module Overview

**Purpose:** User interface, screen rendering, input handling, game display

**Responsibility:** Display layer and user interaction

**Stability Level:** HIGH - Most stable module (225 all-version functions)

**Dependencies:** D2Common, D2Win, Fog

---

## API Statistics

| Metric | Value |
|--------|-------|
| Total Functions | 225 |
| Primary Categories | 10 |

### Functions by Category

- **Utility** (94 functions) - General utility and helper functions
- **Bit Operations** (38 functions) - Functions for bit manipulation and flag handling
- **Game Logic** (22 functions) - Core game logic and mechanics functions
- **String Operations** (18 functions) - Functions for string manipulation and formatting
- **UI/Windows** (13 functions) - User interface and window management
- **Memory Management** (12 functions) - Functions for allocating, freeing, and managing memory
- **Data Structures** (10 functions) - Data structure manipulation and management
- **Math Operations** (8 functions) - Mathematical calculations and numeric operations
- **Graphics/Rendering** (5 functions) - Graphics rendering and visual effects
- **File I/O** (5 functions) - File reading, writing, and management


### Complexity Distribution

| Complexity | Count |
|------------|-------|
| Trivial | 214 (95.1%) |
| Simple | 10 (4.4%) |
| Moderate | 1 (0.4%) |

### Confidence Distribution

| Confidence | Count | Functions |
|------------|-------|-----------|
| High (>= 0.8) | 50 (22.2%) | Public API |
| Medium (0.5-0.79) | 175 (77.8%) | Internal API |
| Low (< 0.5) | 0 (0.0%) | Deprecated |

---

## Interface Tiers

### Public API (High Confidence)

Functions well-validated and recommended for cross-version use.

- `BackupKeyBindingsAndReinitialize`
- `CheckValueAndProcessData`
- `CreateFileWrapper`
- `CreatePoolObject`
- `CreateWaypointData`
- `EnableVideoInitialization`
- `ExceptionHandlerLogAndCleanup`
- `FreePoolMemory`
- `FreeTrackedPoolAllocation`
- `GetInitFlag`
- ... and 40 more

**Total:** 50 functions

### Internal API (Medium Confidence)

Functions with estimated signatures, recommend validation before use.

- `AutomapPlayerIconLine_SetField24`
- `CTRL_SetUpdateFlag`
- `CacheMarkSmsCategoriesForCopy`
- `CalculateMenuPanelYPosition`
- `CalculateWindowBorders`
- `CancelScreenFade`
- `CheckTimeoutElapsed50ms`
- `CleanupAndDelete`
- `CleanupPlayerSlots`
- `CleanupPlayerSlotsWrapper`
- ... and 165 more

**Total:** 175 functions

### Deprecated/Low Confidence

Functions with low confidence scores, require verification.

- None

**Total:** 0 functions

---

## Recommendations

1. This module depends on: D2Common, D2Win, Fog - ensure those are documented first
2. Export function signatures from Ghidra for type validation
3. Create Ghidra script to verify inferred calling conventions

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

