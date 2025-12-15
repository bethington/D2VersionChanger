# D2VersionChanger - API Compatibility Matrix

**Purpose:** Show which functions exist in which versions for cross-version development.

**Generated:** 2025-12-13T03:33:42.787042

---

## Matrix Overview

Legend:
- ✅ Function exists in version
- ❌ Function does NOT exist in version
- 🔄 Function exists but may have different signature (check changelog)

---

## All-Version Functions (Present in All 11 Versions)

See `all_version_functions_analysis.json` for the complete list of 572 functions.

**Quick Check:**
- D2Client module: 225 functions guaranteed to exist
- D2Common module: 93 functions guaranteed to exist
- D2Game module: 84 functions guaranteed to exist
- D2Win module: 58 functions guaranteed to exist
- Storm module: 52 functions guaranteed to exist
- Fog module: 60 functions guaranteed to exist

**Total:** 572 all-version functions

---

## Version-Specific Functions

### By Version

| Version | Total Functions | All-Version | Version-Specific | Named % |
|---------|-----------------|-------------|------------------|---------|
| 1.07 | 0 | 572 | -572 | 0.0% |
| 1.08 | 0 | 572 | -572 | 0.0% |
| 1.09 | 0 | 572 | -572 | 0.0% |
| 1.09b | 0 | 572 | -572 | 0.0% |
| 1.09d | 0 | 572 | -572 | 0.0% |
| 1.10 | 0 | 572 | -572 | 0.0% |
| 1.11 | 0 | 572 | -572 | 0.0% |
| 1.11b | 0 | 572 | -572 | 0.0% |
| 1.12a | 0 | 572 | -572 | 0.0% |
| 1.13c | 0 | 572 | -572 | 0.0% |
| 1.13d | 0 | 572 | -572 | 0.0% |

---

## Module Compatibility

Each module has different version availability:

### D2Client Module

| Version | Functions | Named | Stability |
|---------|-----------|-------|-----------|
| 1.07 | 0 | 0 (0%) | ✅ High |
| 1.08 | 0 | 0 (0%) | ✅ High |
| 1.09 | 0 | 0 (0%) | ✅ High |
| 1.09b | 0 | 0 (0%) | ✅ High |
| 1.09d | 0 | 0 (0%) | ✅ High |
| 1.10 | 0 | 0 (0%) | ✅ High |
| 1.11 | 0 | 0 (0%) | ✅ High |
| 1.11b | 0 | 0 (0%) | ✅ High |
| 1.12a | 0 | 0 (0%) | ✅ High |
| 1.13c | 0 | 0 (0%) | ✅ High |
| 1.13d | 0 | 0 (0%) | ✅ High |

---

## For Cross-Version Development

### Strategy 1: Minimal Set
Use ONLY the 572 all-version functions. These are guaranteed to exist and work the same way across all 11 versions.

**Pros:** Maximum compatibility
**Cons:** Limited functionality

### Strategy 2: Version-Specific
Use all-version functions as base, add version-specific functions as needed.

**Pros:** More functionality
**Cons:** Need to check which version is running

### Strategy 3: Compatibility Layers
Build wrappers that detect version and call appropriate functions.

**Pros:** Optimal functionality and compatibility
**Cons:** Most complex to implement

---

## Testing Compatibility

For each version:
1. Load binary in Ghidra
2. Verify all 572 all-version functions exist
3. Check named function counts against this matrix
4. Run appropriate version-specific rename script

**Expected Result:** All 572 functions should be identically named across versions.

---

