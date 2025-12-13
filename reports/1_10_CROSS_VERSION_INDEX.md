# Diablo 2 LoD 1.10 Cross-Version Function Index

## Executive Summary

This document provides a comprehensive analysis of Diablo 2 Lord of Destruction version 1.10 functions and their presence across all major LoD versions (1.07 through 1.13d).

**Key Finding:** 1,927 out of 3,317 human-named functions in 1.10 are present across all 11 LoD versions analyzed (58.1% overall consistency).

## Overview

### Baseline
- **Version:** 1.10
- **Analysis Date:** 2025-12-13
- **Total Functions Analyzed:** 3,317 (across 6 major modules)
- **Functions in All 11 Versions:** 1,927 (58.1%)
- **Version-Specific Functions:** 1,390 (41.9%)

### Versions Included
1. 1.07 (early LoD)
2. 1.08
3. 1.09
4. 1.09b
5. 1.09d (late pre-expansion era)
6. **1.10** (baseline/expansion release)
7. 1.11 (post-expansion major changes)
8. 1.11b
9. 1.12a
10. 1.13c
11. 1.13d (current as of analysis)

## Module Analysis

### Stability Ranking

| Rank | Module    | Total Functions | All 11 Versions | Stability % | Best For |
|------|-----------|-----------------|-----------------|-------------|----------|
| 1    | D2Game    | 371             | 251             | 67.7%       | Game logic anchors |
| 2    | D2Client  | 1,228           | 804             | 65.5%       | UI/Client anchors |
| 3    | D2Common  | 608             | 330             | 54.3%       | Common utilities |
| 4    | D2Win     | 376             | 200             | 53.2%       | Window management |
| 5    | Fog       | 437             | 207             | 47.4%       | Rendering support |
| 6    | Storm     | 297             | 135             | 45.5%       | Storm library |

### Module Details

#### D2Game (Game Logic Engine)
- **Total Functions:** 371
- **Consistency Breakdown:**
  - All 11 versions: 251 (67.7%)
  - 9+ versions: 4 additional (1.1%)
  - 8 versions: 5 additional (1.3%)
  - 7 or fewer: 111 (29.9%)
- **Stability:** Highest of all modules
- **Recommendation:** Excellent choice for cross-version anchoring. Core game logic functions are highly preserved.

#### D2Client (UI/Client Interface)
- **Total Functions:** 1,228
- **Consistency Breakdown:**
  - All 11 versions: 804 (65.5%)
  - 9+ versions: 9 additional (0.7%)
  - 8 versions: 7 additional (0.6%)
  - 7 or fewer: 408 (33.2%)
- **Stability:** High consistency with D2Game
- **Recommendation:** Good for UI-related cross-version anchoring. Largest module overall.

#### D2Common (Common Utilities)
- **Total Functions:** 608
- **Consistency Breakdown:**
  - All 11 versions: 330 (54.3%)
  - 9+ versions: 3 additional (0.5%)
  - 8 versions: 12 additional (2.0%)
  - 7 or fewer: 263 (43.2%)
- **Stability:** Moderate consistency
- **Recommendation:** Good for utility functions but more version-specific variations than game logic.

#### D2Win (Window Management)
- **Total Functions:** 376
- **Consistency Breakdown:**
  - All 11 versions: 200 (53.2%)
  - 9+ versions: 0
  - 8 versions: 0
  - 7 or fewer: 176 (46.8%)
- **Stability:** Lower consistency, significant version variations
- **Recommendation:** Use only for well-established window management functions.

#### Fog (Rendering Support Library)
- **Total Functions:** 437
- **Consistency Breakdown:**
  - All 11 versions: 207 (47.4%)
  - 9+ versions: 0
  - 8 versions: 1 additional (0.2%)
  - 7 or fewer: 229 (52.4%)
- **Stability:** Lower stability, rendering changes across versions
- **Recommendation:** Use established rendering functions, expect version-specific variants.

#### Storm (Storm Library - Blizzard Engine Core)
- **Total Functions:** 297
- **Consistency Breakdown:**
  - All 11 versions: 135 (45.5%)
  - 9+ versions: 17 additional (5.7%)
  - 8 versions: 1 additional (0.3%)
  - 7 or fewer: 144 (48.5%)
- **Stability:** Lowest stability among core modules
- **Recommendation:** Storm library has significant variation. Use high-confidence matches only.

## Cross-Version Consistency Patterns

### High Consistency (Present in All 11 Versions)
Functions found in all versions across all modules:
- Core game logic and state management
- Essential client interface functions
- Common library utilities
- Critical window management

**Total Recommended Anchors:** 1,927 functions

These are the most reliable for cross-version function matching and renaming propagation.

### Moderate Consistency (9-10 Versions)
Functions found in 9 or 10 versions:
- D2Game: 4 functions
- D2Client: 9 functions
- D2Common: 3 functions
- Storm: 17 functions

**Total:** 33 functions

These are reliable but may have minor variations in specific versions.

### Low Consistency (8 or Fewer Versions)
Functions found in 8 or fewer versions:
- Version-specific implementations
- Platform-specific code
- Optimization-specific functions
- API or architecture changes

**Total:** 1,357 functions (41.9% of baseline)

These require careful validation before cross-version propagation.

## Generated Files

### Primary Reports
1. **1_10_comprehensive_mapping_summary.json**
   - Overview of functions in all modules across versions
   - Consistency metrics for each module

2. **1_10_stability_analysis.json**
   - Detailed stability metrics
   - Module ranking by consistency
   - Cross-module analysis

3. **1_10_anchor_recommendations.json**
   - Sample functions present in all 11 versions
   - Recommended cross-version anchors by module
   - Address mappings for reference

### Detailed Module Mappings
1. **1_10_d2game_complete_mapping.json**
   - Complete D2Game 1.10 → all versions mapping
   - Function addresses in each version
   - Match types and confidence

2. **1_10_d2client_complete_mapping.json**
   - Complete D2Client 1.10 → all versions mapping
   - 1,228 functions with version addresses

3. **1_10_d2common_complete_mapping.json**
   - Complete D2Common 1.10 → all versions mapping
   - 608 functions with version addresses

4. **1_10_d2win_complete_mapping.json**
   - Complete D2Win 1.10 → all versions mapping
   - 376 functions with version addresses

5. **1_10_storm_complete_mapping.json**
   - Complete Storm 1.10 → all versions mapping
   - 297 functions with version addresses

6. **1_10_fog_complete_mapping.json**
   - Complete Fog 1.10 → all versions mapping
   - 437 functions with version addresses

## Recommendations for Use

### For Function Renaming Propagation
1. Use D2Game functions as primary anchors (67.7% consistency)
2. Use D2Client functions as secondary anchors (65.5% consistency)
3. Apply D2Common functions with caution (54.3% consistency)
4. Validate Storm and Fog functions individually (45.5% and 47.4%)

### For Cross-Version Matching
1. Start with functions present in all 11 versions (1,927 functions)
2. Use API index matching as primary method
3. Fall back to MNE (mnemonic) index matching
4. Use CFG (control flow graph) matching for complex functions
5. Apply PRO (prototype) matching as last resort

### For Function Renaming
1. Only rename functions with high-confidence matches (all 11 versions)
2. Use the 1,927 anchor functions as reference set
3. Validate each rename against call graphs
4. Consider version-specific variations for remaining functions

## Technical Details

### Matching Methods (Priority Order)
1. **API Index (API)** - Most reliable, based on API call signatures
2. **Mnemonic Index (MNE)** - Based on instruction sequences
3. **Control Flow Graph (CFG)** - Based on function control flow
4. **Prototype Index (PRO)** - Based on function signatures

### Function Consistency Levels
- **Level 10:** Present in all 11 LoD versions
- **Level 9:** Present in 10 versions (missing from 1 version)
- **Level 8:** Present in 9 versions (missing from 2 versions)
- **Level 7:** Present in 8 versions or fewer (significant variation)

## Next Steps

1. **Propagate CSV Renames** - Use the 30 verified CSV renames as baseline
2. **Cross-Version Matching** - Build automated tools using 1.10 anchors
3. **Function Rename Propagation** - Apply consistent naming across all versions
4. **Generate Unified Index** - Create master function index covering all versions
5. **Document Variations** - Record version-specific function differences

## Notes

- Analysis based on human-named functions only (excluded FUN_* and Ordinal_* names)
- Matching uses multi-method approach for reliability
- All addresses are relative virtual addresses (RVA) within each module
- Version numbering follows Blizzard's official releases
- Analysis timestamp: 2025-12-13T03:08:39

---
Generated by: `tools/generate_1_10_cross_version_mappings.py` and `tools/analyze_1_10_stability.py`
