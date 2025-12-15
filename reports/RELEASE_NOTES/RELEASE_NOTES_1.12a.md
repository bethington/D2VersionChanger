# D2VersionChanger - Lord of Destruction 1.12a

**Release Date:** 2005-10-03

**Version Type:** LoD

---

## Version Summary

### Function Statistics

- **Total Functions:** 0
- **Named Functions:** 0 (0.0%)
- **Unnamed Functions:** 0 (100.0%)

### Module Distribution

| Module | Functions | Named | % Named |
|--------|-----------|-------|---------|

## Changes from 1.11b

### Overall Changes

- **New Functions:** 0
- **Removed Functions:** 0
- **Stable Functions:** 5,729 (unchanged)
- **API Churn:** 0.0%

### Module-Level Changes

| Module | New | Removed | Stable | Stability |
|--------|-----|---------|--------|-----------|
| D2Client | 3,210 | 3,218 | 1,165 | 26.6% |
| D2Common | 1,183 | 1,182 | 1,329 | 52.9% |
| D2Game | 3,710 | 3,710 | 988 | 21.0% |
| D2Win | 184 | 184 | 409 | 69.0% |
| Fog | 53 | 51 | 741 | 93.6% |
| Storm | 54 | 56 | 1,097 | 95.1% |

## All-Version Functions

This version includes all 572 core functions that are stable across all LoD versions (1.07-1.13d).

**Import Tip:** Use these functions for cross-version compatibility - they are guaranteed to exist in this version and all other versions.

## Documentation

- **API Reference:** See `API_[Module].md` for complete function signatures
- **Module Profile:** See `MODULE_PROFILE_[Module].md` for architecture details
- **Function Index:** See `unified_function_index.json` for complete function list

## Deployment

### For Ghidra Users

1. Load this version's binary in Ghidra
2. Run the appropriate rename script: `ghidra_scripts/Rename_[Module]_[Version].java`
3. Use the 572 all-version functions as validation baseline

### For Integration

All 572 all-version functions are documented in:
- `all_version_functions_analysis.json` - Categorization and priority
- `api_reference_summary.json` - Complete signatures
- Module profiles - Interface tiers and dependencies

---

**Generated:** {datetime.now().isoformat()}

**Project Phase:** 6 (Release Preparation)

---

