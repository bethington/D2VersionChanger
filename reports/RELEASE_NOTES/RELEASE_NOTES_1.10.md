# D2VersionChanger - Lord of Destruction 1.10

**Release Date:** 2003-10-09

**Version Type:** LoD

---

## Version Summary

🔴 **MAJOR VERSION** - Significant API changes

### Function Statistics

- **Total Functions:** 0
- **Named Functions:** 0 (0.0%)
- **Unnamed Functions:** 0 (100.0%)

### Module Distribution

| Module | Functions | Named | % Named |
|--------|-----------|-------|---------|

## Changes from 1.09d

### Overall Changes

- **New Functions:** 0
- **Removed Functions:** 0
- **Stable Functions:** 4,777 (unchanged)
- **API Churn:** 0.0%

### Module-Level Changes

| Module | New | Removed | Stable | Stability |
|--------|-----|---------|--------|-----------|
| D2Client | 2,019 | 2,272 | 1,421 | 38.5% |
| D2Common | 1,053 | 957 | 995 | 51.0% |
| D2Game | 3,063 | 3,167 | 935 | 22.8% |
| D2Win | 112 | 152 | 428 | 73.8% |
| Fog | 173 | 178 | 467 | 72.4% |
| Storm | 250 | 237 | 531 | 69.1% |

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

