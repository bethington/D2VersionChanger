# D2 Function Morphology - Current Status & Next Steps

## Current State Summary

### What's Been Completed ✓

1. **Function Extraction (d2_function_extractor.py)**
   - Detects functions via prologue/padding patterns
   - Outputs split JS files for viewer: `reports/functions/*.js`
   - 513,080 functions detected across 64 version folders

2. **Ghidra Export (ExportNamesOnly.java + MCP integration)**
   - Exported named functions from Ghidra for all DLLs
   - Output: `data/ghidra_names/*.json` (26 DLLs)
   - D2Client.dll: 4,800 functions, 4,799 named, 4,052 with comments

3. **Optimized Matching Pipeline (tools/optimized_matching/)**
   - **analysis_engine.py**: PE analysis, function detection, signatures, call graphs
   - **matching_engine.py**: 4-tier matching (Export, Exact Bytes, Prologue, Call Graph)
   - **name_propagator.py**: Merges Ghidra names with matched functions
   - **pipeline_runner.py**: Unified CLI

4. **D2Client.dll Matching Test Results**
   - 10,489 total matches
   - Tier 1 (Export): 4 (0.0%)
   - Tier 2 (Exact Bytes): 5,670 (54.1%)
   - Tier 3 (Prologue): 4,721 (45.0%)
   - Tier 4 (Call Graph): 94 (0.9%)
   - Coverage: 60-96% depending on version

5. **Viewer (reports/d2_report_viewer.html)**
   - Displays function tables per DLL
   - Groups by binary variant
   - Shows address morphology across versions

---

## Session Results (2025-12-01)

### Tasks Completed ✓

1. **[x] Stats verification** - D2Client.dll matching is working:
   - 10,489 matches across 31 versions
   - Coverage: 48-96% per version
   - Tier distribution: 54% exact bytes, 45% prologue, 0.9% call graph

2. **[x] Name propagation** - Ghidra names merged:
   - 902 functions got names from Ghidra (LoD/1.13c reference)
   - Names include: GetSecurityValidationFlag, GetDifficultySettings, CreateUnitEffectArray, etc.

3. **[x] Viewer export** - JS files regenerated:
   - `reports/functions/D2Client.dll.js` now has 902 real function names
   - Export ordinal functions have semantic names (not just Ordinal_XXXXX)

4. **[x] Viewer verification** - Display is correct:
   - Viewer at `reports/d2_report_viewer.html` renders named functions
   - Address morphology across versions is visible

5. **[x] Full pipeline run on all major DLLs**:
   - D2Common.dll: 4,125 matches, 1,401 named
   - D2Game.dll: 6,342 matches, 610 named
   - Fog.dll: 985 matches, 315 named
   - Storm.dll: 1,910 matches, 530 named
   - D2Launch.dll: 810 matches, 80 named
   - D2Win.dll: 622 matches, 232 named
   - D2gfx.dll: 305 matches, 104 named
   - D2Multi.dll: 676 matches, 72 named
   - D2Net.dll: 151 matches, 45 named
   - D2sound.dll: 206 matches, 84 named
   - D2Lang.dll: 228 matches, 65 named
   - D2CMP.dll: 695 matches, 160 named

6. **[x] Viewer enhancements**:
   - Added function name search/filter input
   - Added "Named Only" toggle button
   - Named functions highlighted in green
   - Live stats showing filtered/total counts

7. **[x] Additional DLLs processed**:
   - Bnclient.dll: 134 named / 1,216 total
   - D2DDraw.dll: 16 named / 146 total
   - D2Direct3D.dll: 2 named / 352 total
   - D2Gdi.dll: 7 named / 185 total
   - D2Glide.dll: 2 named / 402 total
   - D2MCPClient.dll: 83 named / 246 total
   - Game.exe: 4 named / 20,368 total

8. **[x] 3rd party libraries processed**:
   - Binkw32.dll: 110 named / 155 total (RAD Game Tools)
   - SmackW32.dll: 64 named / 78 total (RAD Game Tools)
   - Ijl11.dll: 2 named / 51 total (Intel JPEG Library)

9. **[x] D2Server.dll single-version export**:
   - Created tools/export_single_version.py for DLLs with only 1 version
   - D2Server.dll: 6 named / 256 total (only exists in Classic/1.00)

---

## What Needs to Be Done

### Phase 1: Complete Pipeline for All DLLs
- [x] 1.1 D2Client.dll matching tested and working
- [x] 1.2 Run pipeline on remaining DLLs (D2Common, D2Game, D2Launch, etc.) ✓ Session 2025-12-01
- [x] 1.3 Propagate Ghidra names for each DLL ✓ Session 2025-12-01
- [x] 1.4 Regenerate all `reports/functions/*.js` files ✓ Session 2025-12-01

### Phase 2: Improve Matching Coverage
- [x] 2.1 Analyze unmatched functions (the ~5-40% gap) ✓ Session 2025-12-01
  - Created tools/analyze_unmatched.py
  - See detailed findings below in "Unmatched Functions Analysis"
- [ ] 2.2 Add fallback matching for image base transitions (1.03→1.04)
- [ ] 2.3 Consider Tier 5: Function similarity matching (optional)

---

## Unmatched Functions Analysis

### Summary by Version Group (D2Client.dll)

| Version Group | Versions | Avg Unmatched | Cause |
|--------------|----------|---------------|-------|
| Early Classic (1.00-1.03) | 4 | ~1,200/version | Version-specific code removed in 1.04 |
| Mid Classic (1.04-1.05b) | 4 | ~42/version | Excellent matching |
| Classic 1.06.x | 2 | ~1,060/version | Transitional version with unique code |
| Classic 1.08+ | 10 | ~51/version | Excellent matching |
| LoD 1.07 | 1 | 2,250 | First LoD version, major restructuring |
| LoD 1.08+ | 10 | ~51/version | Excellent matching |

### Root Causes

**1. Early Classic (1.00-1.03) - ~1,200 unmatched per version**
- These versions used image base `0x10000000`
- Many functions were completely rewritten or removed in version 1.04
- Only 59 functions successfully match across the 1.03→1.04 transition
- This is NOT primarily an image base issue - it's actual code removal/rewrite

**2. LoD 1.07 - 2,250 unmatched (highest)**
- First Lord of Destruction version
- Massive code restructuring from Classic
- Many functions exist only in this version and were rewritten in 1.08
- Likely contains debug code or beta features that were removed

**3. Classic 1.06.x - ~1,000 unmatched per version**
- Transitional version between early and modern code
- Contains unique implementations not present in other versions
- Mix of old (1.00-1.05) and new (1.08+) code patterns

**4. Modern Versions (1.08+) - Only 32-74 unmatched each**
- Highly stable codebase with minimal changes between versions
- 95%+ matching success rate
- Unmatched functions are likely small helper functions with insufficient context

### Image Base Transition Details

```
Classic 1.00-1.03: Image base 0x10000000
Classic 1.04+:     Image base 0x6FB60000 (rebased DLL)
```

The image base change from 1.03 to 1.04 is NOT the primary cause of unmatched functions:
- Our matching uses relative offsets and byte patterns, not absolute addresses
- The real issue is that Blizzard rewrote/removed ~1,200 functions in the 1.04 release
- This was likely a major refactoring or optimization pass

### Implications

1. **The unmatched functions are mostly legitimate** - they represent version-specific code that doesn't exist in other versions
2. **Improving matching won't help much** - these functions genuinely have no counterpart to match against
3. **For research purposes**, early Classic and LoD 1.07 should be analyzed separately as they contain unique implementations

### Deep Analysis Results (Session 2)

**Function Size Analysis:**
| Version | Matched Avg | Unmatched Avg | Unmatched Tiny (<16b) |
|---------|-------------|---------------|----------------------|
| Classic/1.00 | 327 bytes | 221 bytes | 0.4% |
| Classic/1.04b | 271 bytes | 19 bytes | 2.4% |
| LoD/1.07 | 302 bytes | 290 bytes | 0.1% |
| LoD/1.13c | 236 bytes | 12 bytes | 41.5% |

**Key Insight**: In modern versions (1.13c), 41.5% of unmatched functions are tiny (<16 bytes) - these are likely compiler-generated stubs or thunks that lack sufficient context to match.

**Version Group Overlap Matrix** (functions shared between groups):
```
                Early Classic  Mid Classic  Late Classic  LoD 1.07  LoD 1.08+
Early Classic          2180          492           29       401        29
Mid Classic             492         2227           93       347        93
Late Classic             29           93         6668       158      6668
LoD 1.07                401          347          158       570       158
LoD 1.08+                29           93         6668       158      6668
```

**Critical Finding**:
- LoD/1.07 shares **401 functions with Early Classic** but only **158 with Late versions**
- This means LoD/1.07 is architecturally closer to the OLD codebase
- Late Classic and LoD 1.08+ are **identical** (6668 shared functions)

**LoD/1.07 Breakdown** (of 570 matched functions):
- Only in LoD/1.07: 40 functions (unique to this version)
- Shared with Early Classic only: 372 functions (OLD code path)
- Shared with Late versions: 158 functions (NEW code path)

**Conclusion**: LoD/1.07 represents a **hybrid codebase** - it contains old Classic code that was later rewritten in 1.08. The 2,250 unmatched functions are real - they existed only in this transitional version and were removed/replaced.

### Phase 3: Morphology Visualization in Viewer
- [x] 3.1 Add function name search/filter in viewer
- [x] 3.2 Add "show only named functions" toggle
- [x] 3.3 Color-code named functions (green highlight)
- [x] 3.4 Show match tier in function details ✓ Session 2025-12-01
  - Added tier indicators (1-4) with color coding
  - Added tier legend in toolbar
- [ ] 3.5 Add function signature display (from Ghidra data)

### Phase 4: Export & Documentation
- [x] 4.1 Generate function_registry.json with complete morphology ✓ Session 2025-12-01
  - Created tools/generate_registry.py
  - Output: reports/function_registry.json (18 MB, 50743 functions)
- [x] 4.2 Add CSV export for external tools ✓ Session 2025-12-01
  - Created tools/export_csv.py
  - Supports --dll, --all, --summary modes
- [x] 4.3 Update documentation with final workflow ✓ Session 2025-12-01

---

## Commands Reference

```bash
# Run full pipeline on a DLL
python -m tools.optimized_matching.pipeline_runner full --dll D2Client.dll

# Just matching (uses cached analysis)
python -m tools.optimized_matching.pipeline_runner match --dll D2Client.dll

# Statistics
python -m tools.optimized_matching.pipeline_runner stats --dll D2Client.dll

# Apply Ghidra names
python -m tools.optimized_matching.name_propagator \
    --ghidra data/ghidra_names/D2Client.dll.json \
    --state cache/matches/D2Client.dll_state.json \
    --version LoD/1.13c

# Export for viewer
python -m tools.optimized_matching.pipeline_runner viewer-export --dll D2Client.dll
```

---

## Review Summary

### What Works
- Stats command shows comprehensive matching statistics
- Name propagation successfully merges Ghidra names (902/10489 for D2Client.dll)
- Viewer export generates valid JS files with named functions
- HTML viewer displays function morphology across versions

### Observations
- Only ~8.6% of D2Client.dll functions have Ghidra names (902 of 10,489 matches)
- This is because Ghidra names come from the reference version (LoD/1.13c)
- Many matches span only old versions (Classic/1.00-1.03) where 1.13c doesn't have equivalent

### Remaining Work
1. Phase 2.2-2.3: Optional matching improvements
2. Phase 3.5: Function signature display in viewer

### Session 2 Completed (2025-12-01)
- [x] Deep analysis of unmatched functions - documented root causes in detail
- [x] Added Classic/LoD filter to file details view columns
  - Toggling C/L buttons now filters version columns in function table
  - Shows filter indicator in header when filtering is active
- [x] Added version filter buttons based on major refactor discovery:
  - **Pre-Refactor** (Classic 1.00-1.03): Old codebase before major refactor
  - **Post-Refactor** (Classic 1.04+): Refactored modern codebase
  - **LoD** (All LoD versions): Lord of Destruction
  - Each button toggles independently
  - Filter indicator shows active filters in function table header (e.g., `[Pre+LoD]`)

---

## Complete Workflow Documentation

### For Users: How to Use the Function Data

**Viewer (reports/d2_report_viewer.html)**
- Browse any DLL to see function morphology across versions
- Use search to find functions by name
- Toggle "Named Only" to filter to documented functions
- Tier indicators show match confidence (1=Export, 2=Exact, 3=Prologue, 4=CallGraph)

**JSON Registry (reports/function_registry.json)**
- Complete function data for all 23 DLLs
- 50,743 matched functions, 5,101 with names
- Use for external tools or custom analysis

**CSV Export**
```bash
# Export single DLL
python tools/export_csv.py --dll D2Client.dll

# Export all DLLs
python tools/export_csv.py --all

# Export summary
python tools/export_csv.py --summary
```

### For Developers: Adding New Analysis

**Re-run matching for a DLL:**
```bash
python -m tools.optimized_matching.pipeline_runner full --dll D2Client.dll
```

**Propagate Ghidra names:**
```bash
python -m tools.optimized_matching.name_propagator \
    --ghidra data/ghidra_names/D2Client.dll.json \
    --state cache/matches/D2Client.dll_state.json \
    --version LoD/1.13c
```

**Update viewer JS files:**
```bash
python -m tools.optimized_matching.pipeline_runner viewer-export --dll D2Client.dll
```

**Regenerate complete registry:**
```bash
python tools/generate_registry.py
```

### Statistics Summary (2025-12-01)

| Metric | Value |
|--------|-------|
| Total DLLs | 23 |
| Total Functions | 50,743 |
| Named Functions | 5,101 (10%) |
| Tier 1 (Export) | 2,847 (5.6%) |
| Tier 2 (Exact) | 22,915 (45.2%) |
| Tier 3 (Prologue) | 22,958 (45.2%) |
| Tier 4 (CallGraph) | 2,023 (4.0%) |
