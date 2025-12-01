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
- [ ] 1.2 Run pipeline on remaining DLLs (D2Common, D2Game, D2Launch, etc.)
- [ ] 1.3 Propagate Ghidra names for each DLL
- [ ] 1.4 Regenerate all `reports/functions/*.js` files

### Phase 2: Improve Matching Coverage
- [ ] 2.1 Analyze unmatched functions (the ~5-40% gap)
- [ ] 2.2 Add fallback matching for image base transitions (1.03→1.04)
- [ ] 2.3 Consider Tier 5: Function similarity matching (optional)

### Phase 3: Morphology Visualization in Viewer
- [x] 3.1 Add function name search/filter in viewer
- [x] 3.2 Add "show only named functions" toggle
- [x] 3.3 Color-code named functions (green highlight)
- [ ] 3.4 Show match tier in function details
- [ ] 3.5 Add function signature display (from Ghidra data)

### Phase 4: Export & Documentation
- [ ] 4.1 Generate function_registry.json with complete morphology
- [ ] 4.2 Add CSV export for external tools
- [ ] 4.3 Update documentation with final workflow

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

### Next Immediate Steps
1. Run the full pipeline on other major DLLs (D2Common.dll, D2Game.dll)
2. Consider adding viewer features (search, filter by named)
3. Document the complete workflow for end users
