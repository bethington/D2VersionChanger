# D2 Function Extractor - Task Summary

## Completed Tasks

- [x] Analyze binary patterns across versions (1.00, 1.13c)
- [x] Create Python function extractor tool
- [x] Test the tool on sample binaries
- [x] Generate function data for HTML viewer
- [x] Split output by DLL for better file sizes
- [x] Implement version index optimization

## Tool Created

### `tools/d2_function_extractor.py`

A Python tool that extracts function start addresses from Diablo 2 binaries.

**Detection Methods:**
1. PE Export Table - Functions exported by ordinal/name
2. Padding Detection - CC (INT3) or NOP+CC padding between functions
3. Prologue Detection - Common function prologues (PUSH EBP, SUB ESP, etc.)
4. Jump Table Detection - E9 (JMP) sequences at section start (older versions)

**Output (Split Format):**
- `reports/functions/_index.js` (2.4KB) - Version list and file summaries
- `reports/functions/<filename>.js` - Per-DLL function data (16 files, 12.1MB total)
- Uses version indices instead of string keys for ~24% size reduction

**Usage:**
```bash
# Full extraction from all versions
python tools/d2_function_extractor.py

# Single file analysis
python tools/d2_function_extractor.py -f path/to/file.dll

# Custom paths
python tools/d2_function_extractor.py -p /project/root -o /output/dir
```

## Results

| Metric | Value |
|--------|-------|
| Version folders processed | 64 |
| PE files indexed | 16 |
| Total functions detected | 513,080 |
| Total output size | 12.1 MB |

### Functions per Major DLL:
- D2Game.dll: 4,324 functions (max across versions)
- D2Client.dll: 3,246 functions
- D2Common.dll: 2,595 functions
- Storm.dll: 1,366 functions
- Fog.dll: 731 functions
- D2Win.dll: 621 functions
- Game.exe: 15,832 functions (1.14d - merged DLLs)

### Output Files:
| File | Size |
|------|------|
| _index.js | 2.4 KB |
| Game.exe.js | 5.2 MB |
| D2Game.dll.js | 2.0 MB |
| D2Client.dll.js | 1.5 MB |
| D2Common.dll.js | 1.2 MB |
| Storm.dll.js | 631 KB |
| Others | < 400 KB each |

## Data Structure

### Index File (_index.js)
```javascript
const FUNCTION_INDEX = {
  "generated": "2025-11-30T...",
  "version_count": 64,
  "versions": ["Classic/1.00", "Classic/1.01", ...],
  "files": {
    "D2Client.dll": {"function_count": 3246, "version_count": 31},
    ...
  }
}
```

### Per-DLL File (D2Client.dll.js)
```javascript
const FUNCTIONS_D2CLIENT_DLL = {
  "filename": "D2Client.dll",
  "function_count": 3246,
  "version_indices": [0, 1, 2, ...],  // Indices into FUNCTION_INDEX.versions
  "functions": [
    [addr_v0, addr_v1, addr_v2, ...],  // function_0001 addresses by version
    [addr_v0, addr_v1, addr_v2, ...],  // function_0002
    ...
  ]
}
```

## Key Findings

1. **Image Base Variations:**
   - 1.00-1.03: `0x10000000` (standard DLL base)
   - 1.04+: `0x6Fxxxxxx` (relocated to avoid conflicts)

2. **Padding Patterns:**
   - 1.00-1.06: NOP (0x90) + INT3 (0xCC) mixed
   - 1.07+: CC (INT3) only

3. **Jump Tables:**
   - Present in 1.00-1.06 at start of .text section
   - E9 (JMP rel32) sequences for export thunks

4. **1.14 Merger:**
   - All DLLs merged into Game.exe
   - Function count jumps from ~100 to 11,000-15,000

## Next Steps (Future Work)

1. **Phase 2: Function Signatures** - Create byte pattern signatures for each function
2. **Phase 3: Cross-Version Matching** - Match functions across versions using signatures instead of position

## Review

### Session 1: Initial Tool Creation
The function extractor tool successfully:
- Parses PE files to extract .text section and export tables
- Detects function boundaries using multiple heuristics
- Handles both old (1.00) and new (1.13c) binary formats
- Generates viewer-compatible JavaScript data
- Provides sequential function naming for temporary cross-version linkage

Current limitation: Functions are linked by position (function_0001 in v1.00 maps to function_0001 in v1.01). This will be improved with signature-based matching in Phase 2.

### Session 2: File Size Optimization
Implemented split output format to reduce file sizes:
- Split single 16MB file into 17 smaller files (1 index + 16 per-DLL)
- Replaced version string keys with numeric indices
- Addresses stored as sparse arrays indexed by version number
- **Result: 24% size reduction (16MB → 12.1MB)**
- Enables lazy loading of per-DLL data in browser viewer
