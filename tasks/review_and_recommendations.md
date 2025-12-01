# Project Review and Recommendations

**Date:** 2025-12-01
**Reviewer:** Claude

---

## Executive Summary

The D2VersionChanger function morphology system has made significant progress with 50,743 matched functions across 23 DLLs. The new **Ghidra-centric approach** using method-prefixed canonical indexes has been designed and the core infrastructure is **already implemented**. The next step is to run the Ghidra export on all versions and generate the unified registry.

---

## Implementation Status

### Already Implemented ✓

| Component | File | Status |
|-----------|------|--------|
| **Ghidra Export Script** | `ghidra_scripts/ExportFunctionIndex.java` | Complete - exports all functions with multi-index system |
| **Merge Tool** | `tools/merge_function_index.py` | Complete - merges per-version exports into unified registry |
| **Index Method Design** | `docs/function_identification_methods.md` | Complete - documents all 6 index methods |
| **Version Ordering** | In merge tool | Complete - 41 versions ordered for conflict resolution |

### Needs Execution

| Task | Description |
|------|-------------|
| **Run Ghidra exports** | Execute `ExportFunctionIndex.java` on each binary in Ghidra project |
| **Generate registry** | Run `python tools/merge_function_index.py` to create `function_registry_v2.json` |
| **Update viewer** | Modify `d2_report_viewer.html` to use new registry format |

---

## Current State Analysis

### What Works Well

1. **Function Detection:** The Python-based prologue/padding detection finds functions reliably
2. **Tiered Matching:** The 4-tier system (Export → Exact Bytes → Prologue → Call Graph) achieves 95%+ coverage for stable versions
3. **Viewer:** The HTML viewer effectively displays function morphology with filtering
4. **Split Data Files:** Pre/Post/LoD split reduces load times and improves relevance
5. **NEW: Index System Infrastructure:** Scripts ready for Ghidra-centric workflow

### Critical Gaps (Being Addressed)

| Issue | Impact | Solution Status |
|-------|--------|-----------------|
| **No version info in Ghidra exports** | Can't track function identity across versions | ✓ ExportFunctionIndex.java auto-detects version from path |
| **Python-based function detection** | Duplicates Ghidra's superior analysis | ✓ New script exports ALL Ghidra-detected functions |
| **Sequential matching IDs** | `func_00001` is arbitrary, not stable | ✓ New system uses method-prefixed indexes (EXP:, MNE:, etc.) |
| **Single-version name source** | Only LoD/1.13c names used | ✓ Merge tool uses earliest-version-wins for naming |
| **No fallback indexes** | If primary match fails, function is "unmatched" | ✓ Each function stores ALL 6 index types |

### Data Flow (Current - Legacy)

```
[Python PE Analysis] → [Function Detection] → [Tiered Matching] → [Name Propagation] → [Viewer JS]
        ↓                      ↓                     ↓                    ↓
  cache/analysis/        (Prologue/Size)        (Sequential IDs)    (Single version)
```

### Data Flow (New - Ready to Execute)

```
[Ghidra Analysis] → [Export with Indexes] → [Merge Tool] → [Unified Registry] → [Viewer JS]
       ↓                    ↓                    ↓                 ↓
  (All functions)    (Version folders)    (Canonical IDs)   (Multi-version names)
```

---

## Proposed Solution: Method-Prefixed Canonical Index

### Core Concept

Each function gets a **canonical ID** based on its most reliable identifying characteristic:

```
<METHOD>:<HASH>

Examples:
  EXP:10042           → Export ordinal 10042
  STR:a3f2e8c1...     → Unique string reference hash
  API:c7e8d9f0...     → API call sequence hash
  MNE:d1a2b3c4...     → Mnemonic sequence + size hash
  CFG:e5f6a7b8...     → Control flow graph hash
  PRO:f9a0b1c2...     → Prologue bytes + size hash
```

### Why This Works

1. **Intrinsic Identity:** The ID is computed from the function itself, not assigned arbitrarily
2. **Cross-Version Stability:** Same function in different versions computes same ID
3. **Fallback Mechanism:** Store ALL indexes, use best one as primary
4. **Self-Documenting:** `MNE_d1a2b3c4` as a function name tells you it's mnemonic-matched

### Index Priority (Reliability Order)

| Priority | Method | Prefix | When Used | Reliability |
|----------|--------|--------|-----------|-------------|
| 1 | Export Ordinal | `EXP:` | Function is DLL export | 100% |
| 2 | Unique Strings | `STR:` | Has unique string refs | 99% |
| 3 | API Sequence | `API:` | Calls ≥2 imported APIs | 95% |
| 4 | Mnemonic+Size | `MNE:` | Default (always available) | 85% |
| 5 | CFG Structure | `CFG:` | Has ≥2 basic blocks | 80% |
| 6 | Prologue+Size | `PRO:` | Fallback for tiny functions | 70% |

---

## Implementation Plan

### Phase 1: Update Ghidra Export Script

**File:** `ghidra_scripts/ExportFunctionIndex.java`

**Changes:**
1. Auto-detect version from program path (e.g., `/Classic/1.10/D2Client.dll` → version = `Classic/1.10`)
2. Export ALL functions (not just named ones)
3. Compute all index types for each function
4. Select best index as primary `index` field
5. Output to version-specific folder: `data/function_index/Classic/1.10/D2Client.dll.json`

**Output Format:**
```json
{
  "program_name": "D2Client.dll",
  "version": "Classic/1.10",
  "image_base": "0x6FAB0000",
  "functions": {
    "0x6FAB1000": {
      "name": "DeleteObjectMemory",
      "index": "EXP:10001",
      "index_method": "EXP",
      "indexes": {
        "EXP": "10001",
        "STR": null,
        "API": "c7e8d9f0a1b2...",
        "MNE": "d1a2b3c4e5f6...",
        "CFG": "e5f6a7b8c9d0...",
        "PRO": "f9a0b1c2d3e4..."
      },
      "signature": "void DeleteObjectMemory(void * objectPtr)",
      "comment": "Memory cleanup handler"
    }
  }
}
```

### Phase 2: Create Merge Tool

**File:** `tools/merge_function_index.py`

**Purpose:** Combine per-version exports into unified registry

**Algorithm:**
```python
for each version in sorted_versions:
    for each function in version.functions:
        canonical_id = function.index

        if canonical_id in registry:
            # Function already known - add this version's address
            registry[canonical_id].addresses[version] = function.address

            # Name conflict resolution: earliest version wins
            if not registry[canonical_id].name and function.name:
                registry[canonical_id].name = function.name
        else:
            # New function
            registry[canonical_id] = FunctionEntry(
                index=canonical_id,
                name=function.name or f"{function.index_method}_{function.indexes[function.index_method][:8]}",
                addresses={version: function.address},
                ...
            )
```

### Phase 3: Update Viewer

**Changes:**
1. Load from new registry format
2. Display index-based IDs for unnamed functions
3. Show index method indicator (EXP/STR/API/MNE/CFG/PRO)

---

## Detailed Ghidra Script Requirements

### Version Detection

```java
// Extract version from program path
// Path: /F:/D2VersionChanger/VersionChanger/LoD/1.07/Binkw32.dll
// Result: "LoD/1.07"

String executablePath = currentProgram.getExecutablePath();
String version = extractVersion(executablePath);

private String extractVersion(String path) {
    // Match Classic/X.XX or LoD/X.XX pattern
    Pattern p = Pattern.compile("(Classic|LoD)/([0-9]+\\.[0-9]+[a-z]?)");
    Matcher m = p.matcher(path);
    if (m.find()) {
        return m.group(1) + "/" + m.group(2);
    }
    return "unknown";
}
```

### Index Computation Methods

```java
// 1. Export Index (highest priority)
String computeExportIndex(Function func) {
    Symbol[] symbols = func.getSymbol().getReferences();
    // Check if function has export ordinal
    ExternalReference ref = getExportReference(func);
    if (ref != null && ref.getOrdinal() >= 0) {
        return "EXP:" + ref.getOrdinal();
    }
    return null;
}

// 2. String Reference Index
String computeStringIndex(Function func) {
    Set<String> strings = getReferencedStrings(func);
    Set<String> uniqueStrings = filterUniqueStrings(strings);
    if (!uniqueStrings.isEmpty()) {
        String combined = String.join("|", sortedStrings);
        return "STR:" + md5(combined).substring(0, 16);
    }
    return null;
}

// 3. API Call Sequence Index
String computeAPIIndex(Function func) {
    List<String> apiCalls = getImportedAPICalls(func);
    if (apiCalls.size() >= 2) {
        String sequence = String.join(",", apiCalls);
        return "API:" + md5(sequence).substring(0, 16);
    }
    return null;
}

// 4. Mnemonic Sequence Index (always available)
String computeMnemonicIndex(Function func) {
    List<String> mnemonics = getMnemonicSequence(func);
    int size = (int) func.getBody().getNumAddresses();
    String data = String.join(",", mnemonics) + "|" + size;
    return "MNE:" + md5(data).substring(0, 16);
}

// 5. CFG Structure Index
String computeCFGIndex(Function func) {
    BasicBlockModel bbModel = new BasicBlockModel(currentProgram);
    CodeBlockIterator blocks = bbModel.getCodeBlocksContaining(func.getBody(), monitor);
    int blockCount = 0;
    int edgeCount = 0;
    StringBuilder structure = new StringBuilder();
    // ... build CFG hash
    if (blockCount >= 2) {
        return "CFG:" + md5(structure.toString()).substring(0, 16);
    }
    return null;
}

// 6. Prologue Index (fallback)
String computePrologueIndex(Function func) {
    byte[] prologue = getBytes(func.getEntryPoint(), 16);
    int size = (int) func.getBody().getNumAddresses();
    String data = bytesToHex(prologue) + "|" + size;
    return "PRO:" + md5(data).substring(0, 16);
}
```

### Best Index Selection

```java
String selectBestIndex(Function func) {
    String[] methods = {"EXP", "STR", "API", "MNE", "CFG", "PRO"};
    Map<String, String> indexes = new HashMap<>();

    indexes.put("EXP", computeExportIndex(func));
    indexes.put("STR", computeStringIndex(func));
    indexes.put("API", computeAPIIndex(func));
    indexes.put("MNE", computeMnemonicIndex(func));
    indexes.put("CFG", computeCFGIndex(func));
    indexes.put("PRO", computePrologueIndex(func));

    // Return first non-null in priority order
    for (String method : methods) {
        if (indexes.get(method) != null) {
            return indexes.get(method);
        }
    }
    return "PRO:" + computePrologueIndex(func); // Always works
}
```

---

## File Structure After Implementation

```
data/function_index/
├── Classic/
│   ├── 1.00/
│   │   ├── D2Client.dll.json
│   │   ├── D2Common.dll.json
│   │   └── ...
│   ├── 1.01/
│   ├── 1.02/
│   └── ...
└── LoD/
    ├── 1.07/
    ├── 1.08/
    └── ...

reports/
├── function_registry_v2.json    # Merged canonical registry
└── d2_report_viewer.html        # Updated viewer
```

---

## Migration Path

### Step 1: Create New Export Script
- Keep `ExportNamesOnly.java` for backward compatibility
- Create `ExportFunctionIndex.java` with full index computation

### Step 2: Export All Versions
- Run new script on each binary in Ghidra project
- Outputs go to `data/function_index/{version}/{dll}.json`

### Step 3: Build Merge Tool
- Python script to combine all per-version exports
- Outputs unified `function_registry_v2.json`

### Step 4: Update Viewer
- Add support for new registry format
- Display index-based names for unnamed functions

### Step 5: Deprecate Python Matching
- Remove `tools/optimized_matching/` once new system validated
- Keep as reference/archive

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Mnemonic collisions | Medium | Functions mis-matched | Use multiple indexes as fallback |
| String changes between versions | Low | STR index breaks | Fall back to MNE/CFG |
| API call order changes | Medium | API index breaks | Include call count, not just sequence |
| Large export time | Medium | Slow iteration | Cache intermediate results |

---

## Questions for User

1. **Export scope:** Should the new script export ALL functions or only named ones?
   - Recommendation: ALL functions (we can filter in viewer)

2. **Name conflict resolution:** Earliest version wins, or most recent?
   - Recommendation: Earliest (original names are typically more accurate)

3. **Minimum index reliability:** Should we skip indexes below a certain reliability?
   - Recommendation: Always compute all, but mark confidence level

4. **Viewer display:** How should unnamed functions appear?
   - Recommendation: `MNE_d1a2b3c4` format (method prefix + hash truncated)

---

## Conclusion

The proposed method-prefixed canonical index system will:

1. **Eliminate arbitrary IDs:** Functions identified by intrinsic properties
2. **Enable reliable cross-version matching:** Same function → same ID
3. **Support multi-version name inheritance:** Best names propagate automatically
4. **Provide fallback matching:** Multiple indexes stored per function
5. **Leverage Ghidra's superior analysis:** Stop duplicating work in Python

The implementation can proceed incrementally without breaking existing functionality.

---

## Appendix: Current vs Proposed Comparison

### Current Matching Output
```json
{
  "func_00001": {
    "addresses": {"Classic/1.00": "0x10001014", "Classic/1.01": "0x10001014"},
    "confidence": 0.99,
    "match_tier": 1,
    "ghidra_name": "QueryInterface"
  }
}
```

### Proposed Index Output
```json
{
  "EXP:10000": {
    "name": "QueryInterface",
    "index": "EXP:10000",
    "index_method": "EXP",
    "indexes": {
      "EXP": "10000",
      "MNE": "d1a2b3c4e5f6...",
      "PRO": "f9a0b1c2d3e4..."
    },
    "addresses": {"Classic/1.00": "0x10001014", "Classic/1.01": "0x10001014"},
    "source_version": "Classic/1.00"
  }
}
```

The key difference: **the ID itself tells you how the function was identified**.
