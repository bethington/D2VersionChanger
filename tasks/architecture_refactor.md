# Function Registry Architecture Refactor

## Problem with Current System

The current merge system tries to create "canonical IDs" that unify functions across all versions. This causes:
- Collision issues when different functions get the same "index"
- Loss of data when functions overwrite each other
- Complexity in tracking what came from where

## Proposed Architecture

### 1. Primary Data Structure

Each binary has its own function library, organized by version and address:

```
data/functions/
  D2Common.dll/
    1.07.json      # All functions for D2Common.dll 1.07
    1.08.json
    1.09.json
    ...
```

Each version file contains functions indexed by address:

```json
{
  "binary": "D2Common.dll",
  "game_type": "LoD",
  "version": "1.07",
  "functions": {
    "0x6FDC1B20": {
      "name": "InitializeUnitSkills",
      "hashes": {
        "API": "6d17131afa7443348dd3e77a30b8ee2c",
        "MNE": "60d9f9deb8e4895ec30c8c263ed129b1",
        "CFG": "abc123...",
        "STR": null,
        "EXP": null
      },
      "prev_match": {
        "version": "1.06b",
        "address": "0x6FDC1A10",
        "confidence": 0.95,
        "method": "API"
      },
      "next_match": {
        "version": "1.08",
        "address": "0x6FDC1C30",
        "confidence": 0.95,
        "method": "API"
      }
    },
    "0x6FDD2E50": {
      "name": "UNITS_GetField08",
      ...
    }
  }
}
```

### 2. Hash Types (renamed from "indexes")

| Hash | Description | Reliability |
|------|-------------|-------------|
| API | Hash of called functions | High |
| MNE | Hash of instruction mnemonics | High |
| CFG | Control flow graph hash | High |
| STR | Hash of string references | Medium |
| PRO | Function prototype hash | Medium |
| EXP | Export ordinal | Low (version-specific) |

### 3. Two-Tier Matching System

**Tier 1: Hash Matching (Fast)**
- Compare hashes between adjacent versions
- If any hash matches with high confidence, link the functions
- Priority: API > MNE > CFG > STR > PRO

**Tier 2: Fuzzy Matching (When Tier 1 Fails)**
- Instruction sequence similarity
- Caller/callee graph comparison
- Name similarity (if named)
- Position-based heuristics

### 4. Version Chain

Versions are ordered chronologically:
```
Classic: 1.00 → 1.01 → 1.02 → 1.03 → 1.04b → 1.04c → 1.05 → 1.05b → 1.06 → 1.06b
LoD:     1.07 → 1.08 → 1.09 → 1.09b → 1.09d → 1.10 → 1.11 → 1.11b → 1.12a → 1.13c → 1.13d → 1.14a → 1.14b → 1.14c → 1.14d
```

Matching happens between adjacent versions only, creating a chain:
- From 1.07's InitializeUnitSkills → find match in 1.08
- From 1.08's match → find match in 1.09
- etc.

### 5. Viewer Integration

The viewer can traverse the chain in either direction:
- User selects D2Common.dll, version 1.10, function InitializeUnitSkills
- Viewer shows prev_match chain: 1.09d ← 1.09b ← 1.09 ← 1.08 ← 1.07
- Viewer shows next_match chain: 1.11 → 1.11b → 1.12a → 1.13c → 1.13d

## Implementation Plan

### Phase 1: Data Structure
- [ ] Create new storage format (per-binary, per-version JSON)
- [ ] Export tool writes to new format
- [ ] Keep "hashes" terminology instead of "indexes"

### Phase 2: Tier 1 Matching
- [ ] Build hash-based matcher for adjacent versions
- [ ] Create version chain configuration
- [ ] Populate prev_match/next_match links

### Phase 3: Tier 2 Matching
- [ ] Implement fuzzy matching for unmatched functions
- [ ] Add confidence scores to all matches

### Phase 4: Viewer Update
- [ ] Update viewer to use new data format
- [ ] Add version navigation (prev/next)
- [ ] Show match confidence

## Benefits

1. **No data loss** - Every function in every version is preserved
2. **Clear provenance** - Address is the stable identifier
3. **Bidirectional navigation** - Follow chains in either direction
4. **Graceful degradation** - Unmatched functions just have no links
5. **Incremental updates** - Adding a new version only requires matching to adjacent versions
