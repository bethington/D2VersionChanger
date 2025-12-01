# Function Identification Methods

This document catalogs approaches for identifying and matching the same function across multiple versions of a binary. This is particularly relevant for the D2VersionChanger project, which tracks function morphology across 31+ versions of Diablo 2 (from Classic 1.00 to LoD 1.14d).

## Table of Contents

1. [Overview](#overview)
2. [Method Catalog](#method-catalog)
3. [Current Implementation](#current-implementation)
4. [Reliability Analysis](#reliability-analysis)
5. [Recommendations](#recommendations)

---

## Overview

### The Challenge

When Blizzard releases a new patch for Diablo 2, functions may:
- Stay identical (same bytes)
- Be relocated (different address, same code)
- Be recompiled (same logic, different register allocation)
- Be modified (bug fixes, new features)
- Be removed or added

Our goal is to track function identity across these changes, enabling:
- Applying reverse-engineered names to all versions
- Understanding what changed between patches
- Building version-independent modding tools

### Matching Tiers

We use a tiered approach, trying the most reliable methods first:

```
Tier 1 (Most Reliable) → Tier N (Least Reliable)
     ↓ If no match, try next tier
```

---

## Method Catalog

### 1. Export/Symbol Name Matching

**How it works:** Match functions by their DLL export name or debug symbol.

**Example:**
```
D2Client.dll exports:
  Ordinal 10000 → "GetDifficulty"
  Ordinal 10001 → "GetPlayerUnit"
```

If both v1.09 and v1.10 export `GetDifficulty` at ordinal 10000, they're the same function.

**Strengths:**
- 100% reliable when available
- Survives complete rewrites

**Weaknesses:**
- Only works for exported functions (~5% of codebase)
- Internal functions have no exports

**D2 Project Usage:** Tier 1 - Our most trusted match source.

---

### 2. Exact Byte Matching

**How it works:** SHA256 hash of complete function bytes.

**Example:**
```python
def hash_function(func_bytes):
    return hashlib.sha256(func_bytes).hexdigest()

# v1.09 D2Client.dll @ 0x6FAB1000
hash_v109 = "a3f2e8c1..."  # 156 bytes

# v1.10 D2Client.dll @ 0x6FAB2400
hash_v110 = "a3f2e8c1..."  # Same hash = same function
```

**Strengths:**
- Fast and simple
- No false positives

**Weaknesses:**
- Breaks on ANY change (even NOP padding)
- Breaks on relocation if absolute addresses embedded

**D2 Project Usage:** Tier 2 - Catches ~45% of functions that survived unchanged.

---

### 3. Prologue + Size Matching

**How it works:** Match first N bytes of function combined with total size.

**Example:**
```
Function prologue patterns:
  55 8B EC        = push ebp; mov ebp, esp (standard)
  55 8B EC 83 EC  = push ebp; mov ebp, esp; sub esp, N

Signature: (prologue_16_bytes, function_size)

v1.09: ("558BEC83EC1053565733FF", 428)
v1.10: ("558BEC83EC1053565733FF", 428)  # Match!
```

**Strengths:**
- Survives relocation
- Survives internal code movement

**Weaknesses:**
- Common prologues cause collisions
- Size changes break matches

**D2 Project Usage:** Tier 3 - Catches another ~45% of functions.

---

### 4. Call Graph Signature

**How it works:** Hash the pattern of functions called by this function.

**Example:**
```
ProcessPlayer() calls:
  1. GetPlayerUnit()    → hash: 0x1A2B
  2. ValidateState()    → hash: 0x3C4D
  3. UpdatePosition()   → hash: 0x5E6F

Call signature = hash([0x1A2B, 0x3C4D, 0x5E6F]) = "7f8a9b..."
```

**Strengths:**
- Survives complete recompilation
- Captures function "role" in codebase

**Weaknesses:**
- Requires callees to be matched first
- Breaks if call order changes

**D2 Project Usage:** Tier 4 - Catches ~4% of remaining functions.

---

### 5. Instruction Mnemonic Sequence

**How it works:** Extract opcode sequence, ignoring operands.

**Example:**
```asm
; v1.09                      ; v1.10 (different registers)
push ebp                     push ebp
mov ebp, esp                 mov ebp, esp
sub esp, 0x10                sub esp, 0x14      ; Different size
push ebx                     push esi           ; Different register
mov ebx, [ebp+8]             mov esi, [ebp+8]   ; Different register

Mnemonic sequence (both versions):
PUSH, MOV, SUB, PUSH, MOV → hash = "abc123..."
```

**Strengths:**
- Survives register reallocation
- Survives minor constant changes

**Weaknesses:**
- Loses information about what registers/values used
- Common sequences cause false positives

**D2 Project Usage:** Not yet implemented - promising for Tier 5.

---

### 6. Normalized Byte Patterns

**How it works:** Replace variable parts (addresses, offsets) with wildcards.

**Example:**
```
Original bytes:
  E8 4D 02 00 00    CALL +0x24D (relative)
  A1 78 56 B4 6F    MOV EAX, [0x6FB45678]

Normalized:
  E8 ?? ?? ?? ??    CALL <relative>
  A1 ?? ?? ?? ??    MOV EAX, [<absolute>]

Pattern: "E8????????A1????????"
```

**Strengths:**
- Survives relocation
- More specific than mnemonic-only

**Weaknesses:**
- Requires knowing which bytes are addresses
- Complex to implement correctly

**D2 Project Usage:** Not yet implemented - good candidate for improved Tier 2.

---

### 7. Control Flow Graph (CFG) Hashing

**How it works:** Hash the structure of basic blocks and edges.

**Example:**
```
Function CFG:
  Block A (entry) → Block B, Block C
  Block B → Block D
  Block C → Block D
  Block D (exit)

Structure hash = hash("A→B,A→C,B→D,C→D") = "def456..."

Features:
  - 4 basic blocks
  - 4 edges
  - 1 branch point
  - 1 merge point
```

**Strengths:**
- Survives instruction-level changes
- Captures algorithm structure

**Weaknesses:**
- Compiler optimizations can restructure CFG
- Small functions have trivial CFGs (collisions)

**D2 Project Usage:** Not yet implemented - used by BinDiff/Diaphora.

---

### 8. String and Constant References

**How it works:** Match functions by unique strings or magic numbers they reference.

**Example:**
```c
void ShowError() {
    MessageBox(NULL, "Error: Invalid player state %d", "D2 Error", MB_OK);
}
```

Signature: References string `"Error: Invalid player state %d"`

**Strengths:**
- Very reliable for functions with unique strings
- Survives complete rewrites

**Weaknesses:**
- Only ~20% of functions have unique strings
- Strings can be changed between versions

**D2 Project Usage:** Not yet implemented - high value for specific functions.

---

### 9. API Call Sequence

**How it works:** Track sequence of imported Windows/library API calls.

**Example:**
```c
void SaveFile() {
    CreateFileA(...);      // 1
    WriteFile(...);        // 2
    CloseHandle(...);      // 3
}

API signature: [CreateFileA, WriteFile, CloseHandle]
```

**Strengths:**
- API names are stable across versions
- Captures high-level behavior

**Weaknesses:**
- Many functions don't call APIs directly
- Common patterns (malloc/free) cause collisions

**D2 Project Usage:** Not yet implemented - useful for I/O and system functions.

---

### 10. Basic Block Hash (PIC Hash)

**How it works:** Hash each basic block independently, match functions by block overlap.

**Example:**
```
Function has 5 basic blocks:
  Block 1: hash "aaa"
  Block 2: hash "bbb"
  Block 3: hash "ccc"
  Block 4: hash "ddd"
  Block 5: hash "eee"

v1.09 blocks: {aaa, bbb, ccc, ddd, eee}
v1.10 blocks: {aaa, bbb, fff, ddd, eee}  # Block 3 changed

Overlap: 4/5 = 80% → Likely same function
```

**Strengths:**
- Tolerates partial changes
- Position-independent

**Weaknesses:**
- Requires threshold tuning
- Small blocks cause false matches

**D2 Project Usage:** Not yet implemented - good for fuzzy matching.

---

### 11. Feature Vector / Machine Learning

**How it works:** Extract numeric features, use ML for similarity.

**Example features:**
```python
features = {
    'num_basic_blocks': 12,
    'num_calls': 5,
    'num_loops': 2,
    'stack_frame_size': 0x40,
    'num_string_refs': 1,
    'num_arguments': 3,
    'cyclomatic_complexity': 8,
    'instruction_count': 156
}

# Cosine similarity or neural network embedding
similarity = cosine_sim(features_v109, features_v110)
```

**Strengths:**
- Can learn complex patterns
- Tolerates significant changes

**Weaknesses:**
- Requires training data
- Black box (hard to debug false matches)

**D2 Project Usage:** Not yet implemented - research frontier.

---

### 12. Semantic Hashing

**How it works:** Symbolic execution to extract input→output behavior.

**Example:**
```c
// These are semantically identical:
int add_v1(int a, int b) { return a + b; }
int add_v2(int x, int y) { int t = x; t += y; return t; }

Semantic signature: "returns (arg0 + arg1)"
```

**Strengths:**
- Matches functionally identical code
- Compiler-agnostic

**Weaknesses:**
- Computationally expensive
- Loops/recursion are problematic

**D2 Project Usage:** Not practical for large-scale matching.

---

## Current Implementation

### Tier Results for D2Client.dll

| Tier | Method | Matches | Percentage |
|------|--------|---------|------------|
| 1 | Export names | 4 | 0.04% |
| 2 | Exact bytes | 5,670 | 54.1% |
| 3 | Prologue + size | 4,721 | 45.0% |
| 4 | Call graph | 94 | 0.9% |
| **Total** | | **10,489** | **100%** |

### Coverage by Version

| Version Group | Coverage | Notes |
|--------------|----------|-------|
| Classic 1.00-1.03 | 48-52% | Old codebase, many unique functions |
| Classic 1.04-1.06 | 85-92% | Transition period |
| Classic 1.07+ | 94-96% | Stable modern codebase |
| LoD 1.07 | 60% | Hybrid old/new code |
| LoD 1.08+ | 95-96% | Stable modern codebase |

---

## Reliability Analysis

### Ranking by Reliability (Highest to Lowest)

| Rank | Method | False Positive Risk | False Negative Risk | Best For |
|------|--------|--------------------|--------------------|----------|
| 1 | Export/Symbol | None | High (limited coverage) | Exported functions |
| 2 | Exact Bytes | None | High (any change breaks) | Unchanged functions |
| 3 | String References | Very Low | High (few have strings) | Error handlers, UI |
| 4 | API Sequence | Low | Medium | System/I/O functions |
| 5 | Normalized Bytes | Low | Medium | Relocated functions |
| 6 | CFG Hash | Low | Medium | Recompiled functions |
| 7 | Prologue + Size | Medium | Low | General matching |
| 8 | Call Graph | Medium | Medium | Architectural functions |
| 9 | Mnemonic Sequence | Medium | Low | Register-reallocated |
| 10 | Basic Block Hash | Medium | Low | Partially modified |
| 11 | Feature Vector/ML | Variable | Variable | Fuzzy matching |
| 12 | Semantic | Low | High (expensive) | Research only |

### Key Insight: Tier Priority

For cross-version binary matching, prioritize methods that:
1. **Never produce false positives** (exact matches first)
2. **Tolerate relocation** (addresses change between versions)
3. **Tolerate recompilation** (register allocation, instruction scheduling)

---

## Recommendations

### High-Priority Additions for D2 Project

#### 1. String Reference Matching (Recommended: Tier 1.5)

**Why:** D2 has many error messages, debug strings, and UI text that uniquely identify functions.

**Implementation:**
```python
def get_string_signature(func_address):
    strings = get_referenced_strings(func_address)
    unique_strings = [s for s in strings if is_unique_in_binary(s)]
    return hash(tuple(sorted(unique_strings)))
```

**Expected yield:** 5-10% additional matches with very high confidence.

#### 2. Normalized Byte Patterns (Recommended: Improved Tier 2)

**Why:** Many functions are identical except for relocated addresses.

**Implementation:**
```python
def normalize_function(func_bytes):
    # Replace CALL rel32 targets with wildcards
    # Replace absolute address references with wildcards
    # Keep instruction opcodes and register encodings
    return normalized_pattern
```

**Expected yield:** 10-20% recovery of Tier 2 misses.

#### 3. Mnemonic Sequence Matching (Recommended: Tier 5)

**Why:** Catches functions with different register allocation but same logic.

**Implementation:**
```python
def get_mnemonic_hash(func_address):
    instructions = disassemble(func_address)
    mnemonics = [i.mnemonic for i in instructions]
    return hash(tuple(mnemonics))
```

**Expected yield:** 5-15% of remaining unmatched functions.

### Medium-Priority Additions

#### 4. CFG Structure Matching (Tier 6)

Useful for functions that were recompiled with different instruction sequences but same control flow.

#### 5. API Call Sequence (Tier 7)

Useful for Windows API wrapper functions and I/O routines.

### Lower Priority

- **Basic Block Hash:** Complex to implement, overlaps with other methods
- **Feature Vector/ML:** Requires training data, diminishing returns
- **Semantic Hashing:** Too expensive for 500K+ functions

---

## Appendix: D2-Specific Observations

### Version Boundaries

Major code changes occurred at:
- **1.03 → 1.04:** Complete recompilation, image base change, ~1200 functions removed/rewritten
- **1.06 → 1.07:** Lord of Destruction added, major expansion
- **1.07 → 1.08:** LoD stabilization, old code paths removed

### Function Characteristics

| Category | Count | Best Matching Method |
|----------|-------|---------------------|
| Tiny (<16 bytes) | ~8% | Exact bytes only (too small for other methods) |
| Small (16-64 bytes) | ~25% | Prologue + exact bytes |
| Medium (64-256 bytes) | ~45% | All methods effective |
| Large (>256 bytes) | ~22% | CFG, string refs, call graph |

### Recommended Tier Order for D2

```
Tier 1:   Export name matching (100% reliable)
Tier 1.5: Unique string reference (very high reliability)
Tier 2:   Exact byte hash (100% reliable, limited coverage)
Tier 2.5: Normalized byte pattern (high reliability)
Tier 3:   Prologue + size (medium reliability, high coverage)
Tier 4:   Call graph signature (medium reliability)
Tier 5:   Mnemonic sequence (medium reliability)
Tier 6:   CFG structure (fallback)
```

---

## References

- BinDiff: https://www.zynamics.com/bindiff.html
- Diaphora: https://github.com/joxeankoret/diaphora
- Kam1n0: https://github.com/McGill-DMaS/Kam1n0-Community
- SAFE (neural embeddings): https://arxiv.org/abs/1811.05296
