# Function Matching Architecture

## Overview

The sequential matcher compares functions between adjacent versions (e.g., 1.10 → 1.11)
and propagates identities through the version chain.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MATCHING PIPELINE                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Version 1.10                    Version 1.11                               │
│  ┌─────────────┐                ┌─────────────┐                             │
│  │ Function A  │ ──────────────▶│ Function A' │  (Matched)                  │
│  │ Function B  │ ──────────────▶│ Function B' │  (Matched)                  │
│  │ Function C  │ ───────?──────▶│ Function X  │  (False match?)             │
│  └─────────────┘                │ Function C' │  (Unmatched - becomes "new")│
│                                 └─────────────┘                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Step 1: Candidate Selection (find_best_matches)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CANDIDATE FILTERING                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Source Function                                                            │
│  ┌──────────────────────┐                                                   │
│  │ indexes:             │                                                   │
│  │   MNE: "abc123..."   │────▶ Find targets where MNE = "abc123..."        │
│  │   STR: "def456..."   │────▶ Find targets where STR = "def456..."        │
│  │   CAL: "ghi789..."   │────▶ Find targets where CAL = "ghi789..."        │
│  │   CFG: "jkl012..."   │────▶ Find targets where CFG = "jkl012..."        │
│  │   API: "mno345..."   │────▶ Find targets where API = "mno345..."        │
│  └──────────────────────┘                                                   │
│              │                                                              │
│              ▼                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ Candidate Pool = UNION of all index matches                          │  │
│  │                                                                      │  │
│  │ If NO index matches found:                                           │  │
│  │   → Fall back to SIZE FILTER: any target within 80% size ratio       │  │
│  │   → This can include MANY unrelated functions!                       │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Problem with Candidate Selection

When a function has **no matching indexes** in the target version (common after
major code changes), the fallback is pure size-based filtering:

```
Source: FUN_6FB12340 (size: 150 bytes)

Falls back to size filter → Candidates include ANY function with size 120-187 bytes
                           (potentially dozens of unrelated functions)
```

---

## Step 2: Vector Score Calculation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    VECTOR SCORING                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  For each (source, candidate) pair:                                         │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ TIER 1: Hash Matches (Binary 0/1)                    Weight  Max Score ││
│  ├────────────────────────────────────────────────────────────────────────┤│
│  │ mnemonic_hash   = 1.0 if MNE matches, else 0.0       2.0     2.0       ││
│  │ export_ordinal  = 1.0 if EXP matches, else 0.0       0.4     0.4       ││
│  │ export_name     = 1.0 if name matches, else 0.0      0.4     0.4       ││
│  │ str_index       = 1.0/0.5/0.2 based on collisions    1.0     1.0       ││
│  │ cal_index       = 1.0/0.5/0.2 based on collisions    1.0     1.0       ││
│  │ cfg_index       = 1.0/0.5/0.2 based on collisions    0.6     0.6       ││
│  │ api_index       = 1.0 if API matches, else 0.0       1.0     1.0       ││
│  │ con_index       = 1.0 if CON matches, else 0.0       0.5     0.5       ││
│  │ pro_index       = 1.0 if PRO matches (unique)        0.3     0.3       ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ TIER 2: Set Overlaps (Jaccard: 0.0-1.0)              Weight  Max Score ││
│  ├────────────────────────────────────────────────────────────────────────┤│
│  │ callee_overlap   = |A∩B| / |A∪B|                     0.7     0.7       ││
│  │ string_overlap   = |A∩B| / |A∪B|                     0.8     0.8       ││
│  │ constant_overlap = |A∩B| / |A∪B|                     0.4     0.4       ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ TIER 3: Numeric Similarities (Ratio: 0.0-1.0)        Weight  Max Score ││
│  ├────────────────────────────────────────────────────────────────────────┤│
│  │ size_sim         = min(a,b)/max(a,b)                 0.6     0.6       ││
│  │ callee_count_sim = min(a,b)/max(a,b)                 0.6     0.6       ││
│  │ string_count_sim = min(a,b)/max(a,b)                 0.8     0.8       ││
│  │ basic_block_sim  = min(a,b)/max(a,b)                 0.6     0.6       ││
│  │ loop_count_sim   = min(a,b)/max(a,b)                 0.4     0.4       ││
│  │ stack_frame_sim  = min(a,b)/max(a,b)                 0.6     0.6       ││
│  │ param_count_sim  = min(a,b)/max(a,b)                 1.0     1.0       ││
│  │ caller_count_sim = min(a,b)/max(a,b)                 0.6     0.6       ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│  TOTAL MAX SCORE: 13.7                                                      │
│  MIN_MATCH_SCORE: 0.45 (only 3.3% of max needed!)                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## The False Match Problem

### Scenario: No Tier 1 Match

When mnemonic_hash doesn't match (function was recompiled with changes):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Source Function                    Target Function (WRONG MATCH)            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ callers: 0                         callers: 15                              │
│ callees: 3                         callees: 5                               │
│ strings: ["error", "log"]          strings: ["error", "debug"]              │
│ size: 150                          size: 145                                │
│ param_count: 2                     param_count: 2                           │
│                                                                             │
│ Tier 1 Scores (all 0):                                                      │
│   mnemonic_hash:  0.0 × 2.0 = 0.0                                          │
│   str_index:      0.0 × 1.0 = 0.0                                          │
│   cal_index:      0.0 × 1.0 = 0.0                                          │
│   ...                                                                       │
│                                                                             │
│ Tier 2 Scores:                                                              │
│   string_overlap: 0.33 × 0.8 = 0.26  (1 shared: "error")                   │
│   callee_overlap: 0.20 × 0.7 = 0.14  (some shared callees)                 │
│                                                                             │
│ Tier 3 Scores:                                                              │
│   size_sim:         0.97 × 0.6 = 0.58  (145/150 = 0.97)                    │
│   caller_count_sim: 0.00 × 0.6 = 0.00  (0/15 = 0!) ← BIG DIFFERENCE        │
│   callee_count_sim: 0.60 × 0.6 = 0.36  (3/5 = 0.6)                         │
│   param_count_sim:  1.00 × 1.0 = 1.00  (2/2 = 1.0)                         │
│   string_count_sim: 1.00 × 0.8 = 0.80  (2/2 = 1.0)                         │
│   basic_block_sim:  0.80 × 0.6 = 0.48  (similar)                           │
│   stack_frame_sim:  0.90 × 0.6 = 0.54  (similar)                           │
│   loop_count_sim:   1.00 × 0.4 = 0.40  (same)                              │
│                                                                             │
│ TOTAL SCORE: 4.56                                                           │
│ MIN_MATCH_SCORE: 0.45                                                       │
│                                                                             │
│ RESULT: MATCHED! (even though callers differ 0 vs 15)                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Why Tier 1 Works Perfectly

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TIER 1 SUCCESS                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Mnemonic Hash = SHA256(opcode_sequence + size)                             │
│                                                                             │
│  This is a FINGERPRINT of the actual compiled code:                         │
│                                                                             │
│    PUSH EBP                                                                 │
│    MOV EBP, ESP                                                             │
│    SUB ESP, 0x10        ─────▶  SHA256 ─────▶ "abc123def456..."             │
│    MOV EAX, [EBP+8]                                                         │
│    ...                                                                      │
│                                                                             │
│  If mnemonic_hash matches:                                                  │
│    → The compiled code is IDENTICAL (or extremely similar)                  │
│    → This is the SAME FUNCTION, just at a different address                 │
│    → Confidence: ~100%                                                      │
│                                                                             │
│  Weight: 2.0 (highest) + typically other indexes also match                 │
│  Result: Score >> MIN_MATCH_SCORE, definitely correct                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Why Tier 2 Can Fail

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TIER 2 FAILURE MODES                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Problem 1: ACCUMULATION OF WEAK SIGNALS                                    │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                             │
│  When no strong signal (Tier 1) exists, many weak signals can               │
│  accumulate to exceed MIN_MATCH_SCORE:                                      │
│                                                                             │
│    size_sim:         0.9 × 0.6 = 0.54                                      │
│    param_count_sim:  1.0 × 1.0 = 1.00                                      │
│    string_count_sim: 0.8 × 0.8 = 0.64                                      │
│    basic_block_sim:  0.7 × 0.6 = 0.42                                      │
│    ─────────────────────────────────                                       │
│    TOTAL: 2.60 > 0.45 ← MATCHES!                                           │
│                                                                             │
│  These functions could be completely unrelated but happen to have           │
│  similar structural metrics.                                                │
│                                                                             │
│  Problem 2: CALLER MISMATCH NOT A DEAL-BREAKER                              │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                             │
│  caller_count_sim has weight 0.6                                            │
│                                                                             │
│  If callers are 0 vs 10:                                                    │
│    caller_count_sim = 0/10 = 0.0                                           │
│    Contribution: 0.0 × 0.6 = 0.0                                           │
│                                                                             │
│  This only LOSES 0.6 points, not enough to prevent a match                  │
│  if other metrics align.                                                    │
│                                                                             │
│  Problem 3: NO HARD CONSTRAINTS                                             │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                             │
│  The algorithm never says "if X differs by more than Y, reject"             │
│                                                                             │
│  Example hard constraints that could help:                                  │
│    - If caller_count differs by >5× AND source has >0 callers → reject     │
│    - If size differs by >50% → reject                                       │
│    - If param_count differs → reject (very strong signal)                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Recommended Fixes

### Option 1: Add Hard Constraints

```python
def compute_match_score(...):
    # HARD CONSTRAINTS - reject immediately if violated

    # Caller count sanity check
    if source_caller_count > 0 and target_caller_count > 0:
        caller_ratio = min(source_caller_count, target_caller_count) / max(...)
        if caller_ratio < 0.2:  # 5× difference
            return MatchCandidate(score=0, ...)  # Reject

    # If source has callers but target has none (or vice versa)
    if (source_caller_count > 3 and target_caller_count == 0) or \
       (target_caller_count > 3 and source_caller_count == 0):
        return MatchCandidate(score=0, ...)  # Reject

    # Param count must match (very reliable)
    if source_params != target_params and source_params > 0 and target_params > 0:
        return MatchCandidate(score=0, ...)  # Reject
```

### Option 2: Require Minimum Tier 1 Signal

```python
def compute_match_score(...):
    # ... compute all features ...

    # Check if ANY Tier 1 signal matched
    tier1_matched = any([
        features.get("mnemonic_hash", 0) > 0,
        features.get("str_index", 0) > 0,
        features.get("cal_index", 0) > 0,
        features.get("api_index", 0) > 0,
    ])

    if not tier1_matched:
        # No Tier 1 match - require much higher score
        effective_min_score = MIN_MATCH_SCORE * 3  # 1.35 instead of 0.45
        if score < effective_min_score:
            return MatchCandidate(score=0, ...)
```

### Option 3: Increase MIN_MATCH_SCORE

Current: `MIN_MATCH_SCORE = 0.45` (only 3.3% of max 13.7)

Suggested: `MIN_MATCH_SCORE = 2.0` (14.6% of max) - requires at least one
strong signal or multiple medium signals.

---

## Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  TIER 1 (Hash Matches):  Excellent - identifies identical code              │
│                                                                             │
│  TIER 2 (Without Tier 1): Problematic - weak signals accumulate             │
│                                                                             │
│  ROOT CAUSE: No hard constraints + very low MIN_MATCH_SCORE                 │
│                                                                             │
│  THE FIX:                                                                   │
│    1. Add hard constraints for obviously wrong matches                      │
│    2. Require at least one Tier 1 signal, OR                                │
│    3. Require much higher score when no Tier 1 signal present               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```
