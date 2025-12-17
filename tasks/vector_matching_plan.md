# Vector-Based Function Matching Plan

## Goal
Replace the current weighted boolean scoring with a vector similarity approach that computes continuous similarity scores between functions.

---

## Phase 1: Define the Feature Vector

### Numeric Features (directly usable)
These features are already numbers and can be normalized:

| Feature | Source Field | Notes |
|---------|--------------|-------|
| Size | `size` | Byte size of function |
| Callee Count | `len(callees)` | Number of functions called |
| Caller Count | `len(callers)` | Number of functions that call this |
| String Count | `len(strings)` | String references |
| Constant Count | `len(constants)` | Numeric constants |
| Global Count | `len(globals)` | Global variable references |
| Basic Block Count | `basic_block_count` | CFG complexity |
| Loop Count | `loop_count` | Number of loops |
| Stack Frame Size | `stack_frame_size` | Local variable space |
| Parameter Count | `param_count` | Number of parameters |

### Hash-Based Features (binary match)
These are hashes that either match or don't - convert to 0/1:

| Feature | Source Field | Value |
|---------|--------------|-------|
| Mnemonic Hash Match | `indexes.MNE` | 1 if equal, 0 if not |
| Export Ordinal Match | `indexes.EXP` | 1 if equal, 0 if not |
| String Index Match | `indexes.STR` | 1 if equal, 0 if not |
| Callee Index Match | `indexes.CAL` | 1 if equal, 0 if not |
| CFG Index Match | `indexes.CFG` | 1 if equal, 0 if not |
| API Index Match | `indexes.API` | 1 if equal, 0 if not |

### Set-Based Features (overlap ratios)
These compare sets and produce a ratio 0.0-1.0:

| Feature | Calculation |
|---------|-------------|
| Callee Overlap | `len(A & B) / len(A | B)` (Jaccard) |
| String Overlap | `len(A & B) / len(A | B)` |
| Constant Overlap | `len(A & B) / len(A | B)` |
| Global Overlap | `len(A & B) / len(A | B)` |

---

## Phase 2: Normalization Strategy

### For Numeric Features
Use min-max normalization per DLL (functions within same DLL have similar ranges):

```python
normalized = (value - min_value) / (max_value - min_value)
```

Pre-compute min/max for each DLL:
- `size`: typically 10 - 10000 bytes
- `callee_count`: typically 0 - 50
- `string_count`: typically 0 - 20
- etc.

### For Hash Matches
Already binary (0 or 1) - weight them higher since they're strong signals:

```python
mnemonic_match = 1.0 if source.mne == target.mne else 0.0
```

### For Set Overlaps
Already 0.0 - 1.0 range, no normalization needed.

---

## Phase 3: Vector Construction

```python
def build_feature_vector(source_func, target_func, stats):
    """
    Build a feature vector comparing two functions.
    Returns a vector where higher values = more similar.
    """
    vector = []

    # 1. Numeric feature similarities (normalized difference inverted)
    # Similarity = 1 - |normalized_a - normalized_b|
    vector.append(1 - abs(normalize(source.size, stats) - normalize(target.size, stats)))
    vector.append(1 - abs(normalize(source.callee_count, stats) - normalize(target.callee_count, stats)))
    vector.append(1 - abs(normalize(source.string_count, stats) - normalize(target.string_count, stats)))
    vector.append(1 - abs(normalize(source.basic_blocks, stats) - normalize(target.basic_blocks, stats)))
    vector.append(1 - abs(normalize(source.loop_count, stats) - normalize(target.loop_count, stats)))
    vector.append(1 - abs(normalize(source.stack_frame, stats) - normalize(target.stack_frame, stats)))

    # 2. Hash matches (binary)
    vector.append(1.0 if source.mne == target.mne else 0.0)
    vector.append(1.0 if source.exp == target.exp else 0.0)
    vector.append(1.0 if source.str_idx == target.str_idx else 0.0)
    vector.append(1.0 if source.cal_idx == target.cal_idx else 0.0)
    vector.append(1.0 if source.cfg_idx == target.cfg_idx else 0.0)

    # 3. Set overlaps (Jaccard similarity)
    vector.append(jaccard(source.callees, target.callees))
    vector.append(jaccard(source.strings, target.strings))
    vector.append(jaccard(source.constants, target.constants))

    return vector
```

---

## Phase 4: Similarity Calculation

### Option A: Weighted Euclidean Distance (Recommended)
Apply weights to different feature dimensions:

```python
FEATURE_WEIGHTS = [
    0.3,   # size similarity
    0.5,   # callee count similarity
    0.3,   # string count similarity
    0.4,   # basic block similarity
    0.3,   # loop count similarity
    0.2,   # stack frame similarity
    2.0,   # mnemonic hash match (HIGH)
    1.5,   # export ordinal match (HIGH)
    0.8,   # string index match
    0.8,   # callee index match
    0.6,   # cfg index match
    0.7,   # callee set overlap
    0.6,   # string set overlap
    0.4,   # constant set overlap
]

def weighted_similarity(vector, weights):
    """
    Compute weighted sum of similarities.
    All vector values are 0-1 where 1 = perfect match.
    """
    return sum(v * w for v, w in zip(vector, weights))
```

### Option B: Cosine Similarity
Treat the vector as a point in feature space:

```python
def cosine_similarity(vec_a, vec_b):
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    mag_a = math.sqrt(sum(a * a for a in vec_a))
    mag_b = math.sqrt(sum(b * b for b in vec_b))
    return dot / (mag_a * mag_b) if mag_a and mag_b else 0
```

---

## Phase 5: Integration with Existing System

### Minimal Change Approach
Replace `compute_match_score()` in `sequential_matcher.py`:

```python
def compute_match_score(self, source_func, target_func, dll_name, source_ver, target_ver):
    # Build feature vector
    vector = self.build_feature_vector(source_func, target_func)

    # Compute weighted similarity
    score = self.weighted_similarity(vector, FEATURE_WEIGHTS)

    # Determine which methods contributed
    methods = self.get_contributing_methods(vector)

    # Normalize to confidence 0-1
    max_possible = sum(FEATURE_WEIGHTS)
    confidence = score / max_possible

    return MatchCandidate(
        source_addr=source_func['address'],
        target_addr=target_func['address'],
        score=score,
        methods=methods,
        confidence=confidence
    )
```

---

## Phase 6: Testing & Tuning

### A/B Testing
1. Run current matcher on a DLL, record matches
2. Run vector matcher on same DLL, record matches
3. Compare results - look for:
   - Matches gained (good)
   - Matches lost (investigate why)
   - Confidence distribution changes

### Weight Tuning
Start with intuitive weights, then adjust based on:
- False positives (lower the responsible feature's weight)
- False negatives (raise the responsible feature's weight)

---

## Implementation Order

- [x] **Step 1**: Add `build_feature_vector()` function
- [x] **Step 2**: Add `weighted_similarity()` function
- [x] **Step 3**: Pre-compute normalization stats per DLL
- [x] **Step 4**: Replace `compute_match_score()` internals
- [x] **Step 5**: Test on one DLL (D2Client.dll)
- [x] **Step 6**: Compare results with current approach
- [x] **Step 7**: Tune weights based on results
- [x] **Step 8**: Roll out to all DLLs

---

## Benefits of This Approach

1. **Continuous scoring** - No more boolean match/no-match
2. **Graceful degradation** - Partial matches still contribute
3. **Easy tuning** - Adjust weights without code changes
4. **Explainable** - Can see which features contributed most
5. **Extensible** - Easy to add new features to the vector

---

## Review Notes

### Implementation Complete (2024-12-15)

**What was implemented:**
- Vector-based function matching using weighted similarity scoring
- Three categories of features:
  - **Hash-based** (binary 0/1): mnemonic_hash, export_ordinal, export_name, various index matches
  - **Set-based** (Jaccard 0.0-1.0): callee_overlap, string_overlap, constant_overlap
  - **Numeric** (ratio 0.0-1.0): size_sim, callee_count_sim, basic_block_sim, etc.

**Final weights used:**
```python
VECTOR_FEATURE_WEIGHTS = {
    "mnemonic_hash": 2.0,    # Strongest signal
    "export_ordinal": 1.5,   # Export ordinal match
    "export_name": 1.2,      # Named export match
    "str_index": 0.8,        # String hash index
    "cal_index": 0.8,        # Callee names index
    "cfg_index": 0.6,        # CFG structure index
    "api_index": 0.6,        # API sequence index
    "con_index": 0.5,        # Constants index
    "pro_index": 0.3,        # Prologue index
    "callee_overlap": 0.7,   # Callee set overlap
    "string_overlap": 0.6,   # String reference overlap
    "constant_overlap": 0.4, # Constant value overlap
    "size_sim": 0.4,         # Size similarity
    "callee_count_sim": 0.3, # Callee count similarity
    "string_count_sim": 0.3, # String count similarity
    "basic_block_sim": 0.3,  # Basic block count
    "loop_count_sim": 0.2,   # Loop count
    "stack_frame_sim": 0.2,  # Stack frame size
}
```

**Test Results (LoD DLLs):**

| DLL | Unique Functions | Named | Matches | Avg Versions |
|-----|------------------|-------|---------|--------------|
| D2Client.dll | 5,135 | 3,553 | 38,579 | 7.9 |
| D2Game.dll | 6,401 | 3,918 | 42,257 | 7.4 |
| D2Common.dll | 2,991 | 2,392 | 22,377 | 7.6 |
| Storm.dll | 1,340 | 1,119 | 10,331 | 7.4 |
| Fog.dll | 922 | 877 | 7,381 | 8.3 |
| **Total** | **40,298** | **20,935** | - | - |

**Key changes from old approach:**
1. Replaced boolean match/no-match with continuous 0.0-1.0 similarity
2. Added Jaccard similarity for set-based features (callees, strings, constants)
3. Added ratio-based numeric similarity (min/max comparison)
4. Removed backward pass (wasn't finding additional matches)
5. Simplified codebase by ~90 lines

**Outcome:** Vector matching provides smoother scoring and comparable match rates to the previous approach. The weights can be tuned further based on specific needs.
