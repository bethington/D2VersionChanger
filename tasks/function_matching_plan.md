# Function Matching Implementation Plan

## Goal
Match functions across D2 versions so that `function_0001` in v1.00 corresponds to the same logical function in v1.01, v1.02, etc., even if addresses change.

## Current State
- `d2_function_extractor.py` detects functions via prologue/padding patterns
- Functions are linked by **position** (index N in v1.00 → index N in v1.01)
- This breaks when functions are added/removed between versions

## Proposed Solution: Sequential Signature Matching

### Phase 1: Fingerprint Generation (No Dependencies)

For each detected function, compute fingerprints:
```python
fingerprint = {
    'address': 0x10001000,
    'bytes_16': 'a1b2c3d4...',      # MD5 of first 16 bytes
    'bytes_32': 'e5f6g7h8...',      # MD5 of first 32 bytes
    'prologue_4': '558bec83',       # First 4 bytes as hex
    'size_estimate': 156,           # Distance to next function
}
```

### Phase 2: Sequential Version Matching

Process versions in chronological order:
```
1.00 (baseline) → 1.01 → 1.02 → ... → 1.14d
```

For each version transition (N → N+1):
1. Try exact byte_32 match first
2. Fall back to prologue + size match
3. Track unmatched functions as new/removed

### Phase 3: Build Function Registry

```python
function_registry = {
    'function_0001': {
        'first_seen': 'Classic/1.00',
        'last_seen': 'Classic/1.14d',
        'addresses': {
            'Classic/1.00': '10001005',
            'Classic/1.01': '10001005',
            'Classic/1.02': '10001010',  # Address changed
            ...
        },
        'signature': 'a1b2c3d4...',  # Canonical signature
    },
    ...
}
```

### Output Format (Unchanged)

```javascript
var FUNCTIONS_D2CLIENT_DLL = {
    "versions": ["Classic/1.00", "Classic/1.01", ...],
    "functions": {
        "1": {
            "ordinal": 1,
            "name": "function_0001",
            "addresses": {
                "Classic/1.00": "10001005",
                "Classic/1.01": "10001005",
                ...
            }
        },
        ...
    }
}
```

## Implementation Steps

### Step 1: Add fingerprint computation to extract_functions_from_pe()
- Compute bytes_16, bytes_32, prologue_4 for each function
- Estimate function size (distance to next function)

### Step 2: Create new matching module
- `match_functions_sequential()` - match version N to N+1
- `build_function_registry()` - aggregate matches into registry

### Step 3: Update build_function_index()
- Replace position-based linking with signature-based
- Output in same format for viewer compatibility

## Key Design Decisions

1. **Sequential matching** - Each version matches against previous, not all-to-all
2. **Baseline from first version** - Function IDs assigned from v1.00
3. **New functions get new IDs** - Functions added in later versions get next available ID
4. **Removed functions show "—"** - Missing address in later versions

## Testing

1. Run on D2Client.dll across all versions
2. Verify function count per version matches current output
3. Spot-check: functions with same bytes should have same ID
4. Spot-check: functions with different bytes but same prologue should match if size similar
