# Optimized Function Matching Pipeline

## Goal
Replace slow Ghidra MCP-based matching with fast Python-native analysis, using Ghidra only for human-annotated names/signatures.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Stage 0: Ghidra Export (one-time, manual)                  │
│  - Export named functions only                               │
│  - Output: data/ghidra_names.json                           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Stage 1: Version Analysis (per-version, cached)            │
│  - Function detection (prologue/padding)                    │
│  - Byte signature computation                               │
│  - Call graph extraction (capstone)                         │
│  - Output: cache/analysis/<version>/<dll>.json              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Stage 2: Tiered Matching (incremental)                     │
│  - Tier 1: Export ordinal matching                          │
│  - Tier 2: Exact byte hash matching                         │
│  - Tier 3: Partial byte signature matching                  │
│  - Tier 4: Structural similarity matching                   │
│  - Tier 5: Call graph similarity matching                   │
│  - Output: cache/matches/<dll>_matches.json                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Stage 3: Name Propagation                                  │
│  - Merge Ghidra names with matched functions                │
│  - Output: reports/function_registry.json                   │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Module 1: `analysis_engine.py`
- [ ] PE loading and section parsing
- [ ] Function boundary detection
- [ ] Byte signature computation (MD5 of first 16/32/64 bytes)
- [ ] Call graph extraction via capstone
- [ ] Structural metrics (size, call count, basic blocks)
- [ ] Progress reporting with callbacks
- [ ] Caching with invalidation

### Module 2: `matching_engine.py`
- [ ] Base matcher interface
- [ ] Tier 1: ExportMatcher
- [ ] Tier 2: ExactByteMatcher
- [ ] Tier 3: PartialByteMatcher
- [ ] Tier 4: StructuralMatcher
- [ ] Tier 5: CallGraphMatcher
- [ ] Incremental state management
- [ ] Progress reporting

### Module 3: `name_propagator.py`
- [ ] Load Ghidra names export
- [ ] Apply names to matched functions
- [ ] Generate final registry

### Module 4: `pipeline_runner.py`
- [ ] CLI interface
- [ ] Stage selection (--stage, --tier)
- [ ] Target filtering (--dll, --version, --address)
- [ ] Progress display
- [ ] Summary statistics

## Testing Strategy

Each module testable independently:
```bash
# Test analysis on single file
python -m tools.analysis_engine --test D2Client.dll --version LoD/1.13c

# Test specific matcher tier
python -m tools.matching_engine --test --tier 2 --dll D2Client.dll

# Run full pipeline with verbose output
python -m tools.pipeline_runner --all --verbose
```

## Progress Reporting

All long-running operations report:
- Current operation name
- Items processed / total items
- Estimated time remaining
- Per-item details in verbose mode

Example output:
```
[Analysis] Processing LoD/1.13c/D2Client.dll
  Functions detected: 3,246
  Computing signatures... [=====>    ] 52% (1,688/3,246) ETA: 12s
  Building call graph...  [=========>] 100% (3,246/3,246) Done
  Cache saved: cache/analysis/LoD_1.13c/D2Client.dll.json (2.4 MB)

[Matching] Tier 1: Export Matching
  Comparing 39 versions...
  Matched: 2,847 functions (87.7%)
  Unmatched: 399 functions

[Matching] Tier 2: Exact Byte Hash
  Processing unmatched: 399 functions
  Matched: 156 functions (39.1% of remaining)
  Unmatched: 243 functions
```

## File Structure

```
tools/
├── optimized_matching/
│   ├── __init__.py
│   ├── analysis_engine.py    # Module 1
│   ├── matching_engine.py    # Module 2
│   ├── name_propagator.py    # Module 3
│   ├── pipeline_runner.py    # Module 4
│   └── progress.py           # Progress reporting utilities
│
cache/
├── analysis/                 # Cached per-version analysis
│   ├── Classic_1.00/
│   │   ├── D2Client.dll.json
│   │   └── D2Game.dll.json
│   └── LoD_1.13c/
│       └── ...
└── matches/                  # Matching results by tier
    ├── D2Client.dll_tier1.json
    ├── D2Client.dll_tier2.json
    └── ...

data/
└── ghidra_names.json         # Exported from Ghidra (human annotations)

reports/
└── function_registry.json    # Final output with propagated names
```

## Status
- [x] Module 1: analysis_engine.py
- [x] Module 2: matching_engine.py
- [x] Module 3: name_propagator.py
- [x] Module 4: pipeline_runner.py
- [x] Integration testing
- [x] Performance benchmarking

## Results

### Performance Comparison

| Metric | Old (Ghidra MCP) | New (Python Native) |
|--------|------------------|---------------------|
| Analyze 1 DLL | ~60s per version | ~2s per version |
| Analyze 31 versions | ~30+ minutes | ~60 seconds |
| Call graph extraction | HTTP per function | Batch capstone |
| Caching | None | Full caching |

### Test Run: D2Client.dll (31 versions)

```
Total Matches: 10,489
Matches by Tier:
  Tier 1 (Export):        4 (0.0%)
  Tier 2 (Exact Bytes): 5,670 (54.1%)
  Tier 3 (Prologue):    4,721 (45.0%)
  Tier 4 (Call Graph):     94 (0.9%)

Coverage by Version:
  - Classic 1.00-1.03: 60-62% coverage
  - Classic 1.04-1.06: 48-95% coverage (image base change)
  - Classic 1.08+:     95-96% coverage
  - LoD versions:      Similar patterns
```

### Usage

```bash
# Full pipeline
python -m tools.optimized_matching.pipeline_runner full --dll D2Client.dll

# Just matching (uses cached analysis)
python -m tools.optimized_matching.pipeline_runner match --dll D2Client.dll

# Statistics
python -m tools.optimized_matching.pipeline_runner stats --dll D2Client.dll

# Export registry
python -m tools.optimized_matching.pipeline_runner export --dll D2Client.dll -o registry.json

# With Ghidra names (after running ExportNamesOnly.java)
python -m tools.optimized_matching.name_propagator \
    --ghidra data/ghidra_names/D2Client.dll.json \
    --state cache/matches/D2Client.dll_state.json \
    --version LoD/1.13c
```

### Files Created

```
tools/optimized_matching/
├── __init__.py              # Package init
├── progress.py              # Progress reporting utilities
├── analysis_engine.py       # PE analysis (functions, signatures, call graph)
├── matching_engine.py       # Tiered function matching
├── name_propagator.py       # Ghidra name application
└── pipeline_runner.py       # Unified CLI

ghidra_scripts/
└── ExportNamesOnly.java     # Lightweight Ghidra export script

cache/
├── analysis/                # Per-version analysis cache (~1.8-2.2 MB each)
└── matches/                 # Matching state files
```
