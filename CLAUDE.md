# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

D2VersionChanger is a tool for switching between all patch versions of Diablo 2, from 1.00 Classic to 1.14d Lord of Destruction. It can install PlugY and create shortcuts to launch specific patch versions.

## Critical Rules to Follow

1. First think through the problem, read the code base for relevant files, and write a plan to tasks/todo.Md.
2. The plan should have a list of to do items that you can check off as you complete them.
3. Before you begin working, check in with me and I will verify the plan.
4. Then, begin working on the to do items, marking them as complete as you go.
5. Please every step of the way just give me the high level explanation of what changes you made.
6. Make every task and code change you do as simple as possible. We want to avoid making any massive or complex changes. Every change should impact as little code as possible. Everything is about simplicity.
7. Finally, Add a review section to the to do dot MD file with a summary of the changes you made and any other relevant information.
8. Do not be lazy. Never be lazy. If there is a bug find the root cause and fix it. No temporary fixes. You are a senior developer. Never be lazy.
9. Make all fixes and core changes as simple as humanly possible. They should only impact the necessary code relevant to the task and nothing else. It should impact as little code as possible. Your goal is to not introduce any bugs. It's all about simplicity.

## Python Tools

Located in `tools/`:

### Core Tools (Active)

| Script | Purpose |
|--------|---------|
| `refresh_viewer.py` | **One-command refresh**: runs merge + generate steps |
| `merge_function_index.py` | Merges Ghidra function exports into unified registry |
| `generate_function_js.py` | Generates JS files for the function viewer |
| `registry_loader.py` | Load unified registry from split functions_v2 files |
| `sequential_matcher.py` | Primary function matching across versions |
| `fuzzy_matcher.py` | Fuzzy matching with MinHash/LSH |
| `tiered_matcher.py` | Tiered confidence matching |
| `d2_hash_tool.py` | SHA256 hashing, PE version extraction |

### Analysis Tools

| Script | Purpose |
|--------|---------|
| `analyze_unmatched.py` | Analyze functions that only exist in one version |
| `analyze_function_signatures.py` | Signature analysis |
| `build_api_reference.py` | Build API documentation |
| `compare_versions.py` | Compare function data across versions |
| `query_functions.py` | Query function database |

### Archived Tools

Old/superseded scripts are in `tools/archive/`. These include:
- CSV workflow scripts (old renaming system)
- Debug/investigation scripts
- One-off analysis scripts

### Refreshing the Report Viewer

The `reports/d2_report_viewer.html` viewer has two main data sources that need to be refreshed:

#### 1. Hash/Version Data (d2_data.js)

```bash
# Regenerates hash data for version detection
python tools/gen_viewer_data.py
```

#### 2. Function Index Data (functions_v2/*.js)

When Ghidra exports are updated in `data/function_index/`, run:

```bash
# Single command to refresh all function data
python tools/refresh_viewer.py
```

This runs both steps automatically:
1. `merge_function_index.py` - Merge Ghidra exports into unified registry
2. `generate_function_js.py` - Generate JS files for the viewer

**Data Flow:**
```
data/function_index/{LoD,Classic}/{version}/*.json  (Ghidra exports)
    ↓ merge_function_index.py
    ↓ generate_function_js.py
reports/functions_v2/*.js                            (viewer data - split by DLL)
```

Note: The monolithic `function_registry_v2.json` is no longer generated. 
Use `registry_loader.py` to load data from split `functions_v2/*.js` files.

**Configuration:** `config/function_index.json`
- `enabled_game_types`: Enable/disable Classic or LoD processing
- `enabled_versions`: Fine-grained version control
- `disabled_methods`: Index methods to skip (e.g., `["EXP"]` for ordinals)
- `index_priority`: Method priority order for matching

### Ghidra Scripts

Located in `ghidra_scripts/`:

| Script | Purpose |
|--------|---------|
| `ExportFunctionIndex.java` | Exports function data with multi-method indexes for cross-version matching |
| `ExportNamesOnly.java` | Lightweight export of named functions only |

**Exporting from Ghidra:**
1. Open a D2 binary in Ghidra
2. Run `ExportFunctionIndex.java` via Script Manager
3. Save to `data/function_index/{LoD|Classic}/{version}/{DLL}.json`
4. Repeat for all DLLs/versions, then run the merge scripts above

### Running Other Tools

```bash
# Generate full analysis reports
python tools/d2_hash_tool.py

# Specify custom paths
python tools/d2_hash_tool.py -p /path/to/project -o ./custom-reports
```
