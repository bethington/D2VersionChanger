#!/usr/bin/env python3
"""
Generate JavaScript files from function_registry_v2.json for the report viewer.

Reads: reports/function_registry_v2.json
Writes: reports/functions_v2/_index.js and per-DLL files

Output format matches the existing viewer's expectations:
- functions keyed by canonical_id (or RVA for compatibility)
- versions array with version strings
- Each function has: name, signature, comment, addresses per version
- Candidates for empty cells with confidence levels (precomputed)
"""

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Feature weights for count-based similarity (simplified version)
COUNT_FEATURES = {
    'size': {'weight': 1.0, 'tolerance': 0.15},
    'instruction_count': {'weight': 0.9, 'tolerance': 0.15},
    'callee_count': {'weight': 0.8, 'tolerance': 0.2},
    'caller_count': {'weight': 0.7, 'tolerance': 0.25},
    'string_count': {'weight': 0.6, 'tolerance': 0.3},
    'basic_block_count': {'weight': 0.5, 'tolerance': 0.2},
}

def compute_feature_similarity(val1: float, val2: float, tolerance: float) -> float:
    """Compute similarity between two feature values (0-1)."""
    if val1 == 0 and val2 == 0:
        return 1.0
    if val1 == 0 or val2 == 0:
        return 0.0
    diff = abs(val1 - val2)
    avg = (val1 + val2) / 2
    ratio = diff / avg if avg > 0 else 1.0
    if ratio <= tolerance:
        return 1.0
    return max(0, 1.0 - (ratio - tolerance) / (1 - tolerance))

def compute_count_similarity(func1_data: dict, func2_data: dict, version1: str, version2: str) -> float:
    """Compute count-based vector similarity between two functions (0-100)."""
    ver1_data = func1_data.get('versions', {}).get(version1, {})
    ver2_data = func2_data.get('versions', {}).get(version2, {})

    # Extract counts
    def get_count(data, key):
        if key == 'size':
            return data.get('size', 0)
        elif key == 'instruction_count':
            return data.get('instruction_count', 0)
        elif key == 'callee_count':
            return data.get('callee_count', 0) or (len(data.get('callees', [])) if data.get('callees') else 0)
        elif key == 'caller_count':
            return data.get('caller_count', 0) or (len(data.get('callers', [])) if data.get('callers') else 0)
        elif key == 'string_count':
            return data.get('string_count', 0) or (len(data.get('strings', [])) if data.get('strings') else 0)
        elif key == 'basic_block_count':
            return data.get('basic_block_count', 0)
        return 0

    total_weight = 0
    weighted_sum = 0
    feature_count = 0

    for feature, config in COUNT_FEATURES.items():
        val1 = get_count(ver1_data, feature)
        val2 = get_count(ver2_data, feature)

        if val1 > 0 and val2 > 0:
            sim = compute_feature_similarity(val1, val2, config['tolerance'])
            weighted_sum += sim * config['weight']
            total_weight += config['weight']
            feature_count += 1

    if feature_count < 2 or total_weight == 0:
        return 0

    return (weighted_sum / total_weight) * 100

def compute_candidates_for_dll(functions: list, all_versions: list, min_confidence: float = 60.0) -> dict:
    """
    Precompute candidates for empty cells in a DLL's function list.

    Optimizations:
    - Only compute for named functions (worth propagating)
    - Size-based pre-filtering to reduce comparisons
    - Early termination for high-confidence matches

    Returns dict: canonical_id -> {version -> candidate_data}
    """
    candidates_map = {}

    # Build lookup structures per version
    version_func_map = defaultdict(list)  # version -> [(func, canonical_id, size)]
    for func in functions:
        canonical_id = func.get('canonical_id', '')
        for ver, ver_data in func.get('versions', {}).items():
            addr = ver_data.get('address')
            size = ver_data.get('size', 0)
            if addr:
                version_func_map[ver].append((func, canonical_id, size))

    # Only process named functions (ones worth finding candidates for)
    named_functions = [f for f in functions if f.get('name') and not f.get('name', '').startswith('FUN_')]

    if not named_functions:
        return candidates_map

    # Progress tracking
    total = len(named_functions)
    processed = 0

    for func in named_functions:
        processed += 1
        if processed % 100 == 0 or processed == total:
            print(f"      Progress: {processed}/{total} named functions checked", end='\r')
        canonical_id = func.get('canonical_id', '')
        func_versions = set(func.get('versions', {}).keys())

        # Find versions where this function has data (to use as source)
        source_versions = [v for v in all_versions if v in func_versions]
        if not source_versions:
            continue

        # Find versions where this function is missing
        missing_versions = [v for v in all_versions if v not in func_versions]
        if not missing_versions:
            continue

        # Use the first available version as source for comparison
        source_version = source_versions[0]
        source_size = func.get('versions', {}).get(source_version, {}).get('size', 0)

        func_candidates = {}
        for target_version in missing_versions:
            # Find best match in target version using size pre-filter
            best_score = 0
            best_candidate = None

            for target_func, target_cid, target_size in version_func_map[target_version]:
                if target_cid == canonical_id:
                    continue  # Skip self

                # Size pre-filter: skip if sizes differ by more than 50%
                if source_size > 0 and target_size > 0:
                    size_ratio = min(source_size, target_size) / max(source_size, target_size)
                    if size_ratio < 0.5:
                        continue

                score = compute_count_similarity(func, target_func, source_version, target_version)

                if score >= min_confidence and score > best_score:
                    best_score = score
                    target_ver_data = target_func.get('versions', {}).get(target_version, {})
                    best_candidate = {
                        'address': target_ver_data.get('address'),
                        'rva': target_ver_data.get('rva'),
                        'confidence': round(score / 100, 3),
                        'method': 'vector',
                        'source': source_version,
                        'matched_to': target_func.get('name') or target_cid
                    }

                    # Early termination for high confidence matches
                    if score >= 90:
                        break

            if best_candidate:
                func_candidates[target_version] = best_candidate

        if func_candidates:
            candidates_map[canonical_id] = func_candidates

    return candidates_map

def escape_js_string(s):
    """Escape a string for JavaScript."""
    if s is None:
        return ""
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '')

def generate_js_files(base_path: Path):
    registry_file = base_path / "reports" / "function_registry_v2.json"
    output_dir = base_path / "reports" / "functions_v2"
    
    if not registry_file.exists():
        print(f"Error: Registry not found: {registry_file}")
        print("Run merge_function_index.py first.")
        return
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    # Load registry
    with open(registry_file, 'r', encoding='utf-8') as f:
        registry = json.load(f)
    
    print(f"Loaded registry with {registry.get('total_functions', 0)} functions")
    
    dlls = registry.get('dlls', {})
    timestamp = datetime.now().isoformat()
    
    # Generate index file
    index_data = {
        "generated": timestamp,
        "source": "function_registry_v2.json",
        "total_functions": registry.get('total_functions', 0),
        "total_named": registry.get('total_named', 0),
        "files": {}
    }
    
    for dll_name, functions in dlls.items():
        named_count = sum(1 for f in functions if f.get('name'))
        version_set = set()
        for f in functions:
            version_set.update(f.get('versions', {}).keys())
        
        index_data["files"][dll_name] = {
            "count": len(functions),
            "named": named_count,
            "versions": sorted(version_set)
        }
        
        # Generate per-DLL file
        dll_file = output_dir / f"{dll_name}.js"
        write_dll_js(dll_file, dll_name, functions, timestamp)
        print(f"  {dll_name}: {len(functions)} functions, {named_count} named")
    
    # Write index
    index_file = output_dir / "_index.js"
    with open(index_file, 'w', encoding='utf-8') as f:
        f.write(f"// Auto-generated from function_registry_v2.json\n")
        f.write(f"// Generated: {timestamp}\n\n")
        f.write(f"var FUNCTION_INDEX_V2 = ")
        json.dump(index_data, f, indent=2)
        f.write(";\n")
    
    print(f"\nWrote index to: {index_file}")
    print(f"Total DLLs: {len(dlls)}")

def write_dll_js(filepath: Path, dll_name: str, functions: list, timestamp: str, compute_candidates: bool = True):
    """Write a single DLL's function data to a JS file.

    Output format matches existing viewer expectations:
    {
        versions: ["LoD/1.07", "LoD/1.08", ...],
        functions: {
            "canonical_id": {
                name: "FunctionName",
                signature: "void FunctionName(int a)",
                calling_convention: "__cdecl",
                return_type: "void",
                comment: "Does something",
                addresses: {"LoD/1.07": "0x1234", "LoD/1.08": "0x5678"},
                callees: {"LoD/1.07": [...], ...},
                callers: {"LoD/1.07": [...], ...},
                strings: {"LoD/1.07": [...], ...},
                instructions: {"LoD/1.07": [...], ...}
            },
            ...
        }
    }
    """

    # Collect all versions across functions
    all_versions = set()
    for f in functions:
        all_versions.update(f.get('versions', {}).keys())
    all_versions = sorted(all_versions)

    # Precompute candidates for empty cells
    precomputed_candidates = {}
    if compute_candidates and len(functions) < 20000:  # Skip for very large DLLs
        print(f"    Computing candidates for {dll_name}...")
        precomputed_candidates = compute_candidates_for_dll(functions, all_versions)
        if precomputed_candidates:
            print(f"    Found candidates for {len(precomputed_candidates)} functions")
    
    # Build functions dict keyed by canonical_id
    func_dict = {}
    for func in functions:
        canonical_id = func.get('canonical_id', '')
        
        # Build per-version data dicts
        addresses = {}
        rvas = {}
        sizes = {}
        callees = {}
        callers = {}
        strings = {}
        instructions = {}
        instruction_counts = {}
        # New enhanced fields
        stack_frame_sizes = {}
        basic_block_counts = {}
        loop_counts = {}
        mnemonic_hashes = {}
        constants = {}
        globals = {}
        api_calls = {}
        # Count fields (per-version)
        callee_counts = {}
        caller_counts = {}
        string_counts = {}
        constant_counts = {}
        global_counts = {}
        api_counts = {}
        param_counts = {}
        # Additional metadata
        tags = {}
        function_types = {}

        for ver in all_versions:
            ver_data = func.get('versions', {}).get(ver, {})
            addr = ver_data.get('address')
            rva = ver_data.get('rva')
            size = ver_data.get('size')
            
            if addr:
                addresses[ver] = addr
            if rva:
                rvas[ver] = rva
            if size:
                sizes[ver] = size
            
            # Enhanced data (per-version since it can vary)
            if ver_data.get('callees'):
                callees[ver] = ver_data['callees']
            if ver_data.get('callers'):
                callers[ver] = ver_data['callers']
            if ver_data.get('strings'):
                strings[ver] = ver_data['strings']
            if ver_data.get('instructions'):
                instructions[ver] = ver_data['instructions']
            if ver_data.get('instruction_count'):
                instruction_counts[ver] = ver_data['instruction_count']
            # New enhanced fields
            if ver_data.get('stack_frame_size'):
                stack_frame_sizes[ver] = ver_data['stack_frame_size']
            if ver_data.get('basic_block_count'):
                basic_block_counts[ver] = ver_data['basic_block_count']
            if ver_data.get('loop_count') is not None:
                loop_counts[ver] = ver_data['loop_count']
            if ver_data.get('mnemonic_hash'):
                mnemonic_hashes[ver] = ver_data['mnemonic_hash']
            if ver_data.get('constants'):
                constants[ver] = ver_data['constants']
            if ver_data.get('globals'):
                globals[ver] = ver_data['globals']
            if ver_data.get('api_calls'):
                api_calls[ver] = ver_data['api_calls']
            # Count fields (per-version)
            if ver_data.get('callee_count'):
                callee_counts[ver] = ver_data['callee_count']
            if ver_data.get('caller_count'):
                caller_counts[ver] = ver_data['caller_count']
            if ver_data.get('string_count'):
                string_counts[ver] = ver_data['string_count']
            if ver_data.get('constant_count'):
                constant_counts[ver] = ver_data['constant_count']
            if ver_data.get('global_count'):
                global_counts[ver] = ver_data['global_count']
            if ver_data.get('api_count'):
                api_counts[ver] = ver_data['api_count']
            if ver_data.get('param_count'):
                param_counts[ver] = ver_data['param_count']
            # Additional metadata
            if ver_data.get('tags'):
                tags[ver] = ver_data['tags']
            if ver_data.get('function_type'):
                function_types[ver] = ver_data['function_type']

        entry = {
            "addresses": addresses
        }
        
        # Include RVAs if different from addresses (for toggle feature)
        if rvas and rvas != addresses:
            entry["rvas"] = rvas
        
        # Include sizes
        if sizes:
            entry["sizes"] = sizes
        
        # Add optional fields only if present
        if func.get('name'):
            entry["name"] = func['name']
        if func.get('signature'):
            entry["signature"] = func['signature']
        if func.get('calling_convention'):
            entry["calling_convention"] = func['calling_convention']
        if func.get('return_type'):
            entry["return_type"] = func['return_type']
        if func.get('comment'):
            entry["comment"] = func['comment']
        if func.get('name_source'):
            entry["name_source"] = func['name_source']
        if func.get('index_method'):
            entry["method"] = func['index_method']
        if func.get('index'):
            entry["index"] = func['index']
        # Include all individual indexes for detailed comparison
        if func.get('indexes'):
            entry["indexes"] = func['indexes']
        # Include display_name if different from name
        if func.get('display_name') and func.get('display_name') != func.get('name'):
            entry["display_name"] = func['display_name']

        # Enhanced data (per-version)
        if callees:
            entry["callees"] = callees
        if callers:
            entry["callers"] = callers
        if strings:
            entry["strings"] = strings
        if instructions:
            entry["instructions"] = instructions
        if instruction_counts:
            entry["instruction_counts"] = instruction_counts
        # New enhanced fields for comparison
        if stack_frame_sizes:
            entry["stack_frame_sizes"] = stack_frame_sizes
        if basic_block_counts:
            entry["basic_block_counts"] = basic_block_counts
        if loop_counts:
            entry["loop_counts"] = loop_counts
        if mnemonic_hashes:
            entry["mnemonic_hashes"] = mnemonic_hashes
        if constants:
            entry["constants"] = constants
        if globals:
            entry["globals"] = globals
        if api_calls:
            entry["api_calls"] = api_calls
        # Count fields (per-version)
        if callee_counts:
            entry["callee_counts"] = callee_counts
        if caller_counts:
            entry["caller_counts"] = caller_counts
        if string_counts:
            entry["string_counts"] = string_counts
        if constant_counts:
            entry["constant_counts"] = constant_counts
        if global_counts:
            entry["global_counts"] = global_counts
        if api_counts:
            entry["api_counts"] = api_counts
        if param_counts:
            entry["param_counts"] = param_counts
        # Additional metadata (per-version)
        if tags:
            entry["tags"] = tags
        if function_types:
            entry["function_types"] = function_types

        # Add candidates for empty cells
        # Candidates can be stored as dict (new format) or list (old format)
        if func.get('candidates'):
            candidates_by_version = {}
            cand_data = func['candidates']
            
            # Handle dict format: version -> candidate_data
            if isinstance(cand_data, dict):
                for ver, cand in cand_data.items():
                    candidates_by_version[ver] = {
                        'address': cand.get('address'),
                        'rva': cand.get('rva'),
                        'confidence': cand.get('confidence', 0),
                        'method': cand.get('method', ''),
                        'direction': cand.get('direction', 'forward'),
                        'source': cand.get('source_version', '')
                    }
            # Handle list format: [candidate1, candidate2, ...]
            elif isinstance(cand_data, list):
                for cand in cand_data:
                    ver = cand.get('version')
                    if ver:
                        candidates_by_version[ver] = {
                            'address': cand.get('address'),
                            'rva': cand.get('rva'),
                            'confidence': cand.get('confidence', 0),
                            'method': cand.get('method', ''),
                            'direction': cand.get('direction', 'forward'),
                            'source': cand.get('source_version', '')
                        }
            
            if candidates_by_version:
                entry["candidates"] = candidates_by_version

        # Merge in precomputed candidates for empty cells
        if canonical_id in precomputed_candidates:
            if "candidates" not in entry:
                entry["candidates"] = {}
            for ver, cand_data in precomputed_candidates[canonical_id].items():
                # Only add if this version doesn't have an address AND no existing candidate
                if ver not in addresses and ver not in entry["candidates"]:
                    entry["candidates"][ver] = cand_data

        func_dict[canonical_id] = entry
    
    # Write JS file
    var_name = sanitize_var_name(dll_name)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"// Auto-generated from function_registry_v2.json\n")
        f.write(f"// Generated: {timestamp}\n")
        f.write(f"// Functions for {dll_name}\n")
        f.write(f"// Versions: {', '.join(all_versions)}\n\n")
        
        output = {
            "versions": all_versions,
            "functions": func_dict
        }
        
        f.write(f"var FUNCTIONS_{var_name} = ")
        json.dump(output, f, indent=2)
        f.write(";\n")
        
        # Register with global FUNCTION_DATA if it exists
        f.write(f"\nif (typeof FUNCTION_DATA === 'undefined') FUNCTION_DATA = {{}};\n")
        f.write(f"FUNCTION_DATA['{dll_name}'] = FUNCTIONS_{var_name};\n")

def sanitize_var_name(name: str) -> str:
    """Convert filename to valid JS variable name."""
    return name.replace('.', '_').replace(' ', '_').replace('-', '_')


def main():
    base_path = Path(__file__).parent.parent
    generate_js_files(base_path)

if __name__ == '__main__':
    main()
