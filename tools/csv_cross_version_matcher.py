#!/usr/bin/env python3
"""
CSV Cross-Version Matcher - Match CSV functions across LoD versions using indices.

Strategy:
1. Load CSV functions and their modules
2. For each CSV function, find ALL versions that have it
3. Use those as anchor points to find the function in OTHER versions
4. Use index hashes (MNE, CFG, PRO, etc) to match across versions
5. Build a cross-version map for renaming
"""

import csv
import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional

def load_csv_functions():
    """Load CSV with UTF-8 encoding."""
    functions = defaultdict(lambda: defaultdict(list))

    with open('artifacts/d2moo_known_functions.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row['name']
            version = row['version']
            module = row.get('module_hint', '')
            address = row['address_hex']

            functions[name][version].append({
                'module': module,
                'address': address,
            })

    return dict(functions)

def load_version_index(game_type: str, version: str) -> Dict:
    """Load index for a specific version."""
    funcs = {}
    version_dir = Path('data/function_index') / game_type / version

    if not version_dir.exists():
        return funcs

    for dll_file in version_dir.glob('*.json'):
        try:
            with open(dll_file, encoding='utf-8') as f:
                data = json.load(f)
                for func in data.get('functions', []):
                    addr = func.get('address', '')
                    if addr not in funcs:
                        funcs[addr] = {}
                    funcs[addr].update({
                        'dll': dll_file.stem,
                        'name': func.get('name', ''),
                        'has_human_name': func.get('has_human_name', False),
                        'indexes': func.get('indexes', {}),
                        'size': func.get('size', 0),
                    })
        except Exception as e:
            print(f"Warning: Error reading {dll_file}: {e}", file=sys.stderr)

    return funcs

def find_matches_by_hash(target_funcs: Dict, dll: str, search_indexes: Dict[str, str]) -> List[Tuple[str, str, float]]:
    """
    Find functions with matching hashes.
    Returns [(address, match_type, confidence)]
    """
    matches = []

    for addr, func in target_funcs.items():
        if func['dll'] != dll:
            continue

        func_indexes = func.get('indexes', {})
        if not func_indexes:
            continue

        # Check for hash matches
        match_score = 0.0
        match_types = []

        for method in ['EXP', 'STR', 'API', 'MNE', 'CFG', 'PRO']:
            search_hash = search_indexes.get(method)
            func_hash = func_indexes.get(method)

            if search_hash and func_hash and search_hash == func_hash:
                if method == 'EXP':
                    match_score = 1.0
                    match_types = ['EXP']
                    break
                elif method == 'STR':
                    match_score = 0.99
                    match_types = ['STR']
                    break
                elif method == 'API':
                    match_score = 0.95
                    match_types = ['API']
                    break
                elif method == 'MNE':
                    match_score = max(match_score, 0.85)
                    match_types.append('MNE')
                elif method == 'CFG':
                    match_score = max(match_score, 0.80)
                    match_types.append('CFG')
                elif method == 'PRO':
                    match_score = max(match_score, 0.70)
                    match_types.append('PRO')

        if match_score > 0:
            matches.append((addr, '+'.join(match_types), match_score))

    return sorted(matches, key=lambda x: x[2], reverse=True)

def main():
    """Main matching process."""
    print("Loading CSV reference...")
    csv_funcs = load_csv_functions()
    print(f"  Loaded {len(csv_funcs)} unique functions\n")

    # Focus on D2Common which has most functions
    d2common_funcs = {
        name: versions for name, versions in csv_funcs.items()
        if any(e['module'] == 'D2Common' for v in versions.values() for e in v)
    }

    print(f"D2Common functions in CSV: {len(d2common_funcs)}\n")

    lod_versions = [
        '1.07', '1.08', '1.09', '1.09b', '1.09d',
        '1.10', '1.11', '1.11b', '1.12a',
        '1.13c', '1.13d', '1.14a', '1.14b', '1.14c', '1.14d'
    ]

    # Preload all LoD version indices
    print("Pre-loading LoD version indices...")
    indices = {}
    for version in lod_versions:
        print(f"  {version}...", end=' ', flush=True)
        indices[version] = load_version_index('LoD', version)
        print(f"({len(indices[version])} functions)")

    print("\n" + "="*70)
    print("Finding cross-version matches\n")

    # For each CSV function, find where it appears
    rename_map = defaultdict(lambda: {
        'csv_info': None,
        'found_in_versions': [],
        'candidates_by_version': {}
    })

    for func_name in sorted(d2common_funcs.keys()):
        csv_versions = d2common_funcs[func_name]

        rename_map[func_name]['csv_info'] = {
            'name': func_name,
            'versions_in_csv': list(csv_versions.keys())
        }

        # For each LoD version, find if this function exists
        for target_version in lod_versions:
            target_idx = indices[target_version]

            # Check if already named
            for addr, func in target_idx.items():
                if func['dll'] == 'D2Common' and func['has_human_name'] and func['name'] == func_name:
                    rename_map[func_name]['found_in_versions'].append({
                        'version': target_version,
                        'address': addr,
                        'status': 'already_named',
                        'confidence': 1.0
                    })
                    break

            # Try to find by hashes - use any CSV version as reference
            for csv_version, csv_entries in csv_versions.items():
                if not csv_entries:
                    continue

                # Get the index hashes from the first entry
                csv_entry = csv_entries[0]
                csv_addr = csv_entry['address']

                # Try to find a version that has this function
                for ref_version in lod_versions:
                    ref_idx = indices[ref_version]

                    # Find this function in the reference version
                    for ref_addr, ref_func in ref_idx.items():
                        if ref_func['dll'] != 'D2Common' or ref_func['name'] != func_name:
                            continue

                        # Found it! Now use its hashes to find in target
                        ref_indexes = ref_func.get('indexes', {})
                        if not ref_indexes:
                            continue

                        # Search for matching hashes in target version
                        candidates = find_matches_by_hash(target_idx, 'D2Common', ref_indexes)

                        if candidates and target_version not in [c['version'] for c in rename_map[func_name].get('found_in_versions', [])]:
                            for addr, match_type, confidence in candidates[:1]:  # Take best match
                                rename_map[func_name]['candidates_by_version'][target_version] = {
                                    'address': addr,
                                    'match_type': match_type,
                                    'confidence': confidence,
                                    'reference_version': ref_version
                                }
                            break

    # Report results
    print(f"Results:\n")
    found_any = False

    for func_name in sorted(rename_map.keys()):
        data = rename_map[func_name]
        named = data['found_in_versions']
        candidates = data['candidates_by_version']

        if named or candidates:
            found_any = True
            print(f"\n{func_name}")
            print(f"  CSV versions: {data['csv_info']['versions_in_csv']}")

            if named:
                print(f"  Already named in:")
                for n in named:
                    print(f"    - {n['version']}: {n['address']}")

            if candidates:
                print(f"  Candidates for renaming:")
                for version in sorted(candidates.keys()):
                    c = candidates[version]
                    print(f"    - {version}: {c['address']} (conf={c['confidence']:.2f}, match={c['match_type']})")

    if not found_any:
        print("No matches found. This may indicate:")
        print("  1. Function indices don't have hash data yet")
        print("  2. Functions are named differently in indices")
        print("  3. CSV version numbers don't match LoD versions")

if __name__ == '__main__':
    main()
