#!/usr/bin/env python3
"""
CSV Rename Builder - Build rename map using CSV as authoritative source.

Key insight: CSV versions ending in 'f' apply to ALL variants of that version.
- 1.10f = 1.10, 1.10c, 1.10f (all 1.10 variants)
- 1.13f = 1.13c, 1.13d, etc. (all 1.13 variants)
- 1.14d = only 1.14d
"""

import csv
import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Set

def expand_csv_version(csv_version: str) -> List[Tuple[str, str]]:
    """
    Expand CSV version to function_index versions.
    Returns list of (game_type, index_version).
    """
    if csv_version == '1.00':
        return [('Classic', '1.00')]

    # Extract base version and game type
    if csv_version.startswith('1.10'):
        if csv_version == '1.10f':
            # 1.10f applies to all 1.10 variants in LoD
            return [
                ('LoD', '1.10'),
            ]
        else:
            # Specific 1.10 variants
            return [('LoD', csv_version.replace('1.10f', '1.10').replace('1.10c', '1.10').replace('1.10', '1.10'))]

    if csv_version.startswith('1.13'):
        if csv_version == '1.13f':
            # 1.13f applies to all 1.13 variants
            return [
                ('LoD', '1.13c'),
                ('LoD', '1.13d'),
            ]
        else:
            return [('LoD', csv_version.replace('1.13f', '1.13c'))]

    if csv_version.startswith('1.14'):
        return [('LoD', csv_version)]

    return []

def load_csv_functions():
    """Load CSV with expanded version mapping."""
    functions = {}

    with open('artifacts/d2moo_known_functions.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row['name']
            csv_version = row['version']
            module = row.get('module_hint', '')

            if name not in functions:
                functions[name] = {
                    'module': module,
                    'csv_versions': set(),
                    'index_targets': set(),  # (game_type, index_version) tuples
                }

            functions[name]['csv_versions'].add(csv_version)

            # Expand to all matching index versions
            for game_type, index_version in expand_csv_version(csv_version):
                functions[name]['index_targets'].add((game_type, index_version))

    return functions

def find_function_in_index(func_name: str, module: str, game_type: str, version: str) -> Optional[Dict]:
    """Find function in function_index."""
    index_path = Path('data/function_index') / game_type / version / f'{module}.dll.json'

    if not index_path.exists():
        return None

    try:
        with open(index_path, encoding='utf-8') as f:
            data = json.load(f)
            for func in data.get('functions', []):
                if func.get('name') == func_name and func.get('has_human_name'):
                    return {
                        'address': func.get('address'),
                        'indexes': func.get('indexes', {}),
                        'callees': func.get('callees', []),
                        'size': func.get('size', 0),
                    }
    except Exception as e:
        pass

    return None

def find_candidates_by_hash(module: str, game_type: str, target_version: str,
                            source_indexes: Dict[str, str], exclude_named: bool = True) -> List[Tuple[str, str, float, List[str]]]:
    """Find candidates in target version by matching index hashes."""
    index_path = Path('data/function_index') / game_type / target_version / f'{module}.dll.json'

    if not index_path.exists():
        return []

    candidates = []

    try:
        with open(index_path, encoding='utf-8') as f:
            data = json.load(f)
            for func in data.get('functions', []):
                # Skip if already has human name
                if exclude_named and func.get('has_human_name'):
                    continue

                func_indexes = func.get('indexes', {})
                if not func_indexes:
                    continue

                # Score based on index matches
                score = 0.0
                methods = []

                for method in ['EXP', 'STR', 'API', 'MNE', 'CFG', 'PRO']:
                    source_hash = source_indexes.get(method)
                    target_hash = func_indexes.get(method)

                    if source_hash and target_hash and source_hash == target_hash:
                        if method == 'EXP':
                            score = 1.0
                            methods = ['EXP']
                            break
                        elif method == 'STR':
                            score = 0.99
                            methods = ['STR']
                            break
                        elif method == 'API':
                            score = 0.95
                            methods = ['API']
                            break
                        elif method == 'MNE':
                            score = max(score, 0.85)
                            methods.append('MNE')
                        elif method == 'CFG':
                            score = max(score, 0.80)
                            methods.append('CFG')
                        elif method == 'PRO':
                            score = max(score, 0.70)
                            methods.append('PRO')

                if score >= 0.70:
                    candidates.append((func['address'], func.get('name', ''), score, methods))
    except Exception as e:
        pass

    return sorted(candidates, key=lambda x: x[2], reverse=True)

def build_rename_map():
    """Build comprehensive rename map."""
    print("Loading CSV reference with expanded version mapping...")
    csv_funcs = load_csv_functions()
    print(f"  Loaded {len(csv_funcs)} functions\n")

    # Show a few examples of expansion
    print("Version expansion examples:")
    for name in list(csv_funcs.keys())[:3]:
        versions = csv_funcs[name]['csv_versions']
        targets = csv_funcs[name]['index_targets']
        print(f"  {name}")
        print(f"    CSV: {versions}")
        print(f"    -> Index targets: {targets}")

    print("\n" + "="*70)
    print("Finding functions in function_index...")
    anchors_found = 0

    for func_name, func_data in csv_funcs.items():
        # Try each target location
        for game_type, index_version in func_data['index_targets']:
            module = func_data['module']
            if not module:
                continue

            found = find_function_in_index(func_name, module, game_type, index_version)
            if found:
                anchors_found += 1

    print(f"  Found {anchors_found} anchor points\n")

    # Build rename map
    print("="*70)
    print("Searching for matches in LoD versions...\n")

    rename_candidates = defaultdict(lambda: {
        'module': None,
        'csv_versions': set(),
        'found_in': {},  # game_type/version -> address
        'candidates': {}  # version -> list of (address, score, methods)
    })

    lod_versions = ['1.07', '1.08', '1.09', '1.09b', '1.09d',
                    '1.10', '1.11', '1.11b', '1.12a',
                    '1.13c', '1.13d', '1.14a', '1.14b', '1.14c', '1.14d']

    for func_name, func_data in csv_funcs.items():
        module = func_data['module']
        if not module:
            continue

        rename_candidates[func_name]['module'] = module
        rename_candidates[func_name]['csv_versions'] = func_data['csv_versions']

        # Check each target version for anchor
        best_anchor = None
        for game_type, index_version in func_data['index_targets']:
            found = find_function_in_index(func_name, module, game_type, index_version)
            if found:
                rename_candidates[func_name]['found_in'][f'{game_type}/{index_version}'] = found['address']
                if not best_anchor or found['indexes']:
                    best_anchor = found

        # If we found it, use it as anchor for all other LoD versions
        if best_anchor and best_anchor.get('indexes'):
            for lod_version in lod_versions:
                # Skip versions we already found it in
                if any(lod_version in loc for loc in rename_candidates[func_name]['found_in'].keys()):
                    continue

                candidates = find_candidates_by_hash(module, 'LoD', lod_version, best_anchor['indexes'])
                if candidates:
                    # Take best match with score >= 0.75
                    high_conf = [c for c in candidates if c[2] >= 0.75]
                    if high_conf:
                        best = high_conf[0]
                        rename_candidates[func_name]['candidates'][lod_version] = {
                            'address': best[0],
                            'confidence': best[2],
                            'methods': '+'.join(best[3])
                        }

    # Generate report
    print("Results Summary:\n")

    by_module = defaultdict(lambda: {'found': 0, 'candidates': 0})
    total_found = 0
    total_candidates = 0

    for func_name, data in rename_candidates.items():
        module = data['module']
        found = len(data['found_in'])
        candidates = len(data['candidates'])

        if found > 0 or candidates > 0:
            by_module[module]['found'] += found
            by_module[module]['candidates'] += candidates
            total_found += found
            total_candidates += candidates

    for module in sorted(by_module.keys()):
        stats = by_module[module]
        print(f"{module}:")
        print(f"  Already confirmed: {stats['found']}")
        print(f"  Rename candidates: {stats['candidates']}")

    print(f"\nTotal confirmed: {total_found}")
    print(f"Total candidates: {total_candidates}")

    return rename_candidates

def generate_output(rename_candidates):
    """Generate reports and Ghidra script."""
    Path('reports').mkdir(exist_ok=True)

    # Human-readable report
    report = ['CSV to LoD Function Rename Map', '=' * 70, '']

    by_module = defaultdict(list)
    for func_name, data in sorted(rename_candidates.items()):
        if data['found_in'] or data['candidates']:
            by_module[data['module']].append((func_name, data))

    for module in sorted(by_module.keys()):
        report.append(f'\n{module}')
        report.append('-' * 70)

        for func_name, data in by_module[module]:
            report.append(f'\n{func_name}')
            report.append(f"  CSV versions: {', '.join(sorted(data['csv_versions']))}")

            if data['found_in']:
                report.append('  Confirmed in index:')
                for loc, addr in sorted(data['found_in'].items()):
                    report.append(f'    - {loc}: {addr}')

            if data['candidates']:
                report.append('  Rename candidates:')
                for version in sorted(data['candidates'].keys()):
                    cand = data['candidates'][version]
                    report.append(f'    - {version}: {cand["address"]} (conf={cand["confidence"]:.2f}, {cand["methods"]})')

    with open('reports/csv_rename_map_report.txt', 'w') as f:
        f.write('\n'.join(report))

    print("\nReport: reports/csv_rename_map_report.txt")

    # JSON output
    json_data = {}
    for func_name, data in rename_candidates.items():
        if data['found_in'] or data['candidates']:
            json_data[func_name] = {
                'module': data['module'],
                'csv_versions': list(data['csv_versions']),
                'confirmed_in': data['found_in'],
                'candidates': data['candidates']
            }

    with open('reports/csv_rename_map.json', 'w') as f:
        json.dump(json_data, f, indent=2)

    print("JSON map: reports/csv_rename_map.json")

if __name__ == '__main__':
    rename_candidates = build_rename_map()
    print("\n" + "="*70)
    generate_output(rename_candidates)
