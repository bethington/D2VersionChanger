#!/usr/bin/env python3
"""
CSV to Rename Map - Generate rename candidates using tiered matching.

Strategy:
1. Load CSV functions (authoritative source)
2. Find them in function_index using names
3. Use tiered_matcher to find matches across versions
4. Generate rename commands with confidence scores
"""

import csv
import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

def load_csv_functions():
    """Load CSV reference."""
    functions = {}

    with open('artifacts/d2moo_known_functions.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row['name']
            version = row['version']
            module = row.get('module_hint', '')

            if name not in functions:
                functions[name] = {
                    'module': module,
                    'versions_in_csv': [],
                    'confirmed_addresses': {}
                }

            if version not in functions[name]['versions_in_csv']:
                functions[name]['versions_in_csv'].append(version)
            functions[name]['confirmed_addresses'][version] = row['address_hex']

    return functions

def find_in_function_index(func_name: str, module: str, target_version: str) -> Optional[Dict]:
    """Find a function in function_index by exact name match."""
    version_dir = Path('data/function_index') / 'LoD' / target_version

    if not version_dir.exists():
        return None

    dll_file = version_dir / f"{module}.dll.json"
    if not dll_file.exists():
        return None

    try:
        with open(dll_file, encoding='utf-8') as f:
            data = json.load(f)
            for func in data.get('functions', []):
                if func.get('name') == func_name:
                    return {
                        'address': func.get('address'),
                        'display_name': func.get('display_name'),
                        'has_human_name': func.get('has_human_name'),
                        'indexes': func.get('indexes', {}),
                        'callees': func.get('callees', []),
                    }
    except Exception as e:
        pass

    return None

def find_candidates_by_index(func_data: Dict, module: str, target_version: str) -> List[Tuple[str, float]]:
    """Find candidates in target version using index hashes."""
    version_dir = Path('data/function_index') / 'LoD' / target_version

    if not version_dir.exists():
        return []

    dll_file = version_dir / f"{module}.dll.json"
    if not dll_file.exists():
        return []

    source_indexes = func_data.get('indexes', {})
    if not source_indexes:
        return []

    candidates = []

    try:
        with open(dll_file, encoding='utf-8') as f:
            data = json.load(f)
            for func in data.get('functions', []):
                # Skip already-named functions with human names
                if func.get('has_human_name'):
                    continue

                target_indexes = func.get('indexes', {})
                if not target_indexes:
                    continue

                # Score based on index matches
                score = 0.0
                methods_matched = []

                for method in ['EXP', 'STR', 'API', 'MNE', 'CFG', 'PRO']:
                    source_hash = source_indexes.get(method)
                    target_hash = target_indexes.get(method)

                    if source_hash and target_hash and source_hash == target_hash:
                        if method == 'EXP':
                            score = 1.0
                            methods_matched = ['EXP']
                            break
                        elif method == 'STR':
                            score = 0.99
                            methods_matched = ['STR']
                            break
                        elif method == 'API':
                            score = 0.95
                            methods_matched = ['API']
                            break
                        elif method == 'MNE':
                            score = max(score, 0.85)
                            methods_matched.append('MNE')
                        elif method == 'CFG':
                            score = max(score, 0.80)
                            methods_matched.append('CFG')
                        elif method == 'PRO':
                            score = max(score, 0.70)
                            methods_matched.append('PRO')

                if score >= 0.70:  # High confidence threshold
                    candidates.append((func['address'], score, methods_matched))
    except Exception as e:
        pass

    return sorted(candidates, key=lambda x: x[1], reverse=True)

def generate_rename_map():
    """Generate comprehensive rename map."""
    print("Loading CSV reference...")
    csv_funcs = load_csv_functions()
    print(f"  Loaded {len(csv_funcs)} functions\n")

    # Filter to multi-version functions
    multi_ver_funcs = {
        name: data for name, data in csv_funcs.items()
        if len(data['versions_in_csv']) >= 2
    }

    print(f"Multi-version functions: {len(multi_ver_funcs)}")

    lod_versions = [
        '1.07', '1.08', '1.09', '1.09b', '1.09d',
        '1.10', '1.11', '1.11b', '1.12a',
        '1.13c', '1.13d', '1.14a', '1.14b', '1.14c', '1.14d'
    ]

    rename_map = defaultdict(lambda: {
        'csv_info': {},
        'renames': {}  # by version
    })

    print("\n" + "="*70)
    print("Searching for candidates in LoD versions...\n")

    total_found = 0
    total_candidates = 0

    for func_name in sorted(multi_ver_funcs.keys()):
        data = multi_ver_funcs[func_name]
        module = data['module']

        if not module:
            continue

        rename_map[func_name]['csv_info'] = {
            'module': module,
            'csv_versions': data['versions_in_csv'],
            'confirmed_in': {}
        }

        # Try each LoD version
        for target_version in lod_versions:
            # First, check if already named
            found = find_in_function_index(func_name, module, target_version)
            if found and found['has_human_name']:
                rename_map[func_name]['csv_info']['confirmed_in'][target_version] = found['address']
                continue

            # Try to find anchor in any CSV version
            best_candidate = None
            best_score = 0.0

            for csv_version in data['versions_in_csv']:
                # Try to find this function in the CSV version (within LoD)
                anchor = find_in_function_index(func_name, module, csv_version.split('_')[0] if '_' in csv_version else csv_version)

                if not anchor:
                    continue

                # Found anchor, now find candidates in target
                candidates = find_candidates_by_index(anchor, module, target_version)

                if candidates:
                    addr, score, methods = candidates[0]
                    if score > best_score:
                        best_score = score
                        best_candidate = {
                            'address': addr,
                            'score': score,
                            'methods': '+'.join(methods),
                            'source_version': csv_version
                        }

            if best_candidate and best_score >= 0.70:
                rename_map[func_name]['renames'][target_version] = best_candidate
                total_candidates += 1

    # Report results
    print("Results by Module:\n")

    by_module = defaultdict(lambda: {'found': 0, 'candidates': 0})

    for func_name in sorted(rename_map.keys()):
        data = rename_map[func_name]
        module = data['csv_info']['module']

        confirmed = len(data['csv_info']['confirmed_in'])
        candidates = len(data['renames'])

        if confirmed > 0 or candidates > 0:
            by_module[module]['found'] += confirmed
            by_module[module]['candidates'] += candidates
            total_found += confirmed

    for module in sorted(by_module.keys()):
        stats = by_module[module]
        print(f"{module}:")
        print(f"  Already named: {stats['found']}")
        print(f"  Rename candidates: {stats['candidates']}")

    print(f"\nTotal already named: {total_found}")
    print(f"Total candidates found: {total_candidates}")

    return rename_map, lod_versions

def generate_reports(rename_map, lod_versions):
    """Generate human-readable report and Ghidra commands."""

    # Human-readable report
    report = []
    report.append("CSV Function Rename Candidates")
    report.append("=" * 70)
    report.append(f"\nThis report shows functions from d2moo_known_functions.csv that were found")
    report.append(f"in the LoD version function indices.\n")

    by_module = defaultdict(list)

    for func_name in sorted(rename_map.keys()):
        data = rename_map[func_name]
        module = data['csv_info']['module']
        renames = data['renames']
        confirmed = data['csv_info']['confirmed_in']

        if renames or confirmed:
            by_module[module].append((func_name, data))

    for module in sorted(by_module.keys()):
        report.append(f"\n{module}")
        report.append("-" * 70)

        for func_name, data in sorted(by_module[module]):
            report.append(f"\n{func_name}")
            report.append(f"  CSV versions: {', '.join(data['csv_info']['csv_versions'])}")

            if data['csv_info']['confirmed_in']:
                report.append(f"  Already named in LoD:")
                for version, addr in sorted(data['csv_info']['confirmed_in'].items()):
                    report.append(f"    - {version}: {addr}")

            if data['renames']:
                report.append(f"  Rename candidates:")
                for version in sorted(data['renames'].keys()):
                    cand = data['renames'][version]
                    report.append(f"    - {version}: {cand['address']} (confidence={cand['score']:.2f}, method={cand['methods']})")

    # Write report
    report_text = '\n'.join(report)
    with open('reports/csv_rename_candidates.txt', 'w') as f:
        f.write(report_text)

    print("\n" + "="*70)
    print("\nReport written to: reports/csv_rename_candidates.txt")

    # Generate Ghidra script
    ghidra_script = []
    ghidra_script.append("// Auto-generated Ghidra script from CSV rename map")
    ghidra_script.append("// Source: d2moo_known_functions.csv")
    ghidra_script.append("")

    rename_count = 0

    for func_name in sorted(rename_map.keys()):
        data = rename_map[func_name]

        # Only include high-confidence candidates
        for version in sorted(data['renames'].keys()):
            cand = data['renames'][version]
            if cand['score'] >= 0.80:  # Only 80%+ confidence
                ghidra_script.append(f"// {func_name} in {version}")
                ghidra_script.append(f"renameFunction('{cand['address']}', '{func_name}');")
                ghidra_script.append("")
                rename_count += 1

    # Write Ghidra script
    script_text = '\n'.join(ghidra_script)
    with open('tools/apply_csv_renames.java', 'w') as f:
        f.write(script_text)

    print(f"Ghidra script written to: tools/apply_csv_renames.java ({rename_count} renames)")

    # Generate JSON map for programmatic use
    json_map = {}
    for func_name in sorted(rename_map.keys()):
        data = rename_map[func_name]
        if data['renames'] or data['csv_info']['confirmed_in']:
            json_map[func_name] = {
                'module': data['csv_info']['module'],
                'csv_versions': data['csv_info']['csv_versions'],
                'confirmed_in': data['csv_info']['confirmed_in'],
                'candidates': {v: {
                    'address': c['address'],
                    'confidence': c['score'],
                    'method': c['methods']
                } for v, c in data['renames'].items()}
            }

    with open('reports/csv_rename_map.json', 'w') as f:
        json.dump(json_map, f, indent=2)

    print(f"JSON map written to: reports/csv_rename_map.json")

if __name__ == '__main__':
    rename_map, lod_versions = generate_rename_map()
    generate_reports(rename_map, lod_versions)
