#!/usr/bin/env python3
"""
Validate CSV/JSON Functions - Cross-reference CSV with function_index.

Uses the JSON version of the CSV for better data structure and additional fields.
Creates a mapping showing:
1. Functions the CSV claims exist
2. What's actually in function_index at that address
3. Whether we should RENAME or ACCEPT the function_index name
"""

import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

def expand_csv_version(csv_version: str) -> List[Tuple[str, str]]:
    """Expand CSV version to function_index versions."""
    if csv_version == '1.00':
        return [('Classic', '1.00')]

    if csv_version.startswith('1.10'):
        return [('LoD', '1.10')]

    if csv_version.startswith('1.13'):
        if csv_version == '1.13c':
            return [('LoD', '1.13c')]
        else:  # 1.13f covers 1.13c and 1.13d
            return [('LoD', '1.13c'), ('LoD', '1.13d')]

    if csv_version.startswith('1.14'):
        return [('LoD', csv_version)]

    return []

def validate_with_json():
    """Validate using JSON CSV data."""
    print("Loading CSV from JSON...")
    with open('artifacts/d2moo_known_functions.json', 'r', encoding='utf-8') as f:
        csv_entries = json.load(f)

    print(f"  Loaded {len(csv_entries)} entries\n")

    # Group by function name and module
    functions_by_name = defaultdict(lambda: {
        'module': None,
        'entries': []  # (version, address_hex, signature)
    })

    for entry in csv_entries:
        name = entry['name']
        module = entry.get('module_hint', '')
        version = entry['version']
        address = entry['address_hex']
        signature = entry.get('signature', '')
        kind = entry.get('kind', '')

        functions_by_name[name]['module'] = module
        functions_by_name[name]['entries'].append({
            'version': version,
            'address': address,
            'signature': signature,
            'kind': kind
        })

    print(f"Unique function names in CSV: {len(functions_by_name)}\n")

    # Now validate each against function_index
    print("="*80)
    print("Validating against function_index...\n")

    validation_results = defaultdict(lambda: {
        'module': None,
        'csv_entries': [],
        'matches': [],  # function exists at expected address
        'renamed': [],  # function exists at address but with different name
        'missing': [],  # function not found
        'recommendations': []
    })

    for func_name in sorted(functions_by_name.keys()):
        func_data = functions_by_name[func_name]
        module = func_data['module']

        if not module:
            continue

        validation_results[func_name]['module'] = module
        validation_results[func_name]['csv_entries'] = func_data['entries']

        # Check each CSV entry
        for entry in func_data['entries']:
            csv_version = entry['version']
            csv_address = entry['address']
            csv_signature = entry['signature']

            # Expand to function_index versions
            target_versions = expand_csv_version(csv_version)

            for game_type, index_version in target_versions:
                index_path = Path('data/function_index') / game_type / index_version / f'{module}.dll.json'

                if not index_path.exists():
                    validation_results[func_name]['missing'].append({
                        'version': csv_version,
                        'index_version': index_version,
                        'address': csv_address,
                        'reason': 'Index file missing'
                    })
                    continue

                try:
                    with open(index_path, encoding='utf-8') as f:
                        index_data = json.load(f)

                    # Look for function at this address
                    found_func = None
                    for func in index_data.get('functions', []):
                        if func.get('address') == csv_address:
                            found_func = func
                            break

                    if found_func:
                        index_name = found_func.get('name', '')
                        has_human_name = found_func.get('has_human_name', False)

                        if index_name == func_name:
                            # Exact match!
                            validation_results[func_name]['matches'].append({
                                'version': csv_version,
                                'index_version': index_version,
                                'game_type': game_type,
                                'address': csv_address,
                                'has_human_name': has_human_name,
                                'indexes': found_func.get('indexes', {})
                            })
                        else:
                            # Different name
                            validation_results[func_name]['renamed'].append({
                                'version': csv_version,
                                'index_version': index_version,
                                'game_type': game_type,
                                'address': csv_address,
                                'current_name': index_name,
                                'has_human_name': has_human_name,
                                'csv_signature': csv_signature,
                                'indexes': found_func.get('indexes', {})
                            })
                    else:
                        validation_results[func_name]['missing'].append({
                            'version': csv_version,
                            'index_version': index_version,
                            'address': csv_address,
                            'reason': 'No function at this address'
                        })

                except Exception as e:
                    validation_results[func_name]['missing'].append({
                        'version': csv_version,
                        'index_version': index_version,
                        'address': csv_address,
                        'reason': f'Error: {e}'
                    })

    # Generate recommendations
    for func_name, data in validation_results.items():
        if data['matches']:
            data['recommendations'].append('ALREADY_NAMED - Use as anchor for cross-version matching')

        if data['renamed']:
            has_multiple_names = len(set(r['current_name'] for r in data['renamed'])) > 1
            if has_multiple_names:
                data['recommendations'].append('RENAME_CONFLICT - Function has different names in different versions')
            else:
                # Same name everywhere
                current_name = data['renamed'][0]['current_name']
                if current_name.startswith('FUN_'):
                    data['recommendations'].append(f'RENAME_CANDIDATE - Currently named "{current_name}", CSV suggests "{func_name}"')
                elif current_name.startswith('Ordinal_'):
                    data['recommendations'].append(f'RENAME_CANDIDATE - Ordinal function, CSV provides proper name "{func_name}"')
                else:
                    data['recommendations'].append(f'NAME_MISMATCH - Currently "{current_name}", CSV says "{func_name}" - NEEDS REVIEW')

    # Report
    print("VALIDATION SUMMARY\n")

    total_entries = len(csv_entries)
    total_funcs = len(validation_results)
    matched = sum(1 for d in validation_results.values() if d['matches'])
    renamed = sum(1 for d in validation_results.values() if d['renamed'])
    missing = sum(1 for d in validation_results.values() if d['missing'])

    print(f"CSV entries: {total_entries}")
    print(f"Unique functions: {total_funcs}")
    print(f"  Already correctly named: {matched}")
    print(f"  Need renaming/review: {renamed}")
    print(f"  Missing from index: {missing}")

    # Detailed breakdown by module
    print("\n" + "="*80)
    print("BY MODULE\n")

    by_module = defaultdict(lambda: {'matched': 0, 'renamed': 0, 'missing': 0})

    for func_name, data in validation_results.items():
        module = data['module']
        if data['matches']:
            by_module[module]['matched'] += 1
        if data['renamed']:
            by_module[module]['renamed'] += 1
        if data['missing']:
            by_module[module]['missing'] += 1

    for module in sorted(by_module.keys()):
        stats = by_module[module]
        total = stats['matched'] + stats['renamed'] + stats['missing']
        print(f"{module}: {total} functions")
        print(f"  [OK] Correctly named: {stats['matched']}")
        print(f"  [->] Needs renaming: {stats['renamed']}")
        print(f"  [XX] Missing: {stats['missing']}\n")

    # Show functions needing action
    print("="*80)
    print("FUNCTIONS NEEDING RENAMING (high priority)\n")

    rename_candidates = []

    for func_name in sorted(validation_results.keys()):
        data = validation_results[func_name]

        if not data['renamed']:
            continue

        # Check consistency - same name in all versions?
        names_seen = set(r['current_name'] for r in data['renamed'])

        if len(names_seen) == 1:
            current_name = data['renamed'][0]['current_name']

            # Only suggest rename if current is generic or ordinal
            if current_name.startswith('FUN_') or current_name.startswith('Ordinal_'):
                rename_candidates.append({
                    'csv_name': func_name,
                    'current_name': current_name,
                    'module': data['module'],
                    'versions': [r['index_version'] for r in data['renamed']],
                    'addresses': [r['address'] for r in data['renamed']],
                    'recommendation': 'SAFE_TO_RENAME'
                })

    print(f"Found {len(rename_candidates)} safe rename candidates:\n")

    by_module = defaultdict(list)
    for cand in rename_candidates:
        by_module[cand['module']].append(cand)

    for module in sorted(by_module.keys()):
        cands = by_module[module]
        print(f"{module}: {len(cands)} functions\n")

        for cand in sorted(cands, key=lambda x: x['csv_name'])[:10]:
            print(f"  {cand['csv_name']}")
            print(f"    Current: {cand['current_name']}")
            print(f"    Versions: {cand['versions']}")
            print(f"    Addresses: {cand['addresses'][:2]}")  # Show first 2
            print()

        if len(cands) > 10:
            print(f"  ... and {len(cands) - 10} more\n")

    # Save detailed report
    Path('reports').mkdir(exist_ok=True)

    report_data = {
        'summary': {
            'total_csv_entries': total_entries,
            'unique_functions': total_funcs,
            'correctly_named': matched,
            'needs_renaming': renamed,
            'missing': missing
        },
        'by_module': dict(by_module),
        'rename_candidates': rename_candidates,
        'validation_details': {
            name: {
                'module': data['module'],
                'csv_entries': data['csv_entries'],
                'matches': data['matches'],
                'renamed': data['renamed'],
                'missing': data['missing'],
                'recommendations': data['recommendations']
            }
            for name, data in validation_results.items()
            if data['matches'] or data['renamed']
        }
    }

    with open('reports/csv_validation_detailed.json', 'w') as f:
        json.dump(report_data, f, indent=2)

    print("\nDetailed report: reports/csv_validation_detailed.json")

    return validation_results, rename_candidates

if __name__ == '__main__':
    validation_results, rename_candidates = validate_with_json()
