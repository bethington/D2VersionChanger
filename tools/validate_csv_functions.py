#!/usr/bin/env python3
"""
Validate CSV Functions - Check if each CSV function name actually exists
at the specified address in the function_index for that version.

This ensures we only use verified functions as anchors for cross-version matching.
"""

import csv
import json
import sys
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

def validate_csv_functions():
    """Validate each CSV function entry."""
    print("Loading and validating CSV functions...\n")

    # Read CSV
    csv_entries = []
    with open('artifacts/d2moo_known_functions.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            csv_entries.append({
                'name': row['name'],
                'version': row['version'],
                'module': row.get('module_hint', ''),
                'address': row['address_hex'],
                'signature': row.get('signature', ''),
            })

    print(f"Total CSV entries: {len(csv_entries)}\n")

    # Validate each entry
    validation_results = defaultdict(lambda: {
        'confirmed': [],  # (version, game_type, index_version, address, status)
        'not_found': [],
        'address_mismatch': [],
        'name_exists_elsewhere': []
    })

    print("="*70)
    print("Validating each CSV entry...\n")

    for entry in csv_entries:
        name = entry['name']
        csv_version = entry['version']
        module = entry['module']
        csv_address = entry['address']

        if not module:
            continue

        # Expand version
        target_versions = expand_csv_version(csv_version)

        for game_type, index_version in target_versions:
            index_path = Path('data/function_index') / game_type / index_version / f'{module}.dll.json'

            if not index_path.exists():
                validation_results[name]['not_found'].append({
                    'version': csv_version,
                    'index_version': index_version,
                    'game_type': game_type,
                    'reason': 'Index file not found'
                })
                continue

            try:
                with open(index_path, encoding='utf-8') as f:
                    data = json.load(f)

                # Look for this function name
                found_func = None
                for func in data.get('functions', []):
                    if func.get('name') == name:
                        found_func = func
                        break

                if found_func:
                    # Check if address matches
                    index_address = found_func.get('address', '')
                    if index_address == csv_address:
                        # Perfect match!
                        validation_results[name]['confirmed'].append({
                            'csv_version': csv_version,
                            'index_version': index_version,
                            'game_type': game_type,
                            'address': index_address,
                            'has_human_name': found_func.get('has_human_name', False),
                            'indexes': found_func.get('indexes', {})
                        })
                    else:
                        # Name found but address different
                        validation_results[name]['address_mismatch'].append({
                            'csv_version': csv_version,
                            'index_version': index_version,
                            'csv_address': csv_address,
                            'index_address': index_address,
                        })
                else:
                    # Name not found, check if address exists with different name
                    found_at_addr = None
                    for func in data.get('functions', []):
                        if func.get('address') == csv_address:
                            found_at_addr = func.get('name', '')
                            break

                    if found_at_addr:
                        validation_results[name]['address_mismatch'].append({
                            'csv_version': csv_version,
                            'index_version': index_version,
                            'csv_address': csv_address,
                            'actual_name_at_addr': found_at_addr,
                        })
                    else:
                        validation_results[name]['not_found'].append({
                            'version': csv_version,
                            'index_version': index_version,
                            'game_type': game_type,
                            'address': csv_address,
                            'reason': 'Function name not found in index'
                        })

            except Exception as e:
                validation_results[name]['not_found'].append({
                    'version': csv_version,
                    'index_version': index_version,
                    'reason': f'Error reading index: {e}'
                })

    # Generate report
    print("\n" + "="*70)
    print("VALIDATION REPORT\n")

    confirmed_count = 0
    issues_count = 0

    by_module = defaultdict(lambda: {'confirmed': 0, 'issues': 0})

    for func_name in sorted(validation_results.keys()):
        results = validation_results[func_name]

        if results['confirmed']:
            confirmed_count += len(results['confirmed'])

        if results['not_found'] or results['address_mismatch']:
            issues_count += len(results['not_found']) + len(results['address_mismatch'])

    # Show summary
    print(f"Total functions validated: {len(validation_results)}")
    print(f"  Confirmed matches: {confirmed_count}")
    print(f"  Issues found: {issues_count}")

    # Detailed report by status
    print("\n" + "="*70)
    print("CONFIRMED FUNCTIONS (Safe to use as anchors)\n")

    confirmed_by_module = defaultdict(list)

    for func_name in sorted(validation_results.keys()):
        results = validation_results[func_name]
        if results['confirmed']:
            for conf in results['confirmed']:
                module = None
                # Find module from CSV
                for entry in csv_entries:
                    if entry['name'] == func_name:
                        module = entry['module']
                        break

                if module:
                    confirmed_by_module[module].append((func_name, conf))

    for module in sorted(confirmed_by_module.keys()):
        funcs = confirmed_by_module[module]
        print(f"\n{module}: {len(funcs)} confirmed")
        for func_name, conf in sorted(funcs)[:10]:
            game_type = conf['game_type']
            version = conf['index_version']
            address = conf['address']
            has_name = conf['has_human_name']
            indexes = conf['indexes']
            index_methods = [m for m in ['EXP', 'STR', 'API', 'MNE', 'CFG', 'PRO'] if indexes.get(m)]

            print(f"  {func_name}")
            print(f"    {game_type}/{version}: {address} (has_human_name={has_name}, indexes={index_methods})")

        if len(funcs) > 10:
            print(f"  ... and {len(funcs) - 10} more")

    # Issues
    print("\n" + "="*70)
    print("FUNCTIONS WITH ISSUES\n")

    issues_by_module = defaultdict(list)

    for func_name in sorted(validation_results.keys()):
        results = validation_results[func_name]

        if results['not_found']:
            for issue in results['not_found']:
                module = None
                for entry in csv_entries:
                    if entry['name'] == func_name:
                        module = entry['module']
                        break
                if module:
                    issues_by_module[module].append((func_name, 'NOT_FOUND', issue))

        if results['address_mismatch']:
            for issue in results['address_mismatch']:
                module = None
                for entry in csv_entries:
                    if entry['name'] == func_name:
                        module = entry['module']
                        break
                if module:
                    issues_by_module[module].append((func_name, 'ADDRESS_MISMATCH', issue))

    for module in sorted(issues_by_module.keys()):
        issues = issues_by_module[module]
        print(f"\n{module}: {len(issues)} issues")
        for func_name, issue_type, details in sorted(issues, key=lambda x: x[0])[:10]:
            print(f"  {func_name}")
            print(f"    {issue_type}: {details}")

        if len(issues) > 10:
            print(f"  ... and {len(issues) - 10} more")

    # Save detailed JSON
    json_report = {
        'summary': {
            'total_entries': len(csv_entries),
            'confirmed': confirmed_count,
            'issues': issues_count
        },
        'by_function': {}
    }

    for func_name, results in validation_results.items():
        if results['confirmed'] or results['not_found'] or results['address_mismatch']:
            json_report['by_function'][func_name] = {
                'confirmed': results['confirmed'],
                'issues': {
                    'not_found': results['not_found'],
                    'address_mismatch': results['address_mismatch']
                }
            }

    Path('reports').mkdir(exist_ok=True)
    with open('reports/csv_validation_report.json', 'w') as f:
        json.dump(json_report, f, indent=2)

    print("\n\nDetailed JSON report: reports/csv_validation_report.json")

    return validation_results, csv_entries

if __name__ == '__main__':
    validation_results, csv_entries = validate_csv_functions()
