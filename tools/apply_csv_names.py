#!/usr/bin/env python3
"""
Apply CSV Names - Use d2moo reference to identify and rename functions across versions.
"""

import csv
import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional

def load_csv_functions():
    """Load functions from d2moo CSV."""
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
                'signature': row.get('signature', ''),
            })
    
    return dict(functions)

def load_function_index(version_path: str) -> Dict:
    """Load all functions from a version's index."""
    functions = {}
    version_dir = Path('data/function_index') / version_path
    
    if not version_dir.exists():
        return functions
    
    for dll_file in version_dir.glob('*.json'):
        try:
            with open(dll_file, encoding='utf-8') as f:
                data = json.load(f)
                for func in data.get('functions', []):
                    addr = func.get('address', '')
                    functions[addr] = {
                        'dll': dll_file.stem,
                        'name': func.get('name', ''),
                        'display_name': func.get('display_name', ''),
                        'has_human_name': func.get('has_human_name', False),
                        'indexes': func.get('indexes', {}),
                        'callees': func.get('callees', []),
                        'callers': func.get('callers', []),
                    }
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            print(f"Warning: Could not read {dll_file}: {e}", file=sys.stderr)
    
    return functions

def analyze_csv_matches():
    """Main analysis function."""
    csv_funcs = load_csv_functions()
    
    print(f"Loaded {len(csv_funcs)} functions from CSV\n")
    
    # Group by DLL
    by_dll = defaultdict(set)
    for name, versions in csv_funcs.items():
        for version, entries in versions.items():
            for entry in entries:
                if entry['module']:
                    by_dll[entry['module']].add(name)
    
    print("Functions by DLL:")
    for dll in sorted(by_dll.keys()):
        print(f"  {dll}: {len(by_dll[dll])} functions")
    
    # Find high-priority functions
    multi_version_funcs = {
        name: versions for name, versions in csv_funcs.items()
        if len(versions) >= 2
    }
    
    print(f"\nMulti-version functions: {len(multi_version_funcs)}")
    
    lod_versions = [
        'LoD/1.07', 'LoD/1.08', 'LoD/1.09', 'LoD/1.09b', 'LoD/1.09d',
        'LoD/1.10', 'LoD/1.11', 'LoD/1.11b', 'LoD/1.12a',
        'LoD/1.13c', 'LoD/1.13d', 'LoD/1.14a', 'LoD/1.14b', 'LoD/1.14c', 'LoD/1.14d'
    ]
    
    # Scan for matches
    print("\n" + "="*70)
    print("Searching for D2Common functions in LoD versions\n")
    
    d2common_funcs = multi_version_funcs
    
    rename_candidates = defaultdict(lambda: {'csv_data': None, 'matches': []})
    
    for func_name in sorted(d2common_funcs.keys())[:20]:  # Sample first 20
        csv_data = csv_funcs[func_name]
        
        # Get module from CSV
        module = None
        for version, entries in csv_data.items():
            if entries and entries[0]['module']:
                module = entries[0]['module']
                break
        
        if not module:
            continue
        
        rename_candidates[func_name]['csv_data'] = {
            'module': module,
            'versions': list(csv_data.keys())
        }
        
        # Search in LoD versions
        for lod_ver in lod_versions:
            idx = load_function_index(lod_ver)
            if not idx:
                continue
            
            # Find matching DLLs
            for addr, func in idx.items():
                if func['dll'] != module:
                    continue
                
                # Check if already named
                if func['has_human_name'] and func['name'] == func_name:
                    rename_candidates[func_name]['matches'].append({
                        'version': lod_ver,
                        'address': addr,
                        'status': 'already_named',
                        'confidence': 1.0
                    })
                elif not func['has_human_name']:
                    # This could be a candidate
                    rename_candidates[func_name]['matches'].append({
                        'version': lod_ver,
                        'address': addr,
                        'status': 'unnamed_candidate',
                        'confidence': 0.5
                    })
    
    # Report findings
    print("Rename candidates found:\n")
    for func_name in sorted(rename_candidates.keys()):
        data = rename_candidates[func_name]
        if not data['matches']:
            continue
        
        csv_info = data['csv_data']
        print(f"{func_name}")
        print(f"  CSV: {csv_info['module']} in versions {csv_info['versions']}")
        print(f"  Matches in LoD:")
        for match in data['matches']:
            print(f"    - {match['version']}: {match['address']} ({match['status']}, conf={match['confidence']:.2f})")
        print()

if __name__ == '__main__':
    analyze_csv_matches()
