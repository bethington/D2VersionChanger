#!/usr/bin/env python3
"""
Analyze unmatched functions - functions that only exist in one version.
Helps identify if matching can be improved or if these are legitimate unique functions.
"""

import json
from pathlib import Path
from collections import defaultdict

def load_registry():
    with open('reports/function_registry_v2.json') as f:
        return json.load(f)

def load_raw_exports(game_type, version, dll):
    """Load the raw Ghidra export for a specific version."""
    path = Path(f'data/function_index/{game_type}/{version}/{dll}.json')
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None

def analyze_unmatched():
    reg = load_registry()
    
    # Find single-version functions
    single_version = []
    for dll, funcs in reg['dlls'].items():
        for func in funcs:
            if func['version_count'] == 1:
                ver = list(func.get('versions', {}).keys())[0]
                single_version.append({
                    'dll': dll,
                    'canonical_id': func['canonical_id'],
                    'index': func.get('index', ''),
                    'method': func.get('index_method', ''),
                    'name': func.get('name', ''),
                    'version': ver,
                    'address': func['versions'][ver].get('address', ''),
                    'rva': func['versions'][ver].get('rva', ''),
                    'size': func['versions'][ver].get('size', 0),
                })
    
    print(f"Total single-version functions: {len(single_version)}")
    print()
    
    # Group by DLL and version
    by_dll = defaultdict(lambda: {'LoD/1.07': [], 'LoD/1.08': []})
    for f in single_version:
        by_dll[f['dll']][f['version']].append(f)
    
    print("=" * 70)
    print("SUMMARY BY DLL")
    print("=" * 70)
    print(f"{'DLL':<22} {'1.07-only':>10} {'1.08-only':>10}")
    print("-" * 45)
    
    for dll in sorted(by_dll.keys()):
        c107 = len(by_dll[dll]['LoD/1.07'])
        c108 = len(by_dll[dll]['LoD/1.08'])
        if c107 > 0 or c108 > 0:
            print(f"{dll:<22} {c107:>10} {c108:>10}")
    
    print()
    
    # Analyze specific DLLs with many unmatched
    problem_dlls = ['D2Common.dll', 'D2Client.dll', 'D2Game.dll', 'Storm.dll', 'Fog.dll']
    
    for dll in problem_dlls:
        if dll not in by_dll:
            continue
        
        v107_only = by_dll[dll]['LoD/1.07']
        v108_only = by_dll[dll]['LoD/1.08']
        
        if not v107_only and not v108_only:
            continue
            
        print("=" * 70)
        print(f"ANALYSIS: {dll}")
        print("=" * 70)
        
        # Load raw data for deeper analysis
        raw_107 = load_raw_exports('LoD', '1.07', dll)
        raw_108 = load_raw_exports('LoD', '1.08', dll)
        
        # Analyze 1.07-only functions
        if v107_only:
            print(f"\n1.07-only functions ({len(v107_only)}):")
            print("-" * 50)
            
            # Group by method
            by_method = defaultdict(list)
            for f in v107_only:
                by_method[f['method']].append(f)
            
            for method, funcs in sorted(by_method.items()):
                print(f"  {method}: {len(funcs)} functions")
            
            # Sample some functions
            print("\n  Sample 1.07-only functions:")
            for f in v107_only[:8]:
                name = f['name'] or f['canonical_id']
                print(f"    {f['rva']}: {name[:40]} (method={f['method']}, size={f['size']})")
                
                # Check if there's a similar function in 1.08 by size
                if raw_108:
                    similar = [fn for fn in raw_108['functions'] 
                               if fn.get('size') == f['size'] and f['size'] and f['size'] > 20]
                    if similar and len(similar) < 5:
                        print(f"      Possible 1.08 matches by size ({f['size']} bytes): {len(similar)}")
                        for s in similar[:2]:
                            s_name = s.get('name', s.get('rva', ''))
                            print(f"        {s.get('rva')}: {s_name[:30]}")
        
        # Analyze 1.08-only functions
        if v108_only:
            print(f"\n1.08-only functions ({len(v108_only)}):")
            print("-" * 50)
            
            by_method = defaultdict(list)
            for f in v108_only:
                by_method[f['method']].append(f)
            
            for method, funcs in sorted(by_method.items()):
                print(f"  {method}: {len(funcs)} functions")
            
            print("\n  Sample 1.08-only functions:")
            for f in v108_only[:8]:
                name = f['name'] or f['canonical_id']
                print(f"    {f['rva']}: {name[:40]} (method={f['method']}, size={f['size']})")
        
        print()

def check_potential_matches():
    """Check if any unmatched functions could potentially match via alternate indexes."""
    print("\n" + "=" * 70)
    print("CHECKING FOR ACTUAL MERGE FAILURES")
    print("=" * 70)
    
    # Load the merged registry
    registry_path = Path('reports/function_registry_v2.json')
    if not registry_path.exists():
        print("Error: Registry not found")
        return
    
    with open(registry_path) as f:
        registry = json.load(f)
    
    functions = registry.get('functions', {})
    
    # Build reverse lookup: dll/version/rva -> canonical_id
    addr_to_canonical = {}
    for cid, func in functions.items():
        dll = func.get('dll', '')
        for ver, vdata in func.get('versions', {}).items():
            rva = vdata.get('rva')
            if rva:
                key = f"{dll}:{ver}:{rva}"
                addr_to_canonical[key] = cid
    
    # Load raw exports
    raw_107 = {}
    raw_108 = {}
    
    for dll_path in Path('data/function_index/LoD/1.07').glob('*.json'):
        dll = dll_path.stem
        with open(dll_path) as f:
            raw_107[dll] = json.load(f)
    
    for dll_path in Path('data/function_index/LoD/1.08').glob('*.json'):
        dll = dll_path.stem
        with open(dll_path) as f:
            raw_108[dll] = json.load(f)
    
    # Check each DLL for functions that share indexes but ended up in different canonical entries
    total_failures = 0
    failure_details = []
    
    for dll in sorted(raw_107.keys()):
        if dll not in raw_108:
            continue
        
        # Build all indexes for 1.08
        idx_108 = {}  # index -> (rva, func)
        for func in raw_108[dll]['functions']:
            for method, hash_val in func.get('indexes', {}).items():
                if hash_val and method != 'EXP':
                    key = f"{method}:{hash_val}"
                    if key not in idx_108:
                        idx_108[key] = []
                    idx_108[key].append((func.get('rva'), func))
        
        dll_failures = 0
        
        for func_107 in raw_107[dll]['functions']:
            rva_107 = func_107.get('rva')
            indexes_107 = func_107.get('indexes', {})
            
            # Get this function's canonical ID
            cid_107 = addr_to_canonical.get(f"{dll}:LoD/1.07:{rva_107}")
            if not cid_107:
                continue
            
            for method, hash_val in indexes_107.items():
                if not hash_val or method == 'EXP':
                    continue
                
                key = f"{method}:{hash_val}"
                if key not in idx_108:
                    continue
                
                for rva_108, func_108 in idx_108[key]:
                    cid_108 = addr_to_canonical.get(f"{dll}:LoD/1.08:{rva_108}")
                    if not cid_108:
                        continue
                    
                    if cid_107 != cid_108:
                        # Different canonical IDs but share an index - merge failure!
                        dll_failures += 1
                        if dll_failures <= 5:  # Limit details
                            failure_details.append({
                                'dll': dll,
                                'method': method,
                                'rva_107': rva_107,
                                'rva_108': rva_108,
                                'cid_107': cid_107,
                                'cid_108': cid_108,
                                'primary_107': func_107.get('index_method'),
                                'primary_108': func_108.get('index_method'),
                            })
                        break
        
        if dll_failures:
            print(f"\n{dll}: {dll_failures} pairs share an index but have different canonical IDs")
            total_failures += dll_failures
    
    print(f"\n" + "-" * 70)
    print(f"Total potential merge failures: {total_failures}")
    
    if failure_details:
        print(f"\nSample failures (showing first {len(failure_details)}):")
        for f in failure_details:
            print(f"  {f['dll']}: {f['rva_107']} (cid={f['cid_107'][:30]})")
            print(f"       vs {f['rva_108']} (cid={f['cid_108'][:30]})")
            print(f"       shared: {f['method']}, primaries: {f['primary_107']} / {f['primary_108']}")

if __name__ == '__main__':
    analyze_unmatched()
    check_potential_matches()
