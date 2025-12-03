#!/usr/bin/env python3
"""Deep investigation of why functions aren't matching across versions."""

import json
from pathlib import Path
from collections import defaultdict

def load_export(ver, dll="D2Client.dll"):
    p = Path(f'data/function_index/LoD/{ver}/{dll}.json')
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return None

def main():
    versions = ['1.07', '1.08', '1.09', '1.09b', '1.09d', '1.10', '1.11', '1.11b', '1.12a', '1.13c', '1.13d']
    
    print("=" * 70)
    print("DEEP INVESTIGATION: Why aren't functions matching?")
    print("=" * 70)
    
    # Load all versions
    exports = {}
    for ver in versions:
        data = load_export(ver)
        if data:
            exports[ver] = data
            print(f"Loaded {ver}: {len(data['functions'])} functions")
    
    # Build a chain analysis - track functions through consecutive versions
    print("\n" + "=" * 70)
    print("CHAIN ANALYSIS: Tracking function 'survival' across versions")
    print("=" * 70)
    
    # Start with 1.07 and track each function through versions
    base_ver = '1.07'
    base_funcs = exports[base_ver]['functions']
    
    # Build all indexes for each version
    all_indexes = {}
    for ver, data in exports.items():
        idx = {'STR': {}, 'API': {}, 'MNE': {}, 'CFG': {}, 'PRO': {}}
        for f in data['functions']:
            for method in idx.keys():
                val = f.get('indexes', {}).get(method)
                if val:
                    if val not in idx[method]:
                        idx[method][val] = []
                    idx[method][val].append(f)
        all_indexes[ver] = idx
    
    # Track each 1.07 function
    chain_lengths = defaultdict(int)
    broken_at = defaultdict(int)
    
    for func in base_funcs[:500]:  # Sample first 500
        # Try to follow this function through versions
        current_indexes = func.get('indexes', {})
        chain = [base_ver]
        
        for ver in versions[1:]:  # Skip 1.07
            found = False
            for method in ['STR', 'API', 'MNE', 'CFG']:
                val = current_indexes.get(method)
                if val and val in all_indexes[ver][method]:
                    # Found it!
                    found = True
                    # Update current indexes for next iteration
                    matched_func = all_indexes[ver][method][val][0]
                    current_indexes = matched_func.get('indexes', {})
                    chain.append(ver)
                    break
            
            if not found:
                broken_at[ver] += 1
                break
        
        chain_lengths[len(chain)] += 1
    
    print("\nChain lengths (how many versions a function survives):")
    for length in sorted(chain_lengths.keys()):
        print(f"  {length} versions: {chain_lengths[length]} functions")
    
    print("\nWhere chains break (version where tracking is lost):")
    for ver in versions[1:]:
        if broken_at[ver] > 0:
            print(f"  {ver}: {broken_at[ver]} functions lost")
    
    # Deep dive into 1.09d -> 1.10 break
    print("\n" + "=" * 70)
    print("DEEP DIVE: 1.09d -> 1.10 transition")
    print("=" * 70)
    
    # Find functions that exist in 1.09d but NOT in 1.10 via any index
    d109d = exports['1.09d']
    d110 = exports['1.10']
    
    lost_functions = []
    for func in d109d['functions']:
        indexes = func.get('indexes', {})
        found = False
        for method in ['STR', 'API', 'MNE', 'CFG']:
            val = indexes.get(method)
            if val and val in all_indexes['1.10'][method]:
                found = True
                break
        if not found:
            lost_functions.append(func)
    
    print(f"\nFunctions in 1.09d with NO match in 1.10: {len(lost_functions)}")
    
    # Analyze why they don't match
    print("\nAnalyzing WHY they don't match (sample of 20):")
    for func in lost_functions[:20]:
        name = func.get('name') or 'FUN_???'
        indexes = func.get('indexes', {})
        
        # Check what indexes they have
        has_str = bool(indexes.get('STR'))
        has_api = bool(indexes.get('API'))
        has_mne = bool(indexes.get('MNE'))
        has_cfg = bool(indexes.get('CFG'))
        
        # Try to find similar functions in 1.10 by size
        size = func.get('size', 0)
        similar_in_110 = [f for f in d110['functions'] if f.get('size') == size]
        
        print(f"\n  {func['rva']}: {name[:35]}")
        print(f"    Size: {size}, Has: STR={has_str} API={has_api} MNE={has_mne} CFG={has_cfg}")
        print(f"    Similar size in 1.10: {len(similar_in_110)} functions")
        
        if similar_in_110 and len(similar_in_110) <= 3:
            for sf in similar_in_110[:2]:
                sf_name = sf.get('name') or 'FUN_???'
                print(f"      -> {sf['rva']}: {sf_name[:35]}")

    # Check the reverse - new functions in 1.10
    print("\n" + "=" * 70)
    print("NEW functions in 1.10 (not in 1.09d)")
    print("=" * 70)
    
    new_in_110 = []
    for func in d110['functions']:
        indexes = func.get('indexes', {})
        found = False
        for method in ['STR', 'API', 'MNE', 'CFG']:
            val = indexes.get(method)
            if val and val in all_indexes['1.09d'][method]:
                found = True
                break
        if not found:
            new_in_110.append(func)
    
    print(f"Functions in 1.10 with NO match in 1.09d: {len(new_in_110)}")
    
    # This suggests the total "unique" functions between the two versions
    print(f"\n1.09d functions: {len(d109d['functions'])}")
    print(f"1.10 functions: {len(d110['functions'])}")
    print(f"Lost from 1.09d: {len(lost_functions)}")
    print(f"New in 1.10: {len(new_in_110)}")
    print(f"Matched: {len(d109d['functions']) - len(lost_functions)}")

if __name__ == '__main__':
    main()
