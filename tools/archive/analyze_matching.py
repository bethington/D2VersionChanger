#!/usr/bin/env python3
"""Analyze function matching between versions."""

import json
from pathlib import Path
from collections import defaultdict

def load_export(ver, dll="D2Client.dll"):
    p = Path(f'data/function_index/LoD/{ver}/{dll}.json')
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return None

def build_index(data):
    """Build lookup index from export data."""
    idx = {}
    for f in data['functions']:
        for method, val in f.get('indexes', {}).items():
            if val and method != 'EXP':
                key = f'{method}:{val}'
                if key not in idx:
                    idx[key] = []
                idx[key].append(f)
    return idx

def compare_versions(ver1, ver2, dll="D2Client.dll"):
    """Compare two versions and report matching stats."""
    d1 = load_export(ver1, dll)
    d2 = load_export(ver2, dll)
    
    if not d1 or not d2:
        print(f"Missing data for {ver1} or {ver2}")
        return
    
    idx1 = build_index(d1)
    
    matched = 0
    unmatched = []
    matched_by_method = defaultdict(int)
    
    for f in d2['functions']:
        found = False
        match_method = None
        for method in ['STR', 'API', 'MNE', 'CFG', 'PRO']:
            val = f.get('indexes', {}).get(method)
            if val:
                key = f'{method}:{val}'
                if key in idx1:
                    found = True
                    match_method = method
                    break
        
        if found:
            matched += 1
            matched_by_method[match_method] += 1
        else:
            unmatched.append(f)
    
    print(f"\n{dll}: {ver1} -> {ver2}")
    print(f"  {ver1} functions: {len(d1['functions'])}")
    print(f"  {ver2} functions: {len(d2['functions'])}")
    print(f"  Matched: {matched} ({matched/len(d2['functions'])*100:.1f}%)")
    print(f"  Unmatched: {len(unmatched)}")
    
    print(f"\n  Matched by method:")
    for method in ['STR', 'API', 'MNE', 'CFG', 'PRO']:
        if matched_by_method[method]:
            print(f"    {method}: {matched_by_method[method]}")
    
    return unmatched

def analyze_unmatched(unmatched, limit=20):
    """Analyze why functions didn't match."""
    print(f"\n  Sample unmatched functions ({len(unmatched)} total):")
    
    by_method = defaultdict(list)
    for f in unmatched:
        by_method[f.get('index_method', 'UNK')].append(f)
    
    print(f"\n  Unmatched by primary method:")
    for method, funcs in sorted(by_method.items()):
        print(f"    {method}: {len(funcs)}")
    
    print(f"\n  Sample unmatched (first {limit}):")
    for f in unmatched[:limit]:
        name = f.get('name') or f.get('display_name', 'FUN_???')
        name = name[:45]
        indexes = f.get('indexes', {})
        has_str = 'Y' if indexes.get('STR') else 'N'
        has_api = 'Y' if indexes.get('API') else 'N'
        has_mne = 'Y' if indexes.get('MNE') else 'N'
        print(f"    {f['rva']:>8}: {name:<45} STR={has_str} API={has_api} MNE={has_mne} size={f.get('size', 0)}")

def check_near_matches(ver1, ver2, dll="D2Client.dll"):
    """Check if unmatched functions have similar characteristics."""
    d1 = load_export(ver1, dll)
    d2 = load_export(ver2, dll)
    
    if not d1 or not d2:
        return
    
    idx1 = build_index(d1)
    
    # Find unmatched in d2
    unmatched = []
    for f in d2['functions']:
        found = False
        for method in ['STR', 'API', 'MNE', 'CFG', 'PRO']:
            val = f.get('indexes', {}).get(method)
            if val:
                key = f'{method}:{val}'
                if key in idx1:
                    found = True
                    break
        if not found:
            unmatched.append(f)
    
    # Build size index for d1
    size_idx = defaultdict(list)
    for f in d1['functions']:
        size_idx[f.get('size', 0)].append(f)
    
    print(f"\n  Checking size-based near-matches for {len(unmatched)} unmatched:")
    size_matches = 0
    for f in unmatched:
        size = f.get('size', 0)
        if size in size_idx and len(size_idx[size]) == 1:
            # Unique size match
            size_matches += 1
    
    print(f"    Unique size matches possible: {size_matches}")

def main():
    print("=" * 70)
    print("FUNCTION MATCHING ANALYSIS")
    print("=" * 70)
    
    # Compare consecutive versions
    versions = ['1.07', '1.08', '1.09', '1.09b', '1.09d', '1.10', '1.11', '1.11b', '1.12a', '1.13c', '1.13d']
    
    for i in range(len(versions) - 1):
        unmatched = compare_versions(versions[i], versions[i+1])
        if unmatched:
            analyze_unmatched(unmatched, limit=10)
            check_near_matches(versions[i], versions[i+1])
    
    # Deep dive on problematic transitions
    print("\n" + "=" * 70)
    print("DEEP DIVE: 1.09d -> 1.10 TRANSITION")
    print("=" * 70)
    deep_analyze('1.09d', '1.10')

def deep_analyze(ver1, ver2, dll="D2Client.dll"):
    """Deep analysis of why functions don't match."""
    d1 = load_export(ver1, dll)
    d2 = load_export(ver2, dll)
    
    if not d1 or not d2:
        return
    
    # Build comprehensive indexes for ver1
    api_idx = {}
    mne_idx = {}
    str_idx = {}
    cfg_idx = {}
    
    for f in d1['functions']:
        indexes = f.get('indexes', {})
        if indexes.get('API'):
            api_idx[indexes['API']] = f
        if indexes.get('MNE'):
            mne_idx[indexes['MNE']] = f
        if indexes.get('STR'):
            str_idx[indexes['STR']] = f
        if indexes.get('CFG'):
            cfg_idx[indexes['CFG']] = f
    
    # Categorize unmatched functions
    unmatched = []
    partial_matches = []  # Has one index match but not the primary
    
    for f in d2['functions']:
        indexes = f.get('indexes', {})
        
        matches = {
            'API': indexes.get('API') in api_idx if indexes.get('API') else False,
            'MNE': indexes.get('MNE') in mne_idx if indexes.get('MNE') else False,
            'STR': indexes.get('STR') in str_idx if indexes.get('STR') else False,
            'CFG': indexes.get('CFG') in cfg_idx if indexes.get('CFG') else False,
        }
        
        any_match = any(matches.values())
        primary = f.get('index_method', '')
        primary_matches = matches.get(primary, False)
        
        if not any_match:
            unmatched.append(f)
        elif not primary_matches:
            partial_matches.append((f, matches))
    
    print(f"\nTotal {ver2} functions: {len(d2['functions'])}")
    print(f"Completely unmatched (no index hits): {len(unmatched)}")
    print(f"Partial matches (secondary index only): {len(partial_matches)}")
    
    print(f"\nPartial match analysis (first 20):")
    for f, matches in partial_matches[:20]:
        name = (f.get('name') or 'FUN_???')[:30]
        primary = f.get('index_method', '')
        matched_methods = [m for m, v in matches.items() if v]
        print(f"  {f['rva']:>8}: {name:<30} primary={primary} matches={matched_methods}")
    
    # Check if partial matches are due to hash collisions or actual matches
    print(f"\nVerifying partial matches are real:")
    for f, matches in partial_matches[:5]:
        indexes = f.get('indexes', {})
        for method, matched in matches.items():
            if matched and method != f.get('index_method'):
                hash_val = indexes.get(method)
                if method == 'MNE' and hash_val in mne_idx:
                    orig = mne_idx[hash_val]
                    print(f"\n  {ver2} {f['rva']} (size={f.get('size')}) matches via MNE to:")
                    print(f"    {ver1} {orig['rva']} (size={orig.get('size')}) name={orig.get('name', 'FUN_')[:40]}")
                    break

if __name__ == '__main__':
    main()
