#!/usr/bin/env python3
"""
Trace COLLISION_TrySetUnitCollisionMask across all D2 LoD versions.

CONFIRMED via d2moo and decompilation analysis:
- 9 parameters: pRoom1, nX1, nY1, pRoom2, nX2, nY2, nCollisionPattern, nFootprintCollisionMask, nMoveConditionMask
- Has alternative region lookup (FindRegionByCoordinates/Ordinal_10035)
- Has two-path ApplyTileAttributePattern (primary + fallback)
- Size varies: 536 (1.07-1.09d) -> 454 (1.10) -> 476 (1.11+)

The function named "ValidateRegionWithAlternative" in 1.07 IS the correct match.
The function named "QueryRoomCellAttributePattern" is a DIFFERENT function (8 params, simpler logic).
"""
import json
import os
from pathlib import Path

INDEX_DIR = Path('data/function_index/LoD')

# Key callees that identify this function
TARGET_CALLEES = {'ClearMapCellFlagRadius', 'ApplyTileAttributePattern'}

# CONFIRMED addresses based on decompilation analysis (9 params, boundary check, alt lookup)
KNOWN_ADDRESSES = {
    '1.07': '0x6FD638E0',   # ValidateRegionWithAlternative (size 536) - CONFIRMED
    '1.08': '0x6FD638E0',   # Same as 1.07 (ValidateRegionWithAlternative)
    '1.09': '0x6FD438F0',   # ValidateRegionWithAlternative (size 536)
    '1.09b': '0x6FD438F0',  # ValidateRegionWithAlternative (size 536)
    '1.09d': '0x6FD438F0',  # ValidateRegionWithAlternative (size 536)
    '1.10': '0x6FD44FF0',   # FUN_6fd44ff0 (size 454) - CONFIRMED via d2moo
}

def load_version_data(version):
    """Load D2Common function index for a version."""
    path = INDEX_DIR / version / 'D2Common.dll.json'
    if not path.exists():
        return None
    try:
        return json.load(open(path, encoding='utf-8'))
    except:
        return None

def find_matching_function(data, target_callees, prefer_larger=True):
    """Find functions matching the callee pattern.
    
    For COLLISION_TrySetUnitCollisionMask, we prefer the LARGER function (536 bytes in 1.07-1.09d)
    because it has the alternative region lookup logic.
    """
    candidates = []
    for f in data.get('functions', []):
        calls = set(f.get('api_calls', []))
        
        # Must call both key functions
        if not target_callees.issubset(calls):
            continue
            
        candidates.append(f)
    
    return candidates

def main():
    print("=" * 80)
    print("COLLISION_TrySetUnitCollisionMask Version Tracking (CORRECTED)")
    print("=" * 80)
    print()
    print("Reference (d2moo 1.10f):")
    print("  Address: 0x6FD44FF0")
    print("  Signature: int __fastcall COLLISION_TrySetUnitCollisionMask(")
    print("      D2ActiveRoomStrc* pRoom1, int nX1, int nY1,")
    print("      D2ActiveRoomStrc* pRoom2, int nX2, int nY2,")
    print("      int nCollisionPattern, uint16_t nFootprintCollisionMask,")
    print("      uint16_t nMoveConditionMask)")
    print()
    print("Key identifiers:")
    print("  - 9 parameters (2 rooms, 2 coordinate sets)")
    print("  - Alternative region lookup (FindRegionByCoordinates)")
    print("  - Two-path ApplyTileAttributePattern (primary + fallback)")
    print()
    
    # Get all versions
    versions = sorted([d.name for d in INDEX_DIR.iterdir() if d.is_dir()])
    
    print("=" * 80)
    print("Tracking across all LoD versions:")
    print("=" * 80)
    print()
    
    results = []
    
    for version in versions:
        data = load_version_data(version)
        if not data:
            print(f"  {version}: No data")
            continue
            
        # Find candidates
        candidates = find_matching_function(data, TARGET_CALLEES)
        
        if not candidates:
            print(f"  {version}: No match found")
            continue
        
        # Use known address if available
        if version in KNOWN_ADDRESSES:
            known_addr = KNOWN_ADDRESSES[version]
            match = next((c for c in candidates if c['address'] == known_addr), None)
            if match:
                results.append({
                    'version': version,
                    'address': match['address'],
                    'name': match['name'],
                    'size': match['size'],
                    'callees': match.get('api_calls', []),
                    'confirmed': True
                })
                print(f"  {version}: {match['address']} - {match['name']} (size {match['size']}) [CONFIRMED]")
                continue
        
        # For post-1.10 versions, pick by size proximity to 476 (1.11+ size)
        # For pre-1.10 versions, pick the LARGER function (has alt lookup)
        if version in ['1.11', '1.11b', '1.12a', '1.13c', '1.13d']:
            # Post-compiler-change: ~476 bytes
            best = min(candidates, key=lambda x: abs(x.get('size', 0) - 476))
        else:
            # Pre-1.10 or unknown: pick largest (has full boundary check + alt lookup)
            best = max(candidates, key=lambda x: x.get('size', 0))
            
        results.append({
            'version': version,
            'address': best['address'],
            'name': best['name'],
            'size': best['size'],
            'callees': best.get('api_calls', []),
            'confirmed': False
        })
        status = "[INFERRED]" if len(candidates) == 1 else f"[BEST OF {len(candidates)}]"
        print(f"  {version}: {best['address']} - {best['name']} (size {best['size']}) {status}")
        
        if len(candidates) > 1:
            for c in candidates:
                if c['address'] != best['address']:
                    print(f"      Alt: {c['address']} - {c['name']} (size {c['size']})")
    
    print()
    print("=" * 80)
    print("Summary - COLLISION_TrySetUnitCollisionMask addresses by version:")
    print("=" * 80)
    print()
    print(f"{'Version':<12} {'Address':<14} {'Current Name':<40} {'Size':<6}")
    print("-" * 80)
    for r in results:
        marker = "✓" if r['confirmed'] else "?"
        print(f"{r['version']:<12} {r['address']:<14} {r['name']:<40} {r['size']:<6} {marker}")
    
    print()
    print("Legend: ✓ = Confirmed via d2moo/decompilation, ? = Inferred via size/callee matching")
    
    # Output for Ghidra renaming
    print()
    print("=" * 80)
    print("Ghidra rename commands needed:")
    print("=" * 80)
    for r in results:
        if r['name'] != 'COLLISION_TrySetUnitCollisionMask':
            print(f"  {r['version']}: Rename {r['address']} from '{r['name']}' to 'COLLISION_TrySetUnitCollisionMask'")
    
    # Output JSON for automation
    output = {
        'function_name': 'COLLISION_TrySetUnitCollisionMask',
        'signature': 'int __fastcall COLLISION_TrySetUnitCollisionMask(D2ActiveRoomStrc* pRoom1, int nX1, int nY1, D2ActiveRoomStrc* pRoom2, int nX2, int nY2, int nCollisionPattern, uint16_t nFootprintCollisionMask, uint16_t nMoveConditionMask)',
        'source_file': 'source/D2Common/src/D2Collision.cpp',
        'line': 1220,
        'versions': {r['version']: {'address': r['address'], 'current_name': r['name'], 'size': r['size'], 'confirmed': r['confirmed']} for r in results}
    }
    
    with open('reports/collision_trysetunitcollisionmask_tracking.json', 'w') as f:
        json.dump(output, f, indent=2)
    print()
    print(f"Saved tracking data to reports/collision_trysetunitcollisionmask_tracking.json")
    
    return results

if __name__ == '__main__':
    main()
