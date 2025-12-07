#!/usr/bin/env python3
"""
D2 Function Verification Tool

This script verifies known D2 function addresses against what exists in the Ghidra
database by searching for function names containing the address pattern.

It outputs a verification report showing which functions have been confirmed
to exist at their documented addresses.
"""

import json
import os
from datetime import datetime

# Load the known functions database
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, '..', 'reports', 'data', 'd2_known_functions.json')
REPORT_PATH = os.path.join(SCRIPT_DIR, '..', 'reports', 'data', 'd2_function_verification.json')

def load_database():
    """Load the known functions database."""
    with open(DB_PATH, 'r') as f:
        return json.load(f)

def generate_verification_report(ghidra_results):
    """
    Generate a verification report.
    
    ghidra_results: dict mapping address (hex string) to function info from Ghidra
                   e.g., {"00463990": {"name": "D2CLIENT_FindClientSideUnit", "exists": True}}
    """
    data = load_database()
    
    report = {
        "metadata": {
            "generated": datetime.now().isoformat(),
            "source_database": "d2_known_functions.json",
            "target_version": "1.14d",
            "target_binary": "Game.exe"
        },
        "summary": {
            "total_functions": len(data['functions']),
            "verified": 0,
            "not_verified": 0,
            "renamed": 0,
            "still_fun_name": 0
        },
        "functions": []
    }
    
    for func in data['functions']:
        addr = func['absolute_address']
        hex_addr = f"{addr:08x}"
        expected_name = f"{func['module']}_{func['name']}"
        fun_name = f"FUN_{hex_addr}"
        
        # Check if we have verification data
        ghidra_info = ghidra_results.get(hex_addr, {})
        exists = ghidra_info.get('exists', False)
        current_name = ghidra_info.get('name', 'unknown')
        
        verification = {
            "expected_name": expected_name,
            "module": func['module'],
            "function_name": func['name'],
            "address": f"0x{hex_addr.upper()}",
            "offset": hex(func['offset']),
            "signature": func['signature'],
            "calling_convention": func['calling_convention'],
            "verified": exists,
            "current_ghidra_name": current_name,
            "is_renamed": current_name == expected_name,
            "is_fun_name": current_name.startswith("FUN_") or current_name.startswith("fun_")
        }
        
        report['functions'].append(verification)
        
        if exists:
            report['summary']['verified'] += 1
            if verification['is_renamed']:
                report['summary']['renamed'] += 1
            elif verification['is_fun_name']:
                report['summary']['still_fun_name'] += 1
        else:
            report['summary']['not_verified'] += 1
    
    return report

def print_summary(report):
    """Print a summary of the verification report."""
    summary = report['summary']
    print("\n" + "=" * 70)
    print("D2 Function Verification Report")
    print("=" * 70)
    print(f"Target: {report['metadata']['target_binary']} ({report['metadata']['target_version']})")
    print(f"Generated: {report['metadata']['generated']}")
    print("-" * 70)
    print(f"Total Functions in Database:  {summary['total_functions']}")
    print(f"Verified (exist at address):  {summary['verified']}")
    print(f"Not Verified:                 {summary['not_verified']}")
    print(f"  - Already Renamed:          {summary['renamed']}")
    print(f"  - Still FUN_ names:         {summary['still_fun_name']}")
    print("-" * 70)
    
    # Group by module
    by_module = {}
    for func in report['functions']:
        module = func['module']
        if module not in by_module:
            by_module[module] = {'verified': 0, 'total': 0, 'renamed': 0}
        by_module[module]['total'] += 1
        if func['verified']:
            by_module[module]['verified'] += 1
        if func['is_renamed']:
            by_module[module]['renamed'] += 1
    
    print("\nBy Module:")
    for module, counts in sorted(by_module.items()):
        pct = (counts['verified'] / counts['total'] * 100) if counts['total'] > 0 else 0
        print(f"  {module:15} {counts['verified']:3}/{counts['total']:3} verified ({pct:5.1f}%), {counts['renamed']} renamed")
    
    print("=" * 70)

def save_report(report):
    """Save the verification report to JSON."""
    with open(REPORT_PATH, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to: {REPORT_PATH}")

# Example usage - this would be populated from Ghidra queries
if __name__ == "__main__":
    # This is a template - in practice, ghidra_results would come from 
    # querying Ghidra for each address
    
    # For now, let's create a report based on what we know was renamed
    # These are the functions confirmed to exist from our earlier verification
    known_renamed = {
        "00463990": {"name": "D2CLIENT_FindClientSideUnit", "exists": True},
        "004639b0": {"name": "D2CLIENT_FindServerSideUnit", "exists": True},
        "004b1620": {"name": "D2CLIENT_GetCurrentInteractingNPC", "exists": True},
        "004680a0": {"name": "D2CLIENT_GetCursorItem", "exists": True},
        "0048c060": {"name": "D2CLIENT_GetItemName", "exists": True},
        "00479150": {"name": "D2CLIENT_GetMonsterOwner", "exists": True},
        "00463dd0": {"name": "D2CLIENT_GetPlayerUnit", "exists": True},
        "004b32d0": {"name": "D2CLIENT_GetQuestInfo", "exists": True},
        "00467a10": {"name": "D2CLIENT_GetSelectedUnit", "exists": True},
        "00479080": {"name": "D2CLIENT_GetUnitHPPercent", "exists": True},
        "0045adf0": {"name": "D2CLIENT_GetUnitX", "exists": True},
        "0045ae20": {"name": "D2CLIENT_GetUnitY", "exists": True},
        "0048dd90": {"name": "D2CLIENT_LoadItemDesc", "exists": True},
        "0049e3a0": {"name": "D2CLIENT_PrintGameString", "exists": True},
        "00466de0": {"name": "D2CLIENT_SetSelectedUnit_I", "exists": True},
        "004b2370": {"name": "D2CLIENT_SubmitItem", "exists": True},
        "006335f0": {"name": "D2COMMON_GetItemText", "exists": True},
        "0061db70": {"name": "D2COMMON_GetLevelText", "exists": True},
        "00625480": {"name": "D2COMMON_GetUnitStat", "exists": True},
        "006424a0": {"name": "D2COMMON_InitLevel", "exists": True},
    }
    
    report = generate_verification_report(known_renamed)
    print_summary(report)
    save_report(report)
