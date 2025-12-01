#!/usr/bin/env python3
"""
Export function data from Ghidra via Claude MCP tools.

This script is designed to be run by Claude Code, which has access to the
Ghidra MCP tools. It collects function data from multiple search queries
and combines them into a single anchor file.

Usage:
    Run this script, then paste the collected results into the RESULTS dict below.
"""

import json
import re
from pathlib import Path
from datetime import datetime


def parse_mcp_search_results(raw_text):
    """
    Parse function search results from Ghidra MCP.
    Format: "FunctionName @ hexaddress" separated by newlines or concatenated.
    """
    functions = {}

    # Pattern to match "Name @ address" format
    # Handles various function name characters including special chars
    pattern = r'([A-Za-z_][A-Za-z0-9_@\':\.\`\[\]<>~]*)\s*@\s*([0-9a-fA-F]+)'

    matches = re.findall(pattern, raw_text)

    for name, addr in matches:
        name = name.strip()
        addr = addr.strip().lower()

        # Skip if address is too short
        if len(addr) < 6:
            continue

        addr_key = f"0x{addr}"

        # Only add if not already present, or prefer custom names
        if addr_key not in functions:
            functions[addr_key] = {
                'name': name,
                'address': addr_key,
                'has_custom_name': not name.startswith('FUN_') and not name.startswith('thunk_FUN_')
            }
        elif not functions[addr_key]['has_custom_name'] and not name.startswith('FUN_'):
            functions[addr_key] = {
                'name': name,
                'address': addr_key,
                'has_custom_name': True
            }

    return functions


def build_anchor_file(functions_dict, program_name, version, image_base):
    """Build and save anchor data file."""

    # Convert dict to sorted list
    functions = sorted(functions_dict.values(), key=lambda f: int(f['address'], 16))

    named_count = sum(1 for f in functions if f.get('has_custom_name', False))

    output = {
        "version": version,
        "program_name": program_name,
        "image_base": image_base,
        "export_date": datetime.now().isoformat(),
        "total_functions": len(functions),
        "named_functions": named_count,
        "source": "ghidra_mcp",
        "functions": functions
    }

    output_dir = Path(__file__).parent.parent / "data" / "anchor"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{program_name}.json"

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    print(f"Saved anchor data: {output_file}")
    print(f"  Total functions: {len(functions)}")
    print(f"  Named functions: {named_count}")

    return output_file


# Collected results from MCP queries will be stored here
# Each key is a search prefix, value is the raw result string
COLLECTED_RESULTS = {}


def combine_all_results():
    """Combine all collected results into a single functions dict."""
    all_functions = {}

    for prefix, raw_result in COLLECTED_RESULTS.items():
        funcs = parse_mcp_search_results(raw_result)
        for addr, func in funcs.items():
            if addr not in all_functions:
                all_functions[addr] = func
            elif func['has_custom_name'] and not all_functions[addr]['has_custom_name']:
                all_functions[addr] = func

    return all_functions


if __name__ == "__main__":
    if COLLECTED_RESULTS:
        functions = combine_all_results()
        if functions:
            build_anchor_file(
                functions,
                program_name="D2Client.dll",
                version="LoD/1.13c",
                image_base="0x6FAB0000"
            )
        else:
            print("No functions parsed from collected data")
    else:
        print("No results collected yet.")
        print("Use MCP search_functions_by_name with various prefixes and add results to COLLECTED_RESULTS.")
