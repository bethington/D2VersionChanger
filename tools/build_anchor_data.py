#!/usr/bin/env python3
"""
Build anchor data file from Ghidra MCP search results.

This script is designed to be run with the search results pasted in,
or to parse results from MCP tool calls.
"""

import json
import re
from pathlib import Path
from datetime import datetime


def parse_mcp_function_results(raw_text):
    """
    Parse function search results from Ghidra MCP.
    Format: "FunctionName @ hexaddress" concatenated together
    """
    functions = []

    # Pattern to match "Name @ address" where address is hex
    # The results are concatenated, so we need to find all matches
    pattern = r'([A-Za-z_][A-Za-z0-9_@\':\.`\[\]]*)\s*@\s*([0-9a-fA-F]+)'

    matches = re.findall(pattern, raw_text)

    for name, addr in matches:
        # Clean up the name
        name = name.strip()
        addr = addr.strip().lower()

        # Skip if address is too short (likely a parsing error)
        if len(addr) < 6:
            continue

        functions.append({
            'name': name,
            'address': f"0x{addr}",
            'has_custom_name': not name.startswith('FUN_') and not name.startswith('thunk_FUN_')
        })

    return functions


def merge_function_lists(*lists):
    """Merge multiple function lists, deduplicating by address."""
    seen_addrs = {}

    for func_list in lists:
        for func in func_list:
            addr = func['address'].lower()
            if addr not in seen_addrs:
                seen_addrs[addr] = func
            else:
                # Prefer named functions over unnamed
                if func.get('has_custom_name') and not seen_addrs[addr].get('has_custom_name'):
                    seen_addrs[addr] = func

    # Sort by address
    result = sorted(seen_addrs.values(), key=lambda f: int(f['address'], 16))
    return result


def build_anchor_file(functions, program_name, version, image_base):
    """Build and save anchor data file."""

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


# Sample data - this will be replaced with actual MCP results
SAMPLE_RESULTS = """
"""

if __name__ == "__main__":
    # Parse sample results
    if SAMPLE_RESULTS.strip():
        functions = parse_mcp_function_results(SAMPLE_RESULTS)
        if functions:
            build_anchor_file(
                functions,
                program_name="D2Client.dll",
                version="LoD/1.13c",
                image_base="0x6FAB0000"
            )
        else:
            print("No functions parsed from sample data")
    else:
        print("No sample data provided. Use this script with MCP results.")
