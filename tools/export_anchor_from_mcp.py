#!/usr/bin/env python3
"""
Export anchor version data from Ghidra via MCP REST API.

Queries the running Ghidra MCP server to export all function data
for use as the anchor version in cross-version matching.
"""

import json
import re
import requests
from pathlib import Path
from datetime import datetime

# Ghidra MCP server URL
MCP_BASE_URL = "http://localhost:8080"


def get_metadata():
    """Get program metadata."""
    try:
        resp = requests.get(f"{MCP_BASE_URL}/methods/get_metadata", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data.get('result', '')
    except Exception as e:
        print(f"Error getting metadata: {e}")
        return None


def search_functions(query="", offset=0, limit=100):
    """Search for functions by name pattern."""
    try:
        resp = requests.post(
            f"{MCP_BASE_URL}/methods/search_functions_by_name",
            json={"query": query, "offset": offset, "limit": limit},
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get('result', '')
    except Exception as e:
        print(f"Error searching functions: {e}")
        return None


def list_functions(offset=0, limit=100):
    """List functions with pagination."""
    try:
        resp = requests.post(
            f"{MCP_BASE_URL}/methods/list_functions",
            json={"offset": offset, "limit": limit},
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get('result', '')
    except Exception as e:
        print(f"Error listing functions: {e}")
        return None


def get_function_by_address(address):
    """Get function details by address."""
    try:
        resp = requests.post(
            f"{MCP_BASE_URL}/methods/get_function_by_address",
            json={"address": address},
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get('result', '')
    except Exception as e:
        return None


def parse_function_search_result(raw_result):
    """
    Parse function search results.
    Format: "FunctionName @ address" separated by newlines or other delimiters
    """
    functions = []
    if not raw_result:
        return functions

    # Split by common patterns
    # Pattern: "FunctionName @ hexaddress"
    pattern = r'([A-Za-z_][A-Za-z0-9_]*(?:\s*@\s*[0-9a-fA-Fx]+)?)'

    # Try splitting by known delimiters first
    lines = raw_result.replace('\r', '\n').split('\n')

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Check for "name @ address" format
        if ' @ ' in line:
            parts = line.split(' @ ')
            if len(parts) == 2:
                name = parts[0].strip()
                addr = parts[1].strip()
                functions.append({
                    'name': name,
                    'address': addr,
                    'has_custom_name': not name.startswith('FUN_') and not name.startswith('thunk_FUN_')
                })
        else:
            # Just a name, no address
            functions.append({
                'name': line,
                'address': None,
                'has_custom_name': not line.startswith('FUN_') and not line.startswith('thunk_FUN_')
            })

    return functions


def export_all_functions():
    """Export all functions from Ghidra via MCP."""
    print("Connecting to Ghidra MCP server...")

    # Get metadata
    meta_raw = get_metadata()
    if not meta_raw:
        print("Error: Cannot connect to Ghidra MCP. Is Ghidra running with MCP plugin?")
        return None

    # Parse metadata
    print(f"Metadata:\n{meta_raw}\n")

    meta_dict = {}
    for line in meta_raw.split('\n'):
        if ':' in line:
            key, val = line.split(':', 1)
            meta_dict[key.strip()] = val.strip()

    program_name = meta_dict.get('Program Name', 'Unknown')
    base_addr = meta_dict.get('Base Address', '0x0')
    func_count = int(meta_dict.get('Function Count', '0'))

    print(f"Program: {program_name}")
    print(f"Base Address: {base_addr}")
    print(f"Function Count: {func_count}")

    # Determine version from path or name
    exe_path = meta_dict.get('Executable Path', '')
    version = "LoD/1.13c"  # Default assumption
    if "1.13d" in exe_path.lower():
        version = "LoD/1.13d"
    elif "1.13c" in exe_path.lower() or "pd2" in exe_path.lower():
        version = "LoD/1.13c"

    # Export functions by searching with common prefixes
    # This is a workaround since list_functions doesn't give addresses
    print("\nExporting functions...")

    all_functions = {}

    # Search using alphabet prefixes to get all functions with addresses
    search_prefixes = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        '_', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'FUN_6fab', 'FUN_6fac', 'FUN_6fad', 'FUN_6fae', 'FUN_6faf',
        'FUN_6fb0', 'FUN_6fb1', 'FUN_6fb2', 'FUN_6fb3', 'FUN_6fb4',
        'FUN_6fb5', 'FUN_6fb6', 'FUN_6fb7', 'FUN_6fb8', 'FUN_6fb9',
        'thunk_'
    ]

    for prefix in search_prefixes:
        result = search_functions(prefix, 0, 10000)
        if result:
            funcs = parse_function_search_result(result)
            for f in funcs:
                if f['address'] and f['address'] not in all_functions:
                    all_functions[f['address']] = f
        print(f"  Searched '{prefix}': {len(all_functions)} total functions", end='\r')

    print(f"\n  Total unique functions: {len(all_functions)}")

    # Convert to list sorted by address
    functions_list = sorted(all_functions.values(), key=lambda x: int(x['address'], 16) if x['address'] else 0)

    # Count named functions
    named_count = sum(1 for f in functions_list if f.get('has_custom_name', False))

    print(f"  Named functions: {named_count}")

    # Build output structure
    output = {
        "version": version,
        "program_name": program_name,
        "image_base": base_addr,
        "export_date": datetime.now().isoformat(),
        "total_functions": len(functions_list),
        "named_functions": named_count,
        "source": "ghidra_mcp",
        "functions": functions_list
    }

    # Save to file
    output_dir = Path(__file__).parent.parent / "data" / "anchor"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{program_name}.json"

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    print(f"\nExport complete!")
    print(f"  Output: {output_file}")
    print(f"  Total: {len(functions_list)} functions")
    print(f"  Named: {named_count} functions")

    return output_file


if __name__ == "__main__":
    export_all_functions()
