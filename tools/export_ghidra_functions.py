#!/usr/bin/env python3
"""
Export functions from Ghidra via MCP for anchor-based matching.

This script connects to a running Ghidra instance with MCP and exports
all function data to JSON format for use as an anchor version.

Usage:
    python export_ghidra_functions.py

Output:
    data/anchor/<program_name>.json
"""

import json
import requests
from pathlib import Path
from datetime import datetime

# MCP server endpoint (default Ghidra MCP port)
GHIDRA_MCP_BASE = "http://localhost:8080"


def get_metadata():
    """Get program metadata from Ghidra."""
    resp = requests.get(f"{GHIDRA_MCP_BASE}/metadata")
    resp.raise_for_status()
    return resp.json()


def get_functions(offset=0, limit=100):
    """Get functions from Ghidra with pagination."""
    resp = requests.get(f"{GHIDRA_MCP_BASE}/functions", params={
        "offset": offset,
        "limit": limit
    })
    resp.raise_for_status()
    return resp.json()


def get_function_by_address(address):
    """Get function details by address."""
    resp = requests.get(f"{GHIDRA_MCP_BASE}/function", params={
        "address": address
    })
    if resp.status_code == 200:
        return resp.json()
    return None


def export_all_functions():
    """Export all functions from currently open Ghidra program."""
    print("Connecting to Ghidra MCP...")

    # Get metadata
    try:
        meta = get_metadata()
    except requests.exceptions.ConnectionError:
        print("Error: Cannot connect to Ghidra MCP server.")
        print("Make sure Ghidra is running with the MCP plugin enabled.")
        return None

    # Parse metadata
    meta_lines = meta.get('result', '').split('\n')
    meta_dict = {}
    for line in meta_lines:
        if ':' in line:
            key, val = line.split(':', 1)
            meta_dict[key.strip()] = val.strip()

    program_name = meta_dict.get('Program Name', 'Unknown')
    image_base_str = meta_dict.get('Base Address', '0')
    image_base = int(image_base_str, 16) if image_base_str.startswith('0x') or image_base_str.startswith('0X') else int(image_base_str, 16)
    func_count = int(meta_dict.get('Function Count', 0))

    print(f"Program: {program_name}")
    print(f"Image Base: 0x{image_base:08X}")
    print(f"Function Count: {func_count}")

    # Collect all functions
    functions = []
    offset = 0
    batch_size = 500

    print(f"\nExporting functions...")
    while offset < func_count + batch_size:
        batch = get_functions(offset, batch_size)
        if not batch:
            break

        # Parse function names from response
        if isinstance(batch, str):
            # Response is newline-separated function names
            names = [n.strip() for n in batch.split('\n') if n.strip()]
        elif isinstance(batch, list):
            names = batch
        else:
            break

        if not names:
            break

        for name in names:
            functions.append({
                "name": name,
                "has_custom_name": not name.startswith("FUN_") and not name.startswith("thunk_FUN_")
            })

        offset += batch_size
        print(f"  Collected {len(functions)} functions...", end='\r')

    print(f"\n  Total: {len(functions)} functions")

    # Count named functions
    named_count = sum(1 for f in functions if f.get('has_custom_name', False))

    # Build output
    output = {
        "program_name": program_name,
        "image_base": f"0x{image_base:08X}",
        "export_date": datetime.now().isoformat(),
        "total_functions": len(functions),
        "named_functions": named_count,
        "functions": functions
    }

    # Save to file
    output_dir = Path(__file__).parent.parent / "data" / "anchor"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{program_name}.json"

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    print(f"\nExport complete!")
    print(f"  Named functions: {named_count}")
    print(f"  Output: {output_file}")

    return output_file


if __name__ == "__main__":
    export_all_functions()
