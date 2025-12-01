#!/usr/bin/env python3
"""
Export anchor version data from Ghidra via MCP.

This script exports all function names and addresses from the currently
open Ghidra project to serve as the anchor for cross-version matching.
"""

import json
import subprocess
import re
from pathlib import Path
from datetime import datetime


def run_mcp_command(tool_name, params=None):
    """Run an MCP tool via claude CLI (placeholder - we'll use direct HTTP)."""
    pass


def parse_function_list(raw_output):
    """Parse the raw function list output from Ghidra MCP."""
    # The output is a concatenated string of function names
    # We need to split on capital letters that start new names
    # But this is tricky - let's use a different approach

    # Actually the output seems to be space or newline separated
    # Let's just split and clean
    if isinstance(raw_output, str):
        # Split on common delimiters
        names = re.split(r'[\n\r]+', raw_output)
        return [n.strip() for n in names if n.strip()]
    return []


def main():
    """Export function data from Ghidra."""
    import requests

    # Ghidra MCP typically runs on port 8080
    base_url = "http://localhost:8080"

    print("Exporting anchor data from Ghidra...")

    # We'll construct the data manually by querying Ghidra
    # For now, let's create a template that can be filled in

    output_dir = Path(__file__).parent.parent / "data" / "anchor"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Template structure
    anchor_data = {
        "version": "LoD/1.13c",
        "program_name": "D2Client.dll",
        "image_base": "0x6FAB0000",
        "export_date": datetime.now().isoformat(),
        "source": "ghidra_manual_export",
        "functions": []
    }

    output_file = output_dir / "D2Client.dll.json"

    with open(output_file, 'w') as f:
        json.dump(anchor_data, f, indent=2)

    print(f"Template created: {output_file}")
    print("Run the Ghidra script ExportFunctionsToJSON.java to populate with real data.")


if __name__ == "__main__":
    main()
