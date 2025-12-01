#!/usr/bin/env python3
"""
Golden Reference Exporter for Ghidra MCP

Exports documented function data from a well-annotated Ghidra project to serve
as a "golden reference" for matching functions across other versions.

This script connects to Ghidra via REST API and extracts:
- Function names, addresses, signatures
- Call graph (callees and callers)
- Parameters and local variables
- Export information

The exported data can then be used by d2_function_matcher.py to propagate
names and match functions across different game versions.

Usage:
    python export_golden_reference.py [options]

    Options:
        --output PATH     Output JSON file (default: golden_reference.json)
        --dll NAME        DLL name being exported (default: from Ghidra metadata)
        --version VER     Version string (default: "1.13c")
        --limit N         Limit functions to export (for testing)
        --verbose         Show detailed progress

Requirements:
    - Ghidra running with GhidraMCP plugin (REST API on port 8089)
    - Target DLL loaded in Ghidra
    - requests library (pip install requests)

Author: D2VersionChanger Project
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

try:
    import requests
except ImportError:
    print("Error: requests library required. Install with: pip install requests")
    sys.exit(1)


# Ghidra MCP connection settings
GHIDRA_SERVER = "http://127.0.0.1:8089"
REQUEST_TIMEOUT = 60


@dataclass
class FunctionData:
    """Complete function data from Ghidra."""
    name: str
    address: str
    rva: str  # Relative Virtual Address (address - image_base)
    signature: str
    calling_convention: str
    return_type: str
    parameters: List[Dict[str, str]]
    locals: List[Dict[str, str]]
    callees: List[str]  # Names of functions this calls
    callers: List[str]  # Names of functions that call this
    xref_count: int
    is_export: bool
    export_ordinal: Optional[int]
    export_name: Optional[str]


class GhidraClient:
    """Client for interacting with Ghidra REST API."""

    def __init__(self, server_url: str = GHIDRA_SERVER, verbose: bool = False):
        self.server = server_url
        self.verbose = verbose
        self.session = requests.Session()

    def _get(self, endpoint: str, params: Dict = None) -> Optional[str]:
        """Make GET request to Ghidra server."""
        try:
            url = f"{self.server}/{endpoint}"
            response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            if response.ok:
                return response.text
            if self.verbose:
                print(f"  Warning: {endpoint} returned {response.status_code}")
            return None
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"  Warning: Request error for {endpoint}: {e}")
            return None

    def check_connection(self) -> bool:
        """Check if Ghidra is running and responsive."""
        try:
            result = self._get("methods")
            return result is not None
        except Exception:
            return False

    def get_metadata(self) -> Dict[str, Any]:
        """Get program metadata."""
        result = self._get("metadata")
        if not result:
            return {}
        # Parse text format
        metadata = {}
        for line in result.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                metadata[key.strip()] = value.strip()
        return metadata

    def list_functions_with_addresses(self, offset: int = 0, limit: int = 100) -> List[Dict[str, str]]:
        """List functions with their addresses using pagination."""
        result = self._get("list_functions", {"offset": offset, "limit": limit})
        if not result:
            return []

        functions = []
        for line in result.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Format: "FunctionName at address"
            if " at " in line:
                parts = line.rsplit(" at ", 1)
                if len(parts) == 2:
                    functions.append({
                        "name": parts[0].strip(),
                        "address": parts[1].strip().lower()
                    })
        return functions

    def get_all_functions(self, batch_size: int = 1000) -> List[Dict[str, str]]:
        """Get all functions with addresses using pagination."""
        all_functions = []
        offset = 0

        while True:
            batch = self.list_functions_with_addresses(offset=offset, limit=batch_size)
            if not batch:
                break
            all_functions.extend(batch)
            if self.verbose and len(all_functions) % 1000 == 0:
                print(f"  Fetched {len(all_functions)} functions...")
            offset += batch_size

            # Safety limit
            if len(all_functions) > 50000:
                print("Warning: Hit safety limit of 50000 functions")
                break

        return all_functions

    def get_function_by_address(self, address: str) -> Optional[Dict[str, Any]]:
        """Get function info by address."""
        result = self._get("get_function_by_address", {"address": address})
        if not result:
            return None
        info = {}
        for line in result.split("\n"):
            line = line.strip()
            if line.startswith("Function:"):
                # "Function: <name> at <address>"
                parts = line.replace("Function:", "").strip().split(" at ")
                if len(parts) >= 2:
                    info["name"] = parts[0].strip()
                    info["address"] = parts[1].strip()
            elif line.startswith("Signature:"):
                info["signature"] = line.replace("Signature:", "").strip()
            elif line.startswith("Entry:"):
                info["entry"] = line.replace("Entry:", "").strip()
            elif line.startswith("Body:"):
                info["body"] = line.replace("Body:", "").strip()
        return info

    def decompile_function(self, name: str) -> Optional[str]:
        """Get decompiled code for function."""
        return self._get("decompile_function", {"name": name})

    def get_function_callees(self, name: str, limit: int = 200) -> List[str]:
        """Get list of functions called by this function."""
        result = self._get("function_callees", {"name": name, "limit": limit})
        if not result:
            return []
        # Parse format: "name @ address" or "name -> address"
        callees = []
        for line in result.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Skip error messages
            if line.startswith("No ") or line.startswith("Error"):
                continue
            if " @ " in line:
                callees.append(line.split(" @ ")[0].strip())
            elif " -> " in line:
                callees.append(line.split(" -> ")[0].strip())
            else:
                callees.append(line)
        return callees

    def get_function_callers(self, name: str, limit: int = 200) -> List[str]:
        """Get list of functions that call this function."""
        result = self._get("function_callers", {"name": name, "limit": limit})
        if not result:
            return []
        callers = []
        for line in result.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Skip error messages
            if line.startswith("No ") or line.startswith("Error"):
                continue
            if " @ " in line:
                callers.append(line.split(" @ ")[0].strip())
            elif " -> " in line:
                callers.append(line.split(" -> ")[0].strip())
            else:
                callers.append(line)
        return callers

    def get_function_xrefs(self, name: str, limit: int = 200) -> int:
        """Get cross-reference count to this function."""
        result = self._get("function_xrefs", {"name": name, "limit": limit})
        if not result:
            return 0
        return len([l for l in result.strip().split("\n") if l.strip()])

    def get_function_variables(self, name: str) -> Dict[str, List[Dict]]:
        """Get function parameters and local variables."""
        result = self._get("get_function_variables", {"function_name": name})
        if not result:
            return {"parameters": [], "locals": []}

        variables = {"parameters": [], "locals": []}
        try:
            data = json.loads(result)
            variables["parameters"] = data.get("parameters", [])
            variables["locals"] = data.get("locals", [])
        except json.JSONDecodeError:
            pass
        return variables

    def list_exports(self, limit: int = 2000) -> Dict[str, str]:
        """Get all exports with addresses."""
        result = self._get("exports", {"limit": limit})
        if not result:
            return {}
        exports = {}  # address -> name
        for line in result.strip().split("\n"):
            if " -> " in line:
                name, addr = line.split(" -> ", 1)
                exports[addr.strip().lower()] = name.strip()
        return exports


def parse_signature(signature: str) -> Dict[str, str]:
    """Parse a function signature into components."""
    result = {
        "return_type": "undefined",
        "calling_convention": "__cdecl",
        "name": "",
        "params_str": ""
    }

    if not signature:
        return result

    # Find calling convention
    for cc in ["__fastcall", "__stdcall", "__cdecl", "__thiscall"]:
        if cc in signature:
            result["calling_convention"] = cc
            signature = signature.replace(cc, "").strip()
            break

    # Split return type and rest
    paren_idx = signature.find("(")
    if paren_idx > 0:
        pre_paren = signature[:paren_idx].strip()
        result["params_str"] = signature[paren_idx:]

        # Last word before ( is function name
        parts = pre_paren.rsplit(" ", 1)
        if len(parts) == 2:
            result["return_type"] = parts[0].strip()
            result["name"] = parts[1].strip()
        else:
            result["name"] = parts[0].strip()

    return result


def export_golden_reference(
    output_path: Path,
    dll_name: str = None,
    version: str = "1.13c",
    limit: int = None,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Export golden reference data from Ghidra.

    Args:
        output_path: Path to output JSON file
        dll_name: DLL name (auto-detected if not provided)
        version: Version string for this reference
        limit: Limit number of functions (for testing)
        verbose: Show detailed progress

    Returns:
        Dictionary with export statistics
    """
    client = GhidraClient(verbose=verbose)

    # Check connection
    print("Connecting to Ghidra...")
    if not client.check_connection():
        raise ConnectionError("Cannot connect to Ghidra. Is Ghidra running with GhidraMCP plugin?")
    print("  Connected!")

    # Get metadata
    print("Getting program metadata...")
    metadata = client.get_metadata()
    program_name = metadata.get("Program Name", "Unknown")
    base_address_str = metadata.get("Base Address", "0")
    function_count = metadata.get("Function Count", "0")

    if dll_name is None:
        dll_name = program_name

    print(f"  Program: {program_name}")
    print(f"  Base Address: {base_address_str}")
    print(f"  Function Count: {function_count}")

    # Parse base address
    try:
        image_base = int(base_address_str, 16)
    except ValueError:
        image_base = 0

    # Fallback: Detect image base from first function if metadata failed
    # D2Client.dll typically loads at 0x6FAB0000
    if image_base == 0:
        # Will try to detect from function addresses later
        pass

    # Get exports
    print("Getting exports...")
    exports = client.list_exports()
    print(f"  Found {len(exports)} exports")

    # Get all functions with addresses
    print("Getting all functions...")
    all_functions = client.get_all_functions()
    total_count = len(all_functions)
    print(f"  Found {total_count} functions")

    if limit:
        all_functions = all_functions[:limit]
        print(f"  Limited to {limit} functions for testing")

    # Detect image base from first function address if not set
    if image_base == 0 and all_functions:
        first_addr = int(all_functions[0]["address"], 16)
        # Round down to nearest 0x10000 boundary (typical PE section alignment)
        image_base = (first_addr // 0x10000) * 0x10000
        print(f"  Auto-detected image base: 0x{image_base:08X}")

    # Export each function
    print(f"\nExporting function data...")
    functions = {}
    errors = []
    start_time = time.time()

    for i, func_info in enumerate(all_functions):
        # Progress reporting
        if i > 0 and i % 50 == 0:
            elapsed = time.time() - start_time
            rate = i / elapsed if elapsed > 0 else 0
            eta = (len(all_functions) - i) / rate if rate > 0 else 0
            print(f"  [{i+1}/{len(all_functions)}] Processing... ({rate:.1f}/sec, ETA: {eta:.0f}s)")

        name = func_info["name"]
        address = func_info["address"].lower().replace("0x", "")

        # Get detailed function info including signature
        detailed_info = client.get_function_by_address(f"0x{address}")
        signature = ""
        if detailed_info:
            signature = detailed_info.get("signature", "")
        sig_parts = parse_signature(signature)

        # Calculate RVA
        try:
            addr_int = int(address, 16)
            rva = addr_int - image_base
            rva_str = f"{rva:08X}"
        except ValueError:
            rva_str = ""

        # Get call graph
        callees = client.get_function_callees(name)
        callers = client.get_function_callers(name)
        xref_count = client.get_function_xrefs(name)

        # Get variables
        variables = client.get_function_variables(name)

        # Check if export
        is_export = address in exports
        export_name = exports.get(address)

        # Build function data
        func_data = FunctionData(
            name=name,
            address=address,
            rva=rva_str,
            signature=signature,
            calling_convention=sig_parts["calling_convention"],
            return_type=sig_parts["return_type"],
            parameters=variables.get("parameters", []),
            locals=variables.get("locals", []),
            callees=callees,
            callers=callers,
            xref_count=xref_count,
            is_export=is_export,
            export_ordinal=None,
            export_name=export_name,
        )

        functions[address] = asdict(func_data)

    elapsed = time.time() - start_time
    print(f"\nExported {len(functions)} functions in {elapsed:.1f} seconds")

    if errors and verbose:
        print(f"  {len(errors)} errors occurred")
        for err in errors[:10]:
            print(f"    - {err}")

    # Build call graph summary (name -> [callee names])
    call_graph = {}
    for addr, func in functions.items():
        if func.get("callees"):
            call_graph[func["name"]] = func["callees"]

    # Build reverse lookup (name -> address)
    name_to_address = {func["name"]: addr for addr, func in functions.items()}

    # Build output structure
    output = {
        "metadata": {
            "generated": datetime.now().isoformat(),
            "generator": "export_golden_reference.py",
            "dll_name": dll_name,
            "version": version,
            "image_base": f"0x{image_base:08X}",
            "function_count": len(functions),
            "export_count": len(exports),
            "total_functions_in_ghidra": total_count,
        },
        "exports": exports,
        "name_to_address": name_to_address,
        "functions": functions,
        "call_graph": call_graph,
    }

    # Write output
    print(f"\nWriting to {output_path}...")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    file_size = output_path.stat().st_size
    print(f"  Wrote {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")

    # Summary statistics
    stats = {
        "functions_exported": len(functions),
        "exports_found": len(exports),
        "functions_with_callees": sum(1 for f in functions.values() if f.get("callees")),
        "functions_with_callers": sum(1 for f in functions.values() if f.get("callers")),
        "unique_callees": len(set(c for f in functions.values() for c in f.get("callees", []))),
        "errors": len(errors),
        "elapsed_seconds": elapsed,
    }

    print("\nSummary:")
    print(f"  Functions exported: {stats['functions_exported']}")
    print(f"  With callees: {stats['functions_with_callees']}")
    print(f"  With callers: {stats['functions_with_callers']}")
    print(f"  Unique callees referenced: {stats['unique_callees']}")
    print(f"  Exports: {stats['exports_found']}")

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Export golden reference function data from Ghidra",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Export all functions from current Ghidra project
    python export_golden_reference.py

    # Export to specific file with version tag
    python export_golden_reference.py --output golden_d2client_113c.json --version 1.13c

    # Test with limited functions
    python export_golden_reference.py --limit 100 --verbose
        """
    )

    parser.add_argument(
        "--output", "-o",
        type=str,
        default="golden_reference.json",
        help="Output JSON file path (default: golden_reference.json)"
    )

    parser.add_argument(
        "--dll",
        type=str,
        default=None,
        help="DLL name (default: auto-detect from Ghidra)"
    )

    parser.add_argument(
        "--version", "-v",
        type=str,
        default="1.13c",
        help="Version string (default: 1.13c)"
    )

    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=None,
        help="Limit number of functions to export (for testing)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed progress"
    )

    args = parser.parse_args()

    try:
        stats = export_golden_reference(
            output_path=Path(args.output),
            dll_name=args.dll,
            version=args.version,
            limit=args.limit,
            verbose=args.verbose
        )
        return 0
    except ConnectionError as e:
        print(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
