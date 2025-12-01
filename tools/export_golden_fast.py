#!/usr/bin/env python3
"""
Fast Golden Reference Exporter using MCP batch endpoints.

This version uses the analyze_function_complete endpoint which returns
all function data in a single call, making it 5x faster than the
individual endpoint version.

Usage:
    python export_golden_fast.py [options]

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
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("Error: requests library required. Install with: pip install requests")
    sys.exit(1)


GHIDRA_SERVER = "http://127.0.0.1:8089"
REQUEST_TIMEOUT = 30


class GhidraFastClient:
    """Fast client using batch MCP endpoints."""

    def __init__(self, server_url: str = GHIDRA_SERVER, verbose: bool = False):
        self.server = server_url
        self.verbose = verbose
        self.session = requests.Session()

    def _get(self, endpoint: str, params: Dict = None) -> Optional[str]:
        """Make GET request."""
        try:
            url = f"{self.server}/{endpoint}"
            response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            if response.ok:
                return response.text
            return None
        except Exception as e:
            if self.verbose:
                print(f"  Warning: {endpoint} failed: {e}")
            return None

    def check_connection(self) -> bool:
        """Check if Ghidra is running."""
        try:
            result = self._get("methods")
            return result is not None
        except Exception:
            return False

    def list_functions(self, offset: int = 0, limit: int = 1000) -> List[Dict[str, str]]:
        """List functions with pagination."""
        result = self._get("list_functions", {"offset": offset, "limit": limit})
        if not result:
            return []

        functions = []
        for line in result.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if " at " in line:
                parts = line.rsplit(" at ", 1)
                if len(parts) == 2:
                    functions.append({
                        "name": parts[0].strip(),
                        "address": parts[1].strip().lower()
                    })
        return functions

    def get_all_functions(self, batch_size: int = 1000, max_functions: int = None) -> List[Dict[str, str]]:
        """Get all functions using pagination."""
        all_functions = []
        offset = 0

        while True:
            batch = self.list_functions(offset=offset, limit=batch_size)
            if not batch:
                break
            all_functions.extend(batch)
            if self.verbose and len(all_functions) % 5000 == 0:
                print(f"  Fetched {len(all_functions)} function names...")
            offset += batch_size

            if max_functions and len(all_functions) >= max_functions:
                all_functions = all_functions[:max_functions]
                break

        return all_functions

    def analyze_function_complete(self, name: str) -> Optional[Dict[str, Any]]:
        """Get complete function analysis in one call."""
        result = self._get("analyze_function_complete", {
            "name": name,
            "include_xrefs": "true",
            "include_callees": "true",
            "include_callers": "true",
            "include_disasm": "false",
            "include_variables": "true"
        })
        if not result:
            return None
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return None

    def list_exports(self, limit: int = 2000) -> Dict[str, str]:
        """Get exports."""
        result = self._get("exports", {"limit": limit})
        if not result:
            return {}
        exports = {}
        for line in result.strip().split("\n"):
            if " -> " in line:
                name, addr = line.split(" -> ", 1)
                exports[addr.strip().lower()] = name.strip()
        return exports


def export_golden_fast(
    output_path: Path,
    dll_name: str = None,
    version: str = "1.13c",
    max_functions: int = None,
    workers: int = 4,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Export golden reference using batch endpoint.

    Args:
        output_path: Output JSON file path
        dll_name: DLL name
        version: Version string
        max_functions: Limit functions (for testing)
        workers: Number of parallel workers
        verbose: Show progress

    Returns:
        Export statistics
    """
    client = GhidraFastClient(verbose=verbose)

    print("Connecting to Ghidra...")
    if not client.check_connection():
        raise ConnectionError("Cannot connect to Ghidra")
    print("  Connected!")

    # Get exports
    print("Getting exports...")
    exports = client.list_exports()
    print(f"  Found {len(exports)} exports")

    # Get all function names/addresses
    print("Getting function list...")
    all_functions = client.get_all_functions(max_functions=max_functions)
    total_count = len(all_functions)
    print(f"  Found {total_count} functions")

    # Detect image base from first function
    image_base = 0
    if all_functions:
        first_addr = int(all_functions[0]["address"], 16)
        image_base = (first_addr // 0x10000) * 0x10000
        print(f"  Auto-detected image base: 0x{image_base:08X}")

    # Process functions with batch endpoint
    print(f"\nExporting function data (using {workers} workers)...")
    functions = {}
    call_graph = {}
    errors = []
    start_time = time.time()

    def process_function(func_info: Dict) -> tuple:
        """Process single function using batch endpoint."""
        name = func_info["name"]
        address = func_info["address"].lower().replace("0x", "")

        try:
            data = client.analyze_function_complete(name)
            if not data:
                return address, None, name

            # Calculate RVA
            addr_int = int(address, 16)
            rva = addr_int - image_base
            rva_str = f"{rva:08X}"

            # Extract callees and callers as names only
            callees = data.get("callees", [])
            callers = data.get("callers", [])

            # Check if export
            is_export = address in exports

            func_data = {
                "name": name,
                "address": address,
                "rva": rva_str,
                "signature": data.get("signature", ""),
                "callees": callees if isinstance(callees, list) else [],
                "callers": callers if isinstance(callers, list) else [],
                "parameters": data.get("parameters", []),
                "locals": data.get("locals", []),
                "xref_count": data.get("xref_count", 0),
                "is_export": is_export,
                "export_name": exports.get(address),
            }

            return address, func_data, name

        except Exception as e:
            return address, None, f"{name}: {e}"

    # Process in parallel
    processed = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(process_function, f): f for f in all_functions}

        for future in as_completed(futures):
            processed += 1
            if processed % 100 == 0:
                elapsed = time.time() - start_time
                rate = processed / elapsed if elapsed > 0 else 0
                eta = (total_count - processed) / rate if rate > 0 else 0
                print(f"  [{processed}/{total_count}] Processing... ({rate:.1f}/sec, ETA: {eta:.0f}s)")

            address, func_data, info = future.result()
            if func_data:
                functions[address] = func_data
                # Build call graph
                if func_data.get("callees"):
                    call_graph[func_data["name"]] = func_data["callees"]
            else:
                errors.append(info)

    elapsed = time.time() - start_time
    print(f"\nExported {len(functions)} functions in {elapsed:.1f} seconds")

    # Build name lookup
    name_to_address = {func["name"]: addr for addr, func in functions.items()}

    # Build output
    output = {
        "metadata": {
            "generated": datetime.now().isoformat(),
            "generator": "export_golden_fast.py",
            "dll_name": dll_name or "Unknown",
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

    # Summary
    stats = {
        "functions_exported": len(functions),
        "functions_with_callees": sum(1 for f in functions.values() if f.get("callees")),
        "functions_with_callers": sum(1 for f in functions.values() if f.get("callers")),
        "errors": len(errors),
        "elapsed_seconds": elapsed,
        "rate_per_second": len(functions) / elapsed if elapsed > 0 else 0,
    }

    print("\nSummary:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    return stats


def main():
    parser = argparse.ArgumentParser(description="Fast golden reference export")
    parser.add_argument("--output", "-o", type=str, default="golden_reference.json")
    parser.add_argument("--dll", type=str, default=None)
    parser.add_argument("--version", "-v", type=str, default="1.13c")
    parser.add_argument("--limit", "-l", type=int, default=None)
    parser.add_argument("--workers", "-w", type=int, default=4)
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    try:
        export_golden_fast(
            output_path=Path(args.output),
            dll_name=args.dll,
            version=args.version,
            max_functions=args.limit,
            workers=args.workers,
            verbose=args.verbose
        )
        return 0
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
