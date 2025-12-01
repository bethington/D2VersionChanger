#!/usr/bin/env python3
"""
Function Lookup Tool

Provides a database-like interface to look up functions and find matches.

Use cases:
1. Given an address in a specific version, find all matching addresses in other versions
2. Given a byte signature (MD5), find all functions that match
3. Given a prologue pattern, find candidate functions
4. Search by Ghidra/export name

This enables workflows like:
- You're in Ghidra looking at LoD 1.13c function at 0x6fb12345
- Run: python -m tools.optimized_matching.function_lookup --address 0x6fb12345 --version "LoD/1.13c" --dll D2Client.dll
- Get: All matching addresses across all versions
"""

import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class FunctionMatch:
    """A matched function across versions."""
    match_id: str
    name: str
    confidence: float
    tier: int
    addresses: Dict[str, str]  # version -> address


class FunctionDatabase:
    """
    In-memory function database for quick lookups.

    Indexes:
    - by_address: {version: {address: match_id}}
    - by_signature: {md5_hash: [match_id, ...]}
    - by_name: {name: match_id}
    - by_prologue: {prologue_hex: [match_id, ...]}
    """

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.cache_dir = project_root / "cache"

        # Match data
        self.matches: Dict[str, FunctionMatch] = {}

        # Indexes
        self.by_address: Dict[str, Dict[str, str]] = {}  # version -> {addr: match_id}
        self.by_signature: Dict[str, List[str]] = {}  # md5 -> [match_ids]
        self.by_name: Dict[str, str] = {}  # name -> match_id
        self.by_prologue: Dict[str, List[str]] = {}  # prologue -> [match_ids]

        # Per-version function data (for signature lookups)
        self.version_functions: Dict[str, Dict[str, dict]] = {}  # version -> {addr: func_data}

    def load_dll(self, dll_name: str) -> bool:
        """Load matching state and analysis data for a DLL."""
        state_path = self.cache_dir / "matches" / f"{dll_name}_state.json"

        if not state_path.exists():
            print(f"No matching state found for {dll_name}")
            return False

        # Load matching state
        with open(state_path, 'r', encoding='utf-8') as f:
            state_data = json.load(f)

        # Build indexes from matched functions
        for match_id, match_data in state_data.get('matched', {}).items():
            name = (match_data.get('ghidra_name') or
                   match_data.get('export_name') or
                   match_id)

            match = FunctionMatch(
                match_id=match_id,
                name=name,
                confidence=match_data.get('confidence', 0),
                tier=match_data.get('match_tier', 0),
                addresses=match_data.get('addresses', {})
            )
            self.matches[match_id] = match

            # Index by address
            for version, addr in match.addresses.items():
                if version not in self.by_address:
                    self.by_address[version] = {}
                self.by_address[version][addr.lower()] = match_id

            # Index by name
            if name and name != match_id:
                self.by_name[name.lower()] = match_id

        # Load analysis data for signature lookups
        analysis_dir = self.cache_dir / "analysis"
        for version_dir in analysis_dir.iterdir():
            if not version_dir.is_dir():
                continue

            analysis_file = version_dir / f"{dll_name}.json"
            if not analysis_file.exists():
                continue

            version_str = version_dir.name.replace('_', '/')

            with open(analysis_file, 'r', encoding='utf-8') as f:
                analysis_data = json.load(f)

            self.version_functions[version_str] = {}

            for addr, func_data in analysis_data.get('functions', {}).items():
                self.version_functions[version_str][addr.lower()] = func_data

                # Index by MD5 signatures
                for sig_key in ['bytes_md5_16', 'bytes_md5_32', 'bytes_md5_64']:
                    sig = func_data.get(sig_key)
                    if sig:
                        if sig not in self.by_signature:
                            self.by_signature[sig] = []
                        # Store (version, address) tuple
                        self.by_signature[sig].append((version_str, addr))

                # Index by prologue
                for prol_key in ['prologue_4', 'prologue_8']:
                    prol = func_data.get(prol_key)
                    if prol:
                        if prol not in self.by_prologue:
                            self.by_prologue[prol] = []
                        self.by_prologue[prol].append((version_str, addr))

        print(f"Loaded {len(self.matches)} matched functions for {dll_name}")
        print(f"Loaded analysis for {len(self.version_functions)} versions")
        print(f"Indexed {len(self.by_signature)} unique signatures")
        return True

    def lookup_by_address(self, address: str, version: str) -> Optional[FunctionMatch]:
        """Find a function match by its address in a specific version."""
        addr_lower = address.lower()
        if not addr_lower.startswith('0x'):
            addr_lower = '0x' + addr_lower

        version_addrs = self.by_address.get(version, {})
        match_id = version_addrs.get(addr_lower)

        if match_id:
            return self.matches.get(match_id)
        return None

    def lookup_by_name(self, name: str) -> Optional[FunctionMatch]:
        """Find a function match by name (export or Ghidra name)."""
        match_id = self.by_name.get(name.lower())
        if match_id:
            return self.matches.get(match_id)

        # Try partial match
        name_lower = name.lower()
        for func_name, mid in self.by_name.items():
            if name_lower in func_name:
                return self.matches.get(mid)

        return None

    def lookup_by_signature(self, md5_hash: str) -> List[tuple]:
        """Find functions matching a byte signature (MD5)."""
        return self.by_signature.get(md5_hash.lower(), [])

    def lookup_by_prologue(self, prologue_hex: str) -> List[tuple]:
        """Find functions matching a prologue pattern."""
        return self.by_prologue.get(prologue_hex.lower(), [])

    def get_function_details(self, address: str, version: str) -> Optional[dict]:
        """Get full function analysis data for an address."""
        addr_lower = address.lower()
        if not addr_lower.startswith('0x'):
            addr_lower = '0x' + addr_lower

        version_funcs = self.version_functions.get(version, {})
        return version_funcs.get(addr_lower)

    def find_similar_functions(self, address: str, version: str) -> List[Dict[str, Any]]:
        """
        Find functions similar to the one at the given address.
        Uses multiple matching strategies.
        """
        func_data = self.get_function_details(address, version)
        if not func_data:
            return []

        candidates = []
        seen = set()

        # Strategy 1: Exact byte match
        for sig_key in ['bytes_md5_64', 'bytes_md5_32', 'bytes_md5_16']:
            sig = func_data.get(sig_key)
            if sig:
                for ver, addr in self.lookup_by_signature(sig):
                    if (ver, addr) not in seen and (ver != version or addr.lower() != address.lower()):
                        seen.add((ver, addr))
                        candidates.append({
                            'version': ver,
                            'address': addr,
                            'method': f'byte_match_{sig_key[-2:]}',
                            'confidence': 0.95 if sig_key == 'bytes_md5_64' else 0.90 if sig_key == 'bytes_md5_32' else 0.85
                        })

        # Strategy 2: Prologue match
        for prol_key in ['prologue_8', 'prologue_4']:
            prol = func_data.get(prol_key)
            if prol:
                for ver, addr in self.lookup_by_prologue(prol):
                    if (ver, addr) not in seen and (ver != version or addr.lower() != address.lower()):
                        seen.add((ver, addr))
                        candidates.append({
                            'version': ver,
                            'address': addr,
                            'method': f'prologue_match_{prol_key[-1:]}',
                            'confidence': 0.70 if prol_key == 'prologue_8' else 0.60
                        })

        # Sort by confidence
        candidates.sort(key=lambda x: -x['confidence'])
        return candidates[:50]  # Top 50


def main():
    parser = argparse.ArgumentParser(
        description="Function Lookup Tool - Find functions across versions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Find function by address
  python -m tools.optimized_matching.function_lookup \\
      --dll D2Client.dll --address 0x6fb12e20 --version "LoD/1.13c"

  # Find function by name
  python -m tools.optimized_matching.function_lookup \\
      --dll D2Client.dll --name QueryInterface

  # Find by byte signature (MD5)
  python -m tools.optimized_matching.function_lookup \\
      --dll D2Client.dll --signature cbd880432f163d589e44b2b37f4f9aae

  # Find similar functions (useful for new/unknown addresses)
  python -m tools.optimized_matching.function_lookup \\
      --dll D2Client.dll --address 0x6fab1036 --version "LoD/1.13c" --find-similar
        """
    )

    parser.add_argument("--dll", type=str, required=True,
                        help="DLL name (e.g., D2Client.dll)")
    parser.add_argument("--address", type=str,
                        help="Function address to look up (e.g., 0x6fb12e20)")
    parser.add_argument("--version", type=str,
                        help="Version string (e.g., 'LoD/1.13c')")
    parser.add_argument("--name", type=str,
                        help="Function name to search for")
    parser.add_argument("--signature", type=str,
                        help="MD5 byte signature to search for")
    parser.add_argument("--prologue", type=str,
                        help="Prologue hex pattern to search for")
    parser.add_argument("--find-similar", action="store_true",
                        help="Find similar functions to the specified address")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")

    args = parser.parse_args()

    # Load database
    project_root = Path(__file__).parent.parent.parent
    db = FunctionDatabase(project_root)

    if not db.load_dll(args.dll):
        return 1

    print()

    # Lookup by address
    if args.address and args.version:
        if args.find_similar:
            # Find similar functions
            similar = db.find_similar_functions(args.address, args.version)
            if similar:
                print(f"Functions similar to {args.address} in {args.version}:")
                print("-" * 70)
                for match in similar[:20]:
                    print(f"  {match['version']:20} {match['address']:12} "
                          f"[{match['method']:20}] conf={match['confidence']:.2f}")
            else:
                print(f"No similar functions found for {args.address}")
        else:
            # Exact lookup
            match = db.lookup_by_address(args.address, args.version)
            if match:
                print(f"Found: {match.name}")
                print(f"Match ID: {match.match_id}")
                print(f"Confidence: {match.confidence:.2f}")
                print(f"Tier: {match.tier}")
                print(f"\nAddresses across versions:")
                print("-" * 50)
                for ver, addr in sorted(match.addresses.items()):
                    marker = " <--" if ver == args.version else ""
                    print(f"  {ver:20} {addr}{marker}")
            else:
                print(f"No match found for {args.address} in {args.version}")
                print("\nTry --find-similar to search for candidate matches")

    # Lookup by name
    elif args.name:
        match = db.lookup_by_name(args.name)
        if match:
            print(f"Found: {match.name}")
            print(f"Match ID: {match.match_id}")
            print(f"Confidence: {match.confidence:.2f}")
            print(f"\nAddresses across versions:")
            print("-" * 50)
            for ver, addr in sorted(match.addresses.items()):
                print(f"  {ver:20} {addr}")
        else:
            print(f"No function found with name '{args.name}'")

    # Lookup by signature
    elif args.signature:
        results = db.lookup_by_signature(args.signature)
        if results:
            print(f"Found {len(results)} functions with signature {args.signature}:")
            print("-" * 50)
            for ver, addr in results[:30]:
                print(f"  {ver:20} {addr}")
        else:
            print(f"No functions found with signature '{args.signature}'")

    # Lookup by prologue
    elif args.prologue:
        results = db.lookup_by_prologue(args.prologue)
        if results:
            print(f"Found {len(results)} functions with prologue {args.prologue}:")
            print("-" * 50)
            for ver, addr in results[:30]:
                print(f"  {ver:20} {addr}")
        else:
            print(f"No functions found with prologue '{args.prologue}'")

    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
