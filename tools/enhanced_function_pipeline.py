#!/usr/bin/env python3
"""
Enhanced Function Matching Pipeline

Combines byte-signature matching with golden reference matching for
improved function identification across D2 versions.

Pipeline Strategy:
1. Load golden reference (1.13c documented functions)
2. For each version, first try golden reference matching (call graph + RVA)
3. Then apply byte-signature matching for remaining functions
4. Propagate bidirectionally from golden version

Author: D2VersionChanger Project
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
from dataclasses import dataclass, field

# Import our matching modules
from golden_reference_matcher import GoldenReference, GoldenReferenceMatcher, MatchResult
from d2_function_matcher import (
    FunctionFingerprint,
    FunctionRegistry,
    match_functions_between_versions,
    compute_fingerprint,
)


@dataclass
class EnhancedFunctionMatch:
    """A function match with combined golden reference and byte signature info."""
    function_id: int
    name: str
    golden_name: Optional[str] = None
    addresses: Dict[str, str] = field(default_factory=dict)
    match_sources: Dict[str, str] = field(default_factory=dict)  # version -> source ('golden', 'byte_sig', 'propagated')
    confidence: Dict[str, float] = field(default_factory=dict)   # version -> confidence score


class EnhancedFunctionRegistry:
    """
    Enhanced registry combining golden reference and byte signature matching.
    """

    def __init__(self, golden_ref: Optional[GoldenReference] = None):
        self.golden = golden_ref
        self.functions: Dict[int, EnhancedFunctionMatch] = {}
        self.next_id = 1
        self.version_order: List[str] = []

        # Index for quick lookup
        self.name_to_id: Dict[str, int] = {}
        self.addr_to_id: Dict[str, Dict[str, int]] = defaultdict(dict)  # version -> addr -> id

    def _get_or_create_function(self, name: str, golden_name: Optional[str] = None) -> int:
        """Get existing function ID or create new one."""
        # First check if we have this name
        if name in self.name_to_id:
            return self.name_to_id[name]

        # Check if we have the golden name
        if golden_name and golden_name in self.name_to_id:
            return self.name_to_id[golden_name]

        # Create new function
        func_id = self.next_id
        self.next_id += 1

        display_name = golden_name if golden_name else name
        self.functions[func_id] = EnhancedFunctionMatch(
            function_id=func_id,
            name=display_name,
            golden_name=golden_name,
        )

        self.name_to_id[display_name] = func_id
        if name != display_name:
            self.name_to_id[name] = func_id

        return func_id

    def add_golden_version(self):
        """Add the golden reference version as the anchor point."""
        if not self.golden:
            return

        version = self.golden.version
        self.version_order.append(version)

        for addr, gf in self.golden.functions.items():
            func_id = self._get_or_create_function(gf.name, gf.name)

            self.functions[func_id].addresses[version] = addr
            self.functions[func_id].golden_name = gf.name
            self.functions[func_id].match_sources[version] = 'golden'
            self.functions[func_id].confidence[version] = 1.0

            self.addr_to_id[version][addr] = func_id

        print(f"Added golden version {version}: {len(self.functions)} functions")

    def add_version_with_golden_matching(
        self,
        version: str,
        functions: List[Dict[str, Any]],
        call_graph: Dict[str, List[str]] = None,
    ):
        """
        Add a version using golden reference matching first, then byte signatures.

        Args:
            version: Version string
            functions: List of function dicts with 'name', 'address', 'rva', etc.
            call_graph: Optional call graph {func_name: [callee_names]}
        """
        self.version_order.append(version)

        if not self.golden:
            # No golden reference - just add as baseline
            for func in functions:
                func_id = self._get_or_create_function(func.get('name', ''))
                addr = func.get('address', '')
                self.functions[func_id].addresses[version] = addr
                self.functions[func_id].match_sources[version] = 'baseline'
                self.functions[func_id].confidence[version] = 0.5
                self.addr_to_id[version][addr] = func_id
            return

        # Build reverse call graph
        callers: Dict[str, Set[str]] = defaultdict(set)
        if call_graph:
            for caller, callees in call_graph.items():
                for callee in callees:
                    callers[callee].add(caller)

        # Try golden reference matching
        matcher = GoldenReferenceMatcher(self.golden)
        matched_addrs = set()

        # Sort by call graph connectivity (match most connected first)
        sorted_funcs = sorted(
            functions,
            key=lambda f: len(call_graph.get(f.get('name', ''), [])) +
                         len(callers.get(f.get('name', ''), set()))
                         if call_graph else 0,
            reverse=True
        )

        golden_matches = 0
        for func in sorted_funcs:
            addr = func.get('address', '')
            rva = func.get('rva', '')
            name = func.get('name', '')

            # Get call graph info
            func_callees = set(call_graph.get(name, [])) if call_graph else set()
            func_callers = callers.get(name, set())

            # Try golden reference match
            result = matcher.match_function(rva, func_callees, func_callers)

            if result.matched:
                golden_matches += 1
                func_id = self._get_or_create_function(name, result.golden_name)
                self.functions[func_id].addresses[version] = addr
                self.functions[func_id].golden_name = result.golden_name
                self.functions[func_id].match_sources[version] = f'golden_{result.confidence}'
                self.functions[func_id].confidence[version] = result.score
                self.addr_to_id[version][addr] = func_id
                matched_addrs.add(addr)

        # Add unmatched functions as new
        for func in functions:
            addr = func.get('address', '')
            if addr not in matched_addrs:
                name = func.get('name', '')
                func_id = self._get_or_create_function(name)
                self.functions[func_id].addresses[version] = addr
                self.functions[func_id].match_sources[version] = 'new'
                self.functions[func_id].confidence[version] = 0.3
                self.addr_to_id[version][addr] = func_id

        print(f"Added {version}: {golden_matches} golden matches, {len(functions) - golden_matches} new")

    def add_version_with_byte_matching(
        self,
        version: str,
        fingerprints: List[FunctionFingerprint],
        prev_version: str,
        prev_fingerprints: List[FunctionFingerprint],
    ):
        """
        Add a version using byte signature matching against previous version.

        This is used for versions adjacent to already-matched versions,
        propagating matches outward.
        """
        self.version_order.append(version)

        # Get matches from byte signatures
        matches = match_functions_between_versions(prev_fingerprints, fingerprints)

        # Build reverse lookup for previous version
        prev_addr_to_id = self.addr_to_id.get(prev_version, {})

        matched_new_addrs = set()

        for prev_addr, (new_addr, confidence) in matches.items():
            prev_addr_hex = f"{prev_addr:08X}".lower()
            if prev_addr_hex in prev_addr_to_id:
                func_id = prev_addr_to_id[prev_addr_hex]
                new_addr_hex = f"{new_addr:08X}".lower()

                self.functions[func_id].addresses[version] = new_addr_hex
                self.functions[func_id].match_sources[version] = f'byte_{confidence}'

                # Confidence based on match type
                conf_map = {
                    'exact_64': 0.95,
                    'exact_32': 0.90,
                    'exact_16': 0.80,
                    'prologue_size': 0.70,
                    'prologue_only': 0.50,
                }
                self.functions[func_id].confidence[version] = conf_map.get(confidence, 0.5)
                self.addr_to_id[version][new_addr_hex] = func_id
                matched_new_addrs.add(new_addr)

        # Add unmatched as new functions
        for fp in fingerprints:
            if fp.address not in matched_new_addrs:
                name = fp.export_name if fp.export_name else f"function_{self.next_id:04d}"
                func_id = self._get_or_create_function(name)
                addr_hex = f"{fp.address:08X}".lower()
                self.functions[func_id].addresses[version] = addr_hex
                self.functions[func_id].match_sources[version] = 'new'
                self.functions[func_id].confidence[version] = 0.3
                self.addr_to_id[version][addr_hex] = func_id

        byte_matches = len(matches)
        print(f"Added {version}: {byte_matches} byte matches, {len(fingerprints) - byte_matches} new")

    def to_viewer_format(self) -> Dict[str, Any]:
        """Export to viewer-compatible format."""
        functions_dict = {}

        for func_id, func in sorted(self.functions.items()):
            functions_dict[str(func_id)] = {
                "ordinal": func_id,
                "name": func.name,
                "golden_name": func.golden_name,
                "addresses": func.addresses,
                "match_sources": func.match_sources,
            }

        return {
            "versions": self.version_order,
            "functions": functions_dict,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the registry."""
        total = len(self.functions)

        # Count by source type
        source_counts = defaultdict(int)
        for func in self.functions.values():
            for source in func.match_sources.values():
                source_type = source.split('_')[0]
                source_counts[source_type] += 1

        # Count functions with golden names
        with_golden = sum(1 for f in self.functions.values() if f.golden_name)

        # Version coverage
        version_counts = defaultdict(int)
        for func in self.functions.values():
            for v in func.addresses:
                version_counts[v] += 1

        return {
            "total_functions": total,
            "with_golden_name": with_golden,
            "by_source": dict(source_counts),
            "functions_per_version": dict(version_counts),
        }


def test_pipeline():
    """Test the enhanced pipeline with sample data."""
    print("Enhanced Function Matching Pipeline Test")
    print("=" * 50)

    # Check for golden reference
    golden_path = Path("reports/golden_reference/D2Client.dll_113c.json")
    if golden_path.exists():
        print(f"\nLoading golden reference from {golden_path}...")
        golden = GoldenReference(golden_path)

        registry = EnhancedFunctionRegistry(golden)
        registry.add_golden_version()

        stats = registry.get_stats()
        print("\nRegistry Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    else:
        print(f"\nGolden reference not found at {golden_path}")
        print("Run export_golden_reference.py first to generate it.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(test_pipeline())
