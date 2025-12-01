#!/usr/bin/env python3
"""
Diablo 2 Function Matcher

Matches functions across different game versions using signature-based matching.
This enables tracking the same logical function across versions even when
addresses change due to recompilation.

Matching Strategy:
1. Compute fingerprints for each function (byte hashes, prologue, size)
2. Process versions sequentially (1.00 → 1.01 → 1.02 → ...)
3. Match functions using cascading similarity checks
4. Build a registry mapping function IDs to addresses per version

Author: Generated for D2VersionChanger project
"""

import hashlib
from typing import Dict, List, Tuple, Optional, Set, Any
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class FunctionFingerprint:
    """Fingerprint data for a single function."""
    address: int
    rva: int
    bytes_16: str  # MD5 of first 16 bytes
    bytes_32: str  # MD5 of first 32 bytes
    bytes_64: str  # MD5 of first 64 bytes
    prologue_4: str  # First 4 bytes as hex
    prologue_8: str  # First 8 bytes as hex
    size_estimate: int  # Estimated function size
    source: str  # 'export' or 'detected'
    export_name: Optional[str] = None
    export_ordinal: Optional[int] = None

    def __hash__(self):
        return hash(self.address)

    def __eq__(self, other):
        return self.address == other.address


@dataclass
class FunctionMatch:
    """A matched function across versions."""
    function_id: int
    name: str
    addresses: Dict[str, str] = field(default_factory=dict)  # version -> hex address
    first_seen: str = ""
    last_seen: str = ""
    canonical_signature: str = ""  # bytes_32 from first occurrence
    match_confidence: Dict[str, str] = field(default_factory=dict)  # version -> confidence level


def compute_fingerprint(
    data: bytes,
    func_addr: int,
    image_base: int,
    section_start: int,
    next_func_addr: Optional[int] = None,
    source: str = 'detected',
    export_name: Optional[str] = None,
    export_ordinal: Optional[int] = None
) -> Optional[FunctionFingerprint]:
    """
    Compute fingerprint for a function.

    Args:
        data: Section bytes containing the function
        func_addr: Virtual address of function
        image_base: PE image base
        section_start: Virtual address of section start
        next_func_addr: Address of next function (for size estimate)
        source: 'export' or 'detected'
        export_name: Name if exported
        export_ordinal: Ordinal if exported

    Returns:
        FunctionFingerprint or None if unable to compute
    """
    offset = func_addr - section_start

    if offset < 0 or offset >= len(data):
        return None

    # Compute byte hashes
    bytes_16 = ""
    bytes_32 = ""
    bytes_64 = ""
    prologue_4 = ""
    prologue_8 = ""

    if offset + 16 <= len(data):
        bytes_16 = hashlib.md5(data[offset:offset+16]).hexdigest()[:16]
    if offset + 32 <= len(data):
        bytes_32 = hashlib.md5(data[offset:offset+32]).hexdigest()[:16]
    if offset + 64 <= len(data):
        bytes_64 = hashlib.md5(data[offset:offset+64]).hexdigest()[:16]
    if offset + 4 <= len(data):
        prologue_4 = data[offset:offset+4].hex()
    if offset + 8 <= len(data):
        prologue_8 = data[offset:offset+8].hex()

    # Estimate size
    size_estimate = 0
    if next_func_addr and next_func_addr > func_addr:
        size_estimate = next_func_addr - func_addr

    return FunctionFingerprint(
        address=func_addr,
        rva=func_addr - image_base,
        bytes_16=bytes_16,
        bytes_32=bytes_32,
        bytes_64=bytes_64,
        prologue_4=prologue_4,
        prologue_8=prologue_8,
        size_estimate=size_estimate,
        source=source,
        export_name=export_name,
        export_ordinal=export_ordinal,
    )


def compute_fingerprints_for_functions(
    section_data: bytes,
    section_va: int,
    image_base: int,
    functions: List[Dict[str, Any]]
) -> List[FunctionFingerprint]:
    """
    Compute fingerprints for a list of functions.

    Args:
        section_data: Bytes of the executable section
        section_va: Virtual address of section
        image_base: PE image base
        functions: List of function dicts with 'address', 'source', etc.

    Returns:
        List of FunctionFingerprint objects
    """
    # Sort functions by address for size estimation
    sorted_funcs = sorted(functions, key=lambda f: f['address'])

    fingerprints = []
    for i, func in enumerate(sorted_funcs):
        # Get next function address for size estimate
        next_addr = sorted_funcs[i + 1]['address'] if i + 1 < len(sorted_funcs) else None

        fp = compute_fingerprint(
            data=section_data,
            func_addr=func['address'],
            image_base=image_base,
            section_start=section_va,
            next_func_addr=next_addr,
            source=func.get('source', 'detected'),
            export_name=func.get('name'),
            export_ordinal=func.get('ordinal'),
        )

        if fp:
            fingerprints.append(fp)

    return fingerprints


def match_functions_between_versions(
    source_fps: List[FunctionFingerprint],
    target_fps: List[FunctionFingerprint],
    size_tolerance: float = 0.3
) -> Dict[int, Tuple[int, str]]:
    """
    Match functions from source version to target version.

    Args:
        source_fps: Fingerprints from source version (e.g., v1.00)
        target_fps: Fingerprints from target version (e.g., v1.01)
        size_tolerance: Allowed size difference ratio (0.3 = 30%)

    Returns:
        Dict mapping source address -> (target address, confidence)
        Confidence levels: 'exact_64', 'exact_32', 'exact_16', 'prologue_size', 'prologue_only', 'unmatched'
    """
    matches = {}

    # Build lookup indices for target
    target_by_bytes64 = {fp.bytes_64: fp for fp in target_fps if fp.bytes_64}
    target_by_bytes32 = {fp.bytes_32: fp for fp in target_fps if fp.bytes_32}
    target_by_bytes16 = {fp.bytes_16: fp for fp in target_fps if fp.bytes_16}
    target_by_prologue8 = defaultdict(list)
    target_by_prologue4 = defaultdict(list)

    for fp in target_fps:
        if fp.prologue_8:
            target_by_prologue8[fp.prologue_8].append(fp)
        if fp.prologue_4:
            target_by_prologue4[fp.prologue_4].append(fp)

    # Track which targets have been matched
    matched_targets = set()

    # Pass 1: Exact 64-byte matches (highest confidence)
    for src_fp in source_fps:
        if src_fp.address in matches:
            continue
        if src_fp.bytes_64 and src_fp.bytes_64 in target_by_bytes64:
            tgt_fp = target_by_bytes64[src_fp.bytes_64]
            if tgt_fp.address not in matched_targets:
                matches[src_fp.address] = (tgt_fp.address, 'exact_64')
                matched_targets.add(tgt_fp.address)

    # Pass 2: Exact 32-byte matches
    for src_fp in source_fps:
        if src_fp.address in matches:
            continue
        if src_fp.bytes_32 and src_fp.bytes_32 in target_by_bytes32:
            tgt_fp = target_by_bytes32[src_fp.bytes_32]
            if tgt_fp.address not in matched_targets:
                matches[src_fp.address] = (tgt_fp.address, 'exact_32')
                matched_targets.add(tgt_fp.address)

    # Pass 3: Exact 16-byte matches
    for src_fp in source_fps:
        if src_fp.address in matches:
            continue
        if src_fp.bytes_16 and src_fp.bytes_16 in target_by_bytes16:
            tgt_fp = target_by_bytes16[src_fp.bytes_16]
            if tgt_fp.address not in matched_targets:
                matches[src_fp.address] = (tgt_fp.address, 'exact_16')
                matched_targets.add(tgt_fp.address)

    # Pass 4: Prologue + similar size match
    for src_fp in source_fps:
        if src_fp.address in matches:
            continue

        candidates = []

        # Try 8-byte prologue first
        if src_fp.prologue_8 in target_by_prologue8:
            candidates = target_by_prologue8[src_fp.prologue_8]
        elif src_fp.prologue_4 in target_by_prologue4:
            candidates = target_by_prologue4[src_fp.prologue_4]

        # Filter to unmatched candidates with similar size
        for tgt_fp in candidates:
            if tgt_fp.address in matched_targets:
                continue

            # Check size similarity
            if src_fp.size_estimate > 0 and tgt_fp.size_estimate > 0:
                size_ratio = min(src_fp.size_estimate, tgt_fp.size_estimate) / max(src_fp.size_estimate, tgt_fp.size_estimate)
                if size_ratio >= (1 - size_tolerance):
                    matches[src_fp.address] = (tgt_fp.address, 'prologue_size')
                    matched_targets.add(tgt_fp.address)
                    break

    # Pass 5: Prologue-only match (lower confidence)
    for src_fp in source_fps:
        if src_fp.address in matches:
            continue

        candidates = []
        if src_fp.prologue_8 in target_by_prologue8:
            candidates = target_by_prologue8[src_fp.prologue_8]
        elif src_fp.prologue_4 in target_by_prologue4:
            candidates = target_by_prologue4[src_fp.prologue_4]

        for tgt_fp in candidates:
            if tgt_fp.address not in matched_targets:
                matches[src_fp.address] = (tgt_fp.address, 'prologue_only')
                matched_targets.add(tgt_fp.address)
                break

    return matches


class FunctionRegistry:
    """
    Registry of functions across all versions.

    Tracks function IDs and their addresses in each version.
    """

    def __init__(self):
        self.functions: Dict[int, FunctionMatch] = {}  # function_id -> FunctionMatch
        self.next_id: int = 1
        self.version_order: List[str] = []

    def add_baseline_version(self, version: str, fingerprints: List[FunctionFingerprint]):
        """
        Add the first version as baseline. All functions get new IDs.

        Args:
            version: Version string (e.g., 'Classic/1.00')
            fingerprints: List of function fingerprints
        """
        self.version_order.append(version)

        for fp in sorted(fingerprints, key=lambda f: f.address):
            func_id = self.next_id
            self.next_id += 1

            # Use export name if available, otherwise generate name
            if fp.export_name:
                name = fp.export_name
            else:
                name = f"function_{func_id:04d}"

            self.functions[func_id] = FunctionMatch(
                function_id=func_id,
                name=name,
                addresses={version: f"{fp.address:08X}"},
                first_seen=version,
                last_seen=version,
                canonical_signature=fp.bytes_32,
                match_confidence={version: 'baseline'},
            )

    def add_version_with_matches(
        self,
        version: str,
        fingerprints: List[FunctionFingerprint],
        prev_version: str,
        prev_fingerprints: List[FunctionFingerprint]
    ):
        """
        Add a new version by matching against the previous version.

        Args:
            version: New version string
            fingerprints: Fingerprints for new version
            prev_version: Previous version string
            prev_fingerprints: Fingerprints from previous version
        """
        self.version_order.append(version)

        # Get matches from previous version to this version
        matches = match_functions_between_versions(prev_fingerprints, fingerprints)

        # Build reverse lookup: prev_addr -> function_id
        prev_addr_to_id = {}
        for func_id, func_match in self.functions.items():
            if prev_version in func_match.addresses:
                prev_addr = int(func_match.addresses[prev_version], 16)
                prev_addr_to_id[prev_addr] = func_id

        # Track which new fingerprints were matched
        matched_new_addrs = set()

        # Update existing functions with new addresses
        for prev_addr, (new_addr, confidence) in matches.items():
            if prev_addr in prev_addr_to_id:
                func_id = prev_addr_to_id[prev_addr]
                self.functions[func_id].addresses[version] = f"{new_addr:08X}"
                self.functions[func_id].last_seen = version
                self.functions[func_id].match_confidence[version] = confidence
                matched_new_addrs.add(new_addr)

        # Add new functions that didn't match anything
        for fp in sorted(fingerprints, key=lambda f: f.address):
            if fp.address not in matched_new_addrs:
                func_id = self.next_id
                self.next_id += 1

                if fp.export_name:
                    name = fp.export_name
                else:
                    name = f"function_{func_id:04d}"

                self.functions[func_id] = FunctionMatch(
                    function_id=func_id,
                    name=name,
                    addresses={version: f"{fp.address:08X}"},
                    first_seen=version,
                    last_seen=version,
                    canonical_signature=fp.bytes_32,
                    match_confidence={version: 'new'},
                )

    def to_viewer_format(self) -> Dict[str, Any]:
        """
        Export registry to viewer-compatible format.

        Returns format compatible with EXPORTS_DATA / FUNCTIONS_DATA:
        {
            "versions": ["Classic/1.00", ...],
            "functions": {
                "1": {"ordinal": 1, "name": "function_0001", "addresses": {...}},
                ...
            }
        }
        """
        functions_dict = {}

        for func_id, func_match in sorted(self.functions.items()):
            functions_dict[str(func_id)] = {
                "ordinal": func_id,
                "name": func_match.name,
                "addresses": func_match.addresses,
            }

        return {
            "versions": self.version_order,
            "functions": functions_dict,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the registry."""
        total_functions = len(self.functions)

        # Count functions by how many versions they appear in
        version_counts = defaultdict(int)
        for func in self.functions.values():
            version_counts[len(func.addresses)] += 1

        # Count by confidence level
        confidence_counts = defaultdict(int)
        for func in self.functions.values():
            for conf in func.match_confidence.values():
                confidence_counts[conf] += 1

        return {
            "total_functions": total_functions,
            "total_versions": len(self.version_order),
            "functions_by_version_count": dict(version_counts),
            "matches_by_confidence": dict(confidence_counts),
        }


def process_dll_across_versions(
    version_data: List[Tuple[str, bytes, int, List[Dict]]],
) -> FunctionRegistry:
    """
    Process a DLL across all versions and build function registry.

    Args:
        version_data: List of (version_string, section_data, section_va, image_base, functions_list)
                     Must be in chronological order!

    Returns:
        FunctionRegistry with matched functions
    """
    registry = FunctionRegistry()
    prev_version = None
    prev_fingerprints = None

    for version, section_data, section_va, image_base, functions in version_data:
        # Compute fingerprints for this version
        fingerprints = compute_fingerprints_for_functions(
            section_data, section_va, image_base, functions
        )

        if prev_version is None:
            # First version - baseline
            registry.add_baseline_version(version, fingerprints)
        else:
            # Match against previous version
            registry.add_version_with_matches(
                version, fingerprints, prev_version, prev_fingerprints
            )

        prev_version = version
        prev_fingerprints = fingerprints

    return registry


# Convenience function for testing
def test_matching():
    """Test matching with synthetic data."""
    # Create some test fingerprints
    fp1 = FunctionFingerprint(
        address=0x10001000, rva=0x1000,
        bytes_16="abc123", bytes_32="abc123def456", bytes_64="abc123def456ghi789",
        prologue_4="558bec83", prologue_8="558bec83c0ffffff",
        size_estimate=100, source='detected'
    )

    fp2 = FunctionFingerprint(
        address=0x10001100, rva=0x1100,
        bytes_16="xyz789", bytes_32="xyz789uvw456", bytes_64="xyz789uvw456rst123",
        prologue_4="558bec51", prologue_8="558bec5153565733",
        size_estimate=150, source='detected'
    )

    # Same function at different address
    fp1_moved = FunctionFingerprint(
        address=0x10002000, rva=0x2000,
        bytes_16="abc123", bytes_32="abc123def456", bytes_64="abc123def456ghi789",
        prologue_4="558bec83", prologue_8="558bec83c0ffffff",
        size_estimate=100, source='detected'
    )

    # Modified function (same prologue, similar size)
    fp2_modified = FunctionFingerprint(
        address=0x10002200, rva=0x2200,
        bytes_16="xyz999", bytes_32="xyz999uvw456", bytes_64="xyz999uvw456rst999",
        prologue_4="558bec51", prologue_8="558bec5153565733",
        size_estimate=160, source='detected'
    )

    source_fps = [fp1, fp2]
    target_fps = [fp1_moved, fp2_modified]

    matches = match_functions_between_versions(source_fps, target_fps)

    print("Test matching results:")
    for src_addr, (tgt_addr, confidence) in matches.items():
        print(f"  0x{src_addr:08X} -> 0x{tgt_addr:08X} ({confidence})")

    return matches


if __name__ == "__main__":
    test_matching()
