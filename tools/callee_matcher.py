#!/usr/bin/env python3
"""
Callee Matcher - Match function callees across versions using tiered fallback strategy.

This tool matches callees between two versions of the same parent function using:
1. Hash Match (Primary) - Normalized opcode hash comparison (100% confidence)
2. Position Match (Fallback 1) - Same call order index when counts match (90% confidence)
3. Size+Count Match (Fallback 2) - Instruction/size within tolerance (75% confidence)
4. Signature Match (Fallback 3) - Param count + calling convention (60% confidence)

Usage:
    python tools/callee_matcher.py --source-addr 0x6FD9DFF0 --source-prog "LoD/1.07/D2Common.dll" \\
                                   --target-addr 0x6FD9E4B0 --target-prog "LoD/1.08/D2Common.dll"
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Try to import requests for Ghidra MCP communication
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class CalleeInfo:
    """Information about a callee function."""
    name: str
    address: str
    hash: Optional[str] = None
    instruction_count: Optional[int] = None
    size: Optional[int] = None
    param_count: Optional[int] = None
    calling_convention: Optional[str] = None


@dataclass
class CalleeMatch:
    """Result of matching a callee."""
    source: CalleeInfo
    target: CalleeInfo
    confidence: float
    method: str


class GhidraMCPClient:
    """Simple client for Ghidra MCP REST API."""

    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url

    def _call(self, endpoint: str, params: dict = None) -> dict:
        """Make a request to the Ghidra MCP server."""
        if not HAS_REQUESTS:
            raise RuntimeError("requests library not installed. Run: pip install requests")

        url = f"{self.base_url}/{endpoint}"
        try:
            resp = requests.get(url, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Ghidra MCP request failed: {e}")

    def get_function_callees(self, func_name: str, program: str = None) -> List[dict]:
        """Get callees of a function."""
        params = {"name": func_name}
        if program:
            params["program"] = program
        result = self._call("get_function_callees", params)
        return self._parse_callees_output(result)

    def get_function_hash(self, address: str, program: str = None) -> dict:
        """Get normalized opcode hash for a function."""
        params = {"address": address}
        if program:
            params["program"] = program
        result = self._call("get_function_hash", params)
        if "result" in result:
            return json.loads(result["result"])
        return result

    def get_function_by_address(self, address: str, program: str = None) -> dict:
        """Get function info by address."""
        params = {"address": address}
        if program:
            params["program"] = program
        result = self._call("get_function_by_address", params)
        if "result" in result:
            return json.loads(result["result"]) if isinstance(result["result"], str) else result["result"]
        return result

    def _parse_callees_output(self, result: dict) -> List[dict]:
        """Parse callees output from Ghidra MCP."""
        callees = []
        if "output" in result:
            # Output is list of strings like "FuncName @ address"
            for line in result["output"]:
                if " @ " in line:
                    parts = line.split(" @ ")
                    callees.append({
                        "name": parts[0].strip(),
                        "address": parts[1].strip() if len(parts) > 1 else ""
                    })
        return callees


class CalleeMatcher:
    """
    Match callees between two versions of the same parent function.

    Uses a tiered fallback strategy:
    1. Hash Match - Normalized opcode hash (100% confidence)
    2. Position Match - Same call order index (90% confidence)
    3. Size+Count Match - Similar size/instructions (75% confidence)
    4. Signature Match - Same param count + calling convention (60% confidence)
    """

    # Confidence levels for each matching method
    CONFIDENCE_HASH = 100
    CONFIDENCE_POSITION = 90
    CONFIDENCE_SIZE = 75
    CONFIDENCE_SIGNATURE = 60

    # Tolerances for size/count matching
    SIZE_TOLERANCE = 0.15  # 15% difference allowed
    INSTRUCTION_TOLERANCE = 0.15  # 15% difference allowed

    def __init__(self, ghidra_client: GhidraMCPClient = None):
        """Initialize the matcher with optional Ghidra MCP client."""
        self.ghidra = ghidra_client or GhidraMCPClient()
        self.stats = {
            "hash_matches": 0,
            "position_matches": 0,
            "size_matches": 0,
            "signature_matches": 0,
            "unmatched": 0
        }

    def match_callees(
        self,
        source_callees: List[CalleeInfo],
        target_callees: List[CalleeInfo]
    ) -> Tuple[List[CalleeMatch], List[CalleeInfo], List[CalleeInfo]]:
        """
        Match callees between source and target function versions.

        Args:
            source_callees: List of CalleeInfo from source function
            target_callees: List of CalleeInfo from target function

        Returns:
            Tuple of:
            - List of CalleeMatch for matched callees
            - List of unmatched source callees
            - List of unmatched target callees
        """
        matches = []
        unmatched_source = list(source_callees)
        unmatched_target = list(target_callees)

        # Build hash lookup for target callees
        target_by_hash = {}
        for callee in target_callees:
            if callee.hash:
                target_by_hash[callee.hash] = callee

        # Tier 1: Hash matching
        for source in list(unmatched_source):
            if source.hash and source.hash in target_by_hash:
                target = target_by_hash[source.hash]
                if target in unmatched_target:
                    matches.append(CalleeMatch(
                        source=source,
                        target=target,
                        confidence=self.CONFIDENCE_HASH,
                        method="hash"
                    ))
                    unmatched_source.remove(source)
                    unmatched_target.remove(target)
                    self.stats["hash_matches"] += 1

        # Tier 2: Position matching (only if callee counts are equal)
        if len(source_callees) == len(target_callees) and unmatched_source:
            # Build position maps for remaining unmatched
            source_positions = {source_callees.index(s): s for s in unmatched_source}
            target_positions = {target_callees.index(t): t for t in unmatched_target}

            for pos, source in list(source_positions.items()):
                if pos in target_positions:
                    target = target_positions[pos]
                    matches.append(CalleeMatch(
                        source=source,
                        target=target,
                        confidence=self.CONFIDENCE_POSITION,
                        method="position"
                    ))
                    unmatched_source.remove(source)
                    unmatched_target.remove(target)
                    self.stats["position_matches"] += 1

        # Tier 3: Size + instruction count matching
        for source in list(unmatched_source):
            best_match = None
            best_score = 0.0

            for target in unmatched_target:
                score = self._compute_size_similarity(source, target)
                if score > best_score and score >= 0.85:  # 85% similarity threshold
                    best_score = score
                    best_match = target

            if best_match:
                matches.append(CalleeMatch(
                    source=source,
                    target=best_match,
                    confidence=self.CONFIDENCE_SIZE * best_score,
                    method="size"
                ))
                unmatched_source.remove(source)
                unmatched_target.remove(best_match)
                self.stats["size_matches"] += 1

        # Tier 4: Signature matching (param count + calling convention)
        for source in list(unmatched_source):
            best_match = None

            for target in unmatched_target:
                if self._signatures_match(source, target):
                    best_match = target
                    break

            if best_match:
                matches.append(CalleeMatch(
                    source=source,
                    target=best_match,
                    confidence=self.CONFIDENCE_SIGNATURE,
                    method="signature"
                ))
                unmatched_source.remove(source)
                unmatched_target.remove(best_match)
                self.stats["signature_matches"] += 1

        self.stats["unmatched"] += len(unmatched_source)

        return matches, unmatched_source, unmatched_target

    def _compute_size_similarity(self, source: CalleeInfo, target: CalleeInfo) -> float:
        """Compute similarity based on size and instruction count."""
        scores = []

        # Size similarity
        if source.size and target.size and source.size > 0 and target.size > 0:
            size_ratio = min(source.size, target.size) / max(source.size, target.size)
            scores.append(size_ratio)

        # Instruction count similarity
        if (source.instruction_count and target.instruction_count and
            source.instruction_count > 0 and target.instruction_count > 0):
            instr_ratio = min(source.instruction_count, target.instruction_count) / \
                         max(source.instruction_count, target.instruction_count)
            scores.append(instr_ratio)

        if not scores:
            return 0.0

        return sum(scores) / len(scores)

    def _signatures_match(self, source: CalleeInfo, target: CalleeInfo) -> bool:
        """Check if function signatures match."""
        # Check param count
        if source.param_count is not None and target.param_count is not None:
            if source.param_count != target.param_count:
                return False

        # Check calling convention
        if source.calling_convention and target.calling_convention:
            if source.calling_convention != target.calling_convention:
                return False

        # Need at least one matching criterion
        has_match = (
            (source.param_count is not None and target.param_count is not None) or
            (source.calling_convention and target.calling_convention)
        )

        return has_match

    def match_from_ghidra(
        self,
        source_addr: str,
        target_addr: str,
        source_program: str,
        target_program: str
    ) -> Tuple[List[CalleeMatch], List[CalleeInfo], List[CalleeInfo]]:
        """
        Match callees by querying Ghidra directly.

        Args:
            source_addr: Address of source function (e.g., "0x6FD9DFF0")
            target_addr: Address of target function (e.g., "0x6FD9E4B0")
            source_program: Source program path (e.g., "LoD/1.07/D2Common.dll")
            target_program: Target program path (e.g., "LoD/1.08/D2Common.dll")

        Returns:
            Same as match_callees()
        """
        # Get source function info
        source_func = self.ghidra.get_function_by_address(source_addr, source_program)
        source_name = source_func.get("name", f"FUN_{source_addr}")

        # Get target function info
        target_func = self.ghidra.get_function_by_address(target_addr, target_program)
        target_name = target_func.get("name", f"FUN_{target_addr}")

        # Get callees
        source_callees_raw = self.ghidra.get_function_callees(source_name, source_program)
        target_callees_raw = self.ghidra.get_function_callees(target_name, target_program)

        # Enrich callees with hash info
        source_callees = []
        for c in source_callees_raw:
            info = self._enrich_callee(c, source_program)
            source_callees.append(info)

        target_callees = []
        for c in target_callees_raw:
            info = self._enrich_callee(c, target_program)
            target_callees.append(info)

        return self.match_callees(source_callees, target_callees)

    def _enrich_callee(self, callee: dict, program: str) -> CalleeInfo:
        """Enrich callee info with hash and size data from Ghidra."""
        addr = callee.get("address", "")
        name = callee.get("name", "")

        info = CalleeInfo(name=name, address=addr)

        try:
            # Get hash
            hash_result = self.ghidra.get_function_hash(addr, program)
            info.hash = hash_result.get("hash")
            info.instruction_count = hash_result.get("instruction_count")
            info.size = hash_result.get("size_bytes")
        except Exception:
            pass  # Hash retrieval is optional

        try:
            # Get function info for signature
            func_info = self.ghidra.get_function_by_address(addr, program)
            info.param_count = func_info.get("param_count")
            info.calling_convention = func_info.get("calling_convention")
        except Exception:
            pass

        return info

    def get_stats(self) -> dict:
        """Return matching statistics."""
        return dict(self.stats)

    def reset_stats(self):
        """Reset statistics counters."""
        self.stats = {
            "hash_matches": 0,
            "position_matches": 0,
            "size_matches": 0,
            "signature_matches": 0,
            "unmatched": 0
        }


def format_results(
    matches: List[CalleeMatch],
    unmatched_source: List[CalleeInfo],
    unmatched_target: List[CalleeInfo]
) -> str:
    """Format match results for display."""
    lines = []

    lines.append("=" * 70)
    lines.append("CALLEE MATCHING RESULTS")
    lines.append("=" * 70)
    lines.append("")

    # Matched callees
    lines.append(f"MATCHED CALLEES ({len(matches)})")
    lines.append("-" * 70)

    for match in sorted(matches, key=lambda m: -m.confidence):
        method_icon = {
            "hash": "[HASH]",
            "position": "[POS]",
            "size": "[SIZE]",
            "signature": "[SIG]"
        }.get(match.method, "[?]")

        lines.append(f"  {method_icon} {match.confidence:.0f}%")
        lines.append(f"    Source: {match.source.name} @ {match.source.address}")
        lines.append(f"    Target: {match.target.name} @ {match.target.address}")
        if match.source.hash:
            hash_match = "identical" if match.source.hash == match.target.hash else "different"
            lines.append(f"    Hash: {match.source.hash[:16]}... ({hash_match})")
        lines.append("")

    # Unmatched source
    if unmatched_source:
        lines.append(f"UNMATCHED SOURCE CALLEES ({len(unmatched_source)})")
        lines.append("-" * 70)
        for callee in unmatched_source:
            lines.append(f"  {callee.name} @ {callee.address}")
        lines.append("")

    # Unmatched target
    if unmatched_target:
        lines.append(f"UNMATCHED TARGET CALLEES ({len(unmatched_target)})")
        lines.append("-" * 70)
        for callee in unmatched_target:
            lines.append(f"  {callee.name} @ {callee.address}")
        lines.append("")

    # Summary
    total = len(matches) + len(unmatched_source)
    if total > 0:
        match_rate = len(matches) / total * 100
        lines.append(f"SUMMARY: {len(matches)}/{total} callees matched ({match_rate:.1f}%)")

    return "\n".join(lines)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Match function callees across versions using tiered fallback strategy."
    )
    parser.add_argument(
        "--source-addr", required=True,
        help="Source function address (e.g., 0x6FD9DFF0)"
    )
    parser.add_argument(
        "--target-addr", required=True,
        help="Target function address (e.g., 0x6FD9E4B0)"
    )
    parser.add_argument(
        "--source-prog", required=True,
        help="Source program path (e.g., LoD/1.07/D2Common.dll)"
    )
    parser.add_argument(
        "--target-prog", required=True,
        help="Target program path (e.g., LoD/1.08/D2Common.dll)"
    )
    parser.add_argument(
        "--ghidra-url", default="http://localhost:8080",
        help="Ghidra MCP server URL (default: http://localhost:8080)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON"
    )

    args = parser.parse_args()

    # Initialize matcher
    client = GhidraMCPClient(args.ghidra_url)
    matcher = CalleeMatcher(client)

    try:
        # Run matching
        matches, unmatched_source, unmatched_target = matcher.match_from_ghidra(
            source_addr=args.source_addr,
            target_addr=args.target_addr,
            source_program=args.source_prog,
            target_program=args.target_prog
        )

        if args.json:
            # JSON output
            result = {
                "matches": [
                    {
                        "source": {"name": m.source.name, "address": m.source.address},
                        "target": {"name": m.target.name, "address": m.target.address},
                        "confidence": m.confidence,
                        "method": m.method
                    }
                    for m in matches
                ],
                "unmatched_source": [
                    {"name": c.name, "address": c.address}
                    for c in unmatched_source
                ],
                "unmatched_target": [
                    {"name": c.name, "address": c.address}
                    for c in unmatched_target
                ],
                "stats": matcher.get_stats()
            }
            print(json.dumps(result, indent=2))
        else:
            # Human-readable output
            print(format_results(matches, unmatched_source, unmatched_target))
            print(f"\nStats: {matcher.get_stats()}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def test_with_known_data():
    """
    Test the callee matcher with known data from our earlier analysis.

    Source: UpdateRoomAnimationState @ 0x6FD9DFF0 (LoD/1.07/D2Common.dll)
    Target: Ordinal_10923 @ 0x6FD9E4B0 (LoD/1.08/D2Common.dll)
    """
    print("=" * 70)
    print("CALLEE MATCHER TEST - Known Data from 1.07 vs 1.08")
    print("=" * 70)
    print()

    # Source callees from 1.07 (UpdateRoomAnimationState @ 0x6FD9DFF0)
    source_callees = [
        CalleeInfo(
            name="GetActRoom",
            address="6fd9d490",
            hash=None,  # Will match by name
            instruction_count=None,
            size=None
        ),
        CalleeInfo(
            name="GetLinkedUnitData",
            address="6fd9cb80",
            hash="b84590fbbda74864272cd942f9062927f334caed9ac02b1f92853e88311c2b4c",
            instruction_count=7,
            size=22
        ),
        CalleeInfo(
            name="GetCharacterTierIndex",
            address="6fd85e30",
            hash="bba052b386a9b29f9bf0549bfd2f43a55cd0bfe8aa239e191063bdd92a152db0",
            instruction_count=23,
            size=57
        ),
        CalleeInfo(
            name="AdvanceEnvAnimationFrame",
            address="6fd9e050",
            hash=None,  # Will match by name
            instruction_count=None,
            size=None
        ),
        CalleeInfo(
            name="AdjustRotationAngle",
            address="6fd9dd60",
            hash="6c517d19aa909ef95dadd71f3a58e1346d46f5c9940950f4c7f1f5092089f614",
            instruction_count=101,
            size=305
        ),
        CalleeInfo(
            name="InterpolateCoordinates",
            address="6fd9deb0",
            hash="3a1ba1e683f445d64456fb295b5aaa5c615727520957dc3d38e8cce7ea04b134",
            instruction_count=90,
            size=277
        ),
    ]

    # Target callees from 1.08 (Ordinal_10923 @ 0x6FD9E4B0)
    target_callees = [
        CalleeInfo(
            name="GetActRoom",
            address="6fd9d950",
            hash=None,
            instruction_count=None,
            size=None
        ),
        CalleeInfo(
            name="GetLinkedUnitOrNone",
            address="6fd9d040",
            hash="b84590fbbda74864272cd942f9062927f334caed9ac02b1f92853e88311c2b4c",
            instruction_count=7,
            size=22
        ),
        CalleeInfo(
            name="Ordinal_10001",
            address="6fd862f0",
            hash="bba052b386a9b29f9bf0549bfd2f43a55cd0bfe8aa239e191063bdd92a152db0",
            instruction_count=23,
            size=57
        ),
        CalleeInfo(
            name="AdvanceEnvAnimationFrame",
            address="6fd9e520",
            hash=None,
            instruction_count=None,
            size=None
        ),
        CalleeInfo(
            name="FUN_6fd9e220",
            address="6fd9e220",
            hash="6c517d19aa909ef95dadd71f3a58e1346d46f5c9940950f4c7f1f5092089f614",
            instruction_count=101,
            size=305
        ),
        CalleeInfo(
            name="FUN_6fd9e370",
            address="6fd9e370",
            hash="3a1ba1e683f445d64456fb295b5aaa5c615727520957dc3d38e8cce7ea04b134",
            instruction_count=90,
            size=277
        ),
    ]

    # Run matcher
    matcher = CalleeMatcher()
    matches, unmatched_source, unmatched_target = matcher.match_callees(
        source_callees, target_callees
    )

    # Display results
    print(format_results(matches, unmatched_source, unmatched_target))
    print()
    print(f"Stats: {matcher.get_stats()}")
    print()

    # Verify expected results
    print("=" * 70)
    print("VERIFICATION")
    print("=" * 70)

    expected_matches = {
        "GetLinkedUnitData": "GetLinkedUnitOrNone",
        "GetCharacterTierIndex": "Ordinal_10001",
        "AdjustRotationAngle": "FUN_6fd9e220",
        "InterpolateCoordinates": "FUN_6fd9e370",
    }

    passed = 0
    failed = 0

    for source_name, expected_target in expected_matches.items():
        found = None
        for m in matches:
            if m.source.name == source_name:
                found = m.target.name
                break

        if found == expected_target:
            print(f"  PASS: {source_name} -> {expected_target}")
            passed += 1
        else:
            print(f"  FAIL: {source_name} expected {expected_target}, got {found}")
            failed += 1

    print()
    print(f"Test Results: {passed} passed, {failed} failed")

    return failed == 0


if __name__ == "__main__":
    import sys

    # If --test flag, run test with known data
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        success = test_with_known_data()
        sys.exit(0 if success else 1)

    main()
