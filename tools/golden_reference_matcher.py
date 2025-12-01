#!/usr/bin/env python3
"""
Golden Reference Function Matcher

Enhanced function matching using a well-documented Ghidra project as the
"golden reference" version. This enables:

1. Call-graph based matching - match functions by who they call/are called by
2. Name propagation - propagate documented names to other versions
3. Bidirectional propagation - spread from golden version to older and newer

This works in conjunction with d2_function_matcher.py, adding golden reference
as an additional high-confidence matching strategy.

Author: D2VersionChanger Project
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class GoldenFunction:
    """Function data from golden reference."""
    name: str
    address: str
    rva: str
    signature: str
    callees: List[str]  # Names of functions this calls
    callers: List[str]  # Names of functions that call this
    is_export: bool
    export_name: Optional[str]

    @property
    def callee_set(self) -> Set[str]:
        return set(self.callees)

    @property
    def caller_set(self) -> Set[str]:
        return set(self.callers)

    @property
    def call_graph_signature(self) -> Tuple[frozenset, frozenset]:
        """Unique signature based on call graph."""
        return (frozenset(self.callees), frozenset(self.callers))


class GoldenReference:
    """
    Loaded golden reference data with lookup indices.
    """

    def __init__(self, json_path: Path):
        """Load golden reference from JSON file."""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.metadata = data.get('metadata', {})
        self.dll_name = self.metadata.get('dll_name', 'Unknown')
        self.version = self.metadata.get('version', 'Unknown')
        self.image_base = int(self.metadata.get('image_base', '0'), 16)

        # Parse functions
        self.functions: Dict[str, GoldenFunction] = {}  # address -> GoldenFunction
        self.by_name: Dict[str, GoldenFunction] = {}    # name -> GoldenFunction
        self.by_rva: Dict[str, GoldenFunction] = {}     # rva -> GoldenFunction

        raw_functions = data.get('functions', {})
        for addr, func_data in raw_functions.items():
            gf = GoldenFunction(
                name=func_data.get('name', ''),
                address=addr,
                rva=func_data.get('rva', ''),
                signature=func_data.get('signature', ''),
                callees=func_data.get('callees', []),
                callers=func_data.get('callers', []),
                is_export=func_data.get('is_export', False),
                export_name=func_data.get('export_name'),
            )
            self.functions[addr] = gf
            self.by_name[gf.name] = gf
            if gf.rva:
                self.by_rva[gf.rva.lower()] = gf

        # Build call graph index
        self.call_graph = data.get('call_graph', {})

        # Build reverse call graph (callers -> function)
        self.reverse_call_graph: Dict[str, Set[str]] = defaultdict(set)
        for caller, callees in self.call_graph.items():
            for callee in callees:
                self.reverse_call_graph[callee].add(caller)

        print(f"Loaded golden reference: {self.dll_name} {self.version}")
        print(f"  {len(self.functions)} functions")
        print(f"  {len(self.call_graph)} functions with callees")

    def get_function_by_rva(self, rva: str) -> Optional[GoldenFunction]:
        """Look up function by RVA."""
        rva_clean = rva.lower().lstrip('0x').lstrip('0') or '0'
        # Try with leading zeros
        for length in [8, 7, 6, 5, 4]:
            padded = rva_clean.zfill(length)
            if padded in self.by_rva:
                return self.by_rva[padded]
        return self.by_rva.get(rva_clean)

    def get_function_by_name(self, name: str) -> Optional[GoldenFunction]:
        """Look up function by name."""
        return self.by_name.get(name)

    def find_by_call_graph(self, callees: Set[str], callers: Set[str],
                           min_overlap: float = 0.5) -> List[Tuple[GoldenFunction, float]]:
        """
        Find functions with similar call graph.

        Args:
            callees: Set of callee function names
            callers: Set of caller function names
            min_overlap: Minimum Jaccard similarity to consider a match

        Returns:
            List of (GoldenFunction, similarity_score) tuples, sorted by score
        """
        candidates = []

        for gf in self.functions.values():
            # Calculate Jaccard similarity for callees
            if callees and gf.callees:
                callee_intersection = len(callees & gf.callee_set)
                callee_union = len(callees | gf.callee_set)
                callee_sim = callee_intersection / callee_union if callee_union > 0 else 0
            else:
                callee_sim = 0

            # Calculate Jaccard similarity for callers
            if callers and gf.callers:
                caller_intersection = len(callers & gf.caller_set)
                caller_union = len(callers | gf.caller_set)
                caller_sim = caller_intersection / caller_union if caller_union > 0 else 0
            else:
                caller_sim = 0

            # Combined score (weighted average)
            if callees or callers:
                # Weight callees more heavily (they're more stable)
                combined = (callee_sim * 0.6 + caller_sim * 0.4)
                if combined >= min_overlap:
                    candidates.append((gf, combined))

        # Sort by score descending
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates


@dataclass
class MatchResult:
    """Result of matching a function against golden reference."""
    matched: bool
    golden_name: str = ""
    golden_rva: str = ""
    confidence: str = ""  # 'exact_rva', 'call_graph_high', 'call_graph_medium', 'unmatched'
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'matched': self.matched,
            'golden_name': self.golden_name,
            'golden_rva': self.golden_rva,
            'confidence': self.confidence,
            'score': self.score,
        }


class GoldenReferenceMatcher:
    """
    Matches functions from other versions against the golden reference.
    """

    def __init__(self, golden_ref: GoldenReference):
        self.golden = golden_ref
        self.matched_golden: Set[str] = set()  # Track which golden functions are matched

    def match_by_rva(self, rva: str) -> MatchResult:
        """
        Try to match by RVA (for same version or very similar builds).
        """
        gf = self.golden.get_function_by_rva(rva)
        if gf and gf.address not in self.matched_golden:
            self.matched_golden.add(gf.address)
            return MatchResult(
                matched=True,
                golden_name=gf.name,
                golden_rva=gf.rva,
                confidence='exact_rva',
                score=1.0,
            )
        return MatchResult(matched=False)

    def match_by_call_graph(self, callees: Set[str], callers: Set[str],
                           min_score: float = 0.5) -> MatchResult:
        """
        Try to match by call graph similarity.

        Args:
            callees: Names of functions this function calls
            callers: Names of functions that call this function
            min_score: Minimum similarity score to accept
        """
        if not callees and not callers:
            return MatchResult(matched=False)

        candidates = self.golden.find_by_call_graph(callees, callers, min_score)

        # Find first unmatched candidate
        for gf, score in candidates:
            if gf.address not in self.matched_golden:
                self.matched_golden.add(gf.address)
                confidence = 'call_graph_high' if score >= 0.8 else 'call_graph_medium'
                return MatchResult(
                    matched=True,
                    golden_name=gf.name,
                    golden_rva=gf.rva,
                    confidence=confidence,
                    score=score,
                )

        return MatchResult(matched=False)

    def match_function(self, rva: str, callees: Set[str], callers: Set[str]) -> MatchResult:
        """
        Try all matching strategies for a function.

        Args:
            rva: Relative virtual address of function
            callees: Names of functions this function calls
            callers: Names of functions that call this function

        Returns:
            MatchResult with best match found
        """
        # Strategy 1: Exact RVA match (for same/very similar version)
        result = self.match_by_rva(rva)
        if result.matched:
            return result

        # Strategy 2: Call graph similarity
        result = self.match_by_call_graph(callees, callers)
        if result.matched:
            return result

        return MatchResult(matched=False, confidence='unmatched')

    def reset_matches(self):
        """Reset matched golden functions for a new matching pass."""
        self.matched_golden.clear()


def propagate_names_from_golden(
    golden_ref: GoldenReference,
    target_functions: Dict[str, Dict[str, Any]],  # address -> function data
    target_call_graph: Dict[str, List[str]],  # function_name -> [callee_names]
) -> Dict[str, MatchResult]:
    """
    Propagate function names from golden reference to target version.

    Args:
        golden_ref: Loaded golden reference
        target_functions: Functions from target version (address -> {name, rva, ...})
        target_call_graph: Call graph from target version

    Returns:
        Dict mapping target address -> MatchResult
    """
    matcher = GoldenReferenceMatcher(golden_ref)
    results = {}

    # Build reverse call graph for target
    target_callers: Dict[str, Set[str]] = defaultdict(set)
    for caller, callees in target_call_graph.items():
        for callee in callees:
            target_callers[callee].add(caller)

    # Sort functions by number of call graph connections (more connections = more reliable)
    sorted_funcs = sorted(
        target_functions.items(),
        key=lambda x: len(target_call_graph.get(x[1].get('name', ''), [])) +
                      len(target_callers.get(x[1].get('name', ''), set())),
        reverse=True
    )

    for addr, func_data in sorted_funcs:
        func_name = func_data.get('name', '')
        rva = func_data.get('rva', '')

        # Get call graph info
        callees = set(target_call_graph.get(func_name, []))
        callers = target_callers.get(func_name, set())

        result = matcher.match_function(rva, callees, callers)
        results[addr] = result

    return results


def analyze_match_quality(results: Dict[str, MatchResult]) -> Dict[str, Any]:
    """
    Analyze the quality of matching results.

    Returns statistics about match coverage and confidence levels.
    """
    total = len(results)
    matched = sum(1 for r in results.values() if r.matched)

    by_confidence = defaultdict(int)
    for r in results.values():
        by_confidence[r.confidence] += 1

    score_sum = sum(r.score for r in results.values() if r.matched)
    avg_score = score_sum / matched if matched > 0 else 0

    return {
        'total_functions': total,
        'matched': matched,
        'unmatched': total - matched,
        'match_rate': matched / total if total > 0 else 0,
        'by_confidence': dict(by_confidence),
        'average_score': avg_score,
    }


def main():
    """Test the golden reference matcher."""
    import argparse

    parser = argparse.ArgumentParser(description="Test golden reference matching")
    parser.add_argument("golden_json", help="Path to golden reference JSON")
    parser.add_argument("--stats", action="store_true", help="Show statistics")

    args = parser.parse_args()

    # Load golden reference
    golden_path = Path(args.golden_json)
    if not golden_path.exists():
        print(f"Error: Golden reference not found: {golden_path}")
        return 1

    golden = GoldenReference(golden_path)

    if args.stats:
        print("\nGolden Reference Statistics:")
        print(f"  DLL: {golden.dll_name}")
        print(f"  Version: {golden.version}")
        print(f"  Functions: {len(golden.functions)}")
        print(f"  With callees: {len(golden.call_graph)}")

        # Count functions by callee count
        callee_counts = defaultdict(int)
        for name, callees in golden.call_graph.items():
            bucket = len(callees) // 5 * 5  # Bucket by 5s
            callee_counts[bucket] += 1

        print("\n  Functions by callee count:")
        for count in sorted(callee_counts.keys()):
            print(f"    {count}-{count+4}: {callee_counts[count]}")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
