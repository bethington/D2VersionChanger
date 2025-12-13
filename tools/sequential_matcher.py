#!/usr/bin/env python3
"""
Sequential Pairwise Matcher - Match functions between adjacent versions.

This implements the Hybrid Sequential with Bidirectional Propagation approach:

Phase 1: Forward Pass (1.07 → 1.08 → ... → 1.14d)
   - Use multi-signal scoring between adjacent version pairs
   - Propagate identities forward
   - Track "new" functions (first seen in each version)

Phase 2: Backward Pass (1.14d → 1.13d → ... → 1.07)
   - Only process functions still unmatched
   - Propagate identities backward
   - Track "removed" functions (last seen in each version)

Phase 3: Collision Resolution
   - Handle cases where forward and backward paths disagree
   - Use higher-confidence match as tiebreaker

Phase 4: Gap Filling
   - For any remaining unmatched functions, try cross-version matching
   - Use anchor-based positioning as last resort

Key insight: Adjacent versions are ~95% similar, making pairwise matching
much more accurate than trying to match across all versions at once.
"""

import json
import os
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
import hashlib
import math


# Version ordering for each game type
LOD_VERSION_ORDER = [
    "1.07",
    "1.08",
    "1.09",
    "1.09b",
    "1.09d",
    "1.10",
    "1.11",
    "1.11b",
    "1.12a",
    "1.13c",
    "1.13d",
    "1.14a",
    "1.14b",
    "1.14c",
    "1.14d",
]

CLASSIC_VERSION_ORDER = [
    "1.00",
    "1.01",
    "1.02",
    "1.03",
    "1.04b",
    "1.04c",
    "1.05",
    "1.05b",
    "1.06",
    "1.06b",
    "1.08",
    "1.09",
    "1.09b",
    "1.09d",
    "1.10",
    "1.11",
    "1.11b",
    "1.12a",
    "1.13c",
    "1.13d",
    "1.14a",
    "1.14b",
    "1.14c",
    "1.14d",
]


# Match method weights (higher = more reliable)
MATCH_WEIGHTS = {
    "export_ordinal": 1.00,  # Export with ordinal - perfect match
    "mnemonic_hash": 0.98,  # Identical opcode sequence
    "export_name": 0.95,  # Named export match
    "unique_string": 0.92,  # Unique string reference
    "index_exp": 0.90,  # EXP index match
    "index_str": 0.88,  # STR index match
    "index_api": 0.85,  # API sequence match
    "index_mne": 0.82,  # MNE hash match
    "index_cfg": 0.75,  # CFG structure match (improved - stable across recompile)
    "index_pro": 0.60,  # Prologue match (weak)
    "exact_address": 0.55,  # Same address (only useful for same base)
    "callee_set_size": 0.80,  # Same callees + same size
    "callee_overlap": 0.60,  # High callee overlap (>=80%)
    "signature_match": 0.70,  # Same function signature/prototype
    "size_proximity": 0.20,  # Similar size (very weak, tiebreaker)
    "size_exact": 0.30,  # Exact size match
}

# Minimum score to accept a match
MIN_MATCH_SCORE = 0.45  # Lowered slightly to catch more edge cases


@dataclass
class MatchCandidate:
    """A potential match between two functions."""

    source_addr: str
    target_addr: str
    score: float
    methods: List[str]
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FunctionIdentity:
    """Canonical identity for a function tracked across versions."""

    canonical_id: str
    name: str
    first_version: str
    last_version: str
    addresses: Dict[str, str] = field(default_factory=dict)  # version -> address
    rvas: Dict[str, str] = field(default_factory=dict)  # version -> rva
    match_chain: List[Tuple[str, str, float]] = field(
        default_factory=list
    )  # (from_ver, to_ver, confidence)

    def to_dict(self) -> dict:
        return {
            "canonical_id": self.canonical_id,
            "name": self.name,
            "first_version": self.first_version,
            "last_version": self.last_version,
            "addresses": self.addresses,
            "rvas": self.rvas,
            "match_chain": [(f, t, round(c, 3)) for f, t, c in self.match_chain],
        }


class SequentialMatcher:
    """
    Match functions across versions using sequential pairwise comparison.

    Instead of matching all versions at once (which causes hash collisions),
    this matcher compares only adjacent versions, propagating identities
    through the version chain.
    """

    def __init__(self, base_path: Path, config: dict = None):
        self.base_path = base_path
        self.config = config or {}
        self.index_path = base_path / "data" / "function_index"

        # DLL name normalization - map lowercase to canonical name
        self.dll_canonical_name: Dict[str, str] = {}

        # Function data per DLL per version: {dll: {version_key: [functions]}}
        self.function_data: Dict[str, Dict[str, List[dict]]] = {}

        # Address lookup: {dll: {version_key: {address: func}}}
        self.addr_to_func: Dict[str, Dict[str, Dict[str, dict]]] = {}

        # Index lookups: {dll: {version_key: {index_key: [addresses]}}}
        self.index_lookup: Dict[str, Dict[str, Dict[str, List[str]]]] = {}

        # Results: {dll: {canonical_id: FunctionIdentity}}
        self.identities: Dict[str, Dict[str, FunctionIdentity]] = {}

        # Reverse lookup: {dll: {version_key: {address: canonical_id}}}
        self.addr_to_identity: Dict[str, Dict[str, Dict[str, str]]] = {}

        # Statistics
        self.stats = defaultdict(lambda: defaultdict(int))

    def normalize_dll_name(self, dll_name: str) -> str:
        """Normalize DLL name to lowercase for consistent keying."""
        return dll_name.lower()

    def register_dll_name(self, dll_name: str) -> str:
        """Register a DLL name and return its normalized key.

        Keeps track of the first-seen canonical name for display purposes.
        """
        key = self.normalize_dll_name(dll_name)
        if key not in self.dll_canonical_name:
            self.dll_canonical_name[key] = dll_name
        return key

    def load_dll_data(self, dll_name: str, game_type: str) -> Dict[str, List[dict]]:
        """Load function data for a specific DLL across all versions."""
        game_path = self.index_path / game_type
        if not game_path.exists():
            return {}

        version_order = (
            LOD_VERSION_ORDER if game_type == "LoD" else CLASSIC_VERSION_ORDER
        )
        data = {}

        for version in version_order:
            version_path = game_path / version / f"{dll_name}.json"
            if not version_path.exists():
                continue

            try:
                with open(version_path, "r", encoding="utf-8") as f:
                    file_data = json.load(f)

                functions = file_data.get("functions", [])
                version_key = f"{game_type}/{version}"
                data[version_key] = functions

            except Exception as e:
                print(f"  Warning: Error loading {version_path}: {e}")

        return data

    def build_lookups(self, dll_name: str, version_data: Dict[str, List[dict]]) -> None:
        """Build lookup indexes for a DLL's version data."""
        if dll_name not in self.addr_to_func:
            self.addr_to_func[dll_name] = {}
            self.index_lookup[dll_name] = {}

        for version_key, functions in version_data.items():
            self.addr_to_func[dll_name][version_key] = {}
            self.index_lookup[dll_name][version_key] = defaultdict(list)

            for func in functions:
                addr = func.get("address", "")
                if addr:
                    self.addr_to_func[dll_name][version_key][addr] = func

                # Build index lookups
                indexes = func.get("indexes", {})
                for method, hash_val in indexes.items():
                    if hash_val:
                        key = f"{method}:{hash_val}"
                        self.index_lookup[dll_name][version_key][key].append(addr)

                # Also index by primary index
                primary_index = func.get("index", "")
                if primary_index:
                    self.index_lookup[dll_name][version_key][primary_index].append(addr)

    def compute_match_score(
        self,
        source_func: dict,
        target_func: dict,
        dll_name: str,
        source_ver: str,
        target_ver: str,
    ) -> MatchCandidate:
        """
        Compute multi-signal match score between two functions.

        Returns a MatchCandidate with the total score and matched methods.
        """
        source_addr = source_func.get("address", "")
        target_addr = target_func.get("address", "")

        score = 0.0
        methods = []
        details = {}

        # Check export ordinal match (highest confidence)
        source_indexes = source_func.get("indexes", {})
        target_indexes = target_func.get("indexes", {})

        source_exp = source_indexes.get("EXP")
        target_exp = target_indexes.get("EXP")
        if source_exp and target_exp and source_exp == target_exp:
            score += MATCH_WEIGHTS["export_ordinal"]
            methods.append("export_ordinal")
            details["exp_match"] = source_exp

        # Check mnemonic hash (very high confidence)
        source_mne = source_indexes.get("MNE")
        target_mne = target_indexes.get("MNE")
        if source_mne and target_mne and source_mne == target_mne:
            score += MATCH_WEIGHTS["mnemonic_hash"]
            methods.append("mnemonic_hash")

        # Check named export match
        source_name = source_func.get("name", "")
        target_name = target_func.get("name", "")
        source_has_human = source_func.get("has_human_name", False)
        target_has_human = target_func.get("has_human_name", False)

        if (
            source_has_human
            and target_has_human
            and source_name
            and target_name
            and source_name == target_name
            and not source_name.startswith("FUN_")
        ):
            score += MATCH_WEIGHTS["export_name"]
            methods.append("export_name")

        # Check unique string references
        source_strings = set(source_func.get("string_refs", []) or [])
        target_strings = set(target_func.get("string_refs", []) or [])
        if source_strings and target_strings:
            common_strings = source_strings & target_strings
            if common_strings:
                # Weight by uniqueness - single shared unique string is strong
                string_score = min(len(common_strings) * 0.3, 0.9)
                score += string_score * MATCH_WEIGHTS["unique_string"]
                methods.append("unique_string")
                details["common_strings"] = list(common_strings)[:3]

        # Check other index matches (with collision awareness)
        for method in ["STR", "API"]:
            source_idx = source_indexes.get(method)
            target_idx = target_indexes.get(method)
            if source_idx and target_idx and source_idx == target_idx:
                # Verify uniqueness in target version
                key = f"{method}:{source_idx}"
                matches_in_target = self.index_lookup[dll_name][target_ver].get(key, [])
                if len(matches_in_target) == 1:  # Unique match
                    score += MATCH_WEIGHTS[f"index_{method.lower()}"]
                    methods.append(f"index_{method.lower()}")
                elif len(matches_in_target) <= 3:  # Few collisions, still useful
                    score += MATCH_WEIGHTS[f"index_{method.lower()}"] * 0.5
                    methods.append(f"index_{method.lower()}_ambig")

        # Check CFG - improved weight, check uniqueness more carefully
        source_cfg = source_indexes.get("CFG")
        target_cfg = target_indexes.get("CFG")
        if source_cfg and target_cfg and source_cfg == target_cfg:
            key = f"CFG:{source_cfg}"
            matches_in_target = self.index_lookup[dll_name][target_ver].get(key, [])
            matches_in_source = self.index_lookup[dll_name][source_ver].get(key, [])
            # Unique in both versions = very reliable
            if len(matches_in_target) == 1 and len(matches_in_source) == 1:
                score += MATCH_WEIGHTS["index_cfg"]
                methods.append("index_cfg")
            elif len(matches_in_target) <= 2:  # Slightly ambiguous but still useful
                score += MATCH_WEIGHTS["index_cfg"] * 0.6
                methods.append("index_cfg_ambig")

        # Check PRO (prologue) - weaker signal
        source_pro = source_indexes.get("PRO")
        target_pro = target_indexes.get("PRO")
        if source_pro and target_pro and source_pro == target_pro:
            key = f"PRO:{source_pro}"
            matches_in_target = self.index_lookup[dll_name][target_ver].get(key, [])
            if len(matches_in_target) == 1:  # Only if unique
                score += MATCH_WEIGHTS["index_pro"]
                methods.append("index_pro")

        # Check callee set + size match (exact)
        # Support both 'callees' and 'api_calls' field names
        source_callees = set()
        for c in source_func.get("callees", []) or source_func.get("api_calls", []):
            name = c.get("name") if isinstance(c, dict) else c
            if name:
                source_callees.add(name)

        target_callees = set()
        for c in target_func.get("callees", []) or target_func.get("api_calls", []):
            name = c.get("name") if isinstance(c, dict) else c
            if name:
                target_callees.add(name)

        source_size = source_func.get("size", 0)
        target_size = target_func.get("size", 0)

        if (
            len(source_callees) >= 3
            and source_callees == target_callees
            and source_size > 0
            and source_size == target_size
        ):
            score += MATCH_WEIGHTS["callee_set_size"]
            methods.append("callee_set_size")
        elif len(source_callees) >= 2 and len(target_callees) >= 2:
            # Check callee overlap (not exact, but high similarity)
            common_callees = source_callees & target_callees
            all_callees = source_callees | target_callees
            if all_callees:
                overlap_ratio = len(common_callees) / len(all_callees)
                if overlap_ratio >= 0.8:
                    score += MATCH_WEIGHTS["callee_overlap"] * overlap_ratio
                    methods.append("callee_overlap")

        # Check signature/prototype match
        source_sig = source_func.get("signature", "")
        target_sig = target_func.get("signature", "")
        if source_sig and target_sig and source_sig == target_sig:
            score += MATCH_WEIGHTS["signature_match"]
            methods.append("signature_match")

        # Size matching
        if source_size > 0 and target_size > 0:
            if source_size == target_size:
                score += MATCH_WEIGHTS["size_exact"]
                methods.append("size_exact")
            else:
                size_ratio = min(source_size, target_size) / max(
                    source_size, target_size
                )
                if size_ratio >= 0.9:
                    score += MATCH_WEIGHTS["size_proximity"]
                    methods.append("size_proximity")

        # Compute confidence (normalized to 0-1)
        # Maximum possible score if everything matches
        max_possible = sum(
            [
                MATCH_WEIGHTS["export_ordinal"],
                MATCH_WEIGHTS["mnemonic_hash"],
                MATCH_WEIGHTS["export_name"],
            ]
        )
        confidence = min(score / max_possible, 1.0)

        return MatchCandidate(
            source_addr=source_addr,
            target_addr=target_addr,
            score=score,
            methods=methods,
            confidence=confidence,
            details=details,
        )

    def find_best_matches(
        self,
        source_funcs: List[dict],
        target_funcs: List[dict],
        dll_name: str,
        source_ver: str,
        target_ver: str,
        already_matched_targets: Set[str] = None,
    ) -> Dict[str, MatchCandidate]:
        """
        Find best matches between source and target function sets.

        Uses a greedy assignment strategy: highest scoring matches first,
        preventing double-assignment.

        Returns: {source_addr: MatchCandidate}
        """
        if already_matched_targets is None:
            already_matched_targets = set()

        # Build candidate matrix
        all_candidates: List[MatchCandidate] = []

        for source_func in source_funcs:
            source_addr = source_func.get("address", "")
            if not source_addr:
                continue

            # Pre-filter targets using index lookups for efficiency
            candidate_targets = set()
            source_indexes = source_func.get("indexes", {})

            # Find targets with any matching index
            for method, hash_val in source_indexes.items():
                if hash_val:
                    key = f"{method}:{hash_val}"
                    matches = self.index_lookup[dll_name][target_ver].get(key, [])
                    candidate_targets.update(matches)

            # Also consider same address (for unchanged functions)
            if source_addr in self.addr_to_func[dll_name].get(target_ver, {}):
                candidate_targets.add(source_addr)

            # If no index matches, fall back to size-based filtering
            if not candidate_targets:
                source_size = source_func.get("size", 0)
                if source_size > 0:
                    for target_func in target_funcs:
                        target_size = target_func.get("size", 0)
                        if target_size > 0:
                            ratio = min(source_size, target_size) / max(
                                source_size, target_size
                            )
                            if ratio >= 0.8:
                                target_addr = target_func.get("address", "")
                                if target_addr:
                                    candidate_targets.add(target_addr)

            # Score each candidate
            for target_addr in candidate_targets:
                if target_addr in already_matched_targets:
                    continue

                target_func = self.addr_to_func[dll_name][target_ver].get(target_addr)
                if not target_func:
                    continue

                candidate = self.compute_match_score(
                    source_func, target_func, dll_name, source_ver, target_ver
                )

                if candidate.score >= MIN_MATCH_SCORE:
                    all_candidates.append(candidate)

        # Sort by score (highest first)
        all_candidates.sort(key=lambda c: c.score, reverse=True)

        # Greedy assignment
        matched_sources = set()
        matched_targets = set(already_matched_targets)
        results = {}

        for candidate in all_candidates:
            if candidate.source_addr in matched_sources:
                continue
            if candidate.target_addr in matched_targets:
                continue

            results[candidate.source_addr] = candidate
            matched_sources.add(candidate.source_addr)
            matched_targets.add(candidate.target_addr)

        return results

    def generate_canonical_id(self, func: dict, dll_name: str, version: str) -> str:
        """Generate a canonical ID for a new function identity."""
        addr = func.get("address", "unknown")
        name = func.get("name", "")

        # Use export ordinal if available
        indexes = func.get("indexes", {})
        if indexes.get("EXP"):
            return f"{dll_name}_EXP_{indexes['EXP'][:12]}"

        # Use name if it's a human-assigned name
        if func.get("has_human_name") and name and not name.startswith("FUN_"):
            safe_name = name.replace(" ", "_")[:30]
            return f"{dll_name}_{safe_name}"

        # Fall back to primary index
        primary_index = func.get("index", "")
        if primary_index:
            method, hash_val = (
                primary_index.split(":", 1)
                if ":" in primary_index
                else ("UNK", primary_index)
            )
            return f"{dll_name}_{method}_{hash_val[:12]}"

        # Last resort: address-based
        return f"{dll_name}_{version.replace('/', '_')}_{addr}"

    def forward_pass(self, dll_name: str, game_type: str) -> None:
        """
        Forward pass: propagate identities from earliest to latest version.
        """
        version_order = (
            LOD_VERSION_ORDER if game_type == "LoD" else CLASSIC_VERSION_ORDER
        )
        available_versions = [
            v
            for v in version_order
            if f"{game_type}/{v}" in self.function_data[dll_name]
        ]

        if len(available_versions) < 2:
            print(f"    Skipping forward pass: fewer than 2 versions available")
            return

        print(f"    Forward pass: {available_versions[0]} -> {available_versions[-1]}")

        # Initialize identities from first version
        first_ver = f"{game_type}/{available_versions[0]}"
        for func in self.function_data[dll_name][first_ver]:
            addr = func.get("address", "")
            if not addr:
                continue

            canonical_id = self.generate_canonical_id(func, dll_name, first_ver)
            name = func.get("name", addr)

            identity = FunctionIdentity(
                canonical_id=canonical_id,
                name=name,
                first_version=first_ver,
                last_version=first_ver,
                addresses={first_ver: addr},
                rvas={first_ver: func.get("rva", "")},
            )

            self.identities[dll_name][canonical_id] = identity
            self.addr_to_identity[dll_name][first_ver][addr] = canonical_id

        # Propagate through version pairs
        for i in range(len(available_versions) - 1):
            source_ver = f"{game_type}/{available_versions[i]}"
            target_ver = f"{game_type}/{available_versions[i+1]}"

            source_funcs = self.function_data[dll_name][source_ver]
            target_funcs = self.function_data[dll_name][target_ver]

            # Find matches
            matches = self.find_best_matches(
                source_funcs, target_funcs, dll_name, source_ver, target_ver
            )

            # Propagate identities
            matched_targets = set()
            for source_addr, candidate in matches.items():
                source_id = self.addr_to_identity[dll_name][source_ver].get(source_addr)
                if source_id:
                    identity = self.identities[dll_name][source_id]
                    identity.addresses[target_ver] = candidate.target_addr
                    target_func = self.addr_to_func[dll_name][target_ver].get(
                        candidate.target_addr, {}
                    )
                    identity.rvas[target_ver] = target_func.get("rva", "")
                    identity.last_version = target_ver
                    identity.match_chain.append(
                        (source_ver, target_ver, candidate.confidence)
                    )

                    self.addr_to_identity[dll_name][target_ver][
                        candidate.target_addr
                    ] = source_id
                    matched_targets.add(candidate.target_addr)

                    self.stats[dll_name]["forward_matches"] += 1

            # Create new identities for unmatched target functions
            for func in target_funcs:
                addr = func.get("address", "")
                if not addr or addr in matched_targets:
                    continue

                # This function is new in this version
                canonical_id = self.generate_canonical_id(func, dll_name, target_ver)

                # Avoid ID collisions
                if canonical_id in self.identities[dll_name]:
                    canonical_id = f"{canonical_id}_{addr[-4:]}"

                name = func.get("name", addr)

                identity = FunctionIdentity(
                    canonical_id=canonical_id,
                    name=name,
                    first_version=target_ver,
                    last_version=target_ver,
                    addresses={target_ver: addr},
                    rvas={target_ver: func.get("rva", "")},
                )

                self.identities[dll_name][canonical_id] = identity
                self.addr_to_identity[dll_name][target_ver][addr] = canonical_id

                self.stats[dll_name]["new_functions"] += 1

            print(
                f"      {available_versions[i]} -> {available_versions[i+1]}: "
                f"{len(matches)} matched, {len(target_funcs) - len(matched_targets)} new"
            )

    def backward_pass(self, dll_name: str, game_type: str) -> None:
        """
        Backward pass: find functions that exist in later versions but not earlier.
        Only processes functions that weren't matched in forward pass.
        """
        version_order = (
            LOD_VERSION_ORDER if game_type == "LoD" else CLASSIC_VERSION_ORDER
        )
        available_versions = [
            v
            for v in version_order
            if f"{game_type}/{v}" in self.function_data[dll_name]
        ]

        if len(available_versions) < 2:
            return

        print(f"    Backward pass: {available_versions[-1]} -> {available_versions[0]}")

        # Work backwards through version pairs
        for i in range(len(available_versions) - 1, 0, -1):
            source_ver = f"{game_type}/{available_versions[i]}"
            target_ver = f"{game_type}/{available_versions[i-1]}"

            # Only consider source functions that don't have a match in target yet
            unmatched_source_funcs = []
            for func in self.function_data[dll_name][source_ver]:
                addr = func.get("address", "")
                if not addr:
                    continue

                identity_id = self.addr_to_identity[dll_name][source_ver].get(addr)
                if identity_id:
                    identity = self.identities[dll_name][identity_id]
                    # Skip if already has an address in target version
                    if target_ver in identity.addresses:
                        continue

                unmatched_source_funcs.append(func)

            if not unmatched_source_funcs:
                continue

            target_funcs = self.function_data[dll_name][target_ver]

            # Already matched targets from forward pass
            already_matched = set(self.addr_to_identity[dll_name][target_ver].keys())

            # Find matches for unmatched functions
            matches = self.find_best_matches(
                unmatched_source_funcs,
                target_funcs,
                dll_name,
                source_ver,
                target_ver,
                already_matched_targets=already_matched,
            )

            # Propagate identities backward
            for source_addr, candidate in matches.items():
                source_id = self.addr_to_identity[dll_name][source_ver].get(source_addr)
                if source_id:
                    identity = self.identities[dll_name][source_id]
                    identity.addresses[target_ver] = candidate.target_addr
                    target_func = self.addr_to_func[dll_name][target_ver].get(
                        candidate.target_addr, {}
                    )
                    identity.rvas[target_ver] = target_func.get("rva", "")

                    # Update first_version if this is earlier
                    identity.first_version = (
                        target_ver  # Target is earlier in backward pass
                    )
                    identity.match_chain.append(
                        (source_ver, target_ver, candidate.confidence)
                    )

                    self.addr_to_identity[dll_name][target_ver][
                        candidate.target_addr
                    ] = source_id

                    self.stats[dll_name]["backward_matches"] += 1

            if matches:
                print(
                    f"      {available_versions[i]} -> {available_versions[i-1]}: "
                    f"{len(matches)} backward matches"
                )

    def process_dll(self, dll_name: str, game_type: str) -> Dict[str, FunctionIdentity]:
        """
        Process a single DLL through the full matching pipeline.
        Uses normalized (lowercase) DLL name as the key.
        """
        # Normalize DLL name for consistent keying
        norm_name = self.register_dll_name(dll_name)

        print(f"  Processing {dll_name} ({game_type})...")

        # Load data
        version_data = self.load_dll_data(dll_name, game_type)
        if not version_data:
            print(f"    No data found")
            return self.identities.get(norm_name, {})

        # Merge with existing data if any
        if norm_name not in self.function_data:
            self.function_data[norm_name] = {}
        self.function_data[norm_name].update(version_data)

        # Initialize identity tracking if not already present
        if norm_name not in self.identities:
            self.identities[norm_name] = {}
        if norm_name not in self.addr_to_identity:
            self.addr_to_identity[norm_name] = {}

        # Add new versions to addr_to_identity
        for ver in version_data.keys():
            if ver not in self.addr_to_identity[norm_name]:
                self.addr_to_identity[norm_name][ver] = {}

        # Build lookups
        self.build_lookups(norm_name, version_data)

        total_funcs = sum(len(funcs) for funcs in version_data.values())
        print(
            f"    Loaded {len(version_data)} versions, {total_funcs} total function instances"
        )

        # Phase 1: Forward pass
        self.forward_pass(norm_name, game_type)

        # Phase 2: Backward pass
        self.backward_pass(norm_name, game_type)

        # Statistics
        unique_identities = len(self.identities[norm_name])
        named_identities = sum(
            1
            for ident in self.identities[norm_name].values()
            if ident.name and not ident.name.startswith("FUN_")
        )

        print(
            f"    Result: {unique_identities} unique functions ({named_identities} named)"
        )
        print(
            f"    Stats: {self.stats[norm_name]['forward_matches']} forward, "
            f"{self.stats[norm_name]['backward_matches']} backward, "
            f"{self.stats[norm_name]['new_functions']} new"
        )

        return self.identities[norm_name]

    def process_all(self, game_types: List[str] = None, dlls: List[str] = None) -> None:
        """
        Process all DLLs for specified game types.
        DLL names are normalized to lowercase for consistent keying.
        """
        if game_types is None:
            game_types = ["LoD", "Classic"]

        # Collect all unique DLLs across game types (normalized to lowercase)
        dll_to_sources: Dict[str, List[Tuple[str, str]]] = (
            {}
        )  # normalized_name -> [(original_name, game_type)]

        for game_type in game_types:
            game_path = self.index_path / game_type
            if not game_path.exists():
                continue

            for version_dir in game_path.iterdir():
                if version_dir.is_dir():
                    for json_file in version_dir.glob("*.json"):
                        original_name = json_file.stem
                        norm_name = original_name.lower()

                        if norm_name not in dll_to_sources:
                            dll_to_sources[norm_name] = []

                        # Only add if this (original_name, game_type) combo not already recorded
                        key = (original_name, game_type)
                        if key not in dll_to_sources[norm_name]:
                            dll_to_sources[norm_name].append(key)

        # Filter by user-specified DLLs if any
        if dlls:
            dlls_lower = set(d.lower() for d in dlls)
            dll_to_sources = {
                k: v for k, v in dll_to_sources.items() if k in dlls_lower
            }

        # Process each unique DLL (by normalized name)
        for norm_name in sorted(dll_to_sources.keys()):
            sources = dll_to_sources[norm_name]

            # Process LoD first if present, then Classic
            # This ensures LoD data (which typically has more versions) is the base
            sources_sorted = sorted(
                sources, key=lambda x: (0 if x[1] == "LoD" else 1, x[0])
            )

            for original_name, game_type in sources_sorted:
                self.process_dll(original_name, game_type)

    def save_results(self, output_path: Path) -> None:
        """Save the matching results to JSON (internal format for debugging)."""
        output = {
            "metadata": {
                "generator": "sequential_matcher.py",
                "description": "Function identities matched using sequential pairwise comparison",
            },
            "dlls": {},
        }

        for dll_name, identities in self.identities.items():
            output["dlls"][dll_name] = {
                "function_count": len(identities),
                "functions": {
                    canonical_id: identity.to_dict()
                    for canonical_id, identity in identities.items()
                },
            }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)

        print(f"\nSaved debug results to {output_path}")

    def save_registry(self, output_path: Path) -> None:
        """
        Save results in function_registry_v2.json format for generate_function_js.py.

        This is the format expected by the viewer pipeline.
        """
        from datetime import datetime

        total_functions = 0
        total_named = 0
        dlls_output = {}

        for norm_name, identities in self.identities.items():
            # Use canonical (display) name instead of normalized key
            display_name = self.dll_canonical_name.get(norm_name, norm_name)
            functions_list = []

            for canonical_id, identity in identities.items():
                # Get the best source function data (prefer earliest with human name)
                best_func_data = None
                best_version = None

                # Try to find a version with the most data
                for ver in sorted(identity.addresses.keys()):
                    if (
                        norm_name in self.addr_to_func
                        and ver in self.addr_to_func[norm_name]
                    ):
                        addr = identity.addresses[ver]
                        func_data = self.addr_to_func[norm_name][ver].get(addr)
                        if func_data:
                            # Prefer versions with human names
                            if func_data.get("has_human_name") or not best_func_data:
                                best_func_data = func_data
                                best_version = ver
                            if func_data.get("has_human_name"):
                                break

                # Build per-version data
                versions_data = {}
                for ver, addr in identity.addresses.items():
                    func_data = None
                    if (
                        norm_name in self.addr_to_func
                        and ver in self.addr_to_func[norm_name]
                    ):
                        func_data = self.addr_to_func[norm_name][ver].get(addr, {})

                    if not func_data:
                        func_data = {}

                    # Extract callees with names (support both field names)
                    callees = []
                    for c in func_data.get("callees", []) or func_data.get(
                        "api_calls", []
                    ):
                        if isinstance(c, dict):
                            callees.append(c.get("name", str(c)))
                        else:
                            callees.append(str(c))

                    # Extract callers with names
                    callers = []
                    for c in func_data.get("callers", []):
                        if isinstance(c, dict):
                            callers.append(c.get("name", str(c)))
                        else:
                            callers.append(str(c))

                    versions_data[ver] = {
                        "address": addr,
                        "rva": identity.rvas.get(ver, ""),
                        "size": func_data.get("size", 0),
                        "callees": callees,
                        "callers": callers,
                        "strings": func_data.get("string_refs", []) or [],
                        "instructions": [],  # Too large to include
                        "instruction_count": func_data.get("instruction_count", 0),
                        "local_var_count": len(func_data.get("local_variables", [])),
                        "param_count": len(func_data.get("parameters", [])),
                        "stack_frame_size": func_data.get("stack_frame_size", 0),
                        "basic_block_count": func_data.get("basic_block_count", 0),
                        "loop_count": func_data.get("loop_count", 0),
                        "mnemonic_hash": func_data.get("indexes", {}).get("MNE", ""),
                        "constants": func_data.get("constants", [])[:10],  # Limit
                        "globals": func_data.get("globals", [])[:10],  # Limit
                    }

                # Build function entry
                func_entry = {
                    "canonical_id": canonical_id,
                    "dll": display_name,
                    "index": best_func_data.get("index", "") if best_func_data else "",
                    "index_method": (
                        best_func_data.get("index_method", "") if best_func_data else ""
                    ),
                    "indexes": (
                        best_func_data.get("indexes", {}) if best_func_data else {}
                    ),
                    "name": (
                        identity.name
                        if identity.name and not identity.name.startswith("FUN_")
                        else None
                    ),
                    "display_name": identity.name,
                    "name_source": best_version,
                    "signature": (
                        best_func_data.get("signature", "") if best_func_data else ""
                    ),
                    "calling_convention": (
                        best_func_data.get("calling_convention", "")
                        if best_func_data
                        else ""
                    ),
                    "return_type": (
                        best_func_data.get("return_type", "") if best_func_data else ""
                    ),
                    "comment": (
                        best_func_data.get("comment", "") if best_func_data else ""
                    ),
                    "parameters": (
                        best_func_data.get("parameters", []) if best_func_data else []
                    ),
                    "versions": versions_data,
                    "version_count": len(versions_data),
                }

                functions_list.append(func_entry)
                total_functions += 1
                if func_entry["name"]:
                    total_named += 1

            dlls_output[display_name] = functions_list

        output = {
            "version": 2,
            "generated": datetime.now().isoformat(),
            "total_functions": total_functions,
            "total_named": total_named,
            "dlls": dlls_output,
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)

        print(f"\nSaved registry to {output_path}")
        print(f"  Total functions: {total_functions}")
        print(f"  Named functions: {total_named}")

    def print_summary(self) -> None:
        """Print overall matching summary."""
        print("\n" + "=" * 60)
        print("Sequential Matching Summary")
        print("=" * 60)

        total_identities = 0
        total_named = 0

        for norm_name, identities in self.identities.items():
            display_name = self.dll_canonical_name.get(norm_name, norm_name)
            count = len(identities)
            named = sum(
                1
                for i in identities.values()
                if i.name and not i.name.startswith("FUN_")
            )
            total_identities += count
            total_named += named

            # Calculate average versions per function
            avg_versions = sum(len(i.addresses) for i in identities.values()) / max(
                count, 1
            )

            print(
                f"{display_name}: {count} functions ({named} named), avg {avg_versions:.1f} versions each"
            )

        print("-" * 60)
        print(f"Total: {total_identities} unique functions ({total_named} named)")

    def export_for_viewer(self, output_dir: Path) -> None:
        """
        Export results in a format compatible with generate_function_js.py.

        Creates per-DLL JSON files with the structure expected by the viewer.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        for norm_name, identities in self.identities.items():
            display_name = self.dll_canonical_name.get(norm_name, norm_name)

            # Build functions dict
            functions = {}
            all_versions = set()

            for canonical_id, identity in identities.items():
                # Collect all versions this function appears in
                all_versions.update(identity.addresses.keys())

                # Get the earliest version's function data for signature etc.
                earliest_ver = identity.first_version
                earliest_func = None
                if (
                    norm_name in self.function_data
                    and earliest_ver in self.function_data[norm_name]
                ):
                    addr = identity.addresses.get(earliest_ver)
                    if addr:
                        earliest_func = self.addr_to_func[norm_name][earliest_ver].get(
                            addr, {}
                        )

                functions[canonical_id] = {
                    "name": identity.name,
                    "addresses": identity.addresses,
                    "rvas": identity.rvas,
                    "signature": (
                        earliest_func.get("signature", "") if earliest_func else ""
                    ),
                    "calling_convention": (
                        earliest_func.get("calling_convention", "")
                        if earliest_func
                        else ""
                    ),
                    "first_version": identity.first_version,
                    "last_version": identity.last_version,
                    "version_count": len(identity.addresses),
                }

            output = {
                "dll_name": display_name,
                "versions": sorted(all_versions),
                "function_count": len(functions),
                "functions": functions,
            }

            output_path = output_dir / f"{display_name}.json"
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2)

            print(f"  Exported {display_name}: {len(functions)} functions")

        print(f"\nExported viewer data to {output_dir}")


def main():
    """Main entry point."""
    base_path = Path(__file__).parent.parent

    # Parse command line args
    import argparse

    parser = argparse.ArgumentParser(description="Sequential pairwise function matcher")
    parser.add_argument(
        "--game",
        choices=["LoD", "Classic", "all"],
        default="all",
        help="Game type to process",
    )
    parser.add_argument(
        "--dll", type=str, help="Specific DLL to process (e.g., Storm.dll)"
    )
    parser.add_argument(
        "--output", type=str, help="Output file path for simple results JSON (optional)"
    )
    parser.add_argument(
        "--output-registry",
        type=str,
        default="reports/function_registry_v2.json",
        help="Output function registry file (default: reports/function_registry_v2.json)",
    )
    parser.add_argument(
        "--export-viewer",
        action="store_true",
        help="Export viewer-compatible files to reports/functions_sequential/",
    )
    parser.add_argument(
        "--no-registry",
        action="store_true",
        help="Skip generating function_registry_v2.json",
    )
    args = parser.parse_args()

    # Determine game types and DLLs
    game_types = ["LoD", "Classic"] if args.game == "all" else [args.game]
    dlls = [args.dll] if args.dll else None

    # Run matcher
    matcher = SequentialMatcher(base_path)
    matcher.process_all(game_types=game_types, dlls=dlls)

    # Save simple results if requested
    if args.output:
        matcher.save_results(base_path / args.output)

    matcher.print_summary()

    # Generate function registry (default behavior, for viewer pipeline)
    if not args.no_registry:
        print(f"\nGenerating function registry: {args.output_registry}")
        matcher.save_registry(base_path / args.output_registry)
        print(f"Registry saved to {args.output_registry}")

    # Export for viewer if requested (legacy format)
    if args.export_viewer:
        matcher.export_for_viewer(base_path / "reports" / "functions_sequential")


if __name__ == "__main__":
    main()
