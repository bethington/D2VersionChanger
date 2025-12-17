#!/usr/bin/env python3
"""
Sequential Pairwise Matcher - Match functions between adjacent versions.

This implements sequential forward matching:

Phase 1: Forward Pass (1.07 → 1.08 → ... → 1.14d)
   - Use multi-signal scoring between adjacent version pairs
   - Propagate identities forward
   - Track "new" functions (first seen in each version)

Key insight: Adjacent versions are ~95% similar, making pairwise matching
much more accurate than trying to match across all versions at once.

Note: Backward pass was removed as it wasn't picking up additional matches.
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
# NOTE: export_ordinal demoted - ordinals change between D2 versions
MATCH_WEIGHTS = {
    "export_ordinal": 0.50,  # Export ordinal - NOT reliable across versions
    "mnemonic_hash": 0.98,  # Identical opcode sequence
    "index_nop": 0.97,  # NOP index - normalized opcode hash (address-independent)
    "export_name": 0.95,  # Named export match
    "unique_string": 0.92,  # Unique string reference
    "index_exp": 0.50,  # EXP index - NOT reliable across versions
    "index_str": 0.88,  # STR index match
    "index_cal": 0.87,  # CAL index match (sorted callee names - very stable)
    "index_api": 0.85,  # API sequence match (order-dependent)
    "index_aps": 0.84,  # APS index match (sorted API - order-independent)
    "index_con": 0.83,  # CON index match (sorted constants - stable)
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
MIN_MATCH_SCORE = 2.0  # Requires at least one strong signal or multiple medium signals

# Higher threshold when no Tier 1 (hash-based) signal matches
MIN_MATCH_SCORE_NO_TIER1 = 4.0  # Requires multiple strong Tier 2/3 signals

# =============================================================================
# Vector-Based Feature Matching
# =============================================================================
# Feature vector weights - each feature contributes to overall similarity
# Higher weight = more important signal

VECTOR_FEATURE_WEIGHTS = {
    # Hash matches (binary 0/1) - strongest signals
    "mnemonic_hash": 2.0,      # Identical opcode sequence
    "export_ordinal": 0.2,     # Export ordinal - NOT reliable across versions
    "export_name": 0.4,        # Named export match
    "str_index": 1.0,          # String hash index
    "cal_index": 1.0,          # Callee names index
    "cfg_index": 0.6,          # CFG structure index
    "api_index": 1.0,          # API sequence index
    "con_index": 0.5,          # Constants index
    "pro_index": 0.3,          # Prologue index (weak)

    # Set overlaps (0.0-1.0) - Jaccard similarity
    "callee_overlap": 0.7,     # Callee set overlap
    "string_overlap": 0.8,     # String reference overlap
    "constant_overlap": 0.4,   # Constant value overlap

    # Numeric similarities (0.0-1.0)
    "size_sim": 0.6,           # Size similarity
    "callee_count_sim": 0.6,   # Callee count similarity
    "string_count_sim": 0.8,   # String count similarity
    "loop_count_sim": 0.4,     # Loop count similarity
    "stack_frame_sim": 0.6,    # Stack frame size similarity
    "param_count_sim": 1.0,    # Parameter count similarity
    "caller_count_sim": 0.6,   # Caller count similarity
}

# Maximum possible score (sum of all weights)
MAX_VECTOR_SCORE = sum(VECTOR_FEATURE_WEIGHTS.values())


def jaccard_similarity(set_a: set, set_b: set) -> float:
    """Compute Jaccard similarity between two sets: |A ∩ B| / |A ∪ B|"""
    if not set_a and not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


def numeric_similarity(val_a: float, val_b: float, max_val: float = None) -> float:
    """
    Compute similarity between two numeric values.
    Returns 1.0 if equal, decreasing toward 0.0 as they differ.
    Uses ratio-based comparison to handle different scales.
    """
    if val_a == val_b:
        return 1.0
    if val_a == 0 or val_b == 0:
        # One is zero - use absolute difference normalized by the non-zero value
        non_zero = max(val_a, val_b)
        if non_zero == 0:
            return 1.0
        return 0.0  # Zero vs non-zero is a poor match
    # Ratio-based similarity: min/max gives 1.0 for equal, lower for different
    ratio = min(val_a, val_b) / max(val_a, val_b)
    return ratio


def extract_name_from_item(item) -> str:
    """Extract the name part from a callee/caller/string item."""
    if isinstance(item, dict):
        return item.get("name", "")
    # Format: "name|address" or "name@suffix|address"
    s = str(item)
    if "|" in s:
        s = s.split("|")[0]
    if "@" in s:
        s = s.split("@")[0]
    return s


def extract_value_from_item(item) -> str:
    """Extract the value part from a string/constant item."""
    if isinstance(item, dict):
        return item.get("value", str(item))
    # Format: "address|label|value" or "address||value"
    s = str(item)
    parts = s.split("|")
    if len(parts) >= 3:
        return parts[2]
    elif len(parts) == 2:
        return parts[1]
    return s


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
        Compute vector-based similarity score between two functions.

        Uses a feature vector approach where each feature contributes a
        weighted similarity value. Returns a MatchCandidate with the
        total score, contributing methods, and confidence.
        """
        source_addr = source_func.get("address", "")
        target_addr = target_func.get("address", "")

        # Feature vector: {feature_name: similarity_value}
        features = {}
        methods = []
        details = {}

        # Get indexes
        source_indexes = source_func.get("indexes", {})
        target_indexes = target_func.get("indexes", {})

        # =================================================================
        # Hash-based features (binary: 1.0 if match, 0.0 if not)
        # =================================================================

        # Mnemonic hash - strongest signal
        source_mne = source_indexes.get("MNE")
        target_mne = target_indexes.get("MNE")
        if source_mne and target_mne:
            features["mnemonic_hash"] = 1.0 if source_mne == target_mne else 0.0
            if features["mnemonic_hash"] == 1.0:
                methods.append("mnemonic_hash")

        # NOP index - normalized opcode hash (address-independent, very reliable)
        source_nop = source_indexes.get("NOP")
        target_nop = target_indexes.get("NOP")
        if source_nop and target_nop:
            match = source_nop == target_nop
            if match:
                key = f"NOP:{source_nop}"
                collisions = len(self.index_lookup[dll_name][target_ver].get(key, []))
                features["nop_index"] = 1.0 if collisions <= 1 else 0.5 if collisions <= 3 else 0.2
                methods.append("nop_index")
            else:
                features["nop_index"] = 0.0

        # Export ordinal
        source_exp = source_indexes.get("EXP")
        target_exp = target_indexes.get("EXP")
        if source_exp and target_exp:
            features["export_ordinal"] = 1.0 if source_exp == target_exp else 0.0
            if features["export_ordinal"] == 1.0:
                methods.append("export_ordinal")
                details["exp_match"] = source_exp

        # Named export match
        source_name = source_func.get("name", "")
        target_name = target_func.get("name", "")
        source_has_human = source_func.get("has_human_name", False)
        target_has_human = target_func.get("has_human_name", False)
        if source_has_human and target_has_human and source_name and not source_name.startswith("FUN_"):
            features["export_name"] = 1.0 if source_name == target_name else 0.0
            if features["export_name"] == 1.0:
                methods.append("export_name")

        # String index (STR)
        source_str = source_indexes.get("STR")
        target_str = target_indexes.get("STR")
        if source_str and target_str:
            match = source_str == target_str
            # Apply uniqueness penalty
            if match:
                key = f"STR:{source_str}"
                collisions = len(self.index_lookup[dll_name][target_ver].get(key, []))
                features["str_index"] = 1.0 if collisions <= 1 else 0.5 if collisions <= 3 else 0.2
                methods.append("str_index")
            else:
                features["str_index"] = 0.0

        # Callee index (CAL)
        source_cal = source_indexes.get("CAL")
        target_cal = target_indexes.get("CAL")
        if source_cal and target_cal:
            match = source_cal == target_cal
            if match:
                key = f"CAL:{source_cal}"
                collisions = len(self.index_lookup[dll_name][target_ver].get(key, []))
                features["cal_index"] = 1.0 if collisions <= 1 else 0.5 if collisions <= 3 else 0.2
                methods.append("cal_index")
            else:
                features["cal_index"] = 0.0

        # CFG index
        source_cfg = source_indexes.get("CFG")
        target_cfg = target_indexes.get("CFG")
        if source_cfg and target_cfg:
            match = source_cfg == target_cfg
            if match:
                key = f"CFG:{source_cfg}"
                collisions = len(self.index_lookup[dll_name][target_ver].get(key, []))
                features["cfg_index"] = 1.0 if collisions <= 1 else 0.5 if collisions <= 3 else 0.2
                methods.append("cfg_index")
            else:
                features["cfg_index"] = 0.0

        # API index
        source_api = source_indexes.get("API") or source_indexes.get("APS")
        target_api = target_indexes.get("API") or target_indexes.get("APS")
        if source_api and target_api:
            features["api_index"] = 1.0 if source_api == target_api else 0.0
            if features["api_index"] == 1.0:
                methods.append("api_index")

        # Constants index (CON)
        source_con = source_indexes.get("CON")
        target_con = target_indexes.get("CON")
        if source_con and target_con:
            features["con_index"] = 1.0 if source_con == target_con else 0.0
            if features["con_index"] == 1.0:
                methods.append("con_index")

        # Prologue index (PRO) - weak signal
        source_pro = source_indexes.get("PRO")
        target_pro = target_indexes.get("PRO")
        if source_pro and target_pro:
            match = source_pro == target_pro
            if match:
                key = f"PRO:{source_pro}"
                collisions = len(self.index_lookup[dll_name][target_ver].get(key, []))
                features["pro_index"] = 1.0 if collisions <= 1 else 0.0
                if features["pro_index"] > 0:
                    methods.append("pro_index")
            else:
                features["pro_index"] = 0.0

        # =================================================================
        # Set-based features (Jaccard similarity: 0.0 - 1.0)
        # =================================================================

        # Build callee sets
        source_callees = set()
        for c in source_func.get("callees", []) or source_func.get("api_calls", []) or []:
            name = extract_name_from_item(c)
            if name:
                source_callees.add(name)

        target_callees = set()
        for c in target_func.get("callees", []) or target_func.get("api_calls", []) or []:
            name = extract_name_from_item(c)
            if name:
                target_callees.add(name)

        callee_sim = jaccard_similarity(source_callees, target_callees)
        features["callee_overlap"] = callee_sim
        if callee_sim > 0.5:
            methods.append(f"callee_overlap({callee_sim:.0%})")

        # Build string sets
        source_strings = set()
        for s in source_func.get("strings", []) or source_func.get("string_refs", []) or []:
            val = extract_value_from_item(s)
            if val:
                source_strings.add(val)

        target_strings = set()
        for s in target_func.get("strings", []) or target_func.get("string_refs", []) or []:
            val = extract_value_from_item(s)
            if val:
                target_strings.add(val)

        string_sim = jaccard_similarity(source_strings, target_strings)
        features["string_overlap"] = string_sim
        if string_sim > 0.5:
            methods.append(f"string_overlap({string_sim:.0%})")
            details["common_strings"] = list(source_strings & target_strings)[:3]

        # Build constant sets
        source_constants = set()
        for c in source_func.get("constants", []) or []:
            val = extract_value_from_item(c)
            if val:
                source_constants.add(val)

        target_constants = set()
        for c in target_func.get("constants", []) or []:
            val = extract_value_from_item(c)
            if val:
                target_constants.add(val)

        const_sim = jaccard_similarity(source_constants, target_constants)
        features["constant_overlap"] = const_sim
        if const_sim > 0.5:
            methods.append(f"const_overlap({const_sim:.0%})")

        # =================================================================
        # Numeric features (ratio similarity: 0.0 - 1.0)
        # =================================================================

        # Size similarity
        source_size = source_func.get("size", 0) or 0
        target_size = target_func.get("size", 0) or 0
        size_sim = numeric_similarity(source_size, target_size)
        features["size_sim"] = size_sim
        if size_sim == 1.0:
            methods.append("size_exact")
        elif size_sim >= 0.9:
            methods.append(f"size_sim({size_sim:.0%})")

        # Callee count similarity
        callee_count_sim = numeric_similarity(len(source_callees), len(target_callees))
        features["callee_count_sim"] = callee_count_sim

        # String count similarity
        string_count_sim = numeric_similarity(len(source_strings), len(target_strings))
        features["string_count_sim"] = string_count_sim

        # Loop count similarity
        source_loops = source_func.get("loop_count", 0) or 0
        target_loops = target_func.get("loop_count", 0) or 0
        loop_sim = numeric_similarity(source_loops, target_loops)
        features["loop_count_sim"] = loop_sim

        # Stack frame similarity
        source_stack = source_func.get("stack_frame_size", 0) or 0
        target_stack = target_func.get("stack_frame_size", 0) or 0
        stack_sim = numeric_similarity(source_stack, target_stack)
        features["stack_frame_sim"] = stack_sim

        # Parameter count similarity
        source_params = source_func.get("param_count", 0) or 0
        target_params = target_func.get("param_count", 0) or 0
        param_sim = numeric_similarity(source_params, target_params)
        features["param_count_sim"] = param_sim

        # Caller count similarity
        source_caller_count = len(source_func.get("callers", []))
        target_caller_count = len(target_func.get("callers", []))
        caller_count_sim = numeric_similarity(source_caller_count, target_caller_count)
        features["caller_count_sim"] = caller_count_sim

        # =================================================================
        # Hard Constraints - reject obviously wrong matches
        # =================================================================

        # Constraint 1: Parameter count must match (very reliable signal)
        if source_params > 0 and target_params > 0 and source_params != target_params:
            return MatchCandidate(
                source_addr=source_addr,
                target_addr=target_addr,
                score=0.0,
                methods=["rejected:param_mismatch"],
                confidence=0.0,
                details={"rejection": f"param_count {source_params} vs {target_params}"},
            )

        # Constraint 2: Extreme caller count mismatch
        # If one function has many callers and the other has none, likely different functions
        if (source_caller_count > 3 and target_caller_count == 0) or \
           (target_caller_count > 3 and source_caller_count == 0):
            return MatchCandidate(
                source_addr=source_addr,
                target_addr=target_addr,
                score=0.0,
                methods=["rejected:caller_mismatch"],
                confidence=0.0,
                details={"rejection": f"caller_count {source_caller_count} vs {target_caller_count}"},
            )

        # Constraint 3: Caller ratio check (when both have callers)
        if source_caller_count > 0 and target_caller_count > 0:
            caller_ratio = min(source_caller_count, target_caller_count) / max(source_caller_count, target_caller_count)
            if caller_ratio < 0.2:  # 5× difference is too extreme
                return MatchCandidate(
                    source_addr=source_addr,
                    target_addr=target_addr,
                    score=0.0,
                    methods=["rejected:caller_ratio"],
                    confidence=0.0,
                    details={"rejection": f"caller_ratio {caller_ratio:.2f} ({source_caller_count} vs {target_caller_count})"},
                )

        # =================================================================
        # Check for Tier 1 signal (hash-based matches)
        # =================================================================
        tier1_matched = any([
            features.get("mnemonic_hash", 0) > 0,
            features.get("export_ordinal", 0) > 0,
            features.get("export_name", 0) > 0,
            features.get("str_index", 0) > 0,
            features.get("cal_index", 0) > 0,
            features.get("api_index", 0) > 0,
            features.get("cfg_index", 0) > 0,
            features.get("con_index", 0) > 0,
        ])

        # =================================================================
        # Compute weighted score
        # =================================================================
        score = 0.0
        for feature_name, sim_value in features.items():
            weight = VECTOR_FEATURE_WEIGHTS.get(feature_name, 0.1)
            score += sim_value * weight

        # Apply higher threshold if no Tier 1 signal
        effective_min_score = MIN_MATCH_SCORE if tier1_matched else MIN_MATCH_SCORE_NO_TIER1

        # Early rejection if score won't meet threshold
        if score < effective_min_score:
            return MatchCandidate(
                source_addr=source_addr,
                target_addr=target_addr,
                score=0.0,
                methods=["rejected:low_score"],
                confidence=0.0,
                details={"rejection": f"score {score:.2f} < threshold {effective_min_score:.2f}", "tier1": tier1_matched},
            )

        # Confidence is normalized score (0-1)
        confidence = min(score / MAX_VECTOR_SCORE, 1.0)

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

        # Forward pass - match functions between adjacent versions
        self.forward_pass(norm_name, game_type)

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
            f"    Stats: {self.stats[norm_name]['forward_matches']} matched, "
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
        Registry saving skipped - data is now stored as split functions_v2 files.

        The monolithic function_registry_v2.json has been deprecated in favor of
        per-DLL JavaScript files in reports/functions_v2/, saving ~350 MB of disk space.

        Data flows: merge_function_index.py → generate_function_js.py → functions_v2/*.js
        """
        print(f"\nRegistry generation skipped (using split functions_v2/ files)")
        print(f"Generate JavaScript files with: python tools/generate_function_js.py")

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
