#!/usr/bin/env python3
"""
Fuzzy Function Matcher - Match functions using count-based feature vectors.

This module provides fuzzy matching for functions that don't match via exact hash comparison.
Uses structural count metrics rather than names, since names are not reliable across versions.

Key Principle: Match on COUNTS (structural properties) not NAMES (unreliable labels)

Feature Vector Components (in order of reliability):
- instruction_count: Very stable - overall code complexity
- size: Very stable - function byte size
- api_count: High stability - external API dependencies
- param_count: High stability - function signature
- callee_count: Medium stability - internal call structure
- string_count: Medium stability - string references
- global_count: Medium stability - data dependencies
- loop_count: Medium stability - algorithmic structure
- constant_count: Lower stability - optimization dependent
- local_var_count: Lower stability - optimization dependent
- caller_count: Lower stability - depends on other code
- stack_frame_size: Lower stability - optimization dependent

Value Match Bonuses (added to base vector score):
- string_overlap: +10 max - matching string VALUES (not names)
- instruction_overlap: +8 max - matching instruction mnemonics
- constant_overlap: +5 max - matching constant VALUES (filtered)
- global_overlap: +5 max - matching global VALUES
- tag_overlap: +5 max - matching function tags
"""

import json
import math
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict


# ============================================================================
# Value Extraction Helpers
# ============================================================================

def extract_global_value(g) -> str:
    """
    Extract global value from 'address|name|value' format.

    Args:
        g: Global string in format "address|name|value" or just value

    Returns:
        The value portion of the global
    """
    if isinstance(g, str) and '|' in g:
        parts = g.split('|')
        if len(parts) >= 3:
            return parts[2]  # address|name|value -> value
        if len(parts) == 2:
            return parts[1]  # address|value -> value
    return str(g)


def extract_instruction_mnemonic(instr) -> str:
    """
    Extract instruction mnemonic from instruction data.

    Args:
        instr: Instruction string like "0x1234: MOV EAX, EBX" or dict with 'mnemonic'

    Returns:
        Uppercase mnemonic (e.g., "MOV")
    """
    if isinstance(instr, str):
        # Format: "0x1234: MOV EAX, EBX" or "MOV EAX, EBX"
        colon_idx = instr.find(':')
        instr_part = instr[colon_idx + 1:].strip() if colon_idx >= 0 else instr.strip()
        space_idx = instr_part.find(' ')
        mnemonic = instr_part[:space_idx] if space_idx >= 0 else instr_part
        return mnemonic.upper()
    if isinstance(instr, dict) and 'mnemonic' in instr:
        return instr['mnemonic'].upper()
    return str(instr).upper()


def normalize_string_path(s: str) -> str:
    """
    Normalize string paths for cross-version comparison.
    Removes version-specific paths and normalizes separators.

    Args:
        s: String value that might contain a path

    Returns:
        Normalized string
    """
    if not isinstance(s, str):
        return str(s)
    # Normalize path separators
    normalized = s.replace('\\', '/')
    # Remove common version-specific path prefixes
    normalized = re.sub(r'^[A-Z]:/[^/]+/', '', normalized, flags=re.IGNORECASE)
    return normalized.lower()


def compute_jaccard_similarity(set1: Set, set2: Set) -> float:
    """
    Compute Jaccard similarity between two sets.

    Args:
        set1: First set
        set2: Second set

    Returns:
        Jaccard index (intersection / union), 0.0 to 1.0
    """
    if len(set1) == 0 and len(set2) == 0:
        return 1.0
    if len(set1) == 0 or len(set2) == 0:
        return 0.0
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union > 0 else 0.0


# Common constants to filter out (not distinctive)
COMMON_CONSTANTS = {0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024,
                    0xFF, 0xFFFF, 0xFFFFFFFF, 0x7FFFFFFF, -1}


class VectorMatcher:
    """
    Count-based vector matching for cross-version function identification.

    Uses structural count metrics to create feature vectors and compute
    similarity scores. Does NOT rely on names which are unreliable.

    Also computes value match bonuses for string, instruction, constant,
    global, and tag overlaps.
    """

    # Feature definitions with weights based on reliability
    # Higher weight = more reliable for matching
    FEATURES = {
        # Very High Confidence - structural complexity metrics
        'instruction_count': {'weight': 0.15, 'tolerance': 0.15},
        'size': {'weight': 0.15, 'tolerance': 0.15},

        # High Confidence - control flow and signature
        'api_count': {'weight': 0.12, 'tolerance': 0.25},
        'param_count': {'weight': 0.10, 'tolerance': 0.0},  # Must match exactly or very close

        # Medium Confidence - call and reference patterns
        'callee_count': {'weight': 0.08, 'tolerance': 0.25},
        'string_count': {'weight': 0.07, 'tolerance': 0.30},
        'global_count': {'weight': 0.06, 'tolerance': 0.30},
        'loop_count': {'weight': 0.05, 'tolerance': 0.35},

        # Lower Confidence - optimization dependent
        'constant_count': {'weight': 0.04, 'tolerance': 0.40},
        'local_var_count': {'weight': 0.03, 'tolerance': 0.40},
        'caller_count': {'weight': 0.02, 'tolerance': 0.50},
        'stack_frame_size': {'weight': 0.01, 'tolerance': 0.50},
    }

    # Value bonus configuration: max points and minimum items required
    VALUE_BONUS_CONFIG = {
        'string_overlap': {'max_bonus': 10, 'min_items': 1},
        'instruction_overlap': {'max_bonus': 8, 'min_items': 3},
        'constant_overlap': {'max_bonus': 5, 'min_items': 2},
        'global_overlap': {'max_bonus': 5, 'min_items': 1},
        'tag_overlap': {'max_bonus': 5, 'min_items': 1},
    }

    def __init__(self, config: dict = None):
        self.config = config or {}

        # Matching settings
        match_config = self.config.get('vector_matching', {})
        self.enabled = match_config.get('enabled', True)
        # min_similarity is now 0-100 scale (or auto-scaled if < 1)
        min_sim = match_config.get('min_similarity', 75)
        # Auto-scale if user provides 0-1 value
        self.min_similarity = min_sim * 100 if min_sim <= 1 else min_sim
        self.min_features = match_config.get('min_features', 5)  # Require at least 5 features to match

        # Override feature weights if provided
        custom_weights = match_config.get('feature_weights', {})
        self.feature_weights = {}
        self.feature_tolerances = {}
        for name, props in self.FEATURES.items():
            self.feature_weights[name] = custom_weights.get(name, props['weight'])
            self.feature_tolerances[name] = props['tolerance']

        # Normalize weights to sum to 1.0
        total_weight = sum(self.feature_weights.values())
        if total_weight > 0:
            self.feature_weights = {k: v/total_weight for k, v in self.feature_weights.items()}

        # Statistics
        self.stats = defaultdict(int)

        # Indexes built per DLL
        self.dll_indexes: Dict[str, dict] = {}

    def _extract_feature_vector(self, func: dict) -> Dict[str, int]:
        """
        Extract count-based feature vector from a function.

        Returns dict of feature_name -> count value.
        Only includes features that have valid (non-zero or meaningful) values.
        """
        vector = {}

        # Direct count fields
        for field in ['instruction_count', 'loop_count',
                      'stack_frame_size', 'local_var_count', 'param_count',
                      'callee_count', 'caller_count', 'string_count',
                      'constant_count', 'global_count', 'api_count', 'size']:
            value = func.get(field, 0)
            if value is not None and value >= 0:
                vector[field] = value

        return vector

    def _compute_feature_similarity(self, val1: int, val2: int,
                                     feature_name: str) -> float:
        """
        Compute similarity between two feature values.

        Uses ratio-based similarity with tolerance for differences.
        Returns value between 0.0 and 1.0.
        """
        # Handle zero cases
        if val1 == 0 and val2 == 0:
            return 1.0  # Both zero = perfect match
        if val1 == 0 or val2 == 0:
            return 0.0  # One zero = no match

        # Compute ratio similarity (min/max)
        ratio = min(val1, val2) / max(val1, val2)

        # Get tolerance for this feature
        tolerance = self.feature_tolerances.get(feature_name, 0.25)

        # Handle zero tolerance (must match exactly)
        if tolerance <= 0:
            return 1.0 if val1 == val2 else ratio

        # Compute similarity with tolerance curve
        # Values within tolerance get high scores, outside drops off
        if ratio >= (1.0 - tolerance):
            # Within tolerance - linear scale from tolerance edge to perfect
            return 0.5 + 0.5 * (ratio - (1.0 - tolerance)) / tolerance
        else:
            # Outside tolerance - exponential decay
            return 0.5 * ratio / (1.0 - tolerance)

    def _compute_value_match_bonuses(self, func1: dict, func2: dict) -> Tuple[float, dict]:
        """
        Compute value match bonuses for string, instruction, constant, global, and tag overlaps.

        These bonuses are added to the base vector similarity score to boost matches
        that have actual value overlap (not just similar counts).

        Args:
            func1: First function dict with strings, instructions, constants, globals, tags
            func2: Second function dict

        Returns:
            Tuple of (total_bonus, breakdown_dict) where bonus is 0-33 scale
        """
        breakdown = {}
        total_bonus = 0.0

        # 1. String value overlap (+10 max)
        strings1 = func1.get('strings', [])
        strings2 = func2.get('strings', [])
        if strings1 and strings2:
            # Normalize and compare string values
            set1 = {normalize_string_path(s) for s in strings1 if s}
            set2 = {normalize_string_path(s) for s in strings2 if s}
            config = self.VALUE_BONUS_CONFIG['string_overlap']
            if len(set1) >= config['min_items'] and len(set2) >= config['min_items']:
                jaccard = compute_jaccard_similarity(set1, set2)
                bonus = jaccard * config['max_bonus']
                total_bonus += bonus
                breakdown['string_overlap'] = {
                    'jaccard': round(jaccard, 3),
                    'bonus': round(bonus, 2),
                    'count1': len(set1),
                    'count2': len(set2),
                    'matched': len(set1 & set2)
                }

        # 2. Instruction mnemonic overlap (+8 max)
        instrs1 = func1.get('instructions', [])
        instrs2 = func2.get('instructions', [])
        if instrs1 and instrs2:
            # Extract mnemonics and use multiset comparison (count occurrences)
            mnemonics1 = [extract_instruction_mnemonic(i) for i in instrs1]
            mnemonics2 = [extract_instruction_mnemonic(i) for i in instrs2]
            config = self.VALUE_BONUS_CONFIG['instruction_overlap']
            if len(mnemonics1) >= config['min_items'] and len(mnemonics2) >= config['min_items']:
                # Use frequency-based comparison
                from collections import Counter
                counter1 = Counter(mnemonics1)
                counter2 = Counter(mnemonics2)
                all_mnemonics = set(counter1.keys()) | set(counter2.keys())
                if all_mnemonics:
                    intersection_sum = sum(min(counter1.get(m, 0), counter2.get(m, 0)) for m in all_mnemonics)
                    union_sum = sum(max(counter1.get(m, 0), counter2.get(m, 0)) for m in all_mnemonics)
                    jaccard = intersection_sum / union_sum if union_sum > 0 else 0
                    bonus = jaccard * config['max_bonus']
                    total_bonus += bonus
                    breakdown['instruction_overlap'] = {
                        'jaccard': round(jaccard, 3),
                        'bonus': round(bonus, 2),
                        'count1': len(mnemonics1),
                        'count2': len(mnemonics2)
                    }

        # 3. Constant value overlap (+5 max)
        consts1 = func1.get('constants', [])
        consts2 = func2.get('constants', [])
        if consts1 and consts2:
            # Filter out common constants
            def parse_constant(c):
                if isinstance(c, str):
                    # Format might be "addr||value" or just value
                    parts = c.split('||') if '||' in c else c.split('|')
                    val_str = parts[-1] if parts else c
                    try:
                        return int(val_str, 0)  # Handle hex and decimal
                    except (ValueError, TypeError):
                        return None
                return c if isinstance(c, int) else None

            set1 = {parse_constant(c) for c in consts1}
            set2 = {parse_constant(c) for c in consts2}
            # Remove None and common constants
            set1 = {c for c in set1 if c is not None and c not in COMMON_CONSTANTS}
            set2 = {c for c in set2 if c is not None and c not in COMMON_CONSTANTS}

            config = self.VALUE_BONUS_CONFIG['constant_overlap']
            if len(set1) >= config['min_items'] and len(set2) >= config['min_items']:
                jaccard = compute_jaccard_similarity(set1, set2)
                bonus = jaccard * config['max_bonus']
                total_bonus += bonus
                breakdown['constant_overlap'] = {
                    'jaccard': round(jaccard, 3),
                    'bonus': round(bonus, 2),
                    'count1': len(set1),
                    'count2': len(set2),
                    'matched': len(set1 & set2)
                }

        # 4. Global value overlap (+5 max)
        globals1 = func1.get('globals', [])
        globals2 = func2.get('globals', [])
        if globals1 and globals2:
            # Extract values from "address|name|value" format
            set1 = {extract_global_value(g) for g in globals1 if g}
            set2 = {extract_global_value(g) for g in globals2 if g}
            config = self.VALUE_BONUS_CONFIG['global_overlap']
            if len(set1) >= config['min_items'] and len(set2) >= config['min_items']:
                jaccard = compute_jaccard_similarity(set1, set2)
                bonus = jaccard * config['max_bonus']
                total_bonus += bonus
                breakdown['global_overlap'] = {
                    'jaccard': round(jaccard, 3),
                    'bonus': round(bonus, 2),
                    'count1': len(set1),
                    'count2': len(set2),
                    'matched': len(set1 & set2)
                }

        # 5. Tag overlap (+5 max)
        tags1 = func1.get('tags', [])
        tags2 = func2.get('tags', [])
        if tags1 and tags2:
            set1 = set(tags1)
            set2 = set(tags2)
            config = self.VALUE_BONUS_CONFIG['tag_overlap']
            if len(set1) >= config['min_items'] and len(set2) >= config['min_items']:
                jaccard = compute_jaccard_similarity(set1, set2)
                bonus = jaccard * config['max_bonus']
                total_bonus += bonus
                breakdown['tag_overlap'] = {
                    'jaccard': round(jaccard, 3),
                    'bonus': round(bonus, 2),
                    'count1': len(set1),
                    'count2': len(set2),
                    'matched': len(set1 & set2)
                }

        return total_bonus, breakdown

    def compute_vector_similarity(self, func1: dict, func2: dict,
                                    include_value_bonuses: bool = True) -> Tuple[float, dict]:
        """
        Compute weighted similarity score between two functions.

        Args:
            func1: First function dict
            func2: Second function dict
            include_value_bonuses: Whether to compute and include value bonuses

        Returns:
            Tuple of (overall_score, breakdown_dict)
            - overall_score: 0.0 to 100.0 combined similarity (base + bonuses)
            - breakdown: dict with 'vector_features', 'value_bonuses', and summary
        """
        vec1 = self._extract_feature_vector(func1)
        vec2 = self._extract_feature_vector(func2)

        # Find common features
        common_features = set(vec1.keys()) & set(vec2.keys())

        if len(common_features) < self.min_features:
            return 0.0, {'error': f'insufficient_features ({len(common_features)} < {self.min_features})'}

        # Compute weighted similarity for count features
        total_weight = 0.0
        weighted_sum = 0.0
        feature_breakdown = {}

        for feature in common_features:
            val1 = vec1[feature]
            val2 = vec2[feature]
            weight = self.feature_weights.get(feature, 0.0)

            if weight <= 0:
                continue

            sim = self._compute_feature_similarity(val1, val2, feature)
            weighted_sum += sim * weight
            total_weight += weight

            feature_breakdown[feature] = {
                'val1': val1,
                'val2': val2,
                'similarity': round(sim, 3),
                'weight': round(weight, 3),
                'contribution': round(sim * weight, 4)
            }

        if total_weight > 0:
            base_score = weighted_sum / total_weight
        else:
            base_score = 0.0

        # Scale base score to 0-100
        base_score_100 = base_score * 100

        # Compute value match bonuses
        value_bonus = 0.0
        value_breakdown = {}
        if include_value_bonuses:
            value_bonus, value_breakdown = self._compute_value_match_bonuses(func1, func2)

        # Combined score (capped at 100)
        combined_score = min(100.0, base_score_100 + value_bonus)

        breakdown = {
            'vector_features': feature_breakdown,
            'base_score': round(base_score_100, 2),
            'value_bonus': round(value_bonus, 2),
            'value_breakdown': value_breakdown,
            'combined_score': round(combined_score, 2),
            'feature_count': len(common_features)
        }

        return combined_score, breakdown

    def build_indexes(self, dll_name: str, functions: List[dict],
                      version_key: str) -> None:
        """
        Build matching indexes for a DLL version.

        Creates:
        - Function list by version
        - Size bucket index for fast candidate lookup
        - Feature vector cache
        """
        if not self.enabled:
            return

        if dll_name not in self.dll_indexes:
            self.dll_indexes[dll_name] = {
                'functions': {},  # version_key -> list of functions
                'size_buckets': {},  # version_key -> {bucket: [funcs]}
                'vectors': {},  # version_key -> {addr: vector}
            }

        idx = self.dll_indexes[dll_name]
        idx['functions'][version_key] = functions

        # Build size bucket index (for fast candidate filtering)
        # Bucket size of 32 bytes allows ±~15% variance lookup
        size_buckets = defaultdict(list)
        vectors = {}

        for func in functions:
            addr = func.get('address', '')
            size = func.get('size', 0)

            # Store in size buckets (include adjacent buckets for tolerance)
            bucket = size // 32
            size_buckets[bucket].append(func)

            # Cache feature vector
            vectors[addr] = self._extract_feature_vector(func)

        idx['size_buckets'][version_key] = dict(size_buckets)
        idx['vectors'][version_key] = vectors

        self.stats['indexes_built'] += 1

    def find_match(self, func: dict, dll_name: str,
                   target_version: str) -> Optional[Tuple[dict, float, dict]]:
        """
        Find best matching function in target version using vector similarity.

        Args:
            func: Function dict to match
            dll_name: DLL name
            target_version: Version key to search in (e.g., "LoD/1.10")

        Returns:
            Tuple of (matched_func, similarity_score, breakdown) or None
        """
        if not self.enabled:
            return None

        if dll_name not in self.dll_indexes:
            return None

        idx = self.dll_indexes[dll_name]

        if target_version not in idx['functions']:
            return None

        # Get candidate functions by size bucket
        func_size = func.get('size', 0)
        bucket = func_size // 32

        # Check adjacent buckets to allow for size variance
        candidates = []
        size_buckets = idx['size_buckets'].get(target_version, {})
        for b in [bucket - 1, bucket, bucket + 1]:
            if b in size_buckets:
                candidates.extend(size_buckets[b])

        if not candidates:
            # Fall back to all functions if no size match
            candidates = idx['functions'][target_version]

        # Find best match
        best_match = None
        best_score = 0.0
        best_breakdown = None

        for candidate in candidates:
            score, breakdown = self.compute_vector_similarity(func, candidate)

            if score > best_score:
                best_score = score
                best_match = candidate
                best_breakdown = breakdown

        if best_match and best_score >= self.min_similarity:
            self.stats['vector_matches'] += 1
            return (best_match, best_score, best_breakdown)

        return None

    def find_all_matches(self, unmatched: List[dict], dll_name: str,
                         source_version: str, target_version: str) -> List[Tuple[dict, dict, float, dict]]:
        """
        Find matches for a list of unmatched functions.

        Args:
            unmatched: List of unmatched function dicts
            dll_name: DLL name
            source_version: Source version key
            target_version: Target version key to match against

        Returns:
            List of (source_func, matched_func, score, breakdown) tuples
        """
        matches = []

        for func in unmatched:
            result = self.find_match(func, dll_name, target_version)
            if result:
                matched_func, score, breakdown = result
                matches.append((func, matched_func, score, breakdown))

        return matches

    def get_stats(self) -> dict:
        """Return matching statistics."""
        return dict(self.stats)


# Backwards compatibility - keep FuzzyMatcher as alias
class FuzzyMatcher(VectorMatcher):
    """Backwards compatible alias for VectorMatcher."""

    def __init__(self, config: dict = None):
        # Map old config keys to new ones
        if config and 'fuzzy_matching' in config:
            old_config = config['fuzzy_matching']
            config['vector_matching'] = {
                'enabled': old_config.get('enabled', True),
                'min_similarity': old_config.get('min_similarity', 0.75),
            }
        super().__init__(config)

    def find_fuzzy_match(self, func: dict, dll_name: str,
                         target_version: str) -> Optional[Tuple[dict, float, str]]:
        """Backwards compatible interface."""
        result = self.find_match(func, dll_name, target_version)
        if result:
            matched_func, score, breakdown = result
            return (matched_func, score, 'vector')
        return None

    def find_all_fuzzy_matches(self, unmatched: List[dict], dll_name: str,
                               source_version: str, target_version: str) -> List[Tuple[dict, dict, float, str]]:
        """Backwards compatible interface."""
        matches = self.find_all_matches(unmatched, dll_name, source_version, target_version)
        return [(src, tgt, score, 'vector') for src, tgt, score, _ in matches]


def test_vector_matching():
    """Test vector matching on D2Client.dll 1.09d -> 1.10."""
    base_path = Path(__file__).parent.parent

    # Load function data
    path_109d = base_path / 'data/function_index/LoD/1.09d/D2Client.dll.json'
    path_110 = base_path / 'data/function_index/LoD/1.10/D2Client.dll.json'

    if not path_109d.exists() or not path_110.exists():
        print("Test data not found. Skipping test.")
        return

    with open(path_109d) as f:
        d109d = json.load(f)
    with open(path_110) as f:
        d110 = json.load(f)

    # Build exact match indexes for 1.10
    idx_110 = {'STR': {}, 'API': {}, 'MNE': {}, 'CFG': {}}
    for f in d110['functions']:
        for m in idx_110.keys():
            v = f.get('indexes', {}).get(m)
            if v:
                idx_110[m][v] = f

    # Find unmatched 1.09d functions
    unmatched = []
    matched_exact = 0
    for f in d109d['functions']:
        found = False
        for m in ['STR', 'API', 'MNE', 'CFG']:
            v = f.get('indexes', {}).get(m)
            if v and v in idx_110[m]:
                found = True
                matched_exact += 1
                break
        if not found:
            unmatched.append(f)

    print("=== Vector Matching Test ===")
    print(f"Total 1.09d functions: {len(d109d['functions'])}")
    print(f"Matched (exact): {matched_exact}")
    print(f"Unmatched (exact): {len(unmatched)}")
    print()

    # Initialize vector matcher (min_similarity is now 0-100 scale)
    matcher = VectorMatcher({
        'vector_matching': {
            'enabled': True,
            'min_similarity': 80,  # 80% threshold
            'min_features': 5,
        }
    })

    # Build index for 1.10
    matcher.build_indexes('D2Client.dll', d110['functions'], 'LoD/1.10')

    # Find vector matches
    matches = matcher.find_all_matches(
        unmatched, 'D2Client.dll', 'LoD/1.09d', 'LoD/1.10'
    )

    print(f"Vector matches found: {len(matches)}")
    print()

    # Show some examples with breakdown
    print("Sample matches with breakdown:")
    for src, tgt, score, breakdown in matches[:3]:
        print(f"\n  {src.get('address')} -> {tgt.get('address')} (combined score: {score:.1f})")
        print(f"  Source size: {src.get('size')} | Target size: {tgt.get('size')}")

        if isinstance(breakdown, dict) and 'error' not in breakdown:
            # Show score breakdown
            print(f"  Base score: {breakdown.get('base_score', 0):.1f} | "
                  f"Value bonus: {breakdown.get('value_bonus', 0):.1f}")

            # Show top contributing count features
            features = breakdown.get('vector_features', {})
            if features:
                sorted_features = sorted(
                    [(k, v) for k, v in features.items()],
                    key=lambda x: x[1].get('contribution', 0),
                    reverse=True
                )
                print("  Top count features:")
                for feat, data in sorted_features[:5]:
                    print(f"    {feat}: {data['val1']} vs {data['val2']} "
                          f"(sim: {data['similarity']:.2f})")

            # Show value bonus breakdown
            value_breakdown = breakdown.get('value_breakdown', {})
            if value_breakdown:
                print("  Value bonuses:")
                for bonus_type, bonus_data in value_breakdown.items():
                    print(f"    {bonus_type}: +{bonus_data['bonus']:.1f} "
                          f"(jaccard: {bonus_data['jaccard']:.2f}, "
                          f"matched: {bonus_data.get('matched', 'N/A')})")

    print()
    print(f"Stats: {matcher.get_stats()}")
    print()
    print(f"Remaining unmatched: {len(unmatched) - len(matches)}")
    if len(unmatched) > 0:
        print(f"Improvement: {100 * len(matches) / len(unmatched):.1f}%")


if __name__ == '__main__':
    test_vector_matching()
