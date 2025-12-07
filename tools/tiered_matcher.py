#!/usr/bin/env python3
"""
Tiered Identity Matcher - Match functions using tiered identity signals.

This implements the same matching strategy used in the report viewer:

Tier 1: Definitive Matches (100% confidence)
  - Mnemonic hash match (identical opcode sequence)
  - Index hash match (EXP/STR/API signature)
  - Exact callee set + exact size

Tier 2: Rarity-Weighted Identity (variable confidence based on signal rarity)
  - Rare callees are weighted higher than common ones
  - Unique strings provide strong signal
  - Constants provide weak signal
  - Formula: matched_rarity / total_rarity

Tier 3: Structural Validation (used to reject, not to match)
  - Size must be within 50% or match is rejected
  - Block count plausibility check
  - Does NOT create matches, only validates/rejects

Key insight: Function matching is binary ("is this the same function?")
not a sliding scale. Low-confidence matches indicate uncertainty, not similarity.
"""

import json
import math
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class MatchResult:
    """Result of a tiered identity match."""
    matched: bool
    tier: int  # 1, 2, or 3 (0 = no match)
    confidence: float  # 0.0 to 1.0
    method: str
    matched_address: Optional[str] = None
    matched_rva: Optional[str] = None
    details: Dict = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        d = {
            'confidence': round(self.confidence, 3),
            'method': self.method,
            'tier': self.tier,
        }
        if self.matched_address:
            d['address'] = self.matched_address
        if self.matched_rva:
            d['rva'] = self.matched_rva
        if self.warnings:
            d['warnings'] = self.warnings
        return d


class RarityIndex:
    """
    Tracks frequency of features across all functions to compute rarity weights.
    
    Rare features (appearing in few functions) are weighted higher than common ones.
    Formula: rarity = 1 / log2(count + 1)
    """
    
    def __init__(self):
        self.callee_counts: Dict[str, int] = defaultdict(int)
        self.string_counts: Dict[str, int] = defaultdict(int)
        self.constant_counts: Dict[int, int] = defaultdict(int)
        self.total_functions = 0
        
        # Cached rarity scores
        self._callee_rarity: Dict[str, float] = {}
        self._string_rarity: Dict[str, float] = {}
        self._constant_rarity: Dict[int, float] = {}
        self._built = False
    
    def add_function(self, func: dict):
        """Add a function's features to the frequency count."""
        self.total_functions += 1
        
        # Count callees
        seen_callees = set()
        for callee in func.get('callees', []):
            name = callee.get('name', callee) if isinstance(callee, dict) else callee
            if name and name not in seen_callees:
                seen_callees.add(name)
                self.callee_counts[name] += 1
        
        # Count strings
        seen_strings = set()
        for s in func.get('strings', []) or func.get('string_refs', []):
            if s and s not in seen_strings:
                seen_strings.add(s)
                self.string_counts[s] += 1
        
        # Count constants
        seen_constants = set()
        for c in func.get('constants', []):
            if c not in seen_constants:
                seen_constants.add(c)
                self.constant_counts[c] += 1
    
    def build(self):
        """Build rarity scores from frequency counts."""
        # Callees
        for name, count in self.callee_counts.items():
            self._callee_rarity[name] = 1.0 / math.log2(count + 1)
        
        # Strings - default to high rarity
        for s, count in self.string_counts.items():
            self._string_rarity[s] = 1.0 / math.log2(count + 1)
        
        # Constants - filter out very common ones
        half_total = self.total_functions * 0.5
        for c, count in self.constant_counts.items():
            if count > half_total:
                self._constant_rarity[c] = 0.01  # Very low for ubiquitous
            else:
                self._constant_rarity[c] = 1.0 / math.log2(count + 1)
        
        self._built = True
    
    def get_callee_rarity(self, name: str) -> float:
        return self._callee_rarity.get(name, 0.1)
    
    def get_string_rarity(self, s: str) -> float:
        return self._string_rarity.get(s, 0.8)  # Default high for unknown strings
    
    def get_constant_rarity(self, c: int) -> float:
        return self._constant_rarity.get(c, 0.1)


class TieredMatcher:
    """
    Match functions using tiered identity signals.
    
    Unlike fuzzy matching which computes similarity percentages,
    tiered matching asks "is this definitively the same function?"
    """
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        
        # Thresholds
        tier_config = self.config.get('tiered_matching', {})
        self.tier2_min_confidence = tier_config.get('tier2_min_confidence', 0.50)
        self.size_plausibility_ratio = tier_config.get('size_plausibility_ratio', 0.50)
        self.block_plausibility_ratio = tier_config.get('block_plausibility_ratio', 0.50)
        
        # Rarity indexes per DLL
        self.rarity_indexes: Dict[str, RarityIndex] = {}
        
        # Function data per DLL per version
        self.function_data: Dict[str, Dict[str, List[dict]]] = {}
        
        # Address to function lookup
        self.addr_to_func: Dict[str, Dict[str, Dict[str, dict]]] = {}
        
        # Callee name to functions (for matching across versions)
        self.callee_to_funcs: Dict[str, Dict[str, Dict[str, List[dict]]]] = {}
        
        # Stats
        self.stats = defaultdict(int)
    
    def load_function_data(self, base_path: Path) -> None:
        """Load all function data and build rarity indexes."""
        index_path = base_path / "data" / "function_index"
        
        for game_type in ["Classic", "LoD"]:
            game_path = index_path / game_type
            if not game_path.exists():
                continue
            
            for version_dir in sorted(game_path.iterdir()):
                if not version_dir.is_dir():
                    continue
                version = version_dir.name
                version_key = f"{game_type}/{version}"
                
                for json_file in version_dir.glob("*.json"):
                    dll_name = json_file.stem
                    
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        functions = data.get('functions', [])
                        
                        # Initialize data structures
                        if dll_name not in self.function_data:
                            self.function_data[dll_name] = {}
                            self.addr_to_func[dll_name] = {}
                            self.rarity_indexes[dll_name] = RarityIndex()
                            self.callee_to_funcs[dll_name] = {}
                        
                        self.function_data[dll_name][version_key] = functions
                        self.addr_to_func[dll_name][version_key] = {}
                        self.callee_to_funcs[dll_name][version_key] = defaultdict(list)
                        
                        # Build lookups
                        for func in functions:
                            addr = func.get('address')
                            if addr:
                                self.addr_to_func[dll_name][version_key][addr] = func
                            
                            # Index by callees for cross-reference
                            for callee in func.get('callees', []):
                                name = callee.get('name', callee) if isinstance(callee, dict) else callee
                                if name:
                                    self.callee_to_funcs[dll_name][version_key][name].append(func)
                            
                            # Add to rarity index
                            self.rarity_indexes[dll_name].add_function(func)
                        
                    except Exception as e:
                        print(f"Error loading {json_file}: {e}")
        
        # Build rarity scores
        for dll_name, rarity_idx in self.rarity_indexes.items():
            rarity_idx.build()
        
        print(f"Loaded function data for {len(self.function_data)} DLLs")
        for dll, versions in self.function_data.items():
            total_funcs = sum(len(funcs) for funcs in versions.values())
            print(f"  {dll}: {len(versions)} versions, {total_funcs} total functions")
    
    def _get_callee_names(self, func: dict) -> Set[str]:
        """Extract callee names from a function."""
        names = set()
        for callee in func.get('callees', []):
            if isinstance(callee, dict):
                name = callee.get('name')
            else:
                name = callee
            if name:
                names.add(name)
        return names
    
    def _get_strings(self, func: dict) -> Set[str]:
        """Extract strings from a function."""
        strings = func.get('strings', []) or func.get('string_refs', [])
        return set(strings) if strings else set()
    
    def _get_constants(self, func: dict) -> Set[int]:
        """Extract constants from a function."""
        return set(func.get('constants', []))
    
    def _check_tier1_match(self, source: dict, target: dict) -> Optional[MatchResult]:
        """
        Check for Tier 1 definitive match.
        
        Returns MatchResult if definitive match found, None otherwise.
        """
        # Check mnemonic hash (identical opcode sequence)
        source_mhash = source.get('mnemonic_hash', '')
        target_mhash = target.get('mnemonic_hash', '')
        if source_mhash and target_mhash and source_mhash == target_mhash:
            return MatchResult(
                matched=True,
                tier=1,
                confidence=1.0,
                method='mnemonic_hash',
                matched_address=target.get('address'),
                matched_rva=target.get('rva'),
                details={'reason': 'Mnemonic hash match (identical opcodes)'}
            )
        
        # Check index hash match
        source_index = source.get('index', '')
        target_index = target.get('index', '')
        if source_index and target_index and source_index == target_index:
            method = source_index.split(':')[0] if ':' in source_index else 'INDEX'
            return MatchResult(
                matched=True,
                tier=1,
                confidence=0.98,
                method=f'index_{method}',
                matched_address=target.get('address'),
                matched_rva=target.get('rva'),
                details={'reason': f'Index hash match ({method})'}
            )
        
        # Check exact callee set + size
        source_callees = self._get_callee_names(source)
        target_callees = self._get_callee_names(target)
        source_size = source.get('size', 0)
        target_size = target.get('size', 0)
        
        if (len(source_callees) > 2 and 
            source_callees == target_callees and
            source_size > 0 and source_size == target_size):
            return MatchResult(
                matched=True,
                tier=1,
                confidence=0.95,
                method='exact_callees_size',
                matched_address=target.get('address'),
                matched_rva=target.get('rva'),
                details={'reason': 'Exact callee set + size match'}
            )
        
        return None
    
    def _compute_tier2_score(self, source: dict, target: dict, 
                             rarity_idx: RarityIndex) -> Tuple[float, List[dict]]:
        """
        Compute Tier 2 rarity-weighted identity score.
        
        Returns (score, matched_items) where score is 0.0-1.0
        """
        source_callees = self._get_callee_names(source)
        target_callees = self._get_callee_names(target)
        source_strings = self._get_strings(source)
        target_strings = self._get_strings(target)
        source_constants = self._get_constants(source)
        target_constants = self._get_constants(target)
        
        matched_rarity = 0.0
        total_source_rarity = 0.0
        matched_items = []
        
        # Score callees by rarity
        for name in source_callees:
            rarity = rarity_idx.get_callee_rarity(name)
            total_source_rarity += rarity
            if name in target_callees:
                matched_rarity += rarity
                if rarity > 0.5:  # Track rare matches
                    matched_items.append({
                        'type': 'callee',
                        'name': name,
                        'rarity': round(rarity, 2)
                    })
        
        # Score strings (weight 2x - strings are valuable)
        for s in source_strings:
            rarity = rarity_idx.get_string_rarity(s) * 2.0
            total_source_rarity += rarity
            if s in target_strings:
                matched_rarity += rarity
                matched_items.append({
                    'type': 'string',
                    'name': s[:40],
                    'rarity': round(rarity / 2, 2)
                })
        
        # Score constants (weight 0.5x - constants are weak signal)
        for c in source_constants:
            rarity = rarity_idx.get_constant_rarity(c) * 0.5
            total_source_rarity += rarity
            if c in target_constants:
                matched_rarity += rarity
        
        if total_source_rarity > 0:
            score = matched_rarity / total_source_rarity
        else:
            score = 0.0
        
        return score, matched_items[:5]  # Return top 5 matches
    
    def _check_tier3_plausibility(self, source: dict, target: dict) -> Tuple[bool, List[str]]:
        """
        Check structural plausibility (Tier 3 validation).
        
        Returns (is_plausible, warnings)
        """
        warnings = []
        is_plausible = True
        
        source_size = source.get('size', 0)
        target_size = target.get('size', 0)
        
        # Size check
        if source_size > 0 and target_size > 0:
            size_ratio = min(source_size, target_size) / max(source_size, target_size)
            if size_ratio < self.size_plausibility_ratio:
                is_plausible = False
                warnings.append(f"Size mismatch: {source_size} vs {target_size} ({int(size_ratio*100)}%)")
            elif size_ratio < 0.80:
                warnings.append(f"Size differs: {source_size} vs {target_size}")
        
        # Block count check
        source_blocks = source.get('basic_block_count', 0)
        target_blocks = target.get('basic_block_count', 0)
        
        if source_blocks > 0 and target_blocks > 0:
            block_ratio = min(source_blocks, target_blocks) / max(source_blocks, target_blocks)
            if block_ratio < self.block_plausibility_ratio:
                warnings.append(f"Block count mismatch: {source_blocks} vs {target_blocks}")
        
        return is_plausible, warnings
    
    def find_match(self, source_func: dict, dll_name: str, 
                   target_version: str) -> Optional[MatchResult]:
        """
        Find a tiered identity match for a function in target version.
        
        Args:
            source_func: Function dict to match
            dll_name: DLL name  
            target_version: Version key to search in (e.g., "LoD/1.10")
            
        Returns:
            MatchResult if match found, None otherwise
        """
        if dll_name not in self.function_data:
            return None
        
        if target_version not in self.function_data.get(dll_name, {}):
            return None
        
        target_funcs = self.function_data[dll_name][target_version]
        rarity_idx = self.rarity_indexes.get(dll_name, RarityIndex())
        
        best_result = None
        best_score = 0.0
        
        # Pre-filter candidates by shared callees for efficiency
        source_callees = self._get_callee_names(source_func)
        candidate_addrs = set()
        
        if source_callees:
            callee_lookup = self.callee_to_funcs.get(dll_name, {}).get(target_version, {})
            for name in source_callees:
                for func in callee_lookup.get(name, []):
                    addr = func.get('address')
                    if addr:
                        candidate_addrs.add(addr)
        
        # If no callee overlap, check all functions (but this is likely a bad match)
        if not candidate_addrs:
            # Only include functions with similar size for efficiency
            source_size = source_func.get('size', 0)
            if source_size > 0:
                for func in target_funcs:
                    target_size = func.get('size', 0)
                    if target_size > 0:
                        ratio = min(source_size, target_size) / max(source_size, target_size)
                        if ratio >= 0.60:
                            addr = func.get('address')
                            if addr:
                                candidate_addrs.add(addr)
        
        # Evaluate each candidate
        for addr in candidate_addrs:
            target_func = self.addr_to_func[dll_name][target_version].get(addr)
            if not target_func:
                continue
            
            # Tier 1: Definitive match
            tier1_result = self._check_tier1_match(source_func, target_func)
            if tier1_result:
                self.stats['tier1_matches'] += 1
                return tier1_result
            
            # Tier 3: Structural plausibility check (filter out implausible)
            is_plausible, warnings = self._check_tier3_plausibility(source_func, target_func)
            if not is_plausible:
                continue  # Skip implausible matches
            
            # Tier 2: Rarity-weighted identity
            score, matched_items = self._compute_tier2_score(source_func, target_func, rarity_idx)
            
            # Apply penalty for warnings
            if warnings:
                score *= 0.85
            
            if score > best_score:
                best_score = score
                best_result = MatchResult(
                    matched=(score >= self.tier2_min_confidence),
                    tier=2,
                    confidence=score,
                    method='rarity_weighted',
                    matched_address=target_func.get('address'),
                    matched_rva=target_func.get('rva'),
                    details={
                        'matched_items': matched_items,
                        'raw_score': round(score, 3)
                    },
                    warnings=warnings
                )
        
        # Only return if confidence meets threshold
        if best_result and best_result.matched:
            self.stats['tier2_matches'] += 1
            return best_result
        
        # No confident match found
        self.stats['no_match'] += 1
        return None
    
    def print_stats(self):
        """Print matching statistics."""
        print("\nTiered Matching Statistics:")
        for key, value in sorted(self.stats.items()):
            print(f"  {key}: {value}")


def main():
    """Test the tiered matcher."""
    base_path = Path(__file__).parent.parent
    
    matcher = TieredMatcher()
    matcher.load_function_data(base_path)
    
    # Test with a sample function
    print("\nTiered matcher loaded successfully.")
    print("To use: import TieredMatcher from tiered_matcher.py")
    
    matcher.print_stats()


if __name__ == '__main__':
    main()
