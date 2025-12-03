#!/usr/bin/env python3
"""
Fuzzy Function Matcher - Match functions using approximate similarity.

This module provides fuzzy matching for functions that don't match via exact hash comparison.
Uses multiple techniques:

1. MinHash LSH (datasketch) - Jaccard similarity on API calls and string refs
2. Composite Scoring - Weighted similarity across multiple features
3. Unique Feature Matching - Match by unique strings or API patterns

These are fallback methods used after exact hash matching fails.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

# Check for optional dependencies
try:
    from datasketch import MinHash, MinHashLSH
    HAS_DATASKETCH = True
except ImportError:
    HAS_DATASKETCH = False
    print("Note: datasketch not installed. Install with: pip install datasketch")


class FuzzyMatcher:
    """Fuzzy function matching using multiple similarity techniques."""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        
        # Fuzzy matching settings
        fuzzy_config = self.config.get('fuzzy_matching', {})
        self.enabled = fuzzy_config.get('enabled', True)
        self.min_similarity = fuzzy_config.get('min_similarity', 0.7)  # Raised from 0.6 for better precision
        self.min_size_ratio = fuzzy_config.get('min_size_ratio', 0.6)  # Raised from 0.55
        self.min_feature_overlap = fuzzy_config.get('min_feature_overlap', 0.3)  # Require 30% API/string overlap
        self.use_minhash = fuzzy_config.get('use_minhash', True) and HAS_DATASKETCH
        self.use_composite = fuzzy_config.get('use_composite', True)
        self.use_unique_features = fuzzy_config.get('use_unique_features', True)
        self.normalize_strings = fuzzy_config.get('normalize_strings', True)
        
        # Feature weights for composite scoring
        self.weights = fuzzy_config.get('weights', {
            'size': 0.15,
            'blocks': 0.10,
            'api_calls': 0.35,
            'string_refs': 0.40,
        })
        
        # Statistics
        self.stats = defaultdict(int)
        
        # Indexes built per DLL
        self.dll_indexes: Dict[str, dict] = {}
    
    def build_indexes(self, dll_name: str, functions: List[dict], 
                      version_key: str) -> None:
        """
        Build fuzzy matching indexes for a DLL version.
        
        Args:
            dll_name: Name of the DLL
            functions: List of function dicts from that version
            version_key: e.g., "LoD/1.10"
        """
        if not self.enabled:
            return
        
        if dll_name not in self.dll_indexes:
            self.dll_indexes[dll_name] = {
                'functions': {},  # version_key -> list of functions
                'unique_strings': {},  # version_key -> {string: func}
                'unique_strings_normalized': {},  # version_key -> {normalized_string: func}
                'unique_apis': {},  # version_key -> {api_pattern: func}
                'size_blocks': {},  # version_key -> {(size, blocks): [funcs]}
                'minhash_lsh': {},  # version_key -> MinHashLSH index
                'minhash_sigs': {},  # version_key -> {addr: MinHash}
            }
        
        idx = self.dll_indexes[dll_name]
        idx['functions'][version_key] = functions
        
        # Build unique string index (both raw and normalized)
        string_counts = defaultdict(list)
        string_counts_normalized = defaultdict(list)
        for func in functions:
            for s in func.get('string_refs', []):
                string_counts[s].append(func)
                ns = self._normalize_string(s)
                string_counts_normalized[ns].append(func)
        idx['unique_strings'][version_key] = {
            s: funcs[0] for s, funcs in string_counts.items() if len(funcs) == 1
        }
        idx['unique_strings_normalized'][version_key] = {
            ns: funcs[0] for ns, funcs in string_counts_normalized.items() if len(funcs) == 1
        }
        
        # Build unique API pattern index (sorted API calls as key)
        api_counts = defaultdict(list)
        for func in functions:
            apis = tuple(sorted(func.get('api_calls', [])))
            if apis:
                api_counts[apis].append(func)
        idx['unique_apis'][version_key] = {
            apis: funcs[0] for apis, funcs in api_counts.items() if len(funcs) == 1
        }
        
        # Build size+blocks index
        size_blocks = defaultdict(list)
        for func in functions:
            key = (func.get('size', 0), func.get('basic_block_count', 0))
            size_blocks[key].append(func)
        idx['size_blocks'][version_key] = dict(size_blocks)
        
        # Build MinHash LSH index if available
        if self.use_minhash and HAS_DATASKETCH:
            lsh = MinHashLSH(threshold=self.min_similarity, num_perm=128)
            sigs = {}
            
            for func in functions:
                mh = self._create_minhash(func)
                if mh:
                    addr = func.get('address', '')
                    try:
                        lsh.insert(addr, mh)
                        sigs[addr] = mh
                    except ValueError:
                        pass  # Duplicate key
            
            idx['minhash_lsh'][version_key] = lsh
            idx['minhash_sigs'][version_key] = sigs
        
        self.stats['indexes_built'] += 1
    
    def _normalize_string(self, s: str) -> str:
        """Normalize strings by removing path prefixes that vary between versions."""
        if not self.normalize_strings:
            return s
        # Normalize build paths: C:\Src\Diablo2\... -> DIABLO2/...
        # Also handles: C:\projects\D2\head\Diablo2\...
        s = re.sub(r'C:\\\\[^"\\]+\\\\Diablo2\\\\', 'DIABLO2/', s)
        s = re.sub(r'C:[^"]+Diablo2', 'DIABLO2', s)
        return s
    
    def _get_normalized_strings(self, func: dict) -> Set[str]:
        """Get normalized string references for a function."""
        return {self._normalize_string(s) for s in func.get('string_refs', [])}
    
    def _compute_feature_overlap(self, func1: dict, func2: dict) -> float:
        """
        Compute overlap between function features (API calls and strings).
        Returns Jaccard similarity of combined features.
        """
        # Get APIs
        api1 = set(func1.get('api_calls', []))
        api2 = set(func2.get('api_calls', []))
        
        # Get normalized strings
        str1 = self._get_normalized_strings(func1)
        str2 = self._get_normalized_strings(func2)
        
        # Combine features
        features1 = {f"api:{a}" for a in api1} | {f"str:{s}" for s in str1}
        features2 = {f"api:{a}" for a in api2} | {f"str:{s}" for s in str2}
        
        if not features1 or not features2:
            return 0.0
        
        intersection = len(features1 & features2)
        union = len(features1 | features2)
        
        return intersection / union if union > 0 else 0.0
    
    def _create_minhash(self, func: dict) -> Optional['MinHash']:
        """Create MinHash signature from function features."""
        if not HAS_DATASKETCH:
            return None
        
        mh = MinHash(num_perm=128)
        has_content = False
        
        # Add API calls
        for api in func.get('api_calls', []):
            mh.update(f"api:{api}".encode('utf8'))
            has_content = True
        
        # Add normalized string references
        for s in func.get('string_refs', []):
            s_norm = self._normalize_string(s)
            s_short = s_norm[:100] if len(s_norm) > 100 else s_norm
            mh.update(f"str:{s_short}".encode('utf8'))
            has_content = True
        
        # Only include size/blocks if function has semantic features
        # This prevents matching functions with no API/strings based on size alone
        if has_content:
            # Add size bucket (allow ~10% variance)
            size = func.get('size', 0)
            if size > 0:
                size_bucket = size // 32 * 32
                mh.update(f"size:{size_bucket}".encode('utf8'))
            
            # Add block count
            blocks = func.get('basic_block_count', 0)
            if blocks > 0:
                mh.update(f"blocks:{blocks}".encode('utf8'))
        
        return mh if has_content else None
    
    def find_fuzzy_match(self, func: dict, dll_name: str, 
                         target_version: str) -> Optional[Tuple[dict, float, str]]:
        """
        Find a fuzzy match for a function in a target version.
        
        Args:
            func: Function dict to match
            dll_name: DLL name
            target_version: Version key to search in (e.g., "LoD/1.10")
        
        Returns:
            Tuple of (matched_func, similarity_score, match_method) or None
        """
        if not self.enabled:
            return None
        
        if dll_name not in self.dll_indexes:
            return None
        
        idx = self.dll_indexes[dll_name]
        
        if target_version not in idx['functions']:
            return None
        
        best_match = None
        best_score = 0.0
        best_method = None
        
        func_size = func.get('size', 0)
        
        # Method 1: Unique string matching (with size validation)
        if self.use_unique_features:
            unique_strs = idx['unique_strings'].get(target_version, {})
            unique_strs_norm = idx['unique_strings_normalized'].get(target_version, {})
            
            for s in func.get('string_refs', []):
                # Try exact string first
                if s in unique_strs:
                    candidate = unique_strs[s]
                    if self._check_size_ratio(func_size, candidate.get('size', 0)):
                        self.stats['unique_string_matches'] += 1
                        return (candidate, 0.95, 'unique_string')
                
                # Try normalized string (catches path differences)
                ns = self._normalize_string(s)
                if ns in unique_strs_norm:
                    candidate = unique_strs_norm[ns]
                    if self._check_size_ratio(func_size, candidate.get('size', 0)):
                        self.stats['unique_string_normalized_matches'] += 1
                        return (candidate, 0.92, 'unique_string_normalized')
        
        # Method 2: Unique API pattern matching (with size validation)
        if self.use_unique_features:
            unique_apis = idx['unique_apis'].get(target_version, {})
            api_key = tuple(sorted(func.get('api_calls', [])))
            if api_key and api_key in unique_apis:
                candidate = unique_apis[api_key]
                if self._check_size_ratio(func_size, candidate.get('size', 0)):
                    self.stats['unique_api_matches'] += 1
                    return (candidate, 0.90, 'unique_api')
        
        # Method 3: MinHash LSH similarity (with size validation)
        if self.use_minhash and HAS_DATASKETCH:
            lsh = idx['minhash_lsh'].get(target_version)
            sigs = idx['minhash_sigs'].get(target_version, {})
            
            if lsh and sigs:
                query_mh = self._create_minhash(func)
                if query_mh:
                    candidates = lsh.query(query_mh)
                    
                    for addr in candidates:
                        if addr in sigs:
                            sim = query_mh.jaccard(sigs[addr])
                            if sim > best_score:
                                # Find the function by address
                                for f in idx['functions'][target_version]:
                                    if f.get('address') == addr:
                                        # Validate size ratio AND feature overlap
                                        if self._check_size_ratio(func_size, f.get('size', 0)):
                                            # Check feature overlap before accepting
                                            overlap = self._compute_feature_overlap(func, f)
                                            if overlap >= self.min_feature_overlap:
                                                best_match = f
                                                best_score = sim
                                                best_method = 'minhash'
                                        break
        
        # Method 4: Composite scoring (for remaining candidates)
        if self.use_composite and (best_score < self.min_similarity):
            size_blocks = idx['size_blocks'].get(target_version, {})
            func_size = func.get('size', 0)
            func_blocks = func.get('basic_block_count', 0)
            
            # Only try composite if function has features to compare
            if not func.get('api_calls') and not func.get('string_refs'):
                pass  # Skip composite for featureless functions
            else:
                # Check functions with similar size (±20%)
                candidates = []
                for key, funcs in size_blocks.items():
                    size, blocks = key
                    if func_size > 0 and abs(size - func_size) / func_size < 0.2:
                        candidates.extend(funcs)
                
                for candidate in candidates:
                    # Require minimum feature overlap
                    overlap = self._compute_feature_overlap(func, candidate)
                    if overlap < self.min_feature_overlap:
                        continue
                    
                    score = self._composite_similarity(func, candidate)
                    if score > best_score:
                        best_score = score
                        best_match = candidate
                        best_method = 'composite'
        
        if best_match and best_score >= self.min_similarity:
            self.stats[f'{best_method}_matches'] += 1
            return (best_match, best_score, best_method)
        
        return None
    
    def _check_size_ratio(self, size1: int, size2: int) -> bool:
        """Check if two function sizes are within acceptable ratio."""
        if size1 <= 0 or size2 <= 0:
            return True  # Can't check, allow match
        ratio = min(size1, size2) / max(size1, size2)
        return ratio >= self.min_size_ratio
    
    def _composite_similarity(self, func1: dict, func2: dict) -> float:
        """Calculate weighted composite similarity score."""
        scores = []
        total_weight = 0
        
        # Size similarity (allow 20% variance)
        size1 = func1.get('size', 0)
        size2 = func2.get('size', 0)
        if size1 > 0 and size2 > 0:
            size_diff = abs(size1 - size2)
            size_sim = max(0, 1 - size_diff / max(size1, size2))
            scores.append(size_sim * self.weights['size'])
            total_weight += self.weights['size']
        
        # Block count similarity
        bc1 = func1.get('basic_block_count', 0)
        bc2 = func2.get('basic_block_count', 0)
        if bc1 > 0 and bc2 > 0:
            bc_diff = abs(bc1 - bc2)
            bc_sim = max(0, 1 - bc_diff / max(bc1, bc2))
            scores.append(bc_sim * self.weights['blocks'])
            total_weight += self.weights['blocks']
        
        # API calls Jaccard similarity
        api1 = set(func1.get('api_calls', []))
        api2 = set(func2.get('api_calls', []))
        if api1 or api2:
            if api1 and api2:
                api_sim = len(api1 & api2) / len(api1 | api2)
            else:
                api_sim = 0
            scores.append(api_sim * self.weights['api_calls'])
            total_weight += self.weights['api_calls']
        
        # String refs Jaccard similarity
        str1 = set(func1.get('string_refs', []))
        str2 = set(func2.get('string_refs', []))
        if str1 or str2:
            if str1 and str2:
                str_sim = len(str1 & str2) / len(str1 | str2)
            else:
                str_sim = 0
            scores.append(str_sim * self.weights['string_refs'])
            total_weight += self.weights['string_refs']
        
        if total_weight > 0:
            return sum(scores) / total_weight
        return 0.0
    
    def find_all_fuzzy_matches(self, unmatched: List[dict], dll_name: str,
                                source_version: str, target_version: str) -> List[Tuple[dict, dict, float, str]]:
        """
        Find fuzzy matches for a list of unmatched functions.
        
        Args:
            unmatched: List of unmatched function dicts
            dll_name: DLL name
            source_version: Source version key
            target_version: Target version key to match against
        
        Returns:
            List of (source_func, matched_func, score, method) tuples
        """
        matches = []
        
        for func in unmatched:
            result = self.find_fuzzy_match(func, dll_name, target_version)
            if result:
                matched_func, score, method = result
                matches.append((func, matched_func, score, method))
        
        return matches
    
    def get_stats(self) -> dict:
        """Return matching statistics."""
        return dict(self.stats)


def test_fuzzy_matching():
    """Test fuzzy matching on D2Client.dll 1.09d -> 1.10."""
    base_path = Path(__file__).parent.parent
    
    # Load function data
    with open(base_path / 'data/function_index/LoD/1.09d/D2Client.dll.json') as f:
        d109d = json.load(f)
    with open(base_path / 'data/function_index/LoD/1.10/D2Client.dll.json') as f:
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
    for f in d109d['functions']:
        found = False
        for m in ['STR', 'API', 'MNE', 'CFG']:
            v = f.get('indexes', {}).get(m)
            if v and v in idx_110[m]:
                found = True
                break
        if not found:
            unmatched.append(f)
    
    print(f"=== Fuzzy Matching Test ===")
    print(f"Total 1.09d functions: {len(d109d['functions'])}")
    print(f"Unmatched (exact): {len(unmatched)}")
    print()
    
    # Initialize fuzzy matcher
    matcher = FuzzyMatcher({
        'fuzzy_matching': {
            'enabled': True,
            'min_similarity': 0.5,
            'use_minhash': True,
            'use_composite': True,
            'use_unique_features': True,
        }
    })
    
    # Build index for 1.10
    matcher.build_indexes('D2Client.dll', d110['functions'], 'LoD/1.10')
    
    # Find fuzzy matches
    matches = matcher.find_all_fuzzy_matches(
        unmatched, 'D2Client.dll', 'LoD/1.09d', 'LoD/1.10'
    )
    
    print(f"Fuzzy matches found: {len(matches)}")
    print()
    
    # Group by method
    by_method = defaultdict(list)
    for src, tgt, score, method in matches:
        by_method[method].append((src, tgt, score))
    
    print("Matches by method:")
    for method, items in sorted(by_method.items()):
        print(f"  {method}: {len(items)}")
        # Show some examples
        for src, tgt, score in items[:2]:
            print(f"    {src.get('address')} -> {tgt.get('address')} (score: {score:.3f})")
    
    print()
    print(f"Stats: {matcher.get_stats()}")
    print()
    print(f"Remaining unmatched: {len(unmatched) - len(matches)}")
    print(f"Improvement: {100 * len(matches) / len(unmatched):.1f}%")


if __name__ == '__main__':
    test_fuzzy_matching()
