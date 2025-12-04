#!/usr/bin/env python3
"""
Candidate Matcher - Generate best-match candidates for ALL empty version cells.

This module uses multiple strategies to ensure every function has a candidate
in every version where the DLL exists:

Strategy 1: Direct Fuzzy Match
  - Match using API calls, strings, size (existing fuzzy matcher)
  - Highest confidence matches

Strategy 2: Chain Propagation  
  - If A→B and B→C exist, propagate A→C with compound confidence
  - Fills gaps by walking through version chains

Strategy 3: Structural Matching (for featureless functions)
  - Match by size + basic block count
  - Used when no API/string features available

Candidates are stored per function per version with:
- address: The candidate address
- confidence: Match confidence (0.0-1.0)  
- method: Matching method used
- direction: 'forward' or 'reverse'
- source_version: The version the match came from
- chain_length: Number of hops if propagated
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass

from fuzzy_matcher import FuzzyMatcher, HAS_DATASKETCH


# Ordered version lists for chain building
LOD_VERSIONS = [
    "LoD/1.07", "LoD/1.08", "LoD/1.09", "LoD/1.09b", "LoD/1.09d",
    "LoD/1.10", "LoD/1.11", "LoD/1.11b", "LoD/1.12a",
    "LoD/1.13c", "LoD/1.13d", "LoD/1.14a", "LoD/1.14b", "LoD/1.14c", "LoD/1.14d"
]

CLASSIC_VERSIONS = [
    "Classic/1.00", "Classic/1.01", "Classic/1.02", "Classic/1.03",
    "Classic/1.04b", "Classic/1.04c", "Classic/1.05", "Classic/1.05b",
    "Classic/1.06", "Classic/1.06b", "Classic/1.08", "Classic/1.09",
    "Classic/1.09b", "Classic/1.09d", "Classic/1.10", "Classic/1.11",
    "Classic/1.11b", "Classic/1.12a", "Classic/1.13c", "Classic/1.13d",
    "Classic/1.14a", "Classic/1.14b", "Classic/1.14c", "Classic/1.14d"
]

ALL_VERSIONS = LOD_VERSIONS + CLASSIC_VERSIONS


@dataclass
class Candidate:
    """A candidate match for a function in a specific version."""
    address: str
    rva: Optional[str]
    confidence: float
    method: str
    direction: str
    source_version: str
    chain_length: int = 1
    
    def to_dict(self) -> dict:
        d = {
            'address': self.address,
            'confidence': round(self.confidence, 3),
            'method': self.method,
            'direction': self.direction,
            'source_version': self.source_version,
        }
        if self.rva:
            d['rva'] = self.rva
        if self.chain_length > 1:
            d['chain_length'] = self.chain_length
        return d


class CandidateMatcher:
    """Generate best-match candidates for empty version cells."""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        
        # Candidate matching settings
        cand_config = self.config.get('candidate_matching', {})
        self.min_direct_confidence = cand_config.get('min_direct_confidence', 0.35)
        self.min_chain_confidence = cand_config.get('min_chain_confidence', 0.10)
        self.min_structural_confidence = cand_config.get('min_structural_confidence', 0.20)
        self.chain_decay = cand_config.get('chain_decay', 0.90)  # Confidence multiplier per hop
        
        # Initialize fuzzy matcher with relaxed settings for candidates
        fuzzy_config = self.config.copy()
        if 'fuzzy_matching' not in fuzzy_config:
            fuzzy_config['fuzzy_matching'] = {}
        fuzzy_config['fuzzy_matching']['min_similarity'] = 0.30  # Lower for candidates
        fuzzy_config['fuzzy_matching']['min_size_ratio'] = 0.40
        fuzzy_config['fuzzy_matching']['min_feature_overlap'] = 0.10
        self.fuzzy = FuzzyMatcher(fuzzy_config)
        
        # Loaded function data per DLL per version
        self.function_data: Dict[str, Dict[str, List[dict]]] = {}
        
        # Address to function lookup per DLL per version
        self.addr_to_func: Dict[str, Dict[str, Dict[str, dict]]] = {}
        
        # Stats
        self.stats = defaultdict(int)
    
    def load_function_data(self, base_path: Path) -> None:
        """Load all function index data from disk."""
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
                        
                        if dll_name not in self.function_data:
                            self.function_data[dll_name] = {}
                            self.addr_to_func[dll_name] = {}
                        
                        self.function_data[dll_name][version_key] = functions
                        
                        # Build address lookup
                        self.addr_to_func[dll_name][version_key] = {
                            f.get('address'): f for f in functions if f.get('address')
                        }
                        
                        # Build fuzzy index for this version
                        self.fuzzy.build_indexes(dll_name, functions, version_key)
                        
                    except Exception as e:
                        print(f"Error loading {json_file}: {e}")
        
        print(f"Loaded function data for {len(self.function_data)} DLLs")
    
    def _get_version_chain(self, version: str) -> List[str]:
        """Get the ordered version list that contains this version."""
        if version.startswith("LoD/"):
            return LOD_VERSIONS
        elif version.startswith("Classic/"):
            return CLASSIC_VERSIONS
        return []
    
    def _get_version_index(self, version: str) -> int:
        """Get index of version in its ordered list."""
        chain = self._get_version_chain(version)
        try:
            return chain.index(version)
        except ValueError:
            return -1
    
    def _find_direct_match(self, source_func: dict, dll_name: str, 
                           target_version: str) -> Optional[Candidate]:
        """Find a direct fuzzy match for a function in target version."""
        result = self.fuzzy.find_fuzzy_match(source_func, dll_name, target_version)
        
        if result:
            matched_func, score, method = result
            if score >= self.min_direct_confidence:
                return Candidate(
                    address=matched_func.get('address'),
                    rva=matched_func.get('rva'),
                    confidence=score,
                    method=method,
                    direction='direct',
                    source_version=target_version,
                    chain_length=1
                )
        return None
    
    def _find_structural_match(self, source_func: dict, dll_name: str,
                                target_version: str) -> Optional[Candidate]:
        """
        Find a structural match based on size and block count.
        Used for functions without API/string features.
        """
        if target_version not in self.function_data.get(dll_name, {}):
            return None
        
        source_size = source_func.get('size', 0)
        source_blocks = source_func.get('basic_block_count', 0)
        
        if source_size <= 0:
            return None
        
        candidates = []
        target_funcs = self.function_data[dll_name][target_version]
        
        for tf in target_funcs:
            target_size = tf.get('size', 0)
            target_blocks = tf.get('basic_block_count', 0)
            
            if target_size <= 0:
                continue
            
            # Calculate structural similarity
            size_ratio = min(source_size, target_size) / max(source_size, target_size)
            
            if size_ratio < 0.60:  # Must be within 40% size
                continue
            
            # Block count similarity (if available)
            block_sim = 1.0
            if source_blocks > 0 and target_blocks > 0:
                block_sim = min(source_blocks, target_blocks) / max(source_blocks, target_blocks)
                if block_sim < 0.5:
                    continue
            
            # Combined score - cap at 0.45 for structural matches
            score = (size_ratio * 0.6 + block_sim * 0.4) * 0.45
            
            if score >= self.min_structural_confidence:
                candidates.append((tf, score))
        
        if candidates:
            # Return best structural match
            best = max(candidates, key=lambda x: x[1])
            return Candidate(
                address=best[0].get('address'),
                rva=best[0].get('rva'),
                confidence=best[1],
                method='structural',
                direction='direct',
                source_version=target_version,
                chain_length=1
            )
        
        return None
    
    def _propagate_chain(self, func: dict, dll_name: str, 
                         confirmed_versions: Dict[str, str],
                         all_dll_versions: Set[str]) -> Dict[str, Candidate]:
        """
        Find candidates for empty cells using direct matching from anchors.
        
        Instead of chain propagation which breaks at gaps, this approach:
        1. For each empty version, find the closest confirmed anchor
        2. Try direct fuzzy match from that anchor
        3. Apply distance-based confidence decay
        
        Args:
            func: Registry function entry
            dll_name: DLL name
            confirmed_versions: version -> address for confirmed matches
            all_dll_versions: All versions where this DLL exists
            
        Returns:
            Dict of version -> Candidate for found matches
        """
        candidates: Dict[str, Candidate] = {}
        
        # Process each game type's version chain separately  
        for version_chain in [LOD_VERSIONS, CLASSIC_VERSIONS]:
            # Filter to versions that exist for this DLL
            available = [v for v in version_chain if v in all_dll_versions]
            if not available:
                continue
            
            # Build position map for quick distance calculation
            pos_map = {v: i for i, v in enumerate(available)}
            
            # Find confirmed anchors in this chain with their function data
            anchors = []
            for v in available:
                if v in confirmed_versions:
                    addr = confirmed_versions[v]
                    func_data = self.addr_to_func.get(dll_name, {}).get(v, {}).get(addr)
                    if func_data:
                        anchors.append((pos_map[v], v, func_data))
            
            if not anchors:
                continue
            
            # For each empty version, find best candidate from any anchor
            for target_ver in available:
                if target_ver in confirmed_versions:
                    continue  # Already has confirmed address
                    
                target_pos = pos_map[target_ver]
                best_candidate = None
                best_score = 0.0
                
                # Try each anchor
                for anchor_pos, anchor_ver, anchor_func in anchors:
                    # Calculate version distance
                    distance = abs(target_pos - anchor_pos)
                    direction = 'forward' if target_pos > anchor_pos else 'reverse'
                    
                    # Skip if too far (more than 8 versions apart)
                    if distance > 8:
                        continue
                    
                    # Try fuzzy match
                    candidate = self._find_direct_match(anchor_func, dll_name, target_ver)
                    
                    if candidate:
                        # Apply distance decay
                        decay = self.chain_decay ** distance
                        adjusted_score = candidate.confidence * decay
                        
                        if adjusted_score > best_score and adjusted_score >= self.min_chain_confidence:
                            candidate.confidence = adjusted_score
                            candidate.direction = direction
                            candidate.source_version = anchor_ver
                            candidate.chain_length = distance
                            best_candidate = candidate
                            best_score = adjusted_score
                    else:
                        # Try structural match with higher decay
                        structural = self._find_structural_match(anchor_func, dll_name, target_ver)
                        if structural:
                            decay = (self.chain_decay * 0.8) ** distance  # Extra decay for structural
                            adjusted_score = structural.confidence * decay
                            
                            if adjusted_score > best_score and adjusted_score >= self.min_chain_confidence:
                                structural.confidence = adjusted_score
                                structural.direction = direction
                                structural.source_version = anchor_ver
                                structural.chain_length = distance
                                best_candidate = structural
                                best_score = adjusted_score
                
                if best_candidate:
                    candidates[target_ver] = best_candidate
        
        return candidates

    def generate_candidates(self, registry: dict) -> dict:
        """
        Generate candidates for ALL empty cells in the registry.
        """
        print("\nGenerating candidates for empty cells (comprehensive mode)...")
        
        # Track all candidates before conflict resolution
        all_candidates: Dict[str, Dict[str, Candidate]] = {}  # canonical_id -> version -> Candidate
        
        # Track which addresses are confirmed per version (for conflict resolution)
        confirmed_claims: Dict[str, Dict[str, Dict[str, str]]] = {}  # dll -> version -> addr -> canonical_id
        
        for dll_name, functions in registry.get('dlls', {}).items():
            if dll_name not in self.function_data:
                continue
            
            print(f"  Processing {dll_name}...")
            
            # Get all versions where this DLL exists
            dll_versions = set(self.function_data[dll_name].keys())
            
            # Initialize confirmed claims
            if dll_name not in confirmed_claims:
                confirmed_claims[dll_name] = {v: {} for v in dll_versions}
            
            # First pass: record all confirmed addresses
            for func in functions:
                for version, ver_data in func.get('versions', {}).items():
                    addr = ver_data.get('address')
                    if addr and version in confirmed_claims[dll_name]:
                        confirmed_claims[dll_name][version][addr] = func['canonical_id']
            
            # Second pass: generate candidates for each function
            for func in functions:
                canonical_id = func['canonical_id']
                
                # Get confirmed versions for this function
                confirmed_versions = {}
                for version, ver_data in func.get('versions', {}).items():
                    addr = ver_data.get('address')
                    if addr:
                        confirmed_versions[version] = addr
                
                if not confirmed_versions:
                    self.stats['no_confirmed'] += 1
                    continue
                
                # Find missing versions
                missing = dll_versions - set(confirmed_versions.keys())
                if not missing:
                    self.stats['complete_functions'] += 1
                    continue
                
                # Generate candidates using chain propagation
                candidates = self._propagate_chain(func, dll_name, confirmed_versions, dll_versions)
                
                if candidates:
                    all_candidates[canonical_id] = candidates
                    self.stats['functions_with_candidates'] += 1
                    self.stats['total_candidates'] += len(candidates)
        
        # === Conflict Resolution ===
        print("\n  Resolving one-to-many conflicts...")
        
        # Build claims map: dll -> version -> addr -> [(canonical_id, confidence)]
        claims_map: Dict[str, Dict[str, Dict[str, List[Tuple[str, float]]]]] = {}
        
        # Map canonical_id to dll for quick lookup
        id_to_dll = {}
        for dll_name, functions in registry.get('dlls', {}).items():
            for func in functions:
                id_to_dll[func['canonical_id']] = dll_name
        
        for canonical_id, version_candidates in all_candidates.items():
            dll_name = id_to_dll.get(canonical_id)
            if not dll_name:
                continue
            
            if dll_name not in claims_map:
                claims_map[dll_name] = {}
            
            for version, candidate in version_candidates.items():
                if version not in claims_map[dll_name]:
                    claims_map[dll_name][version] = {}
                
                addr = candidate.address
                if addr not in claims_map[dll_name][version]:
                    claims_map[dll_name][version][addr] = []
                
                claims_map[dll_name][version][addr].append((canonical_id, candidate.confidence))
        
        # Determine winners for each address conflict
        winners: Dict[str, Dict[str, Dict[str, str]]] = {}  # dll -> version -> addr -> winning_canonical_id
        
        for dll_name, versions in claims_map.items():
            winners[dll_name] = {}
            for version, addrs in versions.items():
                winners[dll_name][version] = {}
                for addr, claims in addrs.items():
                    # Skip if already confirmed
                    if addr in confirmed_claims.get(dll_name, {}).get(version, {}):
                        continue
                    
                    if len(claims) > 1:
                        self.stats['conflicts'] += 1
                        claims.sort(key=lambda x: x[1], reverse=True)
                    
                    winners[dll_name][version][addr] = claims[0][0]
        
        # Filter candidates to only winners
        final_candidates: Dict[str, Dict[str, Candidate]] = {}
        
        for canonical_id, version_candidates in all_candidates.items():
            dll_name = id_to_dll.get(canonical_id)
            if not dll_name:
                continue
            
            for version, candidate in version_candidates.items():
                addr = candidate.address
                
                # Check if this is the winner
                winner = winners.get(dll_name, {}).get(version, {}).get(addr)
                if winner != canonical_id:
                    self.stats['conflicts_lost'] += 1
                    continue
                
                # Double check not a confirmed address
                if addr in confirmed_claims.get(dll_name, {}).get(version, {}):
                    continue
                
                if canonical_id not in final_candidates:
                    final_candidates[canonical_id] = {}
                final_candidates[canonical_id][version] = candidate
                self.stats['candidates_kept'] += 1
        
        # Add to registry
        for dll_name, functions in registry.get('dlls', {}).items():
            for func in functions:
                canonical_id = func['canonical_id']
                if canonical_id in final_candidates:
                    # Convert to list format expected by viewer
                    func['candidates'] = {
                        v: c.to_dict() for v, c in final_candidates[canonical_id].items()
                    }
        
        # Stats
        print(f"\n  Complete functions (no gaps): {self.stats['complete_functions']}")
        print(f"  Functions with candidates: {self.stats['functions_with_candidates']}")
        print(f"  Total candidates generated: {self.stats['total_candidates']}")
        print(f"  Conflicts resolved: {self.stats['conflicts']}")
        print(f"  Candidates kept: {self.stats['candidates_kept']}")
        print(f"  Candidates lost to conflicts: {self.stats['conflicts_lost']}")
        
        return registry


def add_candidates_to_registry(base_path: Path) -> None:
    """Add candidates to the function registry."""
    registry_file = base_path / "reports" / "function_registry_v2.json"
    
    if not registry_file.exists():
        print(f"Error: Registry not found: {registry_file}")
        return
    
    with open(registry_file, 'r', encoding='utf-8') as f:
        registry = json.load(f)
    
    print(f"Loaded registry with {registry.get('total_functions', 0)} functions")
    
    config_file = base_path / "config" / "function_index.json"
    config = {}
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
    
    matcher = CandidateMatcher(config)
    matcher.load_function_data(base_path)
    registry = matcher.generate_candidates(registry)
    
    with open(registry_file, 'w', encoding='utf-8') as f:
        json.dump(registry, f, indent=2)
    
    print(f"\nUpdated registry saved to: {registry_file}")


def main():
    base_path = Path(__file__).parent.parent
    add_candidates_to_registry(base_path)


if __name__ == '__main__':
    main()
