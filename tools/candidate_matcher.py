#!/usr/bin/env python3
"""
Candidate Matcher - Generate best-match candidates for empty version cells.

This module extends the function registry with candidate matches:
1. For each function, find best matches in versions where it has no confirmed address
2. Bidirectional matching: forward (older→newer) and reverse (newer→older)
3. One-to-many conflict resolution: highest confidence wins
4. Generates candidate data for the viewer to display

Candidates are stored per function per version with:
- address: The candidate address
- confidence: Match confidence (0.0-1.0)
- method: Matching method used (minhash, composite, etc.)
- direction: 'forward' or 'reverse' 
- source_version: The version the match came from

Scope: Adjacent versions only (1.09d↔1.10, not 1.09d↔1.13d)
This is more reliable and matches the typical analysis workflow.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from fuzzy_matcher import FuzzyMatcher, HAS_DATASKETCH


# Version adjacency - only match between adjacent versions
VERSION_ADJACENCY = {
    # LoD versions in order
    "LoD/1.07": ["LoD/1.08"],
    "LoD/1.08": ["LoD/1.07", "LoD/1.09"],
    "LoD/1.09": ["LoD/1.08", "LoD/1.09b"],
    "LoD/1.09b": ["LoD/1.09", "LoD/1.09d"],
    "LoD/1.09d": ["LoD/1.09b", "LoD/1.10"],
    "LoD/1.10": ["LoD/1.09d", "LoD/1.10 Beta 1", "LoD/1.11"],
    "LoD/1.10 Beta 1": ["LoD/1.10", "LoD/1.10 Beta 2"],
    "LoD/1.10 Beta 2": ["LoD/1.10 Beta 1"],
    "LoD/1.11": ["LoD/1.10", "LoD/1.11b"],
    "LoD/1.11b": ["LoD/1.11", "LoD/1.12a"],
    "LoD/1.12a": ["LoD/1.11b", "LoD/1.13c"],
    "LoD/1.13c": ["LoD/1.12a", "LoD/1.13d"],
    "LoD/1.13d": ["LoD/1.13c", "LoD/1.14a"],
    "LoD/1.14a": ["LoD/1.13d", "LoD/1.14b"],
    "LoD/1.14b": ["LoD/1.14a", "LoD/1.14c"],
    "LoD/1.14c": ["LoD/1.14b", "LoD/1.14d"],
    "LoD/1.14d": ["LoD/1.14c"],
    # Classic versions
    "Classic/1.00": ["Classic/1.01"],
    "Classic/1.01": ["Classic/1.00", "Classic/1.02"],
    "Classic/1.02": ["Classic/1.01", "Classic/1.03"],
    "Classic/1.03": ["Classic/1.02", "Classic/1.04b"],
    "Classic/1.04b": ["Classic/1.03", "Classic/1.04c"],
    "Classic/1.04c": ["Classic/1.04b", "Classic/1.05"],
    "Classic/1.05": ["Classic/1.04c", "Classic/1.05b"],
    "Classic/1.05b": ["Classic/1.05", "Classic/1.06"],
    "Classic/1.06": ["Classic/1.05b", "Classic/1.06b"],
    "Classic/1.06b": ["Classic/1.06", "Classic/1.08"],
    "Classic/1.08": ["Classic/1.06b", "Classic/1.09"],
    "Classic/1.09": ["Classic/1.08", "Classic/1.09b"],
    "Classic/1.09b": ["Classic/1.09", "Classic/1.09d"],
    "Classic/1.09d": ["Classic/1.09b", "Classic/1.10"],
    "Classic/1.10": ["Classic/1.09d", "Classic/1.11"],
    "Classic/1.11": ["Classic/1.10", "Classic/1.11b"],
    "Classic/1.11b": ["Classic/1.11", "Classic/1.12a"],
    "Classic/1.12a": ["Classic/1.11b", "Classic/1.13c"],
    "Classic/1.13c": ["Classic/1.12a", "Classic/1.13d"],
    "Classic/1.13d": ["Classic/1.13c", "Classic/1.14a"],
    "Classic/1.14a": ["Classic/1.13d", "Classic/1.14b"],
    "Classic/1.14b": ["Classic/1.14a", "Classic/1.14c"],
    "Classic/1.14c": ["Classic/1.14b", "Classic/1.14d"],
    "Classic/1.14d": ["Classic/1.14c"],
}


class CandidateMatcher:
    """Generate best-match candidates for empty version cells."""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        
        # Candidate matching settings
        cand_config = self.config.get('candidate_matching', {})
        self.min_confidence = cand_config.get('min_confidence', 0.5)
        self.max_candidates_per_cell = cand_config.get('max_candidates', 1)  # Top N per cell
        
        # Initialize fuzzy matcher
        self.fuzzy = FuzzyMatcher(self.config)
        
        # Loaded function data per DLL per version
        self.function_data: Dict[str, Dict[str, List[dict]]] = {}  # dll -> version -> functions
        
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
                        self.function_data[dll_name][version_key] = functions
                        
                        # Build fuzzy index for this version
                        self.fuzzy.build_indexes(dll_name, functions, version_key)
                        
                    except Exception as e:
                        print(f"Error loading {json_file}: {e}")
        
        print(f"Loaded function data for {len(self.function_data)} DLLs")
    
    def generate_candidates(self, registry: dict) -> dict:
        """
        Generate candidates for empty cells in the registry.
        
        Args:
            registry: The function_registry_v2.json data
        
        Returns:
            Updated registry with candidate data
        """
        print("\nGenerating candidates for empty cells...")
        
        # Track which addresses are already claimed per version
        # This is used for one-to-many conflict resolution
        claimed: Dict[str, Dict[str, str]] = {}  # dll -> version -> addr -> canonical_id
        
        # Track candidates before conflict resolution
        all_candidates: Dict[str, List[dict]] = {}  # canonical_id -> [candidate entries]
        
        for dll_name, functions in registry.get('dlls', {}).items():
            if dll_name not in self.function_data:
                continue
            
            print(f"  Processing {dll_name}...")
            
            # Get all versions for this DLL
            dll_versions = set()
            for func in functions:
                dll_versions.update(func.get('versions', {}).keys())
            dll_versions = sorted(dll_versions)
            
            # Build claimed map from confirmed addresses
            if dll_name not in claimed:
                claimed[dll_name] = {}
            for version in dll_versions:
                if version not in claimed[dll_name]:
                    claimed[dll_name][version] = {}
            
            for func in functions:
                for version, ver_data in func.get('versions', {}).items():
                    addr = ver_data.get('address')
                    if addr:
                        claimed[dll_name][version][addr] = func['canonical_id']
            
            # Find candidates for each function's missing versions
            for func in functions:
                canonical_id = func['canonical_id']
                confirmed_versions = set(func.get('versions', {}).keys())
                
                # Get the source function data from a confirmed version
                source_func = None
                source_version = None
                for version in confirmed_versions:
                    if version in self.function_data.get(dll_name, {}):
                        version_funcs = self.function_data[dll_name][version]
                        ver_data = func['versions'][version]
                        target_addr = ver_data.get('address')
                        for vf in version_funcs:
                            if vf.get('address') == target_addr:
                                source_func = vf
                                source_version = version
                                break
                    if source_func:
                        break
                
                if not source_func:
                    continue
                
                # Find missing adjacent versions
                missing_versions = []
                for confirmed_ver in confirmed_versions:
                    adjacent = VERSION_ADJACENCY.get(confirmed_ver, [])
                    for adj_ver in adjacent:
                        if adj_ver not in confirmed_versions and adj_ver in dll_versions:
                            missing_versions.append((adj_ver, confirmed_ver))
                
                # Remove duplicates
                missing_versions = list(set(missing_versions))
                
                # Find candidates for each missing version
                if canonical_id not in all_candidates:
                    all_candidates[canonical_id] = []
                
                for target_version, from_version in missing_versions:
                    if target_version not in self.function_data.get(dll_name, {}):
                        continue
                    
                    # Get the function data from the "from" version
                    from_func = None
                    from_ver_data = func['versions'].get(from_version, {})
                    from_addr = from_ver_data.get('address')
                    if from_addr and from_version in self.function_data.get(dll_name, {}):
                        for vf in self.function_data[dll_name][from_version]:
                            if vf.get('address') == from_addr:
                                from_func = vf
                                break
                    
                    if not from_func:
                        from_func = source_func
                    
                    # Try fuzzy matching to target version
                    result = self.fuzzy.find_fuzzy_match(from_func, dll_name, target_version)
                    
                    if result:
                        matched_func, score, method = result
                        if score >= self.min_confidence:
                            # Determine direction
                            direction = 'forward'  # default
                            from_parts = from_version.split('/')
                            target_parts = target_version.split('/')
                            if len(from_parts) >= 2 and len(target_parts) >= 2:
                                # Compare version numbers
                                from_v = from_parts[1]
                                target_v = target_parts[1]
                                # Simple numeric comparison
                                try:
                                    if float(from_v.replace('Beta ', '').replace('a', '.1').replace('b', '.2').replace('c', '.3').replace('d', '.4')) > \
                                       float(target_v.replace('Beta ', '').replace('a', '.1').replace('b', '.2').replace('c', '.3').replace('d', '.4')):
                                        direction = 'reverse'
                                except:
                                    pass
                            
                            candidate = {
                                'version': target_version,
                                'address': matched_func.get('address'),
                                'rva': matched_func.get('rva'),
                                'confidence': round(score, 3),
                                'method': method,
                                'direction': direction,
                                'source_version': from_version,
                            }
                            all_candidates[canonical_id].append(candidate)
                            self.stats['candidates_found'] += 1
        
        # Conflict resolution: for each version, if multiple functions claim same address,
        # only give it to the highest confidence one
        print("\n  Resolving one-to-many conflicts...")
        
        # Build conflict map: dll -> version -> addr -> [(canonical_id, confidence)]
        conflict_map: Dict[str, Dict[str, Dict[str, List[Tuple[str, float]]]]] = {}
        
        for canonical_id, candidates in all_candidates.items():
            for cand in candidates:
                dll_name = None
                # Find the DLL for this canonical ID
                for dll, funcs in registry.get('dlls', {}).items():
                    for f in funcs:
                        if f['canonical_id'] == canonical_id:
                            dll_name = dll
                            break
                    if dll_name:
                        break
                
                if not dll_name:
                    continue
                
                version = cand['version']
                addr = cand['address']
                
                if dll_name not in conflict_map:
                    conflict_map[dll_name] = {}
                if version not in conflict_map[dll_name]:
                    conflict_map[dll_name][version] = {}
                if addr not in conflict_map[dll_name][version]:
                    conflict_map[dll_name][version][addr] = []
                
                conflict_map[dll_name][version][addr].append((canonical_id, cand['confidence']))
        
        # Find winners for each conflict
        winners: Dict[str, Dict[str, Dict[str, str]]] = {}  # dll -> version -> addr -> canonical_id
        
        for dll_name, versions in conflict_map.items():
            if dll_name not in winners:
                winners[dll_name] = {}
            for version, addrs in versions.items():
                if version not in winners[dll_name]:
                    winners[dll_name][version] = {}
                for addr, claims in addrs.items():
                    if len(claims) > 1:
                        self.stats['conflicts'] += 1
                        # Sort by confidence descending, pick winner
                        claims.sort(key=lambda x: x[1], reverse=True)
                    winners[dll_name][version][addr] = claims[0][0]  # Winner's canonical_id
        
        # Filter candidates to only include winners
        final_candidates: Dict[str, List[dict]] = {}
        
        for canonical_id, candidates in all_candidates.items():
            filtered = []
            for cand in candidates:
                # Find DLL
                dll_name = None
                for dll, funcs in registry.get('dlls', {}).items():
                    for f in funcs:
                        if f['canonical_id'] == canonical_id:
                            dll_name = dll
                            break
                    if dll_name:
                        break
                
                if not dll_name:
                    continue
                
                version = cand['version']
                addr = cand['address']
                
                # Check if this candidate is the winner
                winner = winners.get(dll_name, {}).get(version, {}).get(addr)
                if winner == canonical_id:
                    # Also check not already claimed by confirmed match
                    if addr not in claimed.get(dll_name, {}).get(version, {}):
                        filtered.append(cand)
                        self.stats['candidates_kept'] += 1
            
            if filtered:
                final_candidates[canonical_id] = filtered
        
        # Add candidates to registry
        for dll_name, functions in registry.get('dlls', {}).items():
            for func in functions:
                canonical_id = func['canonical_id']
                if canonical_id in final_candidates:
                    func['candidates'] = final_candidates[canonical_id]
        
        print(f"\n  Candidates found: {self.stats['candidates_found']}")
        print(f"  Conflicts resolved: {self.stats['conflicts']}")
        print(f"  Candidates kept (after conflict resolution): {self.stats['candidates_kept']}")
        
        return registry


def add_candidates_to_registry(base_path: Path) -> None:
    """Add candidates to the function registry."""
    registry_file = base_path / "reports" / "function_registry_v2.json"
    
    if not registry_file.exists():
        print(f"Error: Registry not found: {registry_file}")
        return
    
    # Load registry
    with open(registry_file, 'r', encoding='utf-8') as f:
        registry = json.load(f)
    
    print(f"Loaded registry with {registry.get('total_functions', 0)} functions")
    
    # Load config
    config_file = base_path / "config" / "function_index.json"
    config = {}
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
    
    # Generate candidates
    matcher = CandidateMatcher(config)
    matcher.load_function_data(base_path)
    registry = matcher.generate_candidates(registry)
    
    # Save updated registry
    with open(registry_file, 'w', encoding='utf-8') as f:
        json.dump(registry, f, indent=2)
    
    print(f"\nUpdated registry saved to: {registry_file}")


def main():
    base_path = Path(__file__).parent.parent
    add_candidates_to_registry(base_path)


if __name__ == '__main__':
    main()
