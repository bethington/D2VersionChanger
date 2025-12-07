#!/usr/bin/env python3
"""
Merge Function Index - Combine Ghidra exports from all versions into unified registry.

This tool:
1. Reads function index exports from data/function_index/{Classic,LoD}/{version}/*.json
2. Matches functions across versions using the method-prefixed index system
3. Resolves naming conflicts using earliest version priority
4. Generates a unified function registry with canonical IDs

Configuration: config/function_index.json
  - enabled_game_types: Enable/disable Classic or LoD processing
  - enabled_versions: Fine-grained version control
  - index_priority: Method priority order for matching
  - output: Output file settings

Index Matching Priority:
  EXP: Export ordinal (100% reliable)
  STR: Unique string references (99% reliable)
  API: API call sequence (95% reliable)
  MNE: Mnemonic sequence + size (85% reliable)
  CFG: Control flow structure (80% reliable)
  PRO: Prologue + size (70% reliable)

Output: reports/function_registry_v2.json
"""

import json
import os
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
import hashlib

# Import fuzzy matcher
try:
    from fuzzy_matcher import FuzzyMatcher, HAS_DATASKETCH
except ImportError:
    FuzzyMatcher = None
    HAS_DATASKETCH = False

# Default config if no config file exists
DEFAULT_CONFIG = {
    "enabled_game_types": {"LoD": True, "Classic": True},
    "enabled_versions": {},
    "index_priority": ["EXP", "STR", "API", "MNE", "CFG", "PRO"],
    "output": {
        "registry_file": "reports/function_registry_v2.json",
        "include_unmatched": True,
        "min_versions_for_match": 1
    }
}

# Version ordering for conflict resolution (earliest first)
VERSION_ORDER = [
    # Classic versions
    ("Classic", "1.00"),
    ("Classic", "1.01"),
    ("Classic", "1.02"),
    ("Classic", "1.03"),
    ("Classic", "1.04b"),
    ("Classic", "1.04c"),
    ("Classic", "1.05"),
    ("Classic", "1.05b"),
    ("Classic", "1.06"),
    ("Classic", "1.06b"),
    ("Classic", "1.08"),
    ("Classic", "1.09"),
    ("Classic", "1.09b"),
    ("Classic", "1.09d"),
    ("Classic", "1.10"),
    ("Classic", "1.11"),
    ("Classic", "1.11b"),
    ("Classic", "1.12a"),
    ("Classic", "1.13c"),
    ("Classic", "1.13d"),
    ("Classic", "1.14a"),
    ("Classic", "1.14b"),
    ("Classic", "1.14c"),
    ("Classic", "1.14d"),
    # LoD versions
    ("LoD", "1.07"),
    ("LoD", "1.08"),
    ("LoD", "1.09"),
    ("LoD", "1.09b"),
    ("LoD", "1.09d"),
    ("LoD", "1.10"),
    ("LoD", "1.10 Beta 1"),
    ("LoD", "1.10 Beta 2"),
    ("LoD", "1.11"),
    ("LoD", "1.11b"),
    ("LoD", "1.12a"),
    ("LoD", "1.13c"),
    ("LoD", "1.13d"),
    ("LoD", "1.14a"),
    ("LoD", "1.14b"),
    ("LoD", "1.14c"),
    ("LoD", "1.14d"),
]

# Index method priority (higher = more reliable)
METHOD_PRIORITY = {
    "EXP": 100,
    "STR": 99,
    "API": 95,
    "MNE": 85,
    "CFG": 80,
    "PRO": 70,
    "ADDR": 0,  # Address-based, won't match
}


class FunctionMerger:
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.index_path = self.base_path / "data" / "function_index"
        self.enhanced_path = self.base_path / "data" / "enhanced"  # Enhanced exports with callees/callers/etc.
        self.output_path = self.base_path / "reports"
        self.config_path = self.base_path / "config" / "function_index.json"
        
        # Load configuration
        self.config = self.load_config()
        
        # Enhanced data cache: dll_name -> version_key -> address -> enhanced_data
        self.enhanced_cache: Dict[str, Dict[str, Dict[str, dict]]] = {}
        
        # Master index: canonical_index -> canonical_id
        self.index_to_canonical: Dict[str, str] = {}
        
        # Canonical function data
        self.functions: Dict[str, dict] = {}  # canonical_id -> function data
        
        # Track naming sources
        self.name_sources: Dict[str, Tuple[str, str, str]] = {}  # canonical_id -> (name, game_type, version)
        
        # Statistics
        self.stats = defaultdict(int)
        
        # Initialize fuzzy matcher if available
        self.fuzzy_matcher = None
        if FuzzyMatcher:
            fuzzy_config = self.config.get('fuzzy_matching', {'enabled': True})
            if fuzzy_config.get('enabled', True):
                self.fuzzy_matcher = FuzzyMatcher(self.config)
                print(f"Fuzzy matching: enabled (datasketch: {HAS_DATASKETCH})")
    
    def load_config(self) -> dict:
        """Load configuration from JSON file."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                print(f"Loaded config from: {self.config_path}")
                return config
            except Exception as e:
                print(f"Warning: Failed to load config: {e}")
        
        print("Using default configuration")
        return DEFAULT_CONFIG
    
    def load_enhanced_exports(self):
        """Load enhanced function exports with callees, callers, strings, instructions.
        
        Supports both flat structure (data/enhanced/*.json) and versioned structure
        (data/enhanced/{GameType}/{Version}/*.json).
        """
        if not self.enhanced_path.exists():
            print(f"No enhanced exports found at: {self.enhanced_path}")
            return
        
        print(f"\nLoading enhanced exports from: {self.enhanced_path}")
        enhanced_files = 0
        enhanced_functions = 0
        
        def load_json_file(json_file: Path):
            """Load a single enhanced JSON file."""
            nonlocal enhanced_files, enhanced_functions
            
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Extract program name
                program_name = data.get('program_name', json_file.stem)
                game_type = data.get('game_type', 'Unknown')
                version = data.get('version', 'Unknown')
                version_key = f"{game_type}/{version}"
                
                # Normalize program name (may include .exe/.dll suffix)
                if not program_name.endswith(('.dll', '.exe')):
                    program_name = f"{program_name}.exe"
                
                if program_name not in self.enhanced_cache:
                    self.enhanced_cache[program_name] = {}
                
                if version_key not in self.enhanced_cache[program_name]:
                    self.enhanced_cache[program_name][version_key] = {}
                
                # Index by address for quick lookup
                func_count = 0
                for func in data.get('functions', []):
                    address = func.get('address', '')
                    if address:
                        self.enhanced_cache[program_name][version_key][address] = {
                            'callees': func.get('callees', []),
                            'callers': func.get('callers', []),
                            'strings': func.get('strings', []),
                            'instructions': func.get('instructions', []),
                            'instruction_count': func.get('instruction_count', 0),
                            'calling_convention': func.get('calling_convention', ''),
                            'return_type': func.get('return_type', ''),
                            'local_var_count': func.get('local_var_count', 0),
                            'param_count': func.get('param_count', 0),
                            # New enhanced fields for better matching
                            'stack_frame_size': func.get('stack_frame_size', 0),
                            'basic_block_count': func.get('basic_block_count', 0),
                            'loop_count': func.get('loop_count', 0),
                            'mnemonic_hash': func.get('mnemonic_hash', ''),
                            'constants': func.get('constants', []),
                            'globals': func.get('globals', []),
                        }
                        enhanced_functions += 1
                        func_count += 1
                
                enhanced_files += 1
                print(f"  Loaded enhanced data for {program_name} {version_key}: {func_count} functions")
                
            except Exception as e:
                print(f"Error loading enhanced export {json_file}: {e}")
        
        # Load flat structure: data/enhanced/*.json
        for json_file in self.enhanced_path.glob("*.json"):
            load_json_file(json_file)
        
        # Load versioned structure: data/enhanced/{GameType}/{Version}/*.json
        for game_type_dir in self.enhanced_path.iterdir():
            if game_type_dir.is_dir() and game_type_dir.name in ["Classic", "LoD"]:
                for version_dir in game_type_dir.iterdir():
                    if version_dir.is_dir():
                        for json_file in version_dir.glob("*.json"):
                            load_json_file(json_file)
        
        if enhanced_files > 0:
            print(f"  Total: {enhanced_files} enhanced files, {enhanced_functions} functions with callees/callers/strings")
    
    def get_enhanced_data(self, dll_name: str, version_key: str, address: str) -> Optional[dict]:
        """Get enhanced data (callees, callers, strings, instructions) for a function."""
        # Try exact match first
        if dll_name in self.enhanced_cache:
            if version_key in self.enhanced_cache[dll_name]:
                if address in self.enhanced_cache[dll_name][version_key]:
                    return self.enhanced_cache[dll_name][version_key][address]
        
        # For 1.14+ Game.exe, try mapping from old DLL names
        # In 1.14+, all DLLs are merged into Game.exe
        if 'Game.exe' in self.enhanced_cache:
            if version_key in self.enhanced_cache['Game.exe']:
                if address in self.enhanced_cache['Game.exe'][version_key]:
                    return self.enhanced_cache['Game.exe'][version_key][address]
        
        return None
    
    def is_version_enabled(self, game_type: str, version: str) -> bool:
        """Check if a specific version is enabled in config."""
        # First check game type
        if not self.config.get('enabled_game_types', {}).get(game_type, True):
            return False
        
        # Then check specific version
        version_config = self.config.get('enabled_versions', {}).get(game_type, {})
        if not version_config:
            # No version-specific config, game type enabled = all versions enabled
            return True
        
        # Check specific version, default to True if not specified
        return version_config.get(version, True)
    
    def version_key(self, game_type: str, version: str) -> int:
        """Get sort order for a version (lower = earlier)."""
        try:
            return VERSION_ORDER.index((game_type, version))
        except ValueError:
            return 999  # Unknown versions sort last
    
    def load_exports(self) -> Dict[str, Dict[str, dict]]:
        """Load all function index exports from Ghidra."""
        exports = {}  # dll_name -> {(game_type, version) -> data}
        
        if not self.index_path.exists():
            print(f"Warning: Index path does not exist: {self.index_path}")
            return exports
        
        for game_type in ["Classic", "LoD"]:
            # Check if game type is enabled
            if not self.config.get('enabled_game_types', {}).get(game_type, True):
                print(f"  Skipping {game_type} (disabled in config)")
                continue
            
            game_path = self.index_path / game_type
            if not game_path.exists():
                continue
            
            for version_dir in sorted(game_path.iterdir()):
                if not version_dir.is_dir():
                    continue
                version = version_dir.name
                
                # Check if specific version is enabled
                if not self.is_version_enabled(game_type, version):
                    print(f"  Skipping {game_type}/{version} (disabled in config)")
                    continue
                
                for json_file in version_dir.glob("*.json"):
                    dll_name = json_file.stem  # Remove .json
                    if dll_name.endswith(".dll") or dll_name.endswith(".exe"):
                        pass  # Keep as-is
                    
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        if dll_name not in exports:
                            exports[dll_name] = {}
                        exports[dll_name][(game_type, version)] = data
                        
                        self.stats['files_loaded'] += 1
                        self.stats['functions_loaded'] += len(data.get('functions', []))
                        
                    except Exception as e:
                        print(f"Error loading {json_file}: {e}")
        
        return exports
    
    def match_function(self, func_data: dict, dll_name: str) -> Optional[str]:
        """
        Find or create canonical ID for a function.
        
        Returns canonical_id if matched/created.
        
        Matching strategy:
        1. Try primary index if method is enabled
        2. Try alternate indexes in priority order
        3. For EXP (if in verified_methods), try EXP + verify with secondary index
        """
        index = func_data.get('index', '')
        if not index:
            return None
        
        # Get config settings
        disabled_methods = set(self.config.get('disabled_methods', []))
        verified_methods = set(self.config.get('verified_methods', []))  # Methods that need secondary verification
        index_priority = self.config.get('index_priority', ['STR', 'API', 'MNE', 'CFG', 'PRO'])
        enabled_methods = [m for m in index_priority if m not in disabled_methods]
        
        index_method = func_data.get('index_method', '')
        indexes = func_data.get('indexes', {})
        full_key = f"{dll_name}:{index}"
        
        # Check if this exact index already exists (only if method is enabled)
        if index_method not in disabled_methods and index_method not in verified_methods:
            if full_key in self.index_to_canonical:
                return self.index_to_canonical[full_key]
        
        # Try alternate indexes in priority order (skip disabled methods)
        for method in enabled_methods:
            idx_value = indexes.get(method)
            if idx_value:
                alt_key = f"{dll_name}:{method}:{idx_value}"
                if alt_key in self.index_to_canonical:
                    # Found match via alternate index
                    canonical_id = self.index_to_canonical[alt_key]
                    # Also register the primary index (if method is enabled and not verified-only)
                    if index_method not in disabled_methods and index_method not in verified_methods:
                        self.index_to_canonical[full_key] = canonical_id
                    return canonical_id
        
        # Try verified methods (like EXP) - match only if secondary index also matches
        for method in verified_methods:
            if method in disabled_methods:
                continue
            idx_value = indexes.get(method)
            if idx_value:
                exp_key = f"{dll_name}:{method}:{idx_value}"
                if exp_key in self.index_to_canonical:
                    canonical_id = self.index_to_canonical[exp_key]
                    # Verify with a secondary index
                    existing_func = self.functions.get(canonical_id)
                    if existing_func and self._verify_match(func_data, existing_func):
                        self.stats['verified_matches'] += 1
                        return canonical_id
                    else:
                        self.stats['rejected_exp_matches'] += 1
        
        # No match found - create new canonical ID
        canonical_id = self.generate_canonical_id(dll_name, func_data)
        
        # Register all available indexes (skip disabled methods, include verified)
        if index_method not in disabled_methods:
            self.index_to_canonical[full_key] = canonical_id
        for method in enabled_methods:
            idx_value = indexes.get(method)
            if idx_value:
                alt_key = f"{dll_name}:{method}:{idx_value}"
                self.index_to_canonical[alt_key] = canonical_id
        # Also register verified method indexes for lookup
        for method in verified_methods:
            if method not in disabled_methods:
                idx_value = indexes.get(method)
                if idx_value:
                    alt_key = f"{dll_name}:{method}:{idx_value}"
                    self.index_to_canonical[alt_key] = canonical_id
        
        return canonical_id
    
    def _verify_match(self, func_data: dict, existing_func: dict) -> bool:
        """
        Verify that two functions are the same by checking secondary indexes.
        
        Returns True if at least one secondary index matches.
        """
        indexes_new = func_data.get('indexes', {})
        indexes_existing = existing_func.get('indexes', {})
        
        # Check each verification method
        for method in ['API', 'MNE', 'CFG', 'STR']:
            val_new = indexes_new.get(method)
            val_existing = indexes_existing.get(method)
            if val_new and val_existing:
                if val_new == val_existing:
                    return True  # Found matching secondary index
        
        # No matching secondary index - could be different functions with same ordinal
        return False
    
    def generate_canonical_id(self, dll_name: str, func_data: dict) -> str:
        """Generate a unique canonical ID for a function."""
        # Use the best index as the canonical ID base
        index = func_data.get('index', 'UNKNOWN')
        method = func_data.get('index_method', 'UNK')
        
        # Sanitize for use as ID
        base_name = dll_name.replace('.dll', '').replace('.exe', '')
        
        # Create a short hash component
        if ':' in index:
            hash_part = index.split(':', 1)[1][:12]
        else:
            hash_part = index[:12]
        
        return f"{base_name}_{method}_{hash_part}"
    
    def merge_function_data(self, canonical_id: str, func_data: dict, 
                           game_type: str, version: str, dll_name: str):
        """Merge function data into the canonical entry."""
        
        if canonical_id not in self.functions:
            # Initialize new function entry
            self.functions[canonical_id] = {
                'canonical_id': canonical_id,
                'dll': dll_name,
                'index': func_data.get('index', ''),
                'index_method': func_data.get('index_method', ''),
                'indexes': func_data.get('indexes', {}),
                'name': None,
                'display_name': func_data.get('display_name', canonical_id),
                'name_source': None,
                'signature': None,
                'calling_convention': None,
                'return_type': None,
                'comment': None,
                'parameters': [],
                'versions': {},
                'version_count': 0,
            }
        
        entry = self.functions[canonical_id]
        
        # Add version-specific address
        version_key = f"{game_type}/{version}"
        version_entry = {
            'address': func_data.get('address'),
            'rva': func_data.get('rva'),
            'size': func_data.get('size'),
        }
        
        # Try to get enhanced data (callees, callers, strings, instructions)
        enhanced = self.get_enhanced_data(dll_name, version_key, func_data.get('address', ''))
        if enhanced:
            version_entry['callees'] = enhanced.get('callees', [])
            version_entry['callers'] = enhanced.get('callers', [])
            version_entry['strings'] = enhanced.get('strings', [])
            version_entry['instructions'] = enhanced.get('instructions', [])
            version_entry['instruction_count'] = enhanced.get('instruction_count', 0)
            version_entry['local_var_count'] = enhanced.get('local_var_count', 0)
            version_entry['param_count'] = enhanced.get('param_count', 0)
            # New enhanced fields for comparison
            version_entry['stack_frame_size'] = enhanced.get('stack_frame_size', 0)
            version_entry['basic_block_count'] = enhanced.get('basic_block_count', 0)
            version_entry['loop_count'] = enhanced.get('loop_count', 0)
            version_entry['mnemonic_hash'] = enhanced.get('mnemonic_hash', '')
            version_entry['constants'] = enhanced.get('constants', [])
            version_entry['globals'] = enhanced.get('globals', [])
            
            # Set calling_convention and return_type at function level (from first version with data)
            if not entry.get('calling_convention') and enhanced.get('calling_convention'):
                entry['calling_convention'] = enhanced['calling_convention']
            if not entry.get('return_type') and enhanced.get('return_type'):
                entry['return_type'] = enhanced['return_type']
        
        entry['versions'][version_key] = version_entry
        entry['version_count'] = len(entry['versions'])
        
        # Handle naming (earliest version wins)
        if func_data.get('has_human_name', False):
            name = func_data.get('name', '')
            current_source = self.name_sources.get(canonical_id)
            
            if current_source is None:
                # First name we've seen
                entry['name'] = name
                entry['display_name'] = name
                entry['name_source'] = version_key
                entry['signature'] = func_data.get('signature')
                entry['comment'] = func_data.get('comment')
                entry['parameters'] = func_data.get('parameters', [])
                self.name_sources[canonical_id] = (name, game_type, version)
                self.stats['named_functions'] += 1
            else:
                # Compare version priority
                current_name, current_game, current_ver = current_source
                current_priority = self.version_key(current_game, current_ver)
                new_priority = self.version_key(game_type, version)
                
                if new_priority < current_priority:
                    # New version is earlier, use its name
                    entry['name'] = name
                    entry['display_name'] = name
                    entry['name_source'] = version_key
                    entry['signature'] = func_data.get('signature')
                    entry['comment'] = func_data.get('comment')
                    entry['parameters'] = func_data.get('parameters', [])
                    self.name_sources[canonical_id] = (name, game_type, version)
    
    def process_dll(self, dll_name: str, version_data: Dict[Tuple[str, str], dict]):
        """Process all versions of a single DLL."""
        print(f"\nProcessing {dll_name}...")
        
        # Sort versions by order (earliest first for consistent ID assignment)
        sorted_versions = sorted(
            version_data.items(),
            key=lambda x: self.version_key(x[0][0], x[0][1])
        )
        
        dll_stats = defaultdict(int)
        version_func_map = {}  # version_key -> {address: (func, canonical_id)}
        
        # Pass 1: Exact matching
        for (game_type, version), data in sorted_versions:
            functions = data.get('functions', [])
            version_key = f"{game_type}/{version}"
            version_func_map[version_key] = {}
            
            # Build fuzzy index for this version
            if self.fuzzy_matcher:
                self.fuzzy_matcher.build_indexes(dll_name, functions, version_key)
            
            for func in functions:
                canonical_id = self.match_function(func, dll_name)
                if canonical_id:
                    self.merge_function_data(canonical_id, func, game_type, version, dll_name)
                    version_func_map[version_key][func.get('address')] = (func, canonical_id)
                    dll_stats['matched'] += 1
        
        # Pass 2: Fuzzy matching to merge single-version functions
        if self.fuzzy_matcher:
            fuzzy_merged = 0
            version_keys = list(version_func_map.keys())
            
            for i in range(len(version_keys) - 1):
                src_version = version_keys[i]
                tgt_version = version_keys[i + 1]
                
                # Find functions that appear in only src_version (not in tgt_version)
                src_funcs = version_func_map[src_version]
                tgt_funcs = version_func_map[tgt_version]
                
                # Get canonical IDs that exist in src but not tgt
                src_canonical_ids = {cid for _, (_, cid) in src_funcs.items()}
                tgt_canonical_ids = {cid for _, (_, cid) in tgt_funcs.items()}
                
                # Functions in src not matched to tgt
                unmatched_src_cids = src_canonical_ids - tgt_canonical_ids
                
                for addr, (func, canonical_id) in src_funcs.items():
                    if canonical_id not in unmatched_src_cids:
                        continue
                    
                    # This function didn't match to next version, try fuzzy
                    result = self.fuzzy_matcher.find_fuzzy_match(
                        func, dll_name, tgt_version
                    )
                    
                    if result:
                        matched_func, score, method = result
                        matched_addr = matched_func.get('address')
                        
                        if matched_addr in tgt_funcs:
                            tgt_func, tgt_canonical_id = tgt_funcs[matched_addr]
                            
                            # Check if target has fewer versions (merge into larger)
                            src_entry = self.functions.get(canonical_id)
                            tgt_entry = self.functions.get(tgt_canonical_id)
                            
                            if src_entry and tgt_entry:
                                src_versions = len(src_entry.get('versions', {}))
                                tgt_versions = len(tgt_entry.get('versions', {}))
                                
                                if tgt_versions <= src_versions:
                                    # Merge target into source
                                    self._merge_canonical_entries(canonical_id, tgt_canonical_id)
                                    fuzzy_merged += 1
                                    self.stats[f'fuzzy_{method}'] += 1
                                else:
                                    # Merge source into target
                                    self._merge_canonical_entries(tgt_canonical_id, canonical_id)
                                    fuzzy_merged += 1
                                    self.stats[f'fuzzy_{method}'] += 1
            
            if fuzzy_merged > 0:
                dll_stats['fuzzy_merged'] = fuzzy_merged
        
        # Count functions for this DLL
        dll_functions = [f for f in self.functions.values() if f['dll'] == dll_name]
        named = sum(1 for f in dll_functions if f['name'])
        
        print(f"  {dll_name}: {len(dll_functions)} canonical functions, {named} named")
        print(f"    Matched: {dll_stats['matched']}, Unmatched: {dll_stats['unmatched']}")
        if dll_stats.get('fuzzy_merged', 0) > 0:
            print(f"    Fuzzy merged: {dll_stats['fuzzy_merged']}")
        
        self.stats[f'{dll_name}_functions'] = len(dll_functions)
        self.stats[f'{dll_name}_named'] = named
    
    def _merge_canonical_entries(self, keep_id: str, merge_id: str):
        """Merge one canonical entry into another."""
        if keep_id == merge_id:
            return
        
        keep_entry = self.functions.get(keep_id)
        merge_entry = self.functions.get(merge_id)
        
        if not keep_entry or not merge_entry:
            return
        
        # Merge versions
        for version_key, version_data in merge_entry.get('versions', {}).items():
            if version_key not in keep_entry['versions']:
                keep_entry['versions'][version_key] = version_data
        keep_entry['version_count'] = len(keep_entry['versions'])
        
        # Merge name if keep_entry has no name
        if not keep_entry.get('name') and merge_entry.get('name'):
            keep_entry['name'] = merge_entry['name']
            keep_entry['display_name'] = merge_entry['display_name']
            keep_entry['name_source'] = merge_entry['name_source']
            keep_entry['signature'] = merge_entry.get('signature')
            keep_entry['comment'] = merge_entry.get('comment')
            keep_entry['parameters'] = merge_entry.get('parameters', [])
        
        # Update index mappings
        merge_indexes = merge_entry.get('indexes', {})
        dll_name = merge_entry['dll']
        for method, value in merge_indexes.items():
            if value:
                key = f"{dll_name}:{method}:{value}"
                self.index_to_canonical[key] = keep_id
        
        # Remove merged entry
        del self.functions[merge_id]
    
    def generate_registry(self):
        """Generate the unified function registry."""
        print("\n" + "=" * 70)
        print("MERGING FUNCTION INDEXES")
        print("=" * 70)
        
        # Load enhanced exports first (callees, callers, strings, instructions)
        self.load_enhanced_exports()
        
        # Load all exports
        exports = self.load_exports()
        print(f"\nLoaded {self.stats['files_loaded']} files with {self.stats['functions_loaded']} total function entries")
        
        if not exports:
            print("No exports found. Run ExportFunctionIndex.java in Ghidra first.")
            return
        
        # Process each DLL
        for dll_name in sorted(exports.keys()):
            self.process_dll(dll_name, exports[dll_name])
        
        # Generate output
        self.write_registry()
        self.write_summary()
    
    def write_registry(self):
        """Write the unified registry to JSON."""
        output_file = self.output_path / "function_registry_v2.json"
        
        # Organize by DLL
        by_dll = defaultdict(list)
        for func in self.functions.values():
            by_dll[func['dll']].append(func)
        
        # Sort functions within each DLL by canonical_id
        for dll in by_dll:
            by_dll[dll].sort(key=lambda f: f['canonical_id'])
        
        registry = {
            'version': '2.0',
            'generated': str(Path(sys.argv[0]).name),
            'total_functions': len(self.functions),
            'total_named': self.stats['named_functions'],
            'dlls': dict(by_dll),
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(registry, f, indent=2)
        
        print(f"\nWrote registry to: {output_file}")
        print(f"  Total canonical functions: {len(self.functions)}")
        print(f"  Total named: {self.stats['named_functions']}")
        if self.stats.get('verified_matches', 0) > 0:
            print(f"  Verified EXP matches: {self.stats['verified_matches']}")
        if self.stats.get('rejected_exp_matches', 0) > 0:
            print(f"  Rejected EXP matches (different functions): {self.stats['rejected_exp_matches']}")
        
        # Print fuzzy matching stats
        fuzzy_total = sum(v for k, v in self.stats.items() if k.startswith('fuzzy_'))
        if fuzzy_total > 0:
            print(f"  Fuzzy matches: {fuzzy_total}")
            for k, v in sorted(self.stats.items()):
                if k.startswith('fuzzy_') and v > 0:
                    method = k.replace('fuzzy_', '')
                    print(f"    - {method}: {v}")
    
    def write_summary(self):
        """Write a summary CSV."""
        output_file = self.output_path / "function_registry_v2_summary.csv"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("DLL,Total Functions,Named,Naming %\n")
            
            # Group by DLL
            dll_stats = defaultdict(lambda: {'total': 0, 'named': 0})
            for func in self.functions.values():
                dll = func['dll']
                dll_stats[dll]['total'] += 1
                if func['name']:
                    dll_stats[dll]['named'] += 1
            
            for dll in sorted(dll_stats.keys()):
                stats = dll_stats[dll]
                pct = (stats['named'] / stats['total'] * 100) if stats['total'] > 0 else 0
                f.write(f"{dll},{stats['total']},{stats['named']},{pct:.1f}%\n")
        
        print(f"Wrote summary to: {output_file}")


def main():
    base_path = Path(__file__).parent.parent
    
    merger = FunctionMerger(str(base_path))
    merger.generate_registry()


if __name__ == '__main__':
    main()
