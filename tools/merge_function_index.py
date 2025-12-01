#!/usr/bin/env python3
"""
Merge Function Index - Combine Ghidra exports from all versions into unified registry.

This tool:
1. Reads function index exports from data/function_index/{Classic,LoD}/{version}/*.json
2. Matches functions across versions using the method-prefixed index system
3. Resolves naming conflicts using earliest version priority
4. Generates a unified function registry with canonical IDs

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
        self.output_path = self.base_path / "reports"
        
        # Master index: canonical_index -> canonical_id
        self.index_to_canonical: Dict[str, str] = {}
        
        # Canonical function data
        self.functions: Dict[str, dict] = {}  # canonical_id -> function data
        
        # Track naming sources
        self.name_sources: Dict[str, Tuple[str, str, str]] = {}  # canonical_id -> (name, game_type, version)
        
        # Statistics
        self.stats = defaultdict(int)
    
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
            game_path = self.index_path / game_type
            if not game_path.exists():
                continue
            
            for version_dir in sorted(game_path.iterdir()):
                if not version_dir.is_dir():
                    continue
                version = version_dir.name
                
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
        """
        index = func_data.get('index', '')
        if not index:
            return None
        
        # Check if this exact index already exists
        full_key = f"{dll_name}:{index}"
        if full_key in self.index_to_canonical:
            return self.index_to_canonical[full_key]
        
        # Try alternate indexes in priority order
        indexes = func_data.get('indexes', {})
        for method in ['EXP', 'STR', 'API', 'MNE', 'CFG', 'PRO']:
            idx_value = indexes.get(method)
            if idx_value:
                alt_key = f"{dll_name}:{method}:{idx_value}"
                if alt_key in self.index_to_canonical:
                    # Found match via alternate index
                    canonical_id = self.index_to_canonical[alt_key]
                    # Also register the primary index
                    self.index_to_canonical[full_key] = canonical_id
                    return canonical_id
        
        # No match found - create new canonical ID
        canonical_id = self.generate_canonical_id(dll_name, func_data)
        
        # Register all available indexes
        self.index_to_canonical[full_key] = canonical_id
        for method in ['EXP', 'STR', 'API', 'MNE', 'CFG', 'PRO']:
            idx_value = indexes.get(method)
            if idx_value:
                alt_key = f"{dll_name}:{method}:{idx_value}"
                self.index_to_canonical[alt_key] = canonical_id
        
        return canonical_id
    
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
                'comment': None,
                'parameters': [],
                'versions': {},
                'version_count': 0,
            }
        
        entry = self.functions[canonical_id]
        
        # Add version-specific address
        version_key = f"{game_type}/{version}"
        entry['versions'][version_key] = {
            'address': func_data.get('address'),
            'rva': func_data.get('rva'),
            'size': func_data.get('size'),
        }
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
        
        for (game_type, version), data in sorted_versions:
            functions = data.get('functions', [])
            
            for func in functions:
                canonical_id = self.match_function(func, dll_name)
                if canonical_id:
                    self.merge_function_data(canonical_id, func, game_type, version, dll_name)
                    dll_stats['matched'] += 1
                else:
                    dll_stats['unmatched'] += 1
        
        # Count functions for this DLL
        dll_functions = [f for f in self.functions.values() if f['dll'] == dll_name]
        named = sum(1 for f in dll_functions if f['name'])
        
        print(f"  {dll_name}: {len(dll_functions)} canonical functions, {named} named")
        print(f"    Matched: {dll_stats['matched']}, Unmatched: {dll_stats['unmatched']}")
        
        self.stats[f'{dll_name}_functions'] = len(dll_functions)
        self.stats[f'{dll_name}_named'] = named
    
    def generate_registry(self):
        """Generate the unified function registry."""
        print("\n" + "=" * 70)
        print("MERGING FUNCTION INDEXES")
        print("=" * 70)
        
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
