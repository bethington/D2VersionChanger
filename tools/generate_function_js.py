#!/usr/bin/env python3
"""
Generate JavaScript files from function_registry_v2.json for the report viewer.

Reads: reports/function_registry_v2.json
Writes: reports/functions_v2/_index.js and per-DLL files

Output format matches the existing viewer's expectations:
- functions keyed by canonical_id (or RVA for compatibility)
- versions array with version strings
- Each function has: name, signature, comment, addresses per version
"""

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def escape_js_string(s):
    """Escape a string for JavaScript."""
    if s is None:
        return ""
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '')

def generate_js_files(base_path: Path):
    registry_file = base_path / "reports" / "function_registry_v2.json"
    output_dir = base_path / "reports" / "functions_v2"
    
    if not registry_file.exists():
        print(f"Error: Registry not found: {registry_file}")
        print("Run merge_function_index.py first.")
        return
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    # Load registry
    with open(registry_file, 'r', encoding='utf-8') as f:
        registry = json.load(f)
    
    print(f"Loaded registry with {registry.get('total_functions', 0)} functions")
    
    dlls = registry.get('dlls', {})
    timestamp = datetime.now().isoformat()
    
    # Generate index file
    index_data = {
        "generated": timestamp,
        "source": "function_registry_v2.json",
        "total_functions": registry.get('total_functions', 0),
        "total_named": registry.get('total_named', 0),
        "files": {}
    }
    
    for dll_name, functions in dlls.items():
        named_count = sum(1 for f in functions if f.get('name'))
        version_set = set()
        for f in functions:
            version_set.update(f.get('versions', {}).keys())
        
        index_data["files"][dll_name] = {
            "count": len(functions),
            "named": named_count,
            "versions": sorted(version_set)
        }
        
        # Generate per-DLL file
        dll_file = output_dir / f"{dll_name}.js"
        write_dll_js(dll_file, dll_name, functions, timestamp)
        print(f"  {dll_name}: {len(functions)} functions, {named_count} named")
    
    # Write index
    index_file = output_dir / "_index.js"
    with open(index_file, 'w', encoding='utf-8') as f:
        f.write(f"// Auto-generated from function_registry_v2.json\n")
        f.write(f"// Generated: {timestamp}\n\n")
        f.write(f"var FUNCTION_INDEX_V2 = ")
        json.dump(index_data, f, indent=2)
        f.write(";\n")
    
    print(f"\nWrote index to: {index_file}")
    print(f"Total DLLs: {len(dlls)}")

def write_dll_js(filepath: Path, dll_name: str, functions: list, timestamp: str):
    """Write a single DLL's function data to a JS file.
    
    Output format matches existing viewer expectations:
    {
        versions: ["LoD/1.07", "LoD/1.08", ...],
        functions: {
            "canonical_id": {
                name: "FunctionName",
                signature: "void FunctionName(int a)",
                comment: "Does something",
                addresses: {"LoD/1.07": "0x1234", "LoD/1.08": "0x5678"}
            },
            ...
        }
    }
    """
    
    # Collect all versions across functions
    all_versions = set()
    for f in functions:
        all_versions.update(f.get('versions', {}).keys())
    all_versions = sorted(all_versions)
    
    # Build functions dict keyed by canonical_id
    func_dict = {}
    for func in functions:
        canonical_id = func.get('canonical_id', '')
        
        # Build addresses dict - include both full address and RVA for toggle
        addresses = {}
        rvas = {}
        for ver in all_versions:
            ver_data = func.get('versions', {}).get(ver, {})
            addr = ver_data.get('address')
            rva = ver_data.get('rva')
            if addr:
                addresses[ver] = addr
            if rva:
                rvas[ver] = rva
        
        entry = {
            "addresses": addresses
        }
        
        # Include RVAs if different from addresses (for toggle feature)
        if rvas and rvas != addresses:
            entry["rvas"] = rvas
        
        # Add optional fields only if present
        if func.get('name'):
            entry["name"] = func['name']
        if func.get('signature'):
            entry["signature"] = func['signature']
        if func.get('comment'):
            entry["comment"] = func['comment']
        if func.get('name_source'):
            entry["name_source"] = func['name_source']
        if func.get('index_method'):
            entry["method"] = func['index_method']
        if func.get('index'):
            entry["index"] = func['index']
        
        func_dict[canonical_id] = entry
    
    # Write JS file
    var_name = sanitize_var_name(dll_name)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"// Auto-generated from function_registry_v2.json\n")
        f.write(f"// Generated: {timestamp}\n")
        f.write(f"// Functions for {dll_name}\n")
        f.write(f"// Versions: {', '.join(all_versions)}\n\n")
        
        output = {
            "versions": all_versions,
            "functions": func_dict
        }
        
        f.write(f"var FUNCTIONS_{var_name} = ")
        json.dump(output, f, indent=2)
        f.write(";\n")
        
        # Register with global FUNCTION_DATA if it exists
        f.write(f"\nif (typeof FUNCTION_DATA === 'undefined') FUNCTION_DATA = {{}};\n")
        f.write(f"FUNCTION_DATA['{dll_name}'] = FUNCTIONS_{var_name};\n")

def sanitize_var_name(name: str) -> str:
    """Convert filename to valid JS variable name."""
    return name.replace('.', '_').replace(' ', '_').replace('-', '_')


def main():
    base_path = Path(__file__).parent.parent
    generate_js_files(base_path)

if __name__ == '__main__':
    main()
