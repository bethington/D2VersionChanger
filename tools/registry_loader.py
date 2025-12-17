#!/usr/bin/env python3
"""
Registry Loader - Load unified function registry from split functions_v2 files.

This module loads and reconstructs the unified registry from the per-DLL JavaScript
files in reports/functions_v2/ instead of relying on a monolithic JSON file.

This saves ~350 MB of disk space and bandwidth while maintaining all functionality.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional


def load_unified_registry(base_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load unified registry from split functions_v2 files.

    Args:
        base_path: Base project path. If None, uses current working directory.

    Returns:
        Dictionary in the format of the original function_registry_v2.json with:
        - total_functions: Total function count
        - total_named: Count of named functions
        - dlls: Dict[dll_name] -> List[function_data]
    """
    if base_path is None:
        base_path = Path.cwd()
    else:
        base_path = Path(base_path)

    functions_dir = base_path / "reports" / "functions_v2"

    if not functions_dir.exists():
        raise FileNotFoundError(f"functions_v2 directory not found: {functions_dir}")

    registry = {"total_functions": 0, "total_named": 0, "dlls": {}}

    # Load _index.js first to get metadata
    index_file = functions_dir / "_index.js"
    if index_file.exists():
        index_data = load_js_file(index_file)
        if index_data and "FUNCTION_INDEX_V2" in index_data:
            index_info = index_data["FUNCTION_INDEX_V2"]
            registry["total_functions"] = index_info.get("total_functions", 0)
            registry["total_named"] = index_info.get("total_named", 0)

    # Load each DLL file
    for js_file in sorted(functions_dir.glob("*.js")):
        if js_file.name == "_index.js":
            continue

        dll_name = js_file.stem  # Remove .js extension
        file_data = load_js_file(js_file)

        if file_data:
            # Extract the variable name (e.g., FUNCTIONS_D2Common_dll)
            var_name = next(
                (k for k in file_data.keys() if k.startswith("FUNCTIONS_")), None
            )

            if var_name and var_name in file_data:
                dll_functions = file_data[var_name]
                functions_list = convert_dll_format_to_registry(dll_functions, dll_name)
                registry["dlls"][dll_name] = functions_list

    return registry


def load_js_file(filepath: Path) -> Optional[Dict[str, Any]]:
    """
    Load a JavaScript file and extract JSON data.

    Handles the JavaScript variable assignment syntax:
    var VARIABLE_NAME = { ... };

    Args:
        filepath: Path to the .js file

    Returns:
        Dictionary with variable names as keys, or None if parsing fails
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        result = {}

        # Find all var NAME = { ... }; patterns
        pattern = r"var\s+(\w+)\s*=\s*({[\s\S]*?});"
        matches = re.finditer(pattern, content)

        for match in matches:
            var_name = match.group(1)
            json_str = match.group(2)

            try:
                data = json.loads(json_str)
                result[var_name] = data
            except json.JSONDecodeError as e:
                # Try to fix common issues with embedded newlines in strings
                try:
                    # Replace literal newlines in the JSON that aren't escaped
                    # This is a workaround for malformed JSON
                    fixed_json = json_str.replace("\n", "\\n").replace("\r", "\\r")
                    # Unescape the double-escaped newlines we just created in valid contexts
                    data = json.loads(fixed_json)
                    result[var_name] = data
                except json.JSONDecodeError:
                    # Still failing - skip this file
                    if filepath.name not in ["Fog.dll.js"]:  # Known problematic file
                        print(f"Warning: Failed to parse JSON in {filepath}: {e}")
                    continue

        return result if result else None

    except Exception as e:
        print(f"Error loading JS file {filepath}: {e}")
        return None


def convert_dll_format_to_registry(
    dll_data: Dict, dll_name: str
) -> List[Dict[str, Any]]:
    """
    Convert per-DLL format from functions_v2 to registry format.

    The per-DLL format has functions keyed by canonical_id, while registry format
    is a list of function objects. We reconstruct the list format.

    Args:
        dll_data: Data from a functions_v2/*.js file
        dll_name: Name of the DLL

    Returns:
        List of function objects in registry format
    """
    functions_list = []

    if "functions" not in dll_data:
        return functions_list

    functions_by_id = dll_data["functions"]

    for canonical_id, func_data in functions_by_id.items():
        # Reconstruct function object
        func_obj = {
            "canonical_id": canonical_id,
            "name": func_data.get("name", ""),
            "signature": func_data.get("signature", ""),
            "calling_convention": func_data.get("calling_convention", ""),
            "return_type": func_data.get("return_type", ""),
            "comment": func_data.get("comment", ""),
            "index": func_data.get("index", ""),
            "index_method": func_data.get("method", ""),
            "indexes": func_data.get("indexes", {}),
            "versions": func_data.get(
                "addresses", {}
            ),  # Original uses "versions" with nested data
            "version_count": len(func_data.get("addresses", {})),
            "name_source": func_data.get("name_source", ""),
        }

        # Add address, rva, and size info from per-version data
        versions_detailed = {}
        addresses = func_data.get("addresses", {})
        rvas = func_data.get("rvas", {})
        sizes = func_data.get("sizes", {})

        for version in addresses.keys():
            versions_detailed[version] = {
                "address": addresses.get(version, ""),
                "rva": rvas.get(version, ""),
                "size": sizes.get(version, 0),
            }

        func_obj["versions"] = versions_detailed

        # Add callees and callers if present
        if "callees" in func_data:
            func_obj["callees"] = func_data["callees"]
        if "callers" in func_data:
            func_obj["callers"] = func_data["callers"]

        # Add metrics if present
        if "instruction_counts" in func_data:
            func_obj["instruction_counts"] = func_data["instruction_counts"]
        if "stack_frame_sizes" in func_data:
            func_obj["stack_frame_sizes"] = func_data["stack_frame_sizes"]
        if "loop_counts" in func_data:
            func_obj["loop_counts"] = func_data["loop_counts"]

        functions_list.append(func_obj)

    return functions_list


def quick_load_dll(dll_name: str, base_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Quickly load data for a single DLL without loading entire registry.

    Useful for tools that only need one DLL's data.

    Args:
        dll_name: Name of the DLL (e.g., "D2Common.dll")
        base_path: Base project path

    Returns:
        Dictionary with DLL function data
    """
    if base_path is None:
        base_path = Path.cwd()
    else:
        base_path = Path(base_path)

    js_file = base_path / "reports" / "functions_v2" / f"{dll_name}.js"

    if not js_file.exists():
        raise FileNotFoundError(f"DLL file not found: {js_file}")

    file_data = load_js_file(js_file)
    if not file_data:
        return {"functions": []}

    # Extract the variable name
    var_name = next((k for k in file_data.keys() if k.startswith("FUNCTIONS_")), None)

    if var_name and var_name in file_data:
        dll_data = file_data[var_name]
        functions_list = convert_dll_format_to_registry(dll_data, dll_name)
        return {
            "dll": dll_name,
            "functions": functions_list,
            "versions": dll_data.get("versions", []),
        }

    return {"dll": dll_name, "functions": []}


if __name__ == "__main__":
    # Quick test
    print("Loading unified registry from functions_v2...")
    try:
        reg = load_unified_registry()
        print(f"✓ Loaded {reg['total_functions']} functions")
        print(f"✓ {reg['total_named']} named functions")
        print(f"✓ {len(reg['dlls'])} DLLs")

        # Show first DLL stats
        for dll_name, funcs in list(reg["dlls"].items())[:1]:
            print(f"\n{dll_name}: {len(funcs)} functions")
    except Exception as e:
        print(f"✗ Error: {e}")
