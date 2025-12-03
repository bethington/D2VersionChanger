#!/usr/bin/env python3
"""
Refresh all data for the report viewer.

This script runs all necessary steps to regenerate viewer data:
1. merge_function_index.py - Merge Ghidra exports into unified registry
2. generate_function_js.py - Generate JS files for the function viewer

Usage:
    python tools/refresh_viewer.py
"""

import subprocess
import sys
from pathlib import Path

def main():
    # Get the tools directory
    tools_dir = Path(__file__).parent
    base_dir = tools_dir.parent
    
    scripts = [
        ("Merging function indexes...", tools_dir / "merge_function_index.py"),
        ("Generating viewer JS files...", tools_dir / "generate_function_js.py"),
    ]
    
    for description, script_path in scripts:
        print(f"\n{'='*60}")
        print(description)
        print('='*60)
        
        if not script_path.exists():
            print(f"Error: Script not found: {script_path}")
            sys.exit(1)
        
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(base_dir)
        )
        
        if result.returncode != 0:
            print(f"Error: {script_path.name} failed with code {result.returncode}")
            sys.exit(result.returncode)
    
    print(f"\n{'='*60}")
    print("Done! Viewer data refreshed successfully.")
    print("Open reports/d2_report_viewer.html to view.")
    print('='*60)

if __name__ == "__main__":
    main()
