#!/usr/bin/env python3
"""
Refresh all data for the report viewer.

This script runs all necessary steps to regenerate viewer data:
1. sequential_matcher.py - Match functions across versions using sequential pairwise approach
2. candidate_matcher.py - Generate best-match candidates for empty cells (optional)
3. generate_function_js.py - Generate JS files for the function viewer

Usage:
    python tools/refresh_viewer.py          # LoD versions only (default, faster)
    python tools/refresh_viewer.py --all    # All versions (LoD + Classic)
    python tools/refresh_viewer.py --game Classic  # Classic only
    python tools/refresh_viewer.py --candidates    # Also generate candidates for empty cells
"""

import argparse
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description='Refresh viewer data for D2 function matching'
    )
    parser.add_argument(
        '--all', action='store_true',
        help='Process all versions (LoD + Classic). Default is LoD only.'
    )
    parser.add_argument(
        '--game', choices=['LoD', 'Classic'],
        help='Process specific game type. Overrides --all.'
    )
    parser.add_argument(
        '--candidates', action='store_true',
        help='Generate candidates for empty cells (slower, disabled by default).'
    )
    args = parser.parse_args()
    
    # Determine game mode
    if args.game:
        game_mode = args.game
    elif args.all:
        game_mode = 'all'
    else:
        game_mode = 'LoD'  # Default to LoD only
    
    print(f"Processing mode: {game_mode}")
    if args.candidates:
        print("Candidate generation: enabled")
    
    # Get the tools directory
    tools_dir = Path(__file__).parent
    base_dir = tools_dir.parent
    
    # Scripts to run with their args
    # sequential_matcher supports --game, others process the registry it creates
    scripts = [
        (
            "Matching functions across versions...",
            tools_dir / "sequential_matcher.py",
            ["--game", game_mode],
            True  # Always run
        ),
        (
            "Generating viewer JS files...",
            tools_dir / "generate_function_js.py",
            [],
            True  # Always run
        ),
    ]
    
    # Optionally add candidate generation (before JS generation)
    if args.candidates:
        scripts.insert(1, (
            "Generating candidates for empty cells...",
            tools_dir / "candidate_matcher.py",
            [],
            True
        ))
    
    for description, script_path, extra_args, should_run in scripts:
        if not should_run:
            continue
        print(f"\n{'='*60}")
        print(description)
        print('='*60)
        
        if not script_path.exists():
            print(f"Error: Script not found: {script_path}")
            sys.exit(1)
        
        cmd = [sys.executable, str(script_path)] + extra_args
        print(f"Running: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, cwd=str(base_dir))
        
        if result.returncode != 0:
            print(f"Error: {script_path.name} failed with code {result.returncode}")
            sys.exit(result.returncode)
    
    print(f"\n{'='*60}")
    print("Done! Viewer data refreshed successfully.")
    print(f"Mode: {game_mode}")
    print("Open reports/d2_report_viewer.html to view.")
    print('='*60)


if __name__ == "__main__":
    main()
