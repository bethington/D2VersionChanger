#!/usr/bin/env python3
"""
compare_versions.py - Compare functions across D2 versions using exported index data.

This tool reads ExportFunctionIndex.java outputs and finds matching functions
between two versions using the NOP (Normalized OPcode) hash and other indexes.

Usage:
    python compare_versions.py --source LoD/1.10 --target LoD/1.07 --dll D2Common.dll
    python compare_versions.py --source LoD/1.10 --target LoD/1.07 --all

Output:
    - Exact NOP hash matches (identical functions)
    - STR matches (same string references)
    - CAL matches (same callee functions)
    - Functions that changed between versions
"""

import argparse
import json
import os
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


class VersionComparator:
    """Compare function indexes between two D2 versions."""

    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.index_path = self.base_path / "data" / "function_index"

    def load_version(self, version_path: str, dll_name: str) -> Optional[dict]:
        """Load function index for a specific version/DLL."""
        # Parse version path like "LoD/1.10"
        parts = version_path.split("/")
        if len(parts) != 2:
            print(f"Invalid version path: {version_path}")
            return None

        game_type, version = parts
        json_file = self.index_path / game_type / version / f"{dll_name}.json"

        if not json_file.exists():
            print(f"File not found: {json_file}")
            return None

        try:
            with open(json_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {json_file}: {e}")
            return None

    def compare(
        self, source_version: str, target_version: str, dll_name: str
    ) -> Dict:
        """Compare functions between two versions."""
        source_data = self.load_version(source_version, dll_name)
        target_data = self.load_version(target_version, dll_name)

        if not source_data or not target_data:
            return {"error": "Failed to load one or both versions"}

        results = {
            "source": source_version,
            "target": target_version,
            "dll": dll_name,
            "source_functions": len(source_data.get("functions", [])),
            "target_functions": len(target_data.get("functions", [])),
            "matches": {
                "nop": [],      # NOP hash matches (identical code)
                "str": [],      # String reference matches
                "cal": [],      # Callee name matches
                "api": [],      # API call matches
                "exp": [],      # Export ordinal matches
            },
            "unmatched_source": [],
            "stats": {}
        }

        # Build target indexes
        target_indexes = self._build_index_map(target_data.get("functions", []))

        # Match source functions against target
        matched_source_addrs = set()
        matched_target_addrs = set()

        for src_func in source_data.get("functions", []):
            src_addr = src_func.get("address", "")
            src_name = src_func.get("name", "")
            src_indexes = src_func.get("indexes", {})

            match_found = False
            match_info = None

            # Priority order: EXP > NOP > STR > CAL > API
            for method in ["EXP", "NOP", "STR", "CAL", "API"]:
                idx_value = src_indexes.get(method)
                if not idx_value:
                    continue

                if idx_value in target_indexes[method]:
                    tgt_func = target_indexes[method][idx_value]
                    tgt_addr = tgt_func.get("address", "")
                    tgt_name = tgt_func.get("name", "")

                    # Skip if target already matched
                    if tgt_addr in matched_target_addrs:
                        continue

                    match_info = {
                        "source_name": src_name,
                        "source_addr": src_addr,
                        "target_name": tgt_name,
                        "target_addr": tgt_addr,
                        "method": method,
                        "index": idx_value[:16] + "..." if len(idx_value) > 16 else idx_value,
                        "name_match": src_name == tgt_name,
                    }

                    results["matches"][method.lower()].append(match_info)
                    matched_source_addrs.add(src_addr)
                    matched_target_addrs.add(tgt_addr)
                    match_found = True
                    break

            if not match_found:
                # Try to find by name as fallback
                for tgt_func in target_data.get("functions", []):
                    if tgt_func.get("name") == src_name and src_name and not src_name.startswith("FUN_"):
                        tgt_addr = tgt_func.get("address", "")
                        if tgt_addr not in matched_target_addrs:
                            match_info = {
                                "source_name": src_name,
                                "source_addr": src_addr,
                                "target_name": tgt_func.get("name", ""),
                                "target_addr": tgt_addr,
                                "method": "NAME",
                                "index": "name",
                                "name_match": True,
                            }
                            # Don't add to matches, just note it's a name-only match
                            matched_source_addrs.add(src_addr)
                            matched_target_addrs.add(tgt_addr)
                            match_found = True
                            break

            if not match_found and src_func.get("has_human_name"):
                results["unmatched_source"].append({
                    "name": src_name,
                    "address": src_addr,
                    "best_index": src_func.get("index_method", ""),
                })

        # Calculate stats
        total_matches = sum(len(m) for m in results["matches"].values())
        results["stats"] = {
            "total_matches": total_matches,
            "nop_matches": len(results["matches"]["nop"]),
            "str_matches": len(results["matches"]["str"]),
            "cal_matches": len(results["matches"]["cal"]),
            "api_matches": len(results["matches"]["api"]),
            "exp_matches": len(results["matches"]["exp"]),
            "unmatched_named": len(results["unmatched_source"]),
            "match_rate": f"{total_matches / results['source_functions'] * 100:.1f}%" if results['source_functions'] > 0 else "0%",
        }

        return results

    def _build_index_map(self, functions: List[dict]) -> Dict[str, Dict]:
        """Build lookup maps for each index type."""
        index_map = defaultdict(dict)

        for func in functions:
            indexes = func.get("indexes", {})
            for method, value in indexes.items():
                if value:
                    index_map[method][value] = func

        return index_map


def main():
    parser = argparse.ArgumentParser(description="Compare D2 function indexes across versions")
    parser.add_argument("--source", required=True, help="Source version (e.g., LoD/1.10)")
    parser.add_argument("--target", required=True, help="Target version (e.g., LoD/1.07)")
    parser.add_argument("--dll", default="D2Common.dll", help="DLL to compare")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")

    args = parser.parse_args()

    base_path = Path(__file__).parent.parent
    comparator = VersionComparator(str(base_path))

    print("=" * 70)
    print(f"Comparing {args.source} vs {args.target} ({args.dll})")
    print("=" * 70)

    results = comparator.compare(args.source, args.target, args.dll)

    if "error" in results:
        print(f"Error: {results['error']}")
        return

    # Print summary
    print(f"\nSource: {results['source_functions']} functions")
    print(f"Target: {results['target_functions']} functions")
    print(f"\nMatches by method:")
    print(f"  EXP (export ordinal):  {results['stats']['exp_matches']}")
    print(f"  NOP (identical code):  {results['stats']['nop_matches']}")
    print(f"  STR (string refs):     {results['stats']['str_matches']}")
    print(f"  CAL (callee names):    {results['stats']['cal_matches']}")
    print(f"  API (API calls):       {results['stats']['api_matches']}")
    print(f"\nTotal matches: {results['stats']['total_matches']} ({results['stats']['match_rate']})")
    print(f"Unmatched named: {results['stats']['unmatched_named']}")

    # Show detailed matches
    if args.verbose:
        print("\n" + "-" * 70)
        print("NOP MATCHES (Identical Functions)")
        print("-" * 70)
        for match in results["matches"]["nop"][:20]:
            name_indicator = "=" if match["name_match"] else "!="
            print(f"  {match['source_name']} {name_indicator} {match['target_name']}")
            print(f"    {match['source_addr']} -> {match['target_addr']}")

        if results["unmatched_source"]:
            print("\n" + "-" * 70)
            print("UNMATCHED NAMED FUNCTIONS (may have changed)")
            print("-" * 70)
            for func in results["unmatched_source"][:20]:
                print(f"  {func['name']} @ {func['address']} ({func['best_index']})")

    # Write output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\nWrote results to: {args.output}")


if __name__ == "__main__":
    main()
