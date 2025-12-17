#!/usr/bin/env python3
"""
Cross-version function matcher using 1.10 anchors.
Identifies matching functions across different LoD versions using multi-method indexing.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

FUNCTION_INDEX_PATH = Path("data/function_index")
REPORTS_PATH = Path("reports")

# Stable anchor functions from Phase 2 analysis
ANCHOR_MODULES = ["D2Game", "D2Client", "D2Common", "D2Win", "Storm", "Fog"]
LOD_VERSIONS = ["1.07", "1.08", "1.09", "1.09b", "1.09d", "1.10", "1.11", "1.11b", "1.12a", "1.13c", "1.13d"]


class FunctionMatcher:
    """Matches functions across LoD versions using multiple indexing methods."""

    def __init__(self):
        self.version_data = {}
        self.anchor_functions = defaultdict(list)
        self.match_results = defaultdict(lambda: defaultdict(list))

    def load_version_data(self, module: str, version: str) -> Dict:
        """Load function index for a module and version."""
        file_path = FUNCTION_INDEX_PATH / "LoD" / version / f"{module}.dll.json"
        if not file_path.exists():
            return {}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {module} {version}: {e}")
            return {}

    def extract_function_by_index(self, data: Dict, index_type: str, index_value: str) -> Optional[Dict]:
        """Extract function by specific index type and value."""
        if not data or "functions" not in data:
            return None

        for func in data.get("functions", []):
            if func.get("indexes", {}).get(index_type) == index_value:
                return func
        return None

    def find_matching_function(self, source_func: Dict, target_version_data: Dict, module: str) -> Tuple[Optional[Dict], str]:
        """
        Find matching function in target version using multi-method approach.
        Returns (matched_function, match_type)
        """
        if not target_version_data:
            return None, "no_data"

        source_name = source_func.get("name")

        # Method 1: Name match (highest confidence if has_human_name is true)
        for func in target_version_data.get("functions", []):
            if func.get("name") == source_name and func.get("has_human_name"):
                return func, "name_match"

        # Method 2: API index match (function call signatures)
        source_api = source_func.get("indexes", {}).get("API")
        if source_api:
            matched = self.extract_function_by_index(target_version_data, "API", source_api)
            if matched:
                return matched, "api_match"

        # Method 3: MNE index match (mnemonic/instruction sequences)
        source_mne = source_func.get("indexes", {}).get("MNE")
        if source_mne:
            matched = self.extract_function_by_index(target_version_data, "MNE", source_mne)
            if matched:
                return matched, "mne_match"

        # Method 4: CFG index match (control flow graph)
        source_cfg = source_func.get("indexes", {}).get("CFG")
        if source_cfg:
            matched = self.extract_function_by_index(target_version_data, "CFG", source_cfg)
            if matched:
                return matched, "cfg_match"

        # Method 5: PRO index match (function prototype)
        source_pro = source_func.get("indexes", {}).get("PRO")
        if source_pro:
            matched = self.extract_function_by_index(target_version_data, "PRO", source_pro)
            if matched:
                return matched, "pro_match"

        return None, "no_match"

    def match_function_across_versions(self, module: str, source_func: Dict, source_version: str = "1.10") -> Dict:
        """Match a single function across all versions."""
        result = {
            "function_name": source_func.get("name"),
            "source_module": module,
            "source_version": source_version,
            "source_address": source_func.get("address"),
            "matches": {},
            "summary": {
                "total_matches": 0,
                "high_confidence": 0,
                "medium_confidence": 0,
                "low_confidence": 0,
                "no_match": 0,
            }
        }

        for target_version in LOD_VERSIONS:
            if target_version == source_version:
                # Add source version with high confidence
                result["matches"][target_version] = {
                    "address": source_func.get("address"),
                    "match_type": "source_baseline",
                    "confidence": "high",
                    "matched_function_name": source_func.get("name"),
                }
                result["summary"]["high_confidence"] += 1
                result["summary"]["total_matches"] += 1
                continue

            # Load target version data
            if (module, target_version) not in self.version_data:
                self.version_data[(module, target_version)] = self.load_version_data(module, target_version)

            target_data = self.version_data[(module, target_version)]

            # Find matching function
            matched_func, match_type = self.find_matching_function(source_func, target_data, module)

            if matched_func:
                # Determine confidence level based on match type
                confidence_map = {
                    "name_match": "high",
                    "api_match": "high",
                    "mne_match": "medium",
                    "cfg_match": "medium",
                    "pro_match": "low",
                }
                confidence = confidence_map.get(match_type, "low")

                result["matches"][target_version] = {
                    "address": matched_func.get("address"),
                    "match_type": match_type,
                    "confidence": confidence,
                    "matched_function_name": matched_func.get("name"),
                }

                # Update summary
                result["summary"]["total_matches"] += 1
                if confidence == "high":
                    result["summary"]["high_confidence"] += 1
                elif confidence == "medium":
                    result["summary"]["medium_confidence"] += 1
                else:
                    result["summary"]["low_confidence"] += 1
            else:
                result["matches"][target_version] = {
                    "address": None,
                    "match_type": "no_match",
                    "confidence": None,
                }
                result["summary"]["no_match"] += 1

        return result

    def match_module_across_versions(self, module: str, limit: Optional[int] = None) -> List[Dict]:
        """Match all functions in a module across all versions."""
        print(f"\nMatching {module} functions across versions...")

        # Load 1.10 as baseline
        v110_data = self.load_version_data(module, "1.10")
        if not v110_data or "functions" not in v110_data:
            print(f"  Error: Could not load 1.10 {module}")
            return []

        # Get human-named functions only
        functions = [f for f in v110_data.get("functions", [])
                    if f.get("has_human_name") and
                    not f.get("name", "").startswith("FUN_") and
                    not f.get("name", "").startswith("Ordinal_")]

        if limit:
            functions = functions[:limit]

        print(f"  Found {len(functions)} human-named functions")

        results = []
        for i, func in enumerate(functions):
            if (i + 1) % 50 == 0:
                print(f"  Processed {i + 1}/{len(functions)}...")

            match_result = self.match_function_across_versions(module, func)
            results.append(match_result)

        print(f"  Completed {module}: {len(functions)} functions")
        return results

    def generate_cross_version_index(self) -> Dict:
        """Generate comprehensive cross-version index for all modules."""
        print("="*70)
        print("Generating Cross-Version Function Index")
        print("="*70)

        cross_version_index = {
            "timestamp": __import__('datetime').datetime.now().isoformat(),
            "baseline_version": "1.10",
            "all_versions": LOD_VERSIONS,
            "modules": {}
        }

        for module in ANCHOR_MODULES:
            print(f"\nProcessing {module}...")
            matches = self.match_module_across_versions(module)

            if matches:
                cross_version_index["modules"][module] = {
                    "total_functions": len(matches),
                    "match_summary": self._aggregate_matches(matches),
                    "functions": matches[:100]  # Store first 100 for reference
                }

        return cross_version_index

    def _aggregate_matches(self, matches: List[Dict]) -> Dict:
        """Aggregate match statistics."""
        summary = {
            "total_functions": len(matches),
            "functions_in_all_versions": 0,
            "functions_with_high_confidence": 0,
            "functions_with_partial_matches": 0,
            "functions_with_no_matches": 0,
            "average_match_confidence": 0.0
        }

        high_conf_count = 0
        for match in matches:
            if match["summary"]["total_matches"] == 10:  # All versions except source
                summary["functions_in_all_versions"] += 1

            if match["summary"]["high_confidence"] >= 9:
                summary["functions_with_high_confidence"] += 1
            elif match["summary"]["total_matches"] > 0:
                summary["functions_with_partial_matches"] += 1
            else:
                summary["functions_with_no_matches"] += 1

            high_conf_count += match["summary"]["high_confidence"]

        if len(matches) > 0:
            summary["average_match_confidence"] = high_conf_count / (len(matches) * 10) * 100

        return summary

    def save_index(self, index: Dict, output_file: Optional[str] = None):
        """Save cross-version index to file."""
        if output_file is None:
            output_file = REPORTS_PATH / "cross_version_function_index.json"
        else:
            output_file = REPORTS_PATH / output_file

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(index, f, indent=2)

        print(f"\nSaved index to {output_file}")


def main():
    """Main execution."""
    matcher = FunctionMatcher()

    # Generate comprehensive index
    index = matcher.generate_cross_version_index()

    # Save index
    matcher.save_index(index, "cross_version_function_index.json")

    # Print summary
    print("\n" + "="*70)
    print("CROSS-VERSION MATCHING SUMMARY")
    print("="*70)

    for module in index["modules"]:
        module_data = index["modules"][module]
        summary = module_data["match_summary"]
        print(f"\n{module}:")
        print(f"  Total Functions: {summary['total_functions']}")
        print(f"  All Versions: {summary['functions_in_all_versions']}")
        print(f"  High Confidence: {summary['functions_with_high_confidence']}")
        print(f"  Partial Matches: {summary['functions_with_partial_matches']}")
        print(f"  No Matches: {summary['functions_with_no_matches']}")
        print(f"  Avg Confidence: {summary['average_match_confidence']:.1f}%")


if __name__ == "__main__":
    main()
