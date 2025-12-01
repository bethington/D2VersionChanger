#!/usr/bin/env python3
"""
Pipeline Runner - Unified CLI for the optimized matching pipeline.

Orchestrates the complete workflow:
1. Analyze PE files (extract functions, signatures, call graphs)
2. Match functions across versions (tiered matching)
3. Propagate names from Ghidra export
4. Generate output reports

Usage:
    # Analyze all versions of a DLL
    python -m tools.optimized_matching.pipeline_runner analyze --dll D2Client.dll

    # Match functions across versions
    python -m tools.optimized_matching.pipeline_runner match --dll D2Client.dll

    # Run specific matching tiers
    python -m tools.optimized_matching.pipeline_runner match --dll D2Client.dll --tiers 1,2

    # Full pipeline
    python -m tools.optimized_matching.pipeline_runner full --dll D2Client.dll

    # Show statistics
    python -m tools.optimized_matching.pipeline_runner stats --dll D2Client.dll
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import defaultdict

from .progress import ProgressReporter, format_size, format_duration
from .analysis_engine import AnalysisEngine, VersionAnalysis, analyze_version_folder
from .matching_engine import MatchingEngine, MatchingState


class PipelineRunner:
    """Orchestrates the function matching pipeline."""

    def __init__(self,
                 project_root: Path,
                 cache_dir: Path,
                 reporter: ProgressReporter):
        self.project_root = project_root
        self.cache_dir = cache_dir
        self.reporter = reporter

        # Sub-directories
        self.analysis_cache = cache_dir / "analysis"
        self.match_cache = cache_dir / "matches"
        self.version_root = project_root / "VersionChanger"

        # Engines
        self.analysis_engine = AnalysisEngine(
            cache_dir=self.analysis_cache,
            reporter=reporter
        )
        self.matching_engine = MatchingEngine(
            cache_dir=self.match_cache,
            reporter=reporter
        )

    def find_versions(self, dll_name: str) -> List[tuple]:
        """Find all versions containing the specified DLL."""
        versions = []

        for game_type in ["Classic", "LoD"]:
            game_dir = self.version_root / game_type
            if not game_dir.exists():
                continue

            for version_dir in sorted(game_dir.iterdir()):
                if not version_dir.is_dir():
                    continue

                # Check if DLL exists (case-insensitive)
                dll_path = None
                for item in version_dir.iterdir():
                    if item.is_file() and item.name.lower() == dll_name.lower():
                        dll_path = item
                        break

                if dll_path:
                    version_str = f"{game_type}/{version_dir.name}"
                    versions.append((version_str, dll_path))

        return versions

    def analyze_all(self,
                    dll_name: str,
                    versions: Optional[List[str]] = None,
                    force: bool = False) -> Dict[str, VersionAnalysis]:
        """
        Analyze all versions of a DLL.

        Args:
            dll_name: Name of DLL to analyze
            versions: Optional list of specific versions (e.g., ["Classic/1.00"])
            force: Force re-analysis even if cached

        Returns:
            Dictionary mapping version -> VersionAnalysis
        """
        self.reporter.header(f"Analysis: {dll_name}")

        # Find all versions
        all_versions = self.find_versions(dll_name)
        self.reporter.info(f"Found {len(all_versions)} versions containing {dll_name}")

        if versions:
            all_versions = [(v, p) for v, p in all_versions if v in versions]
            self.reporter.info(f"Filtered to {len(all_versions)} specified versions")

        if not all_versions:
            self.reporter.error(f"No versions found for {dll_name}")
            return {}

        # Analyze each version
        analyses = {}
        start_time = time.time()

        for version_str, dll_path in all_versions:
            try:
                analysis = self.analysis_engine.analyze(
                    dll_path,
                    version_str,
                    force=force
                )
                analyses[version_str] = analysis
            except Exception as e:
                self.reporter.error(f"Failed to analyze {version_str}: {e}")

        elapsed = time.time() - start_time
        self.reporter.success(f"Analyzed {len(analyses)} versions in {format_duration(elapsed)}")

        # Summary table
        rows = []
        for version, analysis in sorted(analyses.items()):
            rows.append([
                version,
                len(analysis.functions),
                len(analysis.exports),
                sum(len(v) for v in analysis.call_graph.values()),
            ])

        self.reporter.table(
            headers=["Version", "Functions", "Exports", "Call Edges"],
            rows=rows[:10],  # Show first 10
            title=f"Analysis Summary (showing {min(10, len(rows))}/{len(rows)})"
        )

        return analyses

    def match_all(self,
                  dll_name: str,
                  versions: Optional[List[str]] = None,
                  tiers: Optional[List[int]] = None,
                  force: bool = False) -> MatchingState:
        """
        Match functions across versions.

        Args:
            dll_name: Name of DLL to match
            versions: Optional list of specific versions
            tiers: Optional list of specific tiers to run
            force: Force re-matching

        Returns:
            Final matching state
        """
        # First, ensure analyses exist
        analyses = self.analyze_all(dll_name, versions, force=False)

        if len(analyses) < 2:
            self.reporter.error("Need at least 2 versions to match")
            return None

        # Run matching
        start_tier = min(tiers) if tiers else 1
        end_tier = max(tiers) if tiers else 4

        state = self.matching_engine.match_all(
            analyses,
            dll_name=dll_name,
            start_tier=start_tier,
            end_tier=end_tier,
            force=force
        )

        return state

    def show_stats(self, dll_name: str):
        """Show statistics for a DLL's matching state."""
        state_path = self.match_cache / f"{dll_name}_state.json"

        if not state_path.exists():
            self.reporter.error(f"No matching state found for {dll_name}")
            self.reporter.info("Run 'match' command first")
            return

        with open(state_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.reporter.header(f"Statistics: {dll_name}")

        # Overall stats
        total_matches = len(data['matched'])
        total_unmatched = sum(len(addrs) for addrs in data['unmatched'].values())
        num_versions = len(data['unmatched'])

        self.reporter.summary("Overall", {
            "Total Matches": total_matches,
            "Total Unmatched": total_unmatched,
            "Versions": num_versions,
            "Avg Unmatched/Version": total_unmatched // max(num_versions, 1),
        })

        # Tier breakdown
        tier_counts = defaultdict(int)
        tier_names = {1: "Export", 2: "Exact Bytes", 3: "Prologue+Size", 4: "Call Graph"}

        for match in data['matched'].values():
            tier_counts[match['match_tier']] += 1

        rows = [
            [tier, tier_names.get(tier, "Unknown"), count, f"{count/max(total_matches,1)*100:.1f}%"]
            for tier, count in sorted(tier_counts.items())
        ]
        self.reporter.table(
            headers=["Tier", "Method", "Matches", "Percent"],
            rows=rows,
            title="Matches by Tier"
        )

        # Version coverage
        version_stats = []
        for version, addrs in sorted(data['unmatched'].items()):
            # Count matched for this version
            matched_in_version = sum(
                1 for m in data['matched'].values()
                if version in m['addresses']
            )
            total_in_version = matched_in_version + len(addrs)
            coverage = matched_in_version / max(total_in_version, 1) * 100
            version_stats.append([
                version,
                total_in_version,
                matched_in_version,
                len(addrs),
                f"{coverage:.1f}%"
            ])

        self.reporter.table(
            headers=["Version", "Total", "Matched", "Unmatched", "Coverage"],
            rows=version_stats[:15],  # Show first 15
            title=f"Coverage by Version (showing {min(15, len(version_stats))}/{len(version_stats)})"
        )

        # Confidence distribution
        confidence_buckets = defaultdict(int)
        for match in data['matched'].values():
            bucket = int(match['confidence'] * 10) * 10  # 0, 10, 20, ... 100
            confidence_buckets[bucket] += 1

        self.reporter.info("\nConfidence Distribution:")
        for bucket in sorted(confidence_buckets.keys(), reverse=True):
            count = confidence_buckets[bucket]
            bar = "=" * (count // 100)
            self.reporter.info(f"  {bucket:3d}%: {count:5d} {bar}")

    def export_registry(self, dll_name: str, output_path: Path):
        """Export matching results to a function registry JSON."""
        state_path = self.match_cache / f"{dll_name}_state.json"

        if not state_path.exists():
            self.reporter.error(f"No matching state found for {dll_name}")
            return

        with open(state_path, 'r', encoding='utf-8') as f:
            state_data = json.load(f)

        self.reporter.header(f"Exporting: {dll_name}")

        # Build registry
        registry = {
            "dll_name": dll_name,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "match_count": len(state_data['matched']),
            "functions": {}
        }

        for match_id, match_data in state_data['matched'].items():
            registry['functions'][match_id] = {
                "addresses": match_data['addresses'],
                "confidence": match_data['confidence'],
                "tier": match_data['match_tier'],
                "method": match_data['match_method'],
                "export_name": match_data.get('export_name'),
                "ghidra_name": match_data.get('ghidra_name'),
            }

        # Write output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(registry, f, indent=2)

        size = output_path.stat().st_size
        self.reporter.success(f"Exported {len(registry['functions'])} functions to {output_path}")
        self.reporter.info(f"File size: {format_size(size)}")

    def export_viewer(self, dll_name: str):
        """Export matching results in format compatible with d2_report_viewer.html."""
        state_path = self.match_cache / f"{dll_name}_state.json"

        if not state_path.exists():
            self.reporter.error(f"No matching state found for {dll_name}")
            return

        with open(state_path, 'r', encoding='utf-8') as f:
            state_data = json.load(f)

        self.reporter.header(f"Exporting viewer data: {dll_name}")

        # Get all versions from the data
        all_versions = set()
        for match in state_data['matched'].values():
            all_versions.update(match['addresses'].keys())
        all_versions = sorted(all_versions)

        # Build viewer-compatible format
        # Format: {versions: [...], functions: {"key": {name, ordinal, addresses: {version: addr}}}}
        functions = {}

        for match_id, match_data in state_data['matched'].items():
            # Determine best name
            name = (match_data.get('ghidra_name') or
                   match_data.get('export_name') or
                   match_id)

            # Extract ordinal if export_name is Ordinal_XXXXX
            ordinal = None
            export_name = match_data.get('export_name', '')
            if export_name and export_name.startswith('Ordinal_'):
                try:
                    ordinal = int(export_name.split('_')[1])
                except (ValueError, IndexError):
                    pass

            functions[match_id] = {
                "name": name,
                "ordinal": ordinal,
                "addresses": match_data['addresses'],
                "confidence": match_data['confidence'],
                "tier": match_data['match_tier'],
            }

        viewer_data = {
            "versions": all_versions,
            "functions": functions,
        }

        # Write JavaScript file
        functions_dir = self.project_root / "reports" / "functions"
        functions_dir.mkdir(parents=True, exist_ok=True)

        safe_name = dll_name.replace('.', '_').replace(' ', '_')
        output_path = functions_dir / f"{dll_name}.js"

        js_content = f"""// Auto-generated by optimized_matching pipeline
// Generated: {time.strftime("%Y-%m-%dT%H:%M:%S")}
// Matched functions for {dll_name}
// Format: {{versions: [...], functions: {{"key": {{name, ordinal, addresses}}, ...}}}}

var FUNCTIONS_{safe_name.upper()} = {json.dumps(viewer_data, separators=(',', ':'))};
"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(js_content)

        size = output_path.stat().st_size
        self.reporter.success(f"Exported {len(functions)} functions to {output_path}")
        self.reporter.info(f"File size: {format_size(size)}")

        # Update the index file
        self._update_viewer_index(dll_name, len(functions), len(all_versions))

    def _update_viewer_index(self, dll_name: str, func_count: int, version_count: int):
        """Update the reports/functions/_index.js with this DLL's info."""
        index_path = self.project_root / "reports" / "functions" / "_index.js"

        # Load existing index or create new
        index_data = {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "version_count": version_count,
            "versions": [],
            "files": {}
        }

        if index_path.exists():
            try:
                content = index_path.read_text(encoding='utf-8')
                # Extract JSON from JavaScript variable
                start = content.find('{')
                if start >= 0:
                    existing = json.loads(content[start:].rstrip().rstrip(';'))
                    index_data = existing
            except Exception as e:
                self.reporter.warning(f"Could not parse existing index: {e}")

        # Update this file's entry
        index_data['files'][dll_name] = {
            "function_count": func_count,
            "version_count": version_count,
        }
        index_data['generated'] = time.strftime("%Y-%m-%dT%H:%M:%S")

        # Write updated index
        js_content = f"""// Auto-generated by optimized_matching pipeline
// Generated: {index_data['generated']}
// Function index for D2 Version Archive
// Load per-file data from functions/<filename>.js

var FUNCTION_INDEX = {json.dumps(index_data, separators=(',', ':'))};
"""
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(js_content)

        self.reporter.info(f"Updated index: {index_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Optimized Function Matching Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  analyze       Analyze PE files and extract function data
  match         Match functions across versions
  full          Run complete pipeline (analyze + match)
  stats         Show matching statistics
  export        Export function registry (JSON)
  viewer-export Export for d2_report_viewer.html (JavaScript)

Examples:
  # Analyze all versions of D2Client.dll
  python -m tools.optimized_matching.pipeline_runner analyze --dll D2Client.dll

  # Match with specific tiers
  python -m tools.optimized_matching.pipeline_runner match --dll D2Client.dll --tiers 1,2,3

  # Full pipeline
  python -m tools.optimized_matching.pipeline_runner full --dll D2Client.dll

  # Show stats
  python -m tools.optimized_matching.pipeline_runner stats --dll D2Client.dll

  # Export results for JSON use
  python -m tools.optimized_matching.pipeline_runner export --dll D2Client.dll -o registry.json

  # Export for HTML viewer
  python -m tools.optimized_matching.pipeline_runner viewer-export --dll D2Client.dll
        """
    )

    parser.add_argument("command", choices=["analyze", "match", "full", "stats", "export", "viewer-export"],
                        help="Command to run")
    parser.add_argument("--dll", type=str, required=True,
                        help="DLL name to process (e.g., D2Client.dll)")
    parser.add_argument("--versions", type=str, nargs="+",
                        help="Specific versions to process")
    parser.add_argument("--tiers", type=str,
                        help="Matching tiers to run (comma-separated, e.g., '1,2,3')")
    parser.add_argument("--cache", type=str, default="cache",
                        help="Cache directory")
    parser.add_argument("--output", "-o", type=str,
                        help="Output file path (for export command)")
    parser.add_argument("--force", action="store_true",
                        help="Force re-processing (ignore cache)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Quiet output (errors only)")

    args = parser.parse_args()

    # Setup
    reporter = ProgressReporter(verbose=args.verbose, quiet=args.quiet)
    project_root = Path(__file__).parent.parent.parent
    cache_dir = project_root / args.cache

    runner = PipelineRunner(
        project_root=project_root,
        cache_dir=cache_dir,
        reporter=reporter
    )

    # Parse tiers
    tiers = None
    if args.tiers:
        tiers = [int(t.strip()) for t in args.tiers.split(",")]

    # Execute command
    start_time = time.time()

    try:
        if args.command == "analyze":
            runner.analyze_all(args.dll, args.versions, force=args.force)

        elif args.command == "match":
            runner.match_all(args.dll, args.versions, tiers, force=args.force)

        elif args.command == "full":
            runner.analyze_all(args.dll, args.versions, force=args.force)
            runner.match_all(args.dll, args.versions, tiers, force=args.force)

        elif args.command == "stats":
            runner.show_stats(args.dll)

        elif args.command == "export":
            output_path = Path(args.output) if args.output else Path(f"reports/{args.dll}_registry.json")
            runner.export_registry(args.dll, output_path)

        elif args.command == "viewer-export":
            runner.export_viewer(args.dll)

    except KeyboardInterrupt:
        reporter.warning("Interrupted by user")
        return 130
    except Exception as e:
        reporter.error(f"Pipeline failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    elapsed = time.time() - start_time
    reporter.info(f"\nTotal time: {format_duration(elapsed)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
