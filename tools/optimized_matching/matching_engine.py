"""
Matching Engine

Tiered function matching across versions:
- Tier 1: Export ordinal/name matching (highest confidence)
- Tier 2: Exact byte hash matching
- Tier 3: Partial byte signature matching
- Tier 4: Structural similarity matching
- Tier 5: Call graph similarity matching

Each tier processes unmatched functions from previous tiers.
Results are cached and can be run incrementally.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

from .progress import ProgressReporter, format_size
from .analysis_engine import VersionAnalysis, FunctionInfo


@dataclass
class FunctionMatch:
    """A matched function across versions."""
    match_id: str                           # Canonical ID (e.g., "func_0001")
    addresses: Dict[str, int]               # version -> address
    confidence: float                       # 0.0 - 1.0
    match_tier: int                         # Which tier matched it
    match_method: str                       # Specific method used
    evidence: Dict[str, Any] = field(default_factory=dict)  # Supporting evidence
    ghidra_name: Optional[str] = None       # Name from Ghidra (if available)
    export_name: Optional[str] = None       # Export name (if exported)

    def to_dict(self) -> dict:
        return {
            'match_id': self.match_id,
            'addresses': {v: f"0x{a:08x}" for v, a in self.addresses.items()},
            'confidence': self.confidence,
            'match_tier': self.match_tier,
            'match_method': self.match_method,
            'evidence': self.evidence,
            'ghidra_name': self.ghidra_name,
            'export_name': self.export_name,
        }


@dataclass
class MatchingState:
    """State of the matching process."""
    matched: Dict[str, FunctionMatch]       # match_id -> FunctionMatch
    unmatched: Dict[str, Set[int]]          # version -> set of unmatched addresses
    next_match_id: int = 1

    def to_dict(self) -> dict:
        return {
            'matched': {k: v.to_dict() for k, v in self.matched.items()},
            'unmatched': {v: [f"0x{a:08x}" for a in addrs] for v, addrs in self.unmatched.items()},
            'next_match_id': self.next_match_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'MatchingState':
        matched = {}
        for match_id, match_data in data.get('matched', {}).items():
            matched[match_id] = FunctionMatch(
                match_id=match_data['match_id'],
                addresses={v: int(a, 16) for v, a in match_data['addresses'].items()},
                confidence=match_data['confidence'],
                match_tier=match_data['match_tier'],
                match_method=match_data['match_method'],
                evidence=match_data.get('evidence', {}),
                ghidra_name=match_data.get('ghidra_name'),
                export_name=match_data.get('export_name'),
            )
        unmatched = {}
        for version, addrs in data.get('unmatched', {}).items():
            unmatched[version] = {int(a, 16) for a in addrs}
        return cls(
            matched=matched,
            unmatched=unmatched,
            next_match_id=data.get('next_match_id', 1),
        )

    def get_next_id(self) -> str:
        """Get next available match ID."""
        match_id = f"func_{self.next_match_id:05d}"
        self.next_match_id += 1
        return match_id


class BaseMatcher(ABC):
    """Base class for function matchers."""

    def __init__(self, reporter: ProgressReporter):
        self.reporter = reporter

    @property
    @abstractmethod
    def tier(self) -> int:
        """Tier number for this matcher."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name."""
        pass

    @property
    @abstractmethod
    def confidence(self) -> float:
        """Base confidence score for matches from this tier."""
        pass

    @abstractmethod
    def match(self,
              analyses: Dict[str, VersionAnalysis],
              state: MatchingState) -> Tuple[List[FunctionMatch], MatchingState]:
        """
        Perform matching on unmatched functions.

        Args:
            analyses: version -> VersionAnalysis
            state: Current matching state

        Returns:
            Tuple of (new matches, updated state)
        """
        pass


class ExportMatcher(BaseMatcher):
    """Tier 1: Match functions by export name/ordinal."""

    @property
    def tier(self) -> int:
        return 1

    @property
    def name(self) -> str:
        return "Export Matching"

    @property
    def confidence(self) -> float:
        return 0.99

    def match(self,
              analyses: Dict[str, VersionAnalysis],
              state: MatchingState) -> Tuple[List[FunctionMatch], MatchingState]:

        self.reporter.info(f"Tier {self.tier}: {self.name}")

        # Group exports by name across versions
        exports_by_name: Dict[str, Dict[str, int]] = defaultdict(dict)

        for version, analysis in analyses.items():
            for addr, name in analysis.exports.items():
                if addr in state.unmatched.get(version, set()):
                    exports_by_name[name][version] = addr

        # Create matches for exports present in multiple versions
        new_matches = []
        for export_name, version_addrs in exports_by_name.items():
            if len(version_addrs) >= 2:  # Must be in at least 2 versions
                match = FunctionMatch(
                    match_id=state.get_next_id(),
                    addresses=version_addrs,
                    confidence=self.confidence,
                    match_tier=self.tier,
                    match_method="export_name",
                    evidence={"export_name": export_name},
                    export_name=export_name,
                )
                new_matches.append(match)

                # Remove from unmatched
                for version, addr in version_addrs.items():
                    state.unmatched[version].discard(addr)

        self.reporter.info(f"  Matched: {len(new_matches)} exports across versions")
        return new_matches, state


class ExactByteMatcher(BaseMatcher):
    """Tier 2: Match functions by exact byte hash."""

    @property
    def tier(self) -> int:
        return 2

    @property
    def name(self) -> str:
        return "Exact Byte Hash"

    @property
    def confidence(self) -> float:
        return 0.95

    def match(self,
              analyses: Dict[str, VersionAnalysis],
              state: MatchingState) -> Tuple[List[FunctionMatch], MatchingState]:

        self.reporter.info(f"Tier {self.tier}: {self.name}")

        # Build hash index for each hash length
        for hash_type, hash_name in [('bytes_md5_64', '64-byte'), ('bytes_md5_32', '32-byte')]:
            hash_index: Dict[str, Dict[str, int]] = defaultdict(dict)  # hash -> {version: addr}

            for version, analysis in analyses.items():
                for addr in state.unmatched.get(version, set()):
                    if addr in analysis.functions:
                        func = analysis.functions[addr]
                        hash_val = getattr(func, hash_type, '')
                        if hash_val:
                            hash_index[hash_val][version] = addr

            # Find hashes that match across versions
            new_matches = []
            matched_addrs: Dict[str, Set[int]] = defaultdict(set)

            for hash_val, version_addrs in hash_index.items():
                if len(version_addrs) >= 2:
                    # Check if any of these addresses are already matched in this round
                    already_matched = any(
                        addr in matched_addrs[version]
                        for version, addr in version_addrs.items()
                    )
                    if already_matched:
                        continue

                    match = FunctionMatch(
                        match_id=state.get_next_id(),
                        addresses=version_addrs.copy(),
                        confidence=self.confidence if hash_type == 'bytes_md5_64' else 0.90,
                        match_tier=self.tier,
                        match_method=f"exact_{hash_name.replace('-', '_')}",
                        evidence={hash_type: hash_val},
                    )
                    new_matches.append(match)

                    # Track matched addresses
                    for version, addr in version_addrs.items():
                        matched_addrs[version].add(addr)

            # Remove from unmatched
            for version, addrs in matched_addrs.items():
                state.unmatched[version] -= addrs

            if new_matches:
                self.reporter.info(f"  {hash_name} matches: {len(new_matches)}")

        total_matches = sum(1 for m in state.matched.values() if m.match_tier == self.tier)
        self.reporter.info(f"  Total tier {self.tier} matches: {len(new_matches)}")

        return new_matches, state


class PrologueMatcher(BaseMatcher):
    """Tier 3: Match by prologue + size similarity."""

    @property
    def tier(self) -> int:
        return 3

    @property
    def name(self) -> str:
        return "Prologue + Size"

    @property
    def confidence(self) -> float:
        return 0.75

    def match(self,
              analyses: Dict[str, VersionAnalysis],
              state: MatchingState) -> Tuple[List[FunctionMatch], MatchingState]:

        self.reporter.info(f"Tier {self.tier}: {self.name}")

        # Build index by prologue
        prologue_index: Dict[str, Dict[str, List[Tuple[int, int]]]] = defaultdict(
            lambda: defaultdict(list)
        )  # prologue -> {version: [(addr, size), ...]}

        for version, analysis in analyses.items():
            for addr in state.unmatched.get(version, set()):
                if addr in analysis.functions:
                    func = analysis.functions[addr]
                    if func.prologue_8:
                        prologue_index[func.prologue_8][version].append(
                            (addr, func.size_estimate)
                        )

        # Match functions with same prologue and similar size
        new_matches = []
        matched_addrs: Dict[str, Set[int]] = defaultdict(set)

        with self.reporter.task("Comparing prologues", len(prologue_index)) as progress:
            for prologue, version_funcs in prologue_index.items():
                if len(version_funcs) < 2:
                    progress.advance()
                    continue

                # Try to match functions across versions
                # For each function in first version, find best match in other versions
                versions = sorted(version_funcs.keys())
                base_version = versions[0]

                for base_addr, base_size in version_funcs[base_version]:
                    if base_addr in matched_addrs[base_version]:
                        continue

                    matches_for_func = {base_version: base_addr}

                    for other_version in versions[1:]:
                        # Find best size match
                        best_match = None
                        best_size_diff = float('inf')

                        for other_addr, other_size in version_funcs[other_version]:
                            if other_addr in matched_addrs[other_version]:
                                continue

                            size_diff = abs(other_size - base_size)
                            # Allow up to 20% size difference
                            if size_diff < best_size_diff and size_diff <= base_size * 0.2:
                                best_match = other_addr
                                best_size_diff = size_diff

                        if best_match:
                            matches_for_func[other_version] = best_match

                    if len(matches_for_func) >= 2:
                        match = FunctionMatch(
                            match_id=state.get_next_id(),
                            addresses=matches_for_func,
                            confidence=self.confidence,
                            match_tier=self.tier,
                            match_method="prologue_size",
                            evidence={"prologue": prologue, "base_size": base_size},
                        )
                        new_matches.append(match)

                        for version, addr in matches_for_func.items():
                            matched_addrs[version].add(addr)

                progress.advance()

        # Remove from unmatched
        for version, addrs in matched_addrs.items():
            state.unmatched[version] -= addrs

        self.reporter.info(f"  Matched: {len(new_matches)} functions")
        return new_matches, state


class CallGraphMatcher(BaseMatcher):
    """Tier 4: Match by call graph similarity."""

    @property
    def tier(self) -> int:
        return 4

    @property
    def name(self) -> str:
        return "Call Graph Similarity"

    @property
    def confidence(self) -> float:
        return 0.70

    def match(self,
              analyses: Dict[str, VersionAnalysis],
              state: MatchingState) -> Tuple[List[FunctionMatch], MatchingState]:

        self.reporter.info(f"Tier {self.tier}: {self.name}")

        # Build reverse mapping: address -> match_id for already matched functions
        addr_to_match: Dict[str, Dict[int, str]] = defaultdict(dict)
        for match in state.matched.values():
            for version, addr in match.addresses.items():
                addr_to_match[version][addr] = match.match_id

        # Build callee signature for each unmatched function
        # Signature = set of match_ids that this function calls
        func_signatures: Dict[str, Dict[int, Set[str]]] = defaultdict(dict)

        for version, analysis in analyses.items():
            for addr in state.unmatched.get(version, set()):
                if addr in analysis.functions:
                    func = analysis.functions[addr]
                    # Get match IDs of callees
                    callee_ids = set()
                    for callee_addr in func.callees:
                        if callee_addr in addr_to_match[version]:
                            callee_ids.add(addr_to_match[version][callee_addr])
                    if callee_ids:
                        func_signatures[version][addr] = callee_ids

        # Group by signature
        sig_to_funcs: Dict[frozenset, Dict[str, int]] = defaultdict(dict)
        for version, addr_sigs in func_signatures.items():
            for addr, sig in addr_sigs.items():
                sig_key = frozenset(sig)
                sig_to_funcs[sig_key][version] = addr

        # Match functions with same callee signature
        new_matches = []
        matched_addrs: Dict[str, Set[int]] = defaultdict(set)

        for sig, version_addrs in sig_to_funcs.items():
            if len(version_addrs) >= 2 and len(sig) >= 2:  # Require at least 2 shared callees
                # Check not already matched
                already_matched = any(
                    addr in matched_addrs[version]
                    for version, addr in version_addrs.items()
                )
                if already_matched:
                    continue

                match = FunctionMatch(
                    match_id=state.get_next_id(),
                    addresses=version_addrs.copy(),
                    confidence=self.confidence,
                    match_tier=self.tier,
                    match_method="call_graph_signature",
                    evidence={"shared_callees": len(sig)},
                )
                new_matches.append(match)

                for version, addr in version_addrs.items():
                    matched_addrs[version].add(addr)

        # Remove from unmatched
        for version, addrs in matched_addrs.items():
            state.unmatched[version] -= addrs

        self.reporter.info(f"  Matched: {len(new_matches)} functions")
        return new_matches, state


class MatchingEngine:
    """
    Coordinates tiered matching across versions.

    Usage:
        engine = MatchingEngine(cache_dir=Path("cache/matches"))
        results = engine.match_all(analyses, start_tier=1, end_tier=4)
    """

    def __init__(self,
                 cache_dir: Optional[Path] = None,
                 reporter: Optional[ProgressReporter] = None):
        self.cache_dir = cache_dir
        self.reporter = reporter or ProgressReporter()

        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)

        # Initialize matchers
        self.matchers = [
            ExportMatcher(self.reporter),
            ExactByteMatcher(self.reporter),
            PrologueMatcher(self.reporter),
            CallGraphMatcher(self.reporter),
        ]

    def _get_state_path(self, dll_name: str) -> Optional[Path]:
        """Get state file path for a DLL."""
        if not self.cache_dir:
            return None
        return self.cache_dir / f"{dll_name}_state.json"

    def _load_state(self, state_path: Path) -> Optional[MatchingState]:
        """Load matching state from cache."""
        if not state_path or not state_path.exists():
            return None
        try:
            with open(state_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return MatchingState.from_dict(data)
        except (json.JSONDecodeError, KeyError) as e:
            self.reporter.warning(f"State file corrupt: {e}")
            return None

    def _save_state(self, state_path: Path, state: MatchingState):
        """Save matching state to cache."""
        if not state_path:
            return
        with open(state_path, 'w', encoding='utf-8') as f:
            json.dump(state.to_dict(), f, indent=2)
        self.reporter.detail(f"State saved: {state_path.name}")

    def _initialize_state(self, analyses: Dict[str, VersionAnalysis]) -> MatchingState:
        """Create initial matching state with all functions unmatched."""
        unmatched = {}
        for version, analysis in analyses.items():
            unmatched[version] = set(analysis.functions.keys())
        return MatchingState(matched={}, unmatched=unmatched)

    def match_all(self,
                  analyses: Dict[str, VersionAnalysis],
                  dll_name: str,
                  start_tier: int = 1,
                  end_tier: int = 4,
                  force: bool = False) -> MatchingState:
        """
        Run matching tiers on analyses.

        Args:
            analyses: version -> VersionAnalysis
            dll_name: Name of DLL being matched (for caching)
            start_tier: First tier to run
            end_tier: Last tier to run
            force: Force re-matching (ignore cache)

        Returns:
            Final matching state
        """
        self.reporter.header(f"Matching: {dll_name}")

        # Load or initialize state
        state_path = self._get_state_path(dll_name)
        state = None if force else self._load_state(state_path)

        if state and not force:
            self.reporter.info(f"Resuming from cached state: {len(state.matched)} matches")
        else:
            state = self._initialize_state(analyses)
            self.reporter.info(f"Starting fresh: {sum(len(v) for v in state.unmatched.values())} functions across {len(analyses)} versions")

        # Run matchers
        for matcher in self.matchers:
            if start_tier <= matcher.tier <= end_tier:
                # Check if there are unmatched functions
                total_unmatched = sum(len(v) for v in state.unmatched.values())
                if total_unmatched == 0:
                    self.reporter.info(f"All functions matched, skipping tier {matcher.tier}")
                    break

                new_matches, state = matcher.match(analyses, state)

                # Add new matches to state
                for match in new_matches:
                    state.matched[match.match_id] = match

                # Save state after each tier
                self._save_state(state_path, state)

        # Final summary
        total_matched = len(state.matched)
        total_unmatched = sum(len(v) for v in state.unmatched.values())
        total_funcs = total_matched + (total_unmatched // len(analyses) if analyses else 0)

        self.reporter.summary("Matching Complete", {
            "Total Matches": total_matched,
            "Unmatched (per version avg)": total_unmatched // len(analyses) if analyses else 0,
            "Match Rate": f"{total_matched / max(total_funcs, 1) * 100:.1f}%",
        })

        # Tier breakdown
        tier_counts = defaultdict(int)
        for match in state.matched.values():
            tier_counts[match.match_tier] += 1

        self.reporter.table(
            headers=["Tier", "Method", "Matches", "Confidence"],
            rows=[
                [m.tier, m.name, tier_counts.get(m.tier, 0), f"{m.confidence:.0%}"]
                for m in self.matchers
            ],
            title="Matches by Tier"
        )

        return state


if __name__ == "__main__":
    import argparse
    from .analysis_engine import AnalysisEngine

    parser = argparse.ArgumentParser(description="Match functions across versions")
    parser.add_argument("--dll", type=str, required=True, help="DLL name to match")
    parser.add_argument("--versions", type=str, nargs="+", help="Version folders to include")
    parser.add_argument("--cache", type=str, default="cache", help="Cache directory")
    parser.add_argument("--start-tier", type=int, default=1, help="Starting tier")
    parser.add_argument("--end-tier", type=int, default=4, help="Ending tier")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--force", action="store_true", help="Force re-matching")

    args = parser.parse_args()

    reporter = ProgressReporter(verbose=args.verbose)
    cache_dir = Path(args.cache)
    analysis_cache = cache_dir / "analysis"
    match_cache = cache_dir / "matches"

    # Load analyses
    reporter.stage("Loading Analyses")
    analysis_engine = AnalysisEngine(cache_dir=analysis_cache, reporter=reporter)
    analyses = {}

    # Find version folders
    version_root = Path("VersionChanger")
    if args.versions:
        version_dirs = [version_root / v for v in args.versions]
    else:
        # Find all version folders
        version_dirs = []
        for game_type in ["Classic", "LoD"]:
            game_dir = version_root / game_type
            if game_dir.exists():
                version_dirs.extend(sorted(game_dir.iterdir()))

    for version_dir in version_dirs:
        if not version_dir.is_dir():
            continue
        dll_path = version_dir / args.dll
        if not dll_path.exists():
            continue

        version = f"{version_dir.parent.name}/{version_dir.name}"
        try:
            analysis = analysis_engine.analyze(dll_path, version)
            analyses[version] = analysis
        except Exception as e:
            reporter.error(f"Failed to analyze {version}: {e}")

    reporter.info(f"Loaded {len(analyses)} versions")

    if len(analyses) < 2:
        reporter.error("Need at least 2 versions to match")
        exit(1)

    # Run matching
    engine = MatchingEngine(cache_dir=match_cache, reporter=reporter)
    state = engine.match_all(
        analyses,
        dll_name=args.dll,
        start_tier=args.start_tier,
        end_tier=args.end_tier,
        force=args.force,
    )
