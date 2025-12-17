#!/usr/bin/env python3
"""
Query tool for the new function registry format.

Provides functions to:
- Look up functions by address, name, or hash
- Follow version chains
- Find equivalent functions across versions
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


@dataclass
class FunctionInfo:
    """Information about a function."""
    binary: str
    game_type: str
    version: str
    address: str
    name: str
    hashes: Dict[str, str]
    prev_match: Optional[Dict]
    next_match: Optional[Dict]


class FunctionRegistry:
    """Query interface for the function registry."""

    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            data_dir = Path(__file__).parent.parent / "data" / "functions"
        self.data_dir = data_dir
        self._cache: Dict[str, Dict] = {}

    def _load_version(self, binary: str, game_type: str, version: str) -> Optional[Dict]:
        """Load a specific version file."""
        cache_key = f"{binary}/{game_type}_{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        file_path = self.data_dir / binary / f"{game_type}_{version}.json"
        if not file_path.exists():
            return None

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self._cache[cache_key] = data
                return data
        except Exception:
            return None

    def get_function(
        self, binary: str, game_type: str, version: str, address: str
    ) -> Optional[FunctionInfo]:
        """Get a function by its exact location."""
        data = self._load_version(binary, game_type, version)
        if not data:
            return None

        func = data.get("functions", {}).get(address)
        if not func:
            return None

        return FunctionInfo(
            binary=binary,
            game_type=game_type,
            version=version,
            address=address,
            name=func.get("name", ""),
            hashes=func.get("hashes", {}),
            prev_match=func.get("prev_match"),
            next_match=func.get("next_match")
        )

    def find_by_name(
        self, binary: str, game_type: str, version: str, name: str
    ) -> List[FunctionInfo]:
        """Find functions by name (substring match)."""
        data = self._load_version(binary, game_type, version)
        if not data:
            return []

        results = []
        name_lower = name.lower()
        for address, func in data.get("functions", {}).items():
            func_name = func.get("name", "")
            if name_lower in func_name.lower():
                results.append(FunctionInfo(
                    binary=binary,
                    game_type=game_type,
                    version=version,
                    address=address,
                    name=func_name,
                    hashes=func.get("hashes", {}),
                    prev_match=func.get("prev_match"),
                    next_match=func.get("next_match")
                ))
        return results

    def follow_chain(
        self, func: FunctionInfo, direction: str = "both", max_steps: int = 50
    ) -> List[FunctionInfo]:
        """
        Follow the version chain from a function.

        direction: "prev", "next", or "both"
        Returns: List of functions in the chain
        """
        chain = [func]

        # Follow previous versions
        if direction in ("prev", "both"):
            current = func
            for _ in range(max_steps):
                if not current.prev_match:
                    break
                prev = self.get_function(
                    current.binary,
                    current.game_type,
                    current.prev_match["version"],
                    current.prev_match["address"]
                )
                if not prev:
                    break
                chain.insert(0, prev)
                current = prev

        # Follow next versions
        if direction in ("next", "both"):
            current = func
            for _ in range(max_steps):
                if not current.next_match:
                    break
                next_func = self.get_function(
                    current.binary,
                    current.game_type,
                    current.next_match["version"],
                    current.next_match["address"]
                )
                if not next_func:
                    break
                chain.append(next_func)
                current = next_func

        return chain

    def get_equivalent(
        self, func: FunctionInfo, target_version: str
    ) -> Optional[FunctionInfo]:
        """Find the equivalent function in a different version."""
        chain = self.follow_chain(func, "both")

        for f in chain:
            if f.version == target_version:
                return f

        return None

    def list_versions(self, binary: str) -> List[Dict[str, str]]:
        """List all available versions for a binary."""
        binary_dir = self.data_dir / binary
        if not binary_dir.exists():
            return []

        versions = []
        for json_file in sorted(binary_dir.glob("*.json")):
            parts = json_file.stem.split("_", 1)
            if len(parts) == 2:
                versions.append({
                    "game_type": parts[0],
                    "version": parts[1]
                })
        return versions

    def list_binaries(self) -> List[str]:
        """List all available binaries."""
        return [d.name for d in sorted(self.data_dir.iterdir()) if d.is_dir()]


def main():
    """Interactive query tool."""
    registry = FunctionRegistry()

    print("=" * 70)
    print("FUNCTION REGISTRY QUERY TOOL")
    print("=" * 70)
    print()

    # Demo: Find InitializeUnitSkills and follow chain
    print("Demo: Finding InitializeUnitSkills in D2Common.dll 1.07")
    print("-" * 50)

    results = registry.find_by_name("D2Common.dll", "LoD", "1.07", "InitializeUnitSkills")
    if results:
        func = results[0]
        print(f"Found: {func.name} at {func.address}")
        print()

        print("Following version chain:")
        chain = registry.follow_chain(func)
        for f in chain:
            print(f"  {f.version}: {f.address} - {f.name}")

        print()
        print("Finding equivalent in 1.13d:")
        equiv = registry.get_equivalent(func, "1.13d")
        if equiv:
            print(f"  Found: {equiv.address} - {equiv.name}")
        else:
            print("  Not found in chain (may need Tier 2 matching)")
    else:
        print("Function not found")

    print()
    print("-" * 50)
    print("Available binaries:")
    for binary in registry.list_binaries()[:10]:
        print(f"  - {binary}")
    print("  ...")


if __name__ == "__main__":
    main()
