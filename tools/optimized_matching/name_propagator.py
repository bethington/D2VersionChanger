"""
Name Propagator

Applies names from Ghidra exports to matched functions.
This is the bridge between human-annotated Ghidra data and the matching results.

Workflow:
1. Load Ghidra names export (from ExportNamesOnly.java script)
2. Load matching state
3. Find matches that include the Ghidra version
4. Propagate names to all matched addresses across versions
"""

import json
from pathlib import Path
from typing import Dict, Optional, Any, List
from dataclasses import dataclass

from .progress import ProgressReporter


@dataclass
class GhidraFunction:
    """Function data from Ghidra export."""
    address: int
    name: str
    rva: int
    signature: str
    calling_convention: str
    parameters: List[Dict[str, str]]


class NamePropagator:
    """
    Propagates Ghidra names to matched functions.

    Usage:
        propagator = NamePropagator(reporter)
        propagator.load_ghidra_names(Path("data/ghidra_names/D2Client.dll.json"))
        updated_state = propagator.propagate(state, ghidra_version="LoD/1.13c")
    """

    def __init__(self, reporter: Optional[ProgressReporter] = None):
        self.reporter = reporter or ProgressReporter()
        self.ghidra_functions: Dict[int, GhidraFunction] = {}
        self.image_base: int = 0

    def load_ghidra_names(self, json_path: Path) -> int:
        """
        Load Ghidra names from exported JSON.

        Args:
            json_path: Path to the Ghidra export JSON file

        Returns:
            Number of named functions loaded
        """
        self.reporter.info(f"Loading Ghidra names from {json_path}")

        if not json_path.exists():
            self.reporter.error(f"File not found: {json_path}")
            return 0

        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.image_base = int(data.get('image_base', '0'), 16)
        self.ghidra_functions = {}

        for addr_str, func_data in data.get('functions', {}).items():
            addr = int(addr_str, 16)
            self.ghidra_functions[addr] = GhidraFunction(
                address=addr,
                name=func_data['name'],
                rva=int(func_data.get('rva', '0'), 16),
                signature=func_data.get('signature', ''),
                calling_convention=func_data.get('calling_convention', ''),
                parameters=func_data.get('parameters', []),
            )

        self.reporter.info(f"Loaded {len(self.ghidra_functions)} named functions")
        return len(self.ghidra_functions)

    def propagate(self,
                  state_data: Dict[str, Any],
                  ghidra_version: str,
                  binary_image_base: Optional[int] = None) -> Dict[str, Any]:
        """
        Propagate Ghidra names to matched functions.

        Args:
            state_data: Matching state dictionary (loaded from JSON)
            ghidra_version: Version string for the Ghidra export (e.g., "LoD/1.13c")
            binary_image_base: Image base of the binary (auto-detected if not provided)

        Returns:
            Updated state data with ghidra_name fields populated
        """
        self.reporter.header("Name Propagation")

        if not self.ghidra_functions:
            self.reporter.warning("No Ghidra names loaded")
            return state_data

        matched = state_data.get('matched', {})
        propagated_count = 0
        not_found = []

        # Build RVA lookup for Ghidra functions
        # This handles cases where Ghidra export has different image base than actual binary
        rva_to_ghidra: Dict[int, GhidraFunction] = {}
        for func in self.ghidra_functions.values():
            rva_to_ghidra[func.rva] = func

        # Get binary image base from state metadata or look for it
        if binary_image_base is None:
            # Check state metadata first
            metadata = state_data.get('metadata', {})
            version_metadata = metadata.get('versions', {}).get(ghidra_version, {})
            if 'image_base' in version_metadata:
                binary_image_base = version_metadata['image_base']
                self.reporter.info(f"Image base from metadata: 0x{binary_image_base:08x}")
            else:
                # Try to detect from matching data - look for common base among all addresses
                # that have .text section starting at 0x1000
                version_addrs = []
                for match_data in matched.values():
                    if ghidra_version in match_data.get('addresses', {}):
                        addr = int(match_data['addresses'][ghidra_version], 16)
                        version_addrs.append(addr)

                if version_addrs:
                    # Find the minimum address and align down to segment boundary
                    min_addr = min(version_addrs)
                    # .text typically starts at base + 0x1000, so subtract that
                    binary_image_base = ((min_addr - 0x1000) >> 16) << 16
                    self.reporter.info(f"Auto-detected binary image base: 0x{binary_image_base:08x}")

            if binary_image_base:
                self.reporter.info(f"Ghidra export image base: 0x{self.image_base:08x}")

        with self.reporter.task("Propagating names", len(matched)) as progress:
            for match_id, match_data in matched.items():
                addresses = match_data.get('addresses', {})

                # Check if this match includes the Ghidra version
                if ghidra_version not in addresses:
                    progress.advance()
                    continue

                # Get the address in the Ghidra version
                ghidra_addr_str = addresses[ghidra_version]
                ghidra_addr = int(ghidra_addr_str, 16)

                # Try direct address match first
                if ghidra_addr in self.ghidra_functions:
                    ghidra_func = self.ghidra_functions[ghidra_addr]
                    match_data['ghidra_name'] = ghidra_func.name
                    match_data['ghidra_signature'] = ghidra_func.signature
                    propagated_count += 1
                    progress.log(f"{match_id}: {ghidra_func.name}")
                else:
                    # Try RVA-based match (handles different image bases)
                    if binary_image_base is not None:
                        rva = ghidra_addr - binary_image_base
                        if rva in rva_to_ghidra:
                            ghidra_func = rva_to_ghidra[rva]
                            match_data['ghidra_name'] = ghidra_func.name
                            match_data['ghidra_signature'] = ghidra_func.signature
                            propagated_count += 1
                            progress.log(f"{match_id}: {ghidra_func.name} (via RVA)")
                        else:
                            not_found.append((match_id, ghidra_addr))
                    else:
                        not_found.append((match_id, ghidra_addr))

                progress.advance()

        self.reporter.summary("Propagation Results", {
            "Total Matches": len(matched),
            "Names Propagated": propagated_count,
            "No Ghidra Name": len(matched) - propagated_count,
        })

        if not_found and self.reporter.verbose:
            self.reporter.info(f"\nFirst 10 matches without Ghidra names:")
            for match_id, addr in not_found[:10]:
                self.reporter.detail(f"{match_id} @ 0x{addr:08x}")

        return state_data

    def generate_registry(self,
                          state_data: Dict[str, Any],
                          output_path: Path):
        """
        Generate a function registry with all available data.

        Args:
            state_data: Matching state (with propagated names)
            output_path: Output JSON file path
        """
        self.reporter.info(f"Generating registry: {output_path}")

        registry = {
            "functions": {},
            "by_name": {},
        }

        for match_id, match_data in state_data.get('matched', {}).items():
            name = match_data.get('ghidra_name') or match_data.get('export_name') or match_id
            signature = match_data.get('ghidra_signature', '')

            registry['functions'][match_id] = {
                "name": name,
                "signature": signature,
                "addresses": match_data['addresses'],
                "confidence": match_data['confidence'],
                "tier": match_data['match_tier'],
            }

            # Index by name for quick lookup
            if name != match_id:
                registry['by_name'][name] = match_id

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(registry, f, indent=2)

        self.reporter.success(f"Registry saved: {output_path}")
        self.reporter.info(f"  Total functions: {len(registry['functions'])}")
        self.reporter.info(f"  Named functions: {len(registry['by_name'])}")


def propagate_names(ghidra_json: Path,
                    state_json: Path,
                    ghidra_version: str,
                    output_json: Path,
                    reporter: Optional[ProgressReporter] = None):
    """
    Convenience function to run the full propagation workflow.

    Args:
        ghidra_json: Path to Ghidra names export
        state_json: Path to matching state
        ghidra_version: Version string for Ghidra export
        output_json: Output path for updated state
        reporter: Progress reporter
    """
    reporter = reporter or ProgressReporter()

    # Load Ghidra names
    propagator = NamePropagator(reporter)
    propagator.load_ghidra_names(ghidra_json)

    # Load matching state
    with open(state_json, 'r', encoding='utf-8') as f:
        state_data = json.load(f)

    # Propagate names
    updated_state = propagator.propagate(state_data, ghidra_version)

    # Save updated state
    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(updated_state, f, indent=2)

    reporter.success(f"Updated state saved: {output_json}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Propagate Ghidra names to matched functions")
    parser.add_argument("--ghidra", type=str, required=True,
                        help="Path to Ghidra names JSON export")
    parser.add_argument("--state", type=str, required=True,
                        help="Path to matching state JSON")
    parser.add_argument("--version", type=str, required=True,
                        help="Ghidra version string (e.g., LoD/1.13c)")
    parser.add_argument("--output", "-o", type=str,
                        help="Output path (default: overwrite state)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    reporter = ProgressReporter(verbose=args.verbose)
    output_path = Path(args.output) if args.output else Path(args.state)

    propagate_names(
        ghidra_json=Path(args.ghidra),
        state_json=Path(args.state),
        ghidra_version=args.version,
        output_json=output_path,
        reporter=reporter
    )
