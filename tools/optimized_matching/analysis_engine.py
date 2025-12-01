"""
Analysis Engine

Analyzes PE files to extract function data:
- Function boundaries (prologue/padding detection)
- Byte signatures (MD5 hashes of function bytes)
- Call graph (via capstone disassembly)
- Structural metrics (size, call count, etc.)

All analysis is cached per-version for fast incremental updates.
"""

import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

try:
    import pefile
except ImportError:
    print("Error: pefile required. Install with: pip install pefile")
    raise

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL, CS_GRP_JUMP
    from capstone.x86 import X86_OP_IMM
    CAPSTONE_AVAILABLE = True
except ImportError:
    print("Warning: capstone not available. Call graph extraction disabled.")
    print("Install with: pip install capstone")
    CAPSTONE_AVAILABLE = False

from .progress import ProgressReporter, format_size


@dataclass
class FunctionInfo:
    """Information about a detected function."""
    address: int                    # Absolute address
    rva: int                        # Relative virtual address
    size_estimate: int              # Estimated size in bytes
    bytes_md5_16: str = ""          # MD5 of first 16 bytes
    bytes_md5_32: str = ""          # MD5 of first 32 bytes
    bytes_md5_64: str = ""          # MD5 of first 64 bytes
    prologue_4: str = ""            # First 4 bytes as hex
    prologue_8: str = ""            # First 8 bytes as hex
    callees: List[int] = field(default_factory=list)   # Addresses this function calls
    callers: List[int] = field(default_factory=list)   # Addresses that call this function
    call_count: int = 0             # Number of CALL instructions
    is_export: bool = False         # Is this an exported function
    export_ordinal: Optional[int] = None
    export_name: Optional[str] = None
    source: str = "detected"        # 'export', 'detected', 'thunk'

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'address': f"0x{self.address:08x}",
            'rva': f"0x{self.rva:08x}",
            'size_estimate': self.size_estimate,
            'bytes_md5_16': self.bytes_md5_16,
            'bytes_md5_32': self.bytes_md5_32,
            'bytes_md5_64': self.bytes_md5_64,
            'prologue_4': self.prologue_4,
            'prologue_8': self.prologue_8,
            'callees': [f"0x{a:08x}" for a in self.callees],
            'callers': [f"0x{a:08x}" for a in self.callers],
            'call_count': self.call_count,
            'is_export': self.is_export,
            'export_ordinal': self.export_ordinal,
            'export_name': self.export_name,
            'source': self.source,
        }


@dataclass
class VersionAnalysis:
    """Complete analysis of a single version's PE file."""
    filename: str
    version: str
    file_hash: str                  # SHA256 of the file (for cache invalidation)
    image_base: int
    text_section_va: int
    text_section_size: int
    functions: Dict[int, FunctionInfo]  # address -> FunctionInfo
    exports: Dict[int, str]         # address -> export name
    call_graph: Dict[int, List[int]]  # caller -> [callees]
    reverse_call_graph: Dict[int, List[int]]  # callee -> [callers]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'filename': self.filename,
            'version': self.version,
            'file_hash': self.file_hash,
            'image_base': f"0x{self.image_base:08x}",
            'text_section_va': f"0x{self.text_section_va:08x}",
            'text_section_size': self.text_section_size,
            'function_count': len(self.functions),
            'export_count': len(self.exports),
            'functions': {f"0x{addr:08x}": func.to_dict() for addr, func in self.functions.items()},
            'exports': {f"0x{addr:08x}": name for addr, name in self.exports.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'VersionAnalysis':
        """Load from dictionary."""
        functions = {}
        for addr_str, func_data in data.get('functions', {}).items():
            addr = int(addr_str, 16)
            functions[addr] = FunctionInfo(
                address=int(func_data['address'], 16),
                rva=int(func_data['rva'], 16),
                size_estimate=func_data['size_estimate'],
                bytes_md5_16=func_data.get('bytes_md5_16', ''),
                bytes_md5_32=func_data.get('bytes_md5_32', ''),
                bytes_md5_64=func_data.get('bytes_md5_64', ''),
                prologue_4=func_data.get('prologue_4', ''),
                prologue_8=func_data.get('prologue_8', ''),
                callees=[int(a, 16) for a in func_data.get('callees', [])],
                callers=[int(a, 16) for a in func_data.get('callers', [])],
                call_count=func_data.get('call_count', 0),
                is_export=func_data.get('is_export', False),
                export_ordinal=func_data.get('export_ordinal'),
                export_name=func_data.get('export_name'),
                source=func_data.get('source', 'detected'),
            )

        exports = {int(addr, 16): name for addr, name in data.get('exports', {}).items()}

        # Rebuild call graphs from functions
        call_graph = defaultdict(list)
        reverse_call_graph = defaultdict(list)
        for addr, func in functions.items():
            call_graph[addr] = func.callees
            for callee in func.callees:
                reverse_call_graph[callee].append(addr)

        return cls(
            filename=data['filename'],
            version=data['version'],
            file_hash=data['file_hash'],
            image_base=int(data['image_base'], 16),
            text_section_va=int(data['text_section_va'], 16),
            text_section_size=data['text_section_size'],
            functions=functions,
            exports=exports,
            call_graph=dict(call_graph),
            reverse_call_graph=dict(reverse_call_graph),
        )


class AnalysisEngine:
    """
    Analyzes PE files to extract function information.

    Usage:
        engine = AnalysisEngine(cache_dir=Path("cache/analysis"))
        analysis = engine.analyze(pe_path, version="LoD/1.13c")
    """

    # Common function prologues (x86 32-bit)
    # These are checked in order - more specific patterns first
    PROLOGUE_PATTERNS = [
        b'\x55\x8b\xec',           # push ebp; mov ebp, esp (most common)
        b'\x55\x89\xe5',           # push ebp; mov ebp, esp (alternate encoding)
        b'\x8b\xff\x55',           # mov edi, edi; push ebp (hotpatch prologue)
        b'\x53\x56\x57',           # push ebx; push esi; push edi
        b'\x56\x57\x8b',           # push esi; push edi; mov
        b'\x53\x8b\x5c',           # push ebx; mov ebx, [esp+...]
        b'\x55\x57\x56',           # push ebp; push edi; push esi
        b'\x83\xec',               # sub esp, imm8
        b'\x81\xec',               # sub esp, imm32
        b'\x6a\xff',               # push -1 (SEH frame start)
        b'\x68',                   # push imm32
        b'\x6a',                   # push imm8
        b'\x56\x8b',               # push esi; mov ...
        b'\x57\x8b',               # push edi; mov ...
        b'\x53\x8b',               # push ebx; mov ...
        b'\x51\x53',               # push ecx; push ebx
        b'\x52\x53',               # push edx; push ebx
        b'\x51',                   # push ecx
        b'\x52',                   # push edx
        b'\x53',                   # push ebx
        b'\x56',                   # push esi
        b'\x57',                   # push edi
        b'\xb8',                   # mov eax, imm32
        b'\xa1',                   # mov eax, [addr]
        b'\x8b\x44',               # mov eax, [esp+...]
        b'\x8b\x4c',               # mov ecx, [esp+...]
        b'\x8b\x54',               # mov edx, [esp+...]
        b'\x33\xc0',               # xor eax, eax
        b'\x33\xc9',               # xor ecx, ecx
        b'\x33\xd2',               # xor edx, edx
    ]

    def __init__(self,
                 cache_dir: Optional[Path] = None,
                 reporter: Optional[ProgressReporter] = None):
        """
        Initialize the analysis engine.

        Args:
            cache_dir: Directory for caching analysis results
            reporter: Progress reporter for output
        """
        self.cache_dir = cache_dir
        self.reporter = reporter or ProgressReporter()

        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, version: str, filename: str) -> Path:
        """Get cache file path for a version/file combination."""
        if not self.cache_dir:
            return None
        # Sanitize version string for filesystem
        safe_version = version.replace('/', '_').replace('\\', '_')
        cache_subdir = self.cache_dir / safe_version
        cache_subdir.mkdir(parents=True, exist_ok=True)
        return cache_subdir / f"{filename}.json"

    def _load_cache(self, cache_path: Path, file_hash: str) -> Optional[VersionAnalysis]:
        """Load cached analysis if valid."""
        if not cache_path or not cache_path.exists():
            return None

        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Check if cache is still valid (file hasn't changed)
            if data.get('file_hash') == file_hash:
                self.reporter.detail(f"Cache hit: {cache_path.name}")
                return VersionAnalysis.from_dict(data)
            else:
                self.reporter.detail(f"Cache stale: {cache_path.name}")
                return None
        except (json.JSONDecodeError, KeyError) as e:
            self.reporter.warning(f"Cache corrupt: {e}")
            return None

    def _save_cache(self, cache_path: Path, analysis: VersionAnalysis):
        """Save analysis to cache."""
        if not cache_path:
            return

        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(analysis.to_dict(), f, indent=2)

        size = cache_path.stat().st_size
        self.reporter.detail(f"Cache saved: {cache_path.name} ({format_size(size)})")

    def _compute_file_hash(self, pe_path: Path) -> str:
        """Compute SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(pe_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def analyze(self,
                pe_path: Path,
                version: str,
                force: bool = False) -> VersionAnalysis:
        """
        Analyze a PE file and extract function information.

        Args:
            pe_path: Path to the PE file
            version: Version string (e.g., "LoD/1.13c")
            force: Force re-analysis even if cached

        Returns:
            VersionAnalysis with all extracted function data
        """
        filename = pe_path.name
        self.reporter.stage(f"Analyzing {version}/{filename}")

        # Compute file hash for cache validation
        file_hash = self._compute_file_hash(pe_path)
        self.reporter.detail(f"File hash: {file_hash[:16]}...")

        # Check cache
        cache_path = self._get_cache_path(version, filename)
        if not force:
            cached = self._load_cache(cache_path, file_hash)
            if cached:
                self.reporter.info(f"Loaded from cache: {len(cached.functions)} functions")
                return cached

        # Load PE file
        self.reporter.info("Loading PE file...")
        pe = pefile.PE(str(pe_path))
        image_base = pe.OPTIONAL_HEADER.ImageBase

        # Find .text section
        text_section = None
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='ignore')
            if name == '.text':
                text_section = section
                break

        if not text_section:
            self.reporter.error("No .text section found")
            pe.close()
            raise ValueError(f"No .text section in {pe_path}")

        text_va = image_base + text_section.VirtualAddress
        text_size = text_section.Misc_VirtualSize
        text_data = text_section.get_data()

        self.reporter.info(f"Image base: 0x{image_base:08x}")
        self.reporter.info(f".text section: 0x{text_va:08x} - 0x{text_va + text_size:08x}")

        # Extract exports
        exports = self._extract_exports(pe)
        self.reporter.info(f"Exports found: {len(exports)}")

        # Detect functions
        functions = self._detect_functions(pe, text_section, text_data, exports)
        self.reporter.info(f"Functions detected: {len(functions)}")

        # Compute signatures for all functions
        self._compute_signatures(functions, text_section, text_data, image_base)

        # Build call graph (if capstone available)
        call_graph, reverse_call_graph = {}, {}
        if CAPSTONE_AVAILABLE:
            call_graph, reverse_call_graph = self._build_call_graph(
                functions, text_section, text_data, image_base
            )
            self.reporter.info(f"Call graph edges: {sum(len(v) for v in call_graph.values())}")
        else:
            self.reporter.warning("Call graph skipped (capstone not available)")

        # Update function callers from reverse graph
        for callee_addr, callers in reverse_call_graph.items():
            if callee_addr in functions:
                functions[callee_addr].callers = list(callers)

        pe.close()

        # Build analysis result
        analysis = VersionAnalysis(
            filename=filename,
            version=version,
            file_hash=file_hash,
            image_base=image_base,
            text_section_va=text_va,
            text_section_size=text_size,
            functions=functions,
            exports=exports,
            call_graph=call_graph,
            reverse_call_graph=reverse_call_graph,
        )

        # Save to cache
        self._save_cache(cache_path, analysis)

        return analysis

    def _extract_exports(self, pe: pefile.PE) -> Dict[int, str]:
        """Extract exported function addresses and names."""
        exports = {}

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.address:
                addr = pe.OPTIONAL_HEADER.ImageBase + exp.address
                name = exp.name.decode('ascii') if exp.name else f"Ordinal_{exp.ordinal}"
                exports[addr] = name

        return exports

    def _detect_functions(self,
                          pe: pefile.PE,
                          text_section,
                          text_data: bytes,
                          exports: Dict[int, str]) -> Dict[int, FunctionInfo]:
        """Detect function boundaries using multiple heuristics."""
        image_base = pe.OPTIONAL_HEADER.ImageBase
        text_va = image_base + text_section.VirtualAddress
        text_size = len(text_data)

        function_addrs: Set[int] = set()

        # Method 1: All exports are functions
        for addr in exports.keys():
            if text_va <= addr < text_va + text_size:
                function_addrs.add(addr)

        # Method 2: Padding detection (CC or 90 sequences)
        # After padding, the next non-padding byte is likely a function start
        self.reporter.detail("Detecting functions via padding...")
        i = 0
        while i < text_size - 4:
            # Look for padding bytes
            if text_data[i] in (0xCC, 0x90):
                # Check if this is actually a padding sequence (multiple bytes)
                padding_start = i
                while i < text_size and text_data[i] in (0xCC, 0x90):
                    i += 1
                padding_len = i - padding_start

                # If we had at least 2 padding bytes, next byte is likely function start
                if padding_len >= 2 and i < text_size:
                    # Verify it's not more padding or data (00 bytes)
                    if text_data[i] not in (0x00, 0xCC, 0x90):
                        function_addrs.add(text_va + i)
            else:
                i += 1

        # Method 3: Jump table detection (E9 sequences at start)
        if text_data[:1] == b'\xe9':
            self.reporter.detail("Detecting jump table thunks...")
            i = 0
            while i < min(text_size, 0x5000) and text_data[i] == 0xE9:
                function_addrs.add(text_va + i)
                i += 5  # E9 + 4-byte relative offset

        # Method 4: Scan for common prologues (catch functions without padding)
        self.reporter.detail("Scanning for function prologues...")
        strong_prologues = [
            b'\x55\x8b\xec',           # push ebp; mov ebp, esp
            b'\x8b\xff\x55\x8b\xec',   # mov edi,edi; push ebp; mov ebp,esp (hotpatch)
            b'\x6a\xff\x68',           # push -1; push addr (SEH setup)
        ]
        for i in range(text_size - 5):
            for pattern in strong_prologues:
                if text_data[i:i+len(pattern)] == pattern:
                    function_addrs.add(text_va + i)
                    break

        # Sort and build function info
        sorted_addrs = sorted(function_addrs)
        functions: Dict[int, FunctionInfo] = {}

        with self.reporter.task("Building function info", len(sorted_addrs)) as progress:
            for idx, addr in enumerate(sorted_addrs):
                # Estimate size
                if idx + 1 < len(sorted_addrs):
                    size_estimate = sorted_addrs[idx + 1] - addr
                else:
                    size_estimate = (text_va + text_size) - addr

                # Cap at reasonable max, skip tiny ones
                size_estimate = min(size_estimate, 0x10000)
                if size_estimate < 4:
                    progress.advance()
                    continue

                rva = addr - image_base
                is_export = addr in exports
                export_name = exports.get(addr)

                functions[addr] = FunctionInfo(
                    address=addr,
                    rva=rva,
                    size_estimate=size_estimate,
                    is_export=is_export,
                    export_ordinal=None,  # Could extract from PE
                    export_name=export_name,
                    source='export' if is_export else 'detected',
                )

                progress.advance()

        return functions

    def _compute_signatures(self,
                            functions: Dict[int, FunctionInfo],
                            text_section,
                            text_data: bytes,
                            image_base: int):
        """Compute byte signatures for all functions."""
        text_va = image_base + text_section.VirtualAddress

        with self.reporter.task("Computing signatures", len(functions)) as progress:
            for addr, func in functions.items():
                offset = addr - text_va

                if 0 <= offset < len(text_data):
                    # Get function bytes
                    func_bytes = text_data[offset:offset + min(func.size_estimate, 64)]

                    # MD5 hashes of first N bytes
                    if len(func_bytes) >= 16:
                        func.bytes_md5_16 = hashlib.md5(func_bytes[:16]).hexdigest()
                    if len(func_bytes) >= 32:
                        func.bytes_md5_32 = hashlib.md5(func_bytes[:32]).hexdigest()
                    if len(func_bytes) >= 64:
                        func.bytes_md5_64 = hashlib.md5(func_bytes[:64]).hexdigest()

                    # Prologue bytes
                    if len(func_bytes) >= 4:
                        func.prologue_4 = func_bytes[:4].hex()
                    if len(func_bytes) >= 8:
                        func.prologue_8 = func_bytes[:8].hex()

                progress.advance()

    def _build_call_graph(self,
                          functions: Dict[int, FunctionInfo],
                          text_section,
                          text_data: bytes,
                          image_base: int) -> Tuple[Dict[int, List[int]], Dict[int, List[int]]]:
        """Build call graph by disassembling and finding CALL instructions."""
        if not CAPSTONE_AVAILABLE:
            return {}, {}

        text_va = image_base + text_section.VirtualAddress
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True

        call_graph: Dict[int, List[int]] = defaultdict(list)
        reverse_call_graph: Dict[int, List[int]] = defaultdict(list)
        function_set = set(functions.keys())

        with self.reporter.task("Building call graph", len(functions)) as progress:
            for addr, func in functions.items():
                offset = addr - text_va
                if offset < 0 or offset >= len(text_data):
                    progress.advance()
                    continue

                # Get function bytes
                func_bytes = text_data[offset:offset + min(func.size_estimate, 0x10000)]

                # Disassemble and find CALLs
                call_count = 0
                try:
                    for insn in md.disasm(func_bytes, addr):
                        if insn.mnemonic == 'call':
                            call_count += 1
                            # Check for direct call (immediate operand)
                            for op in insn.operands:
                                if op.type == X86_OP_IMM:
                                    target = op.imm
                                    # Only track calls to known functions
                                    if target in function_set:
                                        call_graph[addr].append(target)
                                        reverse_call_graph[target].append(addr)
                                        func.callees.append(target)
                except Exception:
                    pass  # Skip functions that fail to disassemble

                func.call_count = call_count
                progress.advance()

        return dict(call_graph), dict(reverse_call_graph)


def analyze_version_folder(folder: Path,
                           version: str,
                           cache_dir: Path,
                           reporter: ProgressReporter,
                           dll_filter: Optional[str] = None) -> Dict[str, VersionAnalysis]:
    """
    Analyze all PE files in a version folder.

    Args:
        folder: Path to version folder
        version: Version string
        cache_dir: Cache directory
        reporter: Progress reporter
        dll_filter: Optional filter for specific DLL name

    Returns:
        Dictionary mapping filename to VersionAnalysis
    """
    engine = AnalysisEngine(cache_dir=cache_dir, reporter=reporter)
    results = {}

    pe_files = list(folder.glob("*.dll")) + list(folder.glob("*.exe"))

    if dll_filter:
        pe_files = [f for f in pe_files if f.name.lower() == dll_filter.lower()]

    reporter.info(f"Found {len(pe_files)} PE files in {folder}")

    for pe_path in sorted(pe_files):
        try:
            analysis = engine.analyze(pe_path, version)
            results[pe_path.name] = analysis
        except Exception as e:
            reporter.error(f"Failed to analyze {pe_path.name}: {e}")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analyze PE files for function data")
    parser.add_argument("--file", "-f", type=str, help="Single PE file to analyze")
    parser.add_argument("--version", "-v", type=str, default="test", help="Version string")
    parser.add_argument("--cache", "-c", type=str, default="cache/analysis", help="Cache directory")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--force", action="store_true", help="Force re-analysis (ignore cache)")

    args = parser.parse_args()

    reporter = ProgressReporter(verbose=args.verbose)
    cache_dir = Path(args.cache)

    if args.file:
        pe_path = Path(args.file)
        if not pe_path.exists():
            print(f"Error: File not found: {pe_path}")
            exit(1)

        engine = AnalysisEngine(cache_dir=cache_dir, reporter=reporter)
        analysis = engine.analyze(pe_path, args.version, force=args.force)

        reporter.header("Analysis Results")
        reporter.summary(f"{analysis.filename}", {
            "Functions": len(analysis.functions),
            "Exports": len(analysis.exports),
            "Image Base": f"0x{analysis.image_base:08x}",
            "Call Graph Edges": sum(len(v) for v in analysis.call_graph.values()),
        })

        # Show sample functions
        reporter.table(
            headers=["Address", "Size", "Prologue", "Calls", "Export"],
            rows=[
                [
                    f"0x{f.address:08x}",
                    f"{f.size_estimate}",
                    f.prologue_4,
                    f"{len(f.callees)}",
                    f.export_name or "-"
                ]
                for f in list(analysis.functions.values())[:10]
            ],
            title="Sample Functions (first 10)"
        )
    else:
        print("Usage: python -m tools.optimized_matching.analysis_engine --file <pe_file>")
        print("       python -m tools.optimized_matching.analysis_engine --file D2Client.dll --version LoD/1.13c")
