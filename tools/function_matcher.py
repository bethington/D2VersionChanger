#!/usr/bin/env python3
"""
function_matcher.py - Cross-version function matching using pefile + capstone

This tool demonstrates multiple approaches for matching functions across
different versions of Diablo II binaries.

Matching Strategies:
1. Normalized opcode hash (ignores absolute addresses)
2. Prologue signature matching
3. String reference anchoring
4. Call graph similarity

Requirements:
    pip install pefile capstone

Usage:
    python function_matcher.py --dll D2Common.dll --versions 1.07,1.10,1.13d
"""

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    print("Warning: pefile not installed. Run: pip install pefile")

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("Warning: capstone not installed. Run: pip install capstone")


@dataclass
class FunctionSignature:
    """Represents a function's identifying characteristics."""
    address: int
    name: str
    size: int
    prologue_bytes: bytes
    normalized_hash: str
    instruction_count: int
    call_targets: List[int] = field(default_factory=list)
    string_refs: List[str] = field(default_factory=list)


@dataclass
class MatchResult:
    """Result of matching a function across versions."""
    function_name: str
    matches: Dict[str, Tuple[int, float]]  # version -> (address, confidence)
    match_type: str  # "exact_hash", "prologue", "call_graph", "string_ref"


class FunctionMatcher:
    """Cross-version function matcher using multiple strategies."""

    # Common x86 function prologues
    PROLOGUE_PATTERNS = [
        b'\x55\x8b\xec',           # push ebp; mov ebp, esp
        b'\x55\x89\xe5',           # push ebp; mov ebp, esp (alternate)
        b'\x83\xec',               # sub esp, imm8
        b'\x81\xec',               # sub esp, imm32
        b'\x53\x56\x57',           # push ebx; push esi; push edi
        b'\x6a',                   # push imm8
        b'\x68',                   # push imm32
    ]

    def __init__(self, base_path: str):
        """Initialize with path to VersionChanger folder."""
        self.base_path = Path(base_path)
        self.function_db: Dict[str, Dict[str, FunctionSignature]] = {}

        if HAS_CAPSTONE:
            self.disasm = Cs(CS_ARCH_X86, CS_MODE_32)
            self.disasm.detail = True
        else:
            self.disasm = None

    def load_binary(self, dll_name: str, version: str, game_type: str = "LoD") -> Optional[pefile.PE]:
        """Load a PE file for analysis."""
        if not HAS_PEFILE:
            return None

        dll_path = self.base_path / "VersionChanger" / game_type / version / dll_name
        if not dll_path.exists():
            print(f"File not found: {dll_path}")
            return None

        try:
            return pefile.PE(str(dll_path))
        except Exception as e:
            print(f"Error loading {dll_path}: {e}")
            return None

    def find_functions_by_prologue(self, pe: pefile.PE) -> List[int]:
        """Find function entry points by prologue pattern scanning."""
        functions = []

        for section in pe.sections:
            if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                data = section.get_data()
                base_va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

                for i in range(len(data) - 4):
                    for pattern in self.PROLOGUE_PATTERNS:
                        if data[i:i+len(pattern)] == pattern:
                            # Verify alignment (most functions are 16-byte aligned)
                            addr = base_va + i
                            if addr % 4 == 0:  # At least DWORD aligned
                                functions.append(addr)
                            break

        return sorted(set(functions))

    def extract_function_bytes(self, pe: pefile.PE, va: int, max_size: int = 4096) -> bytes:
        """Extract bytes at a virtual address."""
        rva = va - pe.OPTIONAL_HEADER.ImageBase
        try:
            return pe.get_data(rva, max_size)
        except:
            return b''

    def compute_normalized_hash(self, data: bytes, base_addr: int) -> Tuple[str, int]:
        """
        Compute a normalized hash that ignores absolute addresses.

        This is the key innovation for cross-version matching:
        - Replace absolute call/jump targets with placeholders
        - Replace absolute data references with placeholders
        - Keep instruction opcodes and relative offsets
        """
        if not self.disasm:
            return hashlib.sha256(data[:64]).hexdigest(), 0

        normalized = []
        instruction_count = 0

        try:
            for insn in self.disasm.disasm(data, base_addr):
                instruction_count += 1

                # Stop at return or invalid instruction
                if insn.mnemonic in ('ret', 'retn', 'int3'):
                    normalized.append(insn.mnemonic)
                    break

                # Normalize instruction
                norm_insn = insn.mnemonic

                # Handle operands
                for op in insn.operands:
                    if op.type == CS_OP_IMM:
                        imm = op.imm
                        # Small immediates are likely constants, keep them
                        if abs(imm) < 0x10000:
                            norm_insn += f"_IMM_{imm}"
                        else:
                            # Large immediates are likely addresses
                            norm_insn += "_ADDR"
                    elif op.type == CS_OP_MEM:
                        # Memory references - normalize displacement
                        if op.mem.disp != 0 and abs(op.mem.disp) > 0x10000:
                            norm_insn += "_MEM_ADDR"
                        else:
                            norm_insn += f"_MEM_{op.mem.disp}"

                normalized.append(norm_insn)

                # Limit analysis
                if instruction_count > 500:
                    break

        except Exception as e:
            pass

        # Create hash from normalized instruction sequence
        norm_str = "|".join(normalized)
        return hashlib.sha256(norm_str.encode()).hexdigest(), instruction_count

    def extract_string_refs(self, pe: pefile.PE, va: int, size: int = 512) -> List[str]:
        """Extract string references from a function."""
        strings = []
        data = self.extract_function_bytes(pe, va, size)

        if not self.disasm:
            return strings

        try:
            for insn in self.disasm.disasm(data, va):
                for op in insn.operands:
                    if op.type == CS_OP_IMM:
                        # Check if this could be a string pointer
                        ref_addr = op.imm
                        try:
                            rva = ref_addr - pe.OPTIONAL_HEADER.ImageBase
                            if 0 < rva < pe.OPTIONAL_HEADER.SizeOfImage:
                                str_data = pe.get_data(rva, 256)
                                # Check for printable string
                                if str_data and str_data[0] > 0x20 and str_data[0] < 0x7f:
                                    null_idx = str_data.find(b'\x00')
                                    if 4 <= null_idx <= 200:
                                        s = str_data[:null_idx].decode('utf-8', errors='ignore')
                                        if s.isprintable() and len(s) >= 4:
                                            strings.append(s)
                        except:
                            pass
        except:
            pass

        return strings

    def extract_call_targets(self, pe: pefile.PE, va: int, size: int = 512) -> List[int]:
        """Extract call targets from a function."""
        targets = []
        data = self.extract_function_bytes(pe, va, size)

        if not self.disasm:
            return targets

        try:
            for insn in self.disasm.disasm(data, va):
                if insn.mnemonic == 'call':
                    for op in insn.operands:
                        if op.type == CS_OP_IMM:
                            targets.append(op.imm)
        except:
            pass

        return targets

    def analyze_function(self, pe: pefile.PE, va: int, name: str = "") -> FunctionSignature:
        """Analyze a single function and create its signature."""
        prologue = self.extract_function_bytes(pe, va, 32)
        full_bytes = self.extract_function_bytes(pe, va, 2048)

        norm_hash, insn_count = self.compute_normalized_hash(full_bytes, va)
        string_refs = self.extract_string_refs(pe, va)
        call_targets = self.extract_call_targets(pe, va)

        # Estimate function size
        size = min(2048, len(full_bytes))

        return FunctionSignature(
            address=va,
            name=name or f"FUN_{va:08x}",
            size=size,
            prologue_bytes=prologue,
            normalized_hash=norm_hash,
            instruction_count=insn_count,
            call_targets=call_targets,
            string_refs=string_refs
        )

    def match_by_hash(self, sig: FunctionSignature,
                       candidates: List[FunctionSignature]) -> Optional[Tuple[FunctionSignature, float]]:
        """Match function by normalized hash."""
        for cand in candidates:
            if cand.normalized_hash == sig.normalized_hash:
                return (cand, 1.0)  # Exact match
        return None

    def match_by_prologue(self, sig: FunctionSignature,
                          candidates: List[FunctionSignature],
                          min_bytes: int = 16) -> Optional[Tuple[FunctionSignature, float]]:
        """Match function by prologue bytes."""
        best_match = None
        best_score = 0.0

        for cand in candidates:
            # Compare prologue bytes
            match_len = 0
            for i in range(min(len(sig.prologue_bytes), len(cand.prologue_bytes))):
                if sig.prologue_bytes[i] == cand.prologue_bytes[i]:
                    match_len += 1
                else:
                    break

            if match_len >= min_bytes:
                score = match_len / 32.0
                if score > best_score:
                    best_score = score
                    best_match = cand

        if best_match and best_score >= 0.5:
            return (best_match, best_score)
        return None

    def match_by_strings(self, sig: FunctionSignature,
                         candidates: List[FunctionSignature]) -> Optional[Tuple[FunctionSignature, float]]:
        """Match function by unique string references."""
        if not sig.string_refs:
            return None

        sig_strings = set(sig.string_refs)

        best_match = None
        best_score = 0.0

        for cand in candidates:
            if not cand.string_refs:
                continue

            cand_strings = set(cand.string_refs)
            intersection = sig_strings & cand_strings

            if intersection:
                # Jaccard similarity
                union = sig_strings | cand_strings
                score = len(intersection) / len(union)

                if score > best_score:
                    best_score = score
                    best_match = cand

        if best_match and best_score >= 0.5:
            return (best_match, best_score)
        return None

    def find_matches(self, source_sig: FunctionSignature,
                     target_sigs: List[FunctionSignature]) -> List[Tuple[str, FunctionSignature, float]]:
        """
        Find matches for a function using multiple strategies.
        Returns list of (match_type, matched_sig, confidence).
        """
        matches = []

        # Strategy 1: Exact hash match (highest confidence)
        result = self.match_by_hash(source_sig, target_sigs)
        if result:
            matches.append(("exact_hash", result[0], result[1]))
            return matches  # Exact match found, no need for other strategies

        # Strategy 2: String reference match
        result = self.match_by_strings(source_sig, target_sigs)
        if result:
            matches.append(("string_ref", result[0], result[1]))

        # Strategy 3: Prologue match
        result = self.match_by_prologue(source_sig, target_sigs)
        if result:
            matches.append(("prologue", result[0], result[1]))

        return matches


def demo_analysis():
    """Demonstrate the function matcher on D2 binaries."""
    print("=" * 60)
    print("D2 Function Matcher - Demo Analysis")
    print("=" * 60)

    if not HAS_PEFILE or not HAS_CAPSTONE:
        print("\nError: Required libraries not installed.")
        print("Run: pip install pefile capstone")
        return

    matcher = FunctionMatcher("F:/D2VersionChanger")

    # Case study functions from D2Moo (1.10 addresses)
    case_study = {
        "COLLISION_TrySetUnitCollisionMask": 0x6FD44FF0,
        "COLLISION_GetFreeCoordinatesImpl": 0x6FD45A00,
        "COLLISION_GetFreeCoordinatesEx": 0x6FD462B0,
        "DRLG_IsTownLevel": 0x6FD751C0,
        "MONSTERS_ApplyClassicScaling": 0x6FDA6790,
    }

    versions = ["1.07", "1.10", "1.13d"]

    print("\n[1] Loading binaries...")
    pe_files = {}
    for ver in versions:
        pe = matcher.load_binary("D2Common.dll", ver)
        if pe:
            pe_files[ver] = pe
            print(f"  Loaded 1.{ver}: ImageBase=0x{pe.OPTIONAL_HEADER.ImageBase:08X}")

    if "1.10" not in pe_files:
        print("Error: Could not load 1.10 binary")
        return

    print("\n[2] Analyzing case study functions in 1.10...")
    source_sigs = {}
    for name, addr in case_study.items():
        sig = matcher.analyze_function(pe_files["1.10"], addr, name)
        source_sigs[name] = sig
        print(f"  {name}:")
        print(f"    Address: 0x{addr:08X}")
        print(f"    Hash: {sig.normalized_hash[:16]}...")
        print(f"    Instructions: {sig.instruction_count}")
        print(f"    Strings: {sig.string_refs[:2] if sig.string_refs else 'None'}")

    print("\n[3] Scanning for functions in other versions...")
    for ver in ["1.07", "1.13d"]:
        if ver not in pe_files:
            continue

        print(f"\n  Version {ver}:")
        pe = pe_files[ver]

        # Find candidate functions
        candidates = []
        func_addrs = matcher.find_functions_by_prologue(pe)
        print(f"    Found {len(func_addrs)} candidate functions by prologue")

        # Analyze a subset for demo
        for addr in func_addrs[:500]:
            sig = matcher.analyze_function(pe, addr)
            candidates.append(sig)

        # Try to match each case study function
        for name, source_sig in source_sigs.items():
            matches = matcher.find_matches(source_sig, candidates)

            if matches:
                best = matches[0]
                print(f"    {name}:")
                print(f"      -> 0x{best[1].address:08X} ({best[0]}, conf={best[2]:.2f})")
            else:
                print(f"    {name}: No match found")

    print("\n" + "=" * 60)
    print("Analysis complete!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="D2 Function Matcher")
    parser.add_argument("--demo", action="store_true", help="Run demo analysis")
    args = parser.parse_args()

    if args.demo:
        demo_analysis()
    else:
        print("Usage: python function_matcher.py --demo")
        print("\nThis tool demonstrates cross-version function matching using:")
        print("  1. Normalized opcode hashing")
        print("  2. Prologue signature matching")
        print("  3. String reference anchoring")
        print("\nRequirements: pip install pefile capstone")
