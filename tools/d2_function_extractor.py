#!/usr/bin/env python3
"""
Diablo 2 Function Extractor Tool

Extracts function start addresses from D2 binaries using PE analysis and
heuristic detection methods. Creates a function index that can be used to
track functions across different game versions.

Detection Methods:
1. PE Export Table - Functions exported by ordinal/name
2. Padding Detection - CC (INT3) or NOP+CC padding between functions
3. Prologue Detection - Common function prologues (PUSH EBP, SUB ESP, etc.)
4. Jump Table Detection - E9 (JMP) sequences at section start (older versions)

Output:
- Function addresses with sequential naming (function_0001, function_0002, ...)
- Cross-version linkage (currently by position - placeholder for signature matching)
- Data formatted for HTML viewer integration
"""

import os
import struct
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any, Set

# Import from existing tools
import sys
sys.path.insert(0, str(Path(__file__).parent))

from d2_hash_tool import (
    get_project_root,
    find_version_folders,
    CORE_VERSION_FILES,
)


# Common function prologue bytes
FUNCTION_PROLOGUES = [
    bytes([0x55]),              # PUSH EBP (most common)
    bytes([0x51]),              # PUSH ECX (fastcall)
    bytes([0x52]),              # PUSH EDX (fastcall)
    bytes([0x53]),              # PUSH EBX
    bytes([0x56]),              # PUSH ESI
    bytes([0x57]),              # PUSH EDI
    bytes([0x6A]),              # PUSH imm8
    bytes([0x68]),              # PUSH imm32
    bytes([0x81, 0xEC]),        # SUB ESP, imm32
    bytes([0x83, 0xEC]),        # SUB ESP, imm8
    bytes([0x64, 0xA1]),        # MOV EAX, FS:[...] (SEH setup)
    bytes([0x8B, 0xFF]),        # MOV EDI, EDI (hot-patchable)
    bytes([0x8B, 0x44, 0x24]),  # MOV EAX, [ESP+disp8] (stack param access)
    bytes([0x8B, 0x4C, 0x24]),  # MOV ECX, [ESP+disp8] (stack param access)
    bytes([0x8B, 0x54, 0x24]),  # MOV EDX, [ESP+disp8] (stack param access)
    bytes([0x33, 0xC0]),        # XOR EAX, EAX (return 0 stub)
    bytes([0xB8]),              # MOV EAX, imm32
    bytes([0xE9]),              # JMP rel32 (thunk functions)
    bytes([0xEB]),              # JMP rel8 (short thunk)
    bytes([0xA1]),              # MOV EAX, [imm32] (global access)
    bytes([0x8A, 0x41]),        # MOV AL, [ECX+disp8]
    bytes([0x8A, 0x51]),        # MOV DL, [ECX+disp8]
    bytes([0x8A, 0x49]),        # MOV CL, [ECX+disp8]
    bytes([0x8B, 0x41]),        # MOV EAX, [ECX+disp8]
    bytes([0x8B, 0x49]),        # MOV ECX, [ECX+disp8]
    bytes([0x8B, 0x51]),        # MOV EDX, [ECX+disp8]
    bytes([0x8B, 0x0D]),        # MOV ECX, [imm32] (global load)
    bytes([0x8B, 0x15]),        # MOV EDX, [imm32] (global load)
    bytes([0x8B, 0x35]),        # MOV ESI, [imm32] (global load)
    bytes([0x8B, 0x3D]),        # MOV EDI, [imm32] (global load)
    bytes([0x83, 0x39]),        # CMP dword ptr [ECX], imm8
    bytes([0x83, 0x3D]),        # CMP dword ptr [imm32], imm8
    bytes([0x3B]),              # CMP reg, r/m32
    bytes([0x85]),              # TEST r/m32, reg
    bytes([0x39]),              # CMP r/m32, reg
    bytes([0xC3]),              # RET (stub functions)
    bytes([0x8B, 0xC1]),        # MOV EAX, ECX
    bytes([0x8B, 0xC2]),        # MOV EAX, EDX
    bytes([0x8B, 0xC6]),        # MOV EAX, ESI
    bytes([0x8B, 0xC7]),        # MOV EAX, EDI
    bytes([0x8B, 0xD1]),        # MOV EDX, ECX
    bytes([0x8B, 0xD9]),        # MOV EBX, ECX
    bytes([0x8B, 0xF1]),        # MOV ESI, ECX
    bytes([0x8B, 0xF9]),        # MOV EDI, ECX
    bytes([0x8B, 0xE9]),        # MOV EBP, ECX
    bytes([0x89, 0x4C, 0x24]),  # MOV [ESP+disp8], ECX (store param)
    bytes([0x89, 0x54, 0x24]),  # MOV [ESP+disp8], EDX (store param)
]

# Bytes that indicate padding between functions
PADDING_BYTES = {0xCC, 0x90}  # INT3 and NOP


class PEParser:
    """Minimal PE parser for extracting section info and exports."""

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.data = None
        self.image_base = 0
        self.sections = []
        self.exports = []
        self.text_section = None

    def parse(self) -> bool:
        """Parse the PE file. Returns True on success."""
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()

            # Check DOS header
            if self.data[:2] != b'MZ':
                return False

            # Get PE header offset
            pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]

            # Check PE signature
            if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return False

            # Read COFF header
            coff_offset = pe_offset + 4
            num_sections = struct.unpack('<H', self.data[coff_offset+2:coff_offset+4])[0]
            optional_header_size = struct.unpack('<H', self.data[coff_offset+16:coff_offset+18])[0]

            # Read optional header
            opt_offset = coff_offset + 20
            magic = struct.unpack('<H', self.data[opt_offset:opt_offset+2])[0]

            if magic == 0x10b:  # PE32
                self.image_base = struct.unpack('<I', self.data[opt_offset+28:opt_offset+32])[0]
                data_dir_offset = opt_offset + 96
            elif magic == 0x20b:  # PE32+
                self.image_base = struct.unpack('<Q', self.data[opt_offset+24:opt_offset+32])[0]
                data_dir_offset = opt_offset + 112
            else:
                return False

            # Read section headers
            section_offset = opt_offset + optional_header_size
            for i in range(num_sections):
                sec_off = section_offset + i * 40
                name = self.data[sec_off:sec_off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack('<I', self.data[sec_off+8:sec_off+12])[0]
                virtual_addr = struct.unpack('<I', self.data[sec_off+12:sec_off+16])[0]
                raw_size = struct.unpack('<I', self.data[sec_off+16:sec_off+20])[0]
                raw_ptr = struct.unpack('<I', self.data[sec_off+20:sec_off+24])[0]
                characteristics = struct.unpack('<I', self.data[sec_off+36:sec_off+40])[0]

                section = {
                    'name': name,
                    'virtual_addr': virtual_addr,
                    'virtual_size': virtual_size,
                    'raw_ptr': raw_ptr,
                    'raw_size': raw_size,
                    'characteristics': characteristics,
                }
                self.sections.append(section)

                # Identify .text section
                if name == '.text' or (characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
                    if self.text_section is None:
                        self.text_section = section

            # Parse exports
            self._parse_exports(data_dir_offset)

            return True

        except Exception as e:
            return False

    def _parse_exports(self, data_dir_offset: int):
        """Parse the export table."""
        try:
            export_rva = struct.unpack('<I', self.data[data_dir_offset:data_dir_offset+4])[0]
            export_size = struct.unpack('<I', self.data[data_dir_offset+4:data_dir_offset+8])[0]

            if export_rva == 0:
                return

            export_offset = self._rva_to_offset(export_rva)
            if export_offset is None:
                return

            # Read export directory
            ordinal_base = struct.unpack('<I', self.data[export_offset+16:export_offset+20])[0]
            num_functions = struct.unpack('<I', self.data[export_offset+20:export_offset+24])[0]
            num_names = struct.unpack('<I', self.data[export_offset+24:export_offset+28])[0]
            addr_table_rva = struct.unpack('<I', self.data[export_offset+28:export_offset+32])[0]
            name_ptr_rva = struct.unpack('<I', self.data[export_offset+32:export_offset+36])[0]
            ordinal_table_rva = struct.unpack('<I', self.data[export_offset+36:export_offset+40])[0]

            # Read address table
            addr_offset = self._rva_to_offset(addr_table_rva)
            if addr_offset is None:
                return

            addresses = []
            for i in range(num_functions):
                addr = struct.unpack('<I', self.data[addr_offset + i*4:addr_offset + i*4 + 4])[0]
                addresses.append(addr)

            # Read name pointer and ordinal tables
            name_offset = self._rva_to_offset(name_ptr_rva)
            ordinal_offset = self._rva_to_offset(ordinal_table_rva)

            ordinal_to_name = {}
            if name_offset and ordinal_offset:
                for i in range(num_names):
                    name_rva = struct.unpack('<I', self.data[name_offset + i*4:name_offset + i*4 + 4])[0]
                    ordinal = struct.unpack('<H', self.data[ordinal_offset + i*2:ordinal_offset + i*2 + 2])[0]

                    name_file_offset = self._rva_to_offset(name_rva)
                    if name_file_offset:
                        name_bytes = b''
                        pos = name_file_offset
                        while pos < len(self.data) and self.data[pos] != 0:
                            name_bytes += bytes([self.data[pos]])
                            pos += 1
                        ordinal_to_name[ordinal] = name_bytes.decode('ascii', errors='replace')

            # Build exports list
            for i, addr in enumerate(addresses):
                if addr == 0:
                    continue

                # Check if forwarder
                is_forwarder = export_rva <= addr < export_rva + export_size
                if is_forwarder:
                    continue

                self.exports.append({
                    'ordinal': ordinal_base + i,
                    'name': ordinal_to_name.get(i),
                    'rva': addr,
                    'address': self.image_base + addr,
                })

        except Exception:
            pass

    def _rva_to_offset(self, rva: int) -> Optional[int]:
        """Convert RVA to file offset."""
        for sec in self.sections:
            if sec['virtual_addr'] <= rva < sec['virtual_addr'] + max(sec['virtual_size'], sec['raw_size']):
                return sec['raw_ptr'] + (rva - sec['virtual_addr'])
        return None

    def get_text_data(self) -> Optional[Tuple[bytes, int, int]]:
        """
        Get .text section data with its virtual address.

        Returns:
            Tuple of (data, virtual_address, image_base) or None
        """
        if self.text_section is None:
            return None

        start = self.text_section['raw_ptr']
        size = self.text_section['raw_size']
        va = self.image_base + self.text_section['virtual_addr']

        return (self.data[start:start+size], va, self.image_base)


def detect_jump_table(data: bytes, start_va: int) -> Tuple[List[int], List[int]]:
    """
    Detect jump table (thunk) at start of .text section.

    Older D2 versions (1.00-1.06) have E9 xx xx xx xx (JMP rel32) sequences
    at the beginning of .text for exports.

    Returns tuple of:
        - thunk_addresses: addresses of the JMP instructions (thunk entry points)
        - target_addresses: addresses the JMPs point to (real function targets)
    """
    thunk_addresses = []
    target_addresses = []
    pos = 0

    # Skip initial padding
    while pos < len(data) and data[pos] in PADDING_BYTES:
        pos += 1

    # Look for consecutive E9 (JMP rel32) instructions
    while pos + 5 <= len(data):
        if data[pos] == 0xE9:
            # JMP rel32 - 5 bytes
            thunk_addr = start_va + pos
            rel32 = struct.unpack('<i', data[pos+1:pos+5])[0]
            target = start_va + pos + 5 + rel32  # Next instruction + offset
            thunk_addresses.append(thunk_addr)
            target_addresses.append(target)
            pos += 5
        elif data[pos] in PADDING_BYTES:
            # Padding between thunks or end of thunk table
            pos += 1
        else:
            # End of jump table
            break

    return thunk_addresses, target_addresses


def find_function_starts(data: bytes, start_va: int, image_base: int) -> List[Dict[str, Any]]:
    """
    Find function start addresses using heuristic detection.

    Detection methods:
    1. After padding sequences (CC, NOP)
    2. After RET instructions (C3, C2 xx xx)
    3. Function prologues after alignment boundaries

    Args:
        data: .text section bytes
        start_va: Virtual address of section start
        image_base: PE image base address

    Returns:
        List of detected function entries
    """
    functions = []
    seen_addresses = set()

    pos = 0
    in_padding = False
    padding_start = 0

    while pos < len(data):
        byte = data[pos]

        # Track padding regions
        if byte in PADDING_BYTES:
            if not in_padding:
                in_padding = True
                padding_start = pos
            pos += 1
            continue

        # End of padding - check if this looks like a function start
        if in_padding:
            in_padding = False
            padding_len = pos - padding_start

            # Require at least 1 byte of padding to reduce false positives
            if padding_len >= 1:
                # Check for function prologue
                if is_function_prologue(data, pos):
                    addr = start_va + pos
                    if addr not in seen_addresses:
                        seen_addresses.add(addr)
                        functions.append({
                            'address': addr,
                            'rva': addr - image_base,
                            'detection': 'padding',
                            'padding_len': padding_len,
                        })

        # Also check after RET instructions
        if byte == 0xC3:  # RET
            # Next byte might be padding or next function
            next_pos = pos + 1
            # Skip any padding
            while next_pos < len(data) and data[next_pos] in PADDING_BYTES:
                next_pos += 1
            # Check for function prologue
            if next_pos < len(data) and is_function_prologue(data, next_pos):
                addr = start_va + next_pos
                if addr not in seen_addresses:
                    seen_addresses.add(addr)
                    functions.append({
                        'address': addr,
                        'rva': addr - image_base,
                        'detection': 'after_ret',
                    })

        elif byte == 0xC2:  # RET imm16
            if pos + 2 < len(data):
                next_pos = pos + 3
                # Skip padding
                while next_pos < len(data) and data[next_pos] in PADDING_BYTES:
                    next_pos += 1
                if next_pos < len(data) and is_function_prologue(data, next_pos):
                    addr = start_va + next_pos
                    if addr not in seen_addresses:
                        seen_addresses.add(addr)
                        functions.append({
                            'address': addr,
                            'rva': addr - image_base,
                            'detection': 'after_ret',
                        })

        pos += 1

    return functions


def is_function_prologue(data: bytes, pos: int) -> bool:
    """Check if position looks like a function prologue."""
    if pos >= len(data):
        return False

    for prologue in FUNCTION_PROLOGUES:
        if pos + len(prologue) <= len(data):
            if data[pos:pos+len(prologue)] == prologue:
                return True

    return False


def extract_functions_from_pe(filepath: Path) -> Optional[Dict[str, Any]]:
    """
    Extract function addresses from a PE file.

    Args:
        filepath: Path to PE file

    Returns:
        Dictionary with file info and function list, or None on error
    """
    pe = PEParser(filepath)
    if not pe.parse():
        return None

    result = {
        'filepath': str(filepath),
        'filename': filepath.name,
        'image_base': pe.image_base,
        'image_base_hex': f"0x{pe.image_base:08X}",
        'text_section': None,
        'exports': [],
        'detected_functions': [],
        'all_functions': [],
    }

    # Get exported functions
    for exp in pe.exports:
        result['exports'].append({
            'ordinal': exp['ordinal'],
            'name': exp['name'],
            'address': exp['address'],
            'address_hex': f"0x{exp['address']:08X}",
            'rva': exp['rva'],
        })

    # Get .text section info
    text_data = pe.get_text_data()
    if text_data:
        data, va, image_base = text_data
        result['text_section'] = {
            'virtual_address': va,
            'virtual_address_hex': f"0x{va:08X}",
            'size': len(data),
        }

        # Detect jump table at start (returns thunk addresses and their targets)
        thunk_addresses, jump_targets = detect_jump_table(data, va)

        # Find function starts using heuristics
        detected = find_function_starts(data, va, image_base)
        result['detected_functions'] = detected

        # Add thunk addresses as functions (they are valid entry points)
        thunk_addr_set = set(thunk_addresses)
        detected_addr_set = {f['address'] for f in detected}
        for thunk_addr in thunk_addresses:
            if thunk_addr not in detected_addr_set:
                detected.append({
                    'address': thunk_addr,
                    'rva': thunk_addr - image_base,
                    'detection': 'thunk',
                })

        # Also check for first real function after jump table
        if thunk_addresses:
            # Find where the jump table ends
            last_thunk_pos = 0
            pos = 0
            # Skip initial padding
            while pos < len(data) and data[pos] in PADDING_BYTES:
                pos += 1
            while pos + 5 <= len(data) and data[pos] == 0xE9:
                last_thunk_pos = pos + 5
                pos += 5

            # Skip padding after jump table
            while last_thunk_pos < len(data) and data[last_thunk_pos] in PADDING_BYTES:
                last_thunk_pos += 1

            if last_thunk_pos < len(data):
                first_real_addr = va + last_thunk_pos
                if first_real_addr not in {f['address'] for f in detected}:
                    detected.insert(0, {
                        'address': first_real_addr,
                        'rva': first_real_addr - image_base,
                        'detection': 'after_jump_table',
                    })

    # Combine exports and detected functions
    all_addrs = set()
    all_functions = []

    # Add exports first (they have names/ordinals)
    for exp in result['exports']:
        addr = exp['address']
        if addr not in all_addrs:
            all_addrs.add(addr)
            all_functions.append({
                'address': addr,
                'address_hex': f"0x{addr:08X}",
                'rva': exp['rva'],
                'source': 'export',
                'ordinal': exp['ordinal'],
                'name': exp['name'],
            })

    # Add detected functions
    for func in result['detected_functions']:
        addr = func['address']
        if addr not in all_addrs:
            all_addrs.add(addr)
            all_functions.append({
                'address': addr,
                'address_hex': f"0x{func['address']:08X}",
                'rva': func['rva'],
                'source': 'detected',
                'detection_method': func.get('detection', 'unknown'),
            })

    # Sort by address
    all_functions.sort(key=lambda x: x['address'])
    result['all_functions'] = all_functions
    result['function_count'] = len(all_functions)

    return result


def extract_functions_from_folder(folder: Path, folder_info: Dict) -> Dict[str, Any]:
    """
    Extract functions from all PE files in a version folder.

    Args:
        folder: Path to version folder
        folder_info: Folder metadata

    Returns:
        Dictionary with version info and per-file function data
    """
    result = {
        'folder_path': str(folder),
        'folder_name': folder_info.get('folder_name', folder.name),
        'game_type': folder_info.get('game_type', 'Unknown'),
        'version': folder_info.get('version', folder.name),
        'is_lod': folder_info.get('is_lod'),
        'is_nocd': folder_info.get('is_nocd', False),
        'files': {},
        'total_functions': 0,
    }

    # Find PE files
    for item in folder.iterdir():
        if not item.is_file():
            continue
        if item.suffix.lower() not in ['.dll', '.exe']:
            continue
        # Skip non-core files (case-insensitive comparison)
        if not any(item.name.lower() == cf.lower() for cf in CORE_VERSION_FILES):
            continue

        pe_result = extract_functions_from_pe(item)
        if pe_result:
            result['files'][item.name] = pe_result
            result['total_functions'] += pe_result['function_count']

    return result


def get_canonical_key(folder_info: Dict, folder_name: str) -> str:
    """Get canonical key for grouping versions."""
    game_type = folder_info.get('game_type', 'Unknown')
    version = folder_name.split('/')[-1] if '/' in folder_name else folder_name
    return f"{game_type}/{version}"


def build_function_index(all_extractions: List[Dict]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Build a function index with sequential naming and cross-version linkage.

    Uses optimized format:
    - Global version list (indexed by position)
    - Per-file: addresses stored as sparse arrays indexed by version number

    For now, linkage is by position (first function in version A links to
    first function in version B). This will be replaced with signature
    matching in a future update.

    Args:
        all_extractions: List of folder extraction results

    Returns:
        Tuple of (index_metadata, per_file_data)
        - index_metadata: versions list and file summary
        - per_file_data: dict of filename -> optimized function data
    """
    # Group by canonical key
    grouped = defaultdict(list)
    for extraction in all_extractions:
        key = get_canonical_key(extraction, extraction['folder_name'])
        grouped[key].append(extraction)

    # Sort version keys
    sorted_keys = sorted(grouped.keys(), key=lambda k: (
        0 if k.startswith('Classic/') else 1,
        k.split('/')[-1]
    ))

    # Create version index map
    version_to_idx = {v: i for i, v in enumerate(sorted_keys)}

    # Get list of all files across versions
    all_files = set()
    for key in sorted_keys:
        for extraction in grouped[key]:
            all_files.update(extraction['files'].keys())

    # Build per-file data with optimized format
    per_file_data = {}
    file_summaries = {}

    for filename in sorted(all_files):
        # Track functions across versions by position
        max_functions = 0
        version_functions = {}  # version_key -> list of addresses
        file_versions = []  # versions that have this file

        for key in sorted_keys:
            for extraction in grouped[key]:
                if filename not in extraction['files']:
                    continue

                file_data = extraction['files'][filename]
                addrs = [f['address'] for f in file_data['all_functions']]

                if key not in version_functions:
                    version_functions[key] = []
                version_functions[key].extend(addrs)

                if key not in file_versions:
                    file_versions.append(key)

                max_functions = max(max_functions, len(addrs))

        # Build functions dict in EXPORTS_DATA-compatible format
        # Format: {"1": {"ordinal": 1, "name": "function_0001", "addresses": {"version": "addr"}}, ...}
        functions_dict = {}

        for i in range(max_functions):
            func_name = f"function_{i+1:04d}"
            ordinal = i + 1

            # Build addresses dict {version_string: hex_addr}
            addresses = {}
            for key in file_versions:
                if key in version_functions:
                    addrs = version_functions[key]
                    if i < len(addrs):
                        addresses[key] = f"{addrs[i]:08X}"

            functions_dict[str(ordinal)] = {
                'ordinal': ordinal,
                'name': func_name,
                'addresses': addresses
            }

        # Store per-file data in EXPORTS_DATA-compatible format
        per_file_data[filename] = {
            'versions': file_versions,
            'functions': functions_dict
        }

        # Summary for index
        file_summaries[filename] = {
            'function_count': max_functions,
            'version_count': len(file_versions),
        }

    # Index metadata (small file)
    index_metadata = {
        'generated': datetime.now().isoformat(),
        'version_count': len(sorted_keys),
        'versions': sorted_keys,
        'files': file_summaries,
    }

    return index_metadata, per_file_data


def generate_function_data(base_path: Path = None, output_dir: Path = None) -> Dict[str, Path]:
    """
    Generate function extraction data for all D2 versions.

    Output structure:
    - reports/functions/_index.js  (small - versions list + file summaries)
    - reports/functions/D2Client.dll.js  (per-file function data)
    - reports/functions/D2Common.dll.js
    - etc.

    Args:
        base_path: Project root path
        output_dir: Output directory for data files

    Returns:
        Dictionary of output file paths
    """
    if base_path is None:
        base_path = get_project_root()

    if output_dir is None:
        output_dir = base_path / 'reports'

    output_dir = Path(output_dir)
    functions_dir = output_dir / 'functions'
    functions_dir.mkdir(parents=True, exist_ok=True)

    print("Extracting functions from D2 binaries...")
    print(f"Project root: {base_path}")

    # Find all version folders
    version_folders = find_version_folders(base_path)
    print(f"Found {len(version_folders)} version folders")

    all_extractions = []
    total_functions = 0

    for folder, folder_info in version_folders:
        print(f"  Processing: {folder_info['folder_name']}...")
        extraction = extract_functions_from_folder(folder, folder_info)
        all_extractions.append(extraction)
        total_functions += extraction['total_functions']

        for filename, file_data in extraction['files'].items():
            print(f"    {filename}: {file_data['function_count']} functions")

    print(f"\nTotal functions detected: {total_functions}")

    # Build function index (returns index + per-file data)
    print("\nBuilding function index...")
    index_metadata, per_file_data = build_function_index(all_extractions)

    import json

    output_files = {}
    total_size = 0

    # Write index file
    index_content = f"""// Auto-generated by d2_function_extractor.py
// Generated: {datetime.now().isoformat()}
// Function index for D2 Version Archive
// Load per-file data from functions/<filename>.js

var FUNCTION_INDEX = {json.dumps(index_metadata, separators=(',', ':'))};
"""
    index_path = functions_dir / '_index.js'
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write(index_content)
    index_size = index_path.stat().st_size
    total_size += index_size
    output_files['_index.js'] = index_path
    print(f"\nGenerated {index_path} ({index_size:,} bytes)")

    # Write per-file data
    print("\nGenerating per-file function data:")
    for filename, file_data in per_file_data.items():
        # Create safe filename (replace special chars)
        safe_name = filename.replace('.', '_').replace(' ', '_')

        file_content = f"""// Auto-generated by d2_function_extractor.py
// Function data for {filename}
// Format: Same as EXPORTS_DATA for viewer compatibility
// {{versions: [...], functions: {{"1": {{ordinal, name, addresses}}, ...}}}}

var FUNCTIONS_{safe_name.upper()} = {json.dumps(file_data, separators=(',', ':'))};
"""
        file_path = functions_dir / f'{filename}.js'
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(file_content)

        file_size = file_path.stat().st_size
        total_size += file_size
        output_files[filename] = file_path
        func_count = len(file_data['functions'])
        print(f"  {filename}.js: {file_size:,} bytes ({func_count} functions)")

    print(f"\nTotal output: {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)")
    print(f"  Index: {index_size:,} bytes")
    print(f"  Data files: {len(per_file_data)} files")

    # Summary
    print(f"\nSummary:")
    print(f"  Versions: {index_metadata['version_count']}")
    print(f"  Files indexed: {len(index_metadata['files'])}")
    for filename, summary in index_metadata['files'].items():
        print(f"    {filename}: {summary['function_count']} functions across {summary['version_count']} versions")

    return output_files


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract function addresses from Diablo 2 binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python d2_function_extractor.py                    # Extract from project root
  python d2_function_extractor.py -p /path/to/proj   # Specify project root
  python d2_function_extractor.py -f D2Client.dll    # Extract single file
        """
    )

    parser.add_argument(
        "-p", "--path",
        type=str,
        default=None,
        help="Path to D2VersionChanger project root"
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output directory for data files"
    )

    parser.add_argument(
        "-f", "--file",
        type=str,
        default=None,
        help="Extract functions from a single PE file"
    )

    args = parser.parse_args()

    # Single file mode
    if args.file:
        filepath = Path(args.file)
        if not filepath.exists():
            print(f"Error: File not found: {filepath}")
            return 1

        result = extract_functions_from_pe(filepath)
        if result is None:
            print(f"Error: Could not parse PE file: {filepath}")
            return 1

        print(f"File: {result['filename']}")
        print(f"Image Base: {result['image_base_hex']}")
        print(f"Functions: {result['function_count']}")
        print(f"  Exports: {len(result['exports'])}")
        print(f"  Detected: {len(result['detected_functions'])}")

        if result['text_section']:
            print(f"  .text: {result['text_section']['virtual_address_hex']} ({result['text_section']['size']} bytes)")

        print("\nFirst 20 functions:")
        for func in result['all_functions'][:20]:
            src = func.get('source', 'unknown')
            if src == 'export':
                name = func.get('name', f"Ordinal_{func.get('ordinal', '?')}")
                print(f"  {func['address_hex']} - {name} (export)")
            else:
                method = func.get('detection_method', 'unknown')
                print(f"  {func['address_hex']} - (detected via {method})")

        if result['function_count'] > 20:
            print(f"  ... and {result['function_count'] - 20} more")

        return 0

    # Full extraction mode
    base_path = Path(args.path).resolve() if args.path else None
    output_path = Path(args.output).resolve() if args.output else None

    try:
        generate_function_data(base_path, output_path)
        return 0
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
