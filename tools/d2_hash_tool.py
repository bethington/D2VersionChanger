#!/usr/bin/env python3
"""
Diablo 2 Installation Hash & Verification Tool

This tool works with the D2VersionChanger project structure:
- VersionChanger/Classic/<version>/  - Classic patch files (Patch_D2.mpq)
- VersionChanger/LoD/<version>/      - LoD patch files (Patch_D2.mpq)
- VersionChanger/NoCD/{Classic,LoD}/<version>/  - NoCD Game.exe files
- reports/data/                      - JSON data files

Functions:
1. Generates SHA256/MD5 hashes for all files in each version folder
2. Compares files across different version folders to find changes
3. Verifies version integrity based on known file signatures
4. Generates detailed reports in JSON format

Author: Auto-generated
Date: 2024
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import re
import struct
from typing import Dict, List, Tuple, Optional, Any


def get_project_root():
    """Get the root directory of the D2VersionChanger project."""
    return Path(__file__).parent.parent.resolve()


# Known file sizes for Diablo 2 versions (Game.exe sizes in bytes)
# These reference values were gathered from actual installations
# Format: (game_type, version) -> Game.exe size in bytes
# game_type: 'C' for Classic, 'L' for LoD
KNOWN_GAME_EXE_SIZES = {
    # Classic versions
    ("C", "1.00a"): 45056,
    ("C", "1.01a"): 45056,
    ("C", "1.02a"): 45056,
    ("C", "1.03a"): 45056,
    ("C", "1.04b"): 86016,
    ("C", "1.04c"): 86016,
    ("C", "1.05a"): 86016,
    ("C", "1.05b"): 86016,
    ("C", "1.06a"): 86016,
    ("C", "1.06b"): 86016,
    ("C", "1.08a"): 86016,
    ("C", "1.09a"): 86016,
    ("C", "1.09b"): 86016,
    ("C", "1.09d"): 86016,
    ("C", "1.10a"): 86016,
    ("C", "1.11a"): 57344,
    ("C", "1.11b"): 57344,
    ("C", "1.12a"): 57344,
    ("C", "1.13c"): 57344,
    ("C", "1.13d"): 61440,
    ("C", "1.14a"): 3586024,
    ("C", "1.14b"): 3586024,
    ("C", "1.14c"): 3581928,
    ("C", "1.14d"): 3614696,
    # LoD versions
    ("L", "1.07a"): 90112,
    ("L", "1.08a"): 90112,
    ("L", "1.09a"): 90112,
    ("L", "1.09b"): 90112,
    ("L", "1.09d"): 90112,
    ("L", "1.10a"): 90112,
    ("L", "1.11a"): 61440,
    ("L", "1.11b"): 61440,
    ("L", "1.12a"): 61440,
    ("L", "1.13c"): 61440,
    ("L", "1.13d"): 65536,
    ("L", "1.14a"): 3590120,
    ("L", "1.14b"): 3590120,
    ("L", "1.14c"): 3586024,
    ("L", "1.14d"): 3618792,
}

# Core game files that should be consistent within a version
CORE_VERSION_FILES = [
    "Game.exe",
    "Diablo II.exe",
    "D2Client.dll",
    "D2Common.dll",
    "D2Game.dll",
    "D2gfx.dll",
    "D2Lang.dll",
    "D2Launch.dll",
    "D2Net.dll",
    "D2sound.dll",
    "D2Win.dll",
    "Fog.dll",
    "Storm.dll",
    "D2CMP.dll",
    "D2Multi.dll",
    "D2MCPClient.dll",
    "Bnclient.dll",
    "ijl11.dll",
    "binkw32.dll",
    "SmackW32.dll",
]

# MPQ files (data files)
DATA_FILES = [
    "d2char.mpq",
    "d2data.mpq",
    "d2sfx.mpq",
    "d2speech.mpq",
    "d2video.mpq",
    "d2music.mpq",
    "d2exp.mpq",
    "D2xMusic.mpq",
    "d2xtalk.mpq",
    "D2xVideo.mpq",
    "Patch_D2.mpq",
]

# Game.exe SHA256 hash to community version lookup
# These map the exact Game.exe hash to the version the D2 community recognizes
GAME_EXE_VERSION_LOOKUP = {
    # Classic Game.exe versions
    "a561dfdbc8ff660e83fd1c74a651e5081731faed4ad324799756cf04312b35b9": "1.00a",
    "cc9e64d0cac0e667b7f361b62080d7f2ae33c1360e73256aa123fffb4e7a3da0": "1.01a",
    "8555607bfb9a2ed5a0772499b27326db12ee8125254eff6da826df2aa07a248c": "1.02a",
    "7f5f17f15dd99baccb90d5e51ef9dd4745a2682a0a16a509007df0167fcb2bb4": "1.03a",
    "98157b1eaafc10433d3cf7b47e5cac5b8755709c18a8a8f89fdbc3c57a31216c": "1.04b",
    "51550c0868c7c487b40c833bd3548371819d2e370147aaad639fa10dcadfd4a1": "1.04c",
    "ada3888c879a2ee4baff8c26857f805bdfdbbabcf31e33d0fcf283f14eac0489": "1.05a",
    "5d1453b20da87a46ab65a6482b6081255e80c010adc926c44b730b641790e704": "1.05b",
    "9bc2fceff33a40a459e0e95cc284e812342f2701a6051fff93f8256a96a03307": "1.06a",
    "b1984c34b4d9d55e19a9f92cfea5ec85e54d3f310d2c620ad7ec4bb8b302b4b6": "1.06b",
    "4be57fb2060a7d515de3f0a26dcf58f23eb153fa23fb2135b6174865b281318b": "1.08a",
    "ddd3dc2557a5cfcbb58d7aea958584030cb4716c8d8a8d2f8cfea4a0adcf5429": "1.09a",
    "256f6aa82f02e155373d885337a3a5060ac21e7e3b8bf49a1d7be9299fbdf2ed": "1.09b",
    "02db9652b98a280067a5aff445b5acc835e07b54019a5669dc01ca6189b6c658": "1.09d",
    "5a17de09dffb03c6b72f2bd16f26e45e73f433232026ba898ab7b7c02722c627": "1.10a",
    "ec4e10073875d5f0214576b4afbdf9d5deb497cbded9dced20196b8cd1d299c2": "1.11a",
    "0ac37d81aebb1468bf42a2c16b0b8e15b10ec60db146fa43b833644c6937921e": "1.11b",
    "3ca642e872dbd9abacb166dca0cbf41c419ed1b1ba48339953117a01d05a270c": "1.12a",
    "4d863b672f3e16fce6dd4e5ee795f4429195db2635c4eacbef37f435b69feb5d": "1.13c",
    "9622ca993de5f5738ad437cc9c4b75ad35e439ec9aaff6a3501870861a5a0ef1": "1.13d",
    "306812bf7f37e21fecb77d11e23f28005c97eeb2c7dd666b1352c2bb1de87cb5": "1.14a",
    "28fac184096fc36a37c5126590e65e71a3c9569c18b9000357fd7613a56b8c3c": "1.14b",
    "6c7b8dfbb4092ec38066f2660d7e065e44e94d80258265a46201e1af073a3173": "1.14c",
    "cbe413edb4af9495db06d489715922d4dcdd77a91701cef089a6b2979d453bbd": "1.14d",
    # LoD Game.exe versions
    "8b07fc9963acfee35c09b8688deab4598543d975bbd994872a6eca6c9160344a": "1.07a",
    "118e0d420e31a5f9bc3dfbf1387d62b3e1c9522a3087ff1702d6f5c2519000b9": "1.08a",
    "a14b150fad042aef91ee866e9991edd1f5d7dae35213c90a236a950b8f95ce9e": "1.09a",
    "2b7391519396228f4f7f902426c67157f35fbeef95c9e1f64014d8f70554e182": "1.09b",
    "1ea46ed66d3b9c12965edf13b6d8141cf570249d53991ecadab4892ed8f99ea9": "1.10a",
    "01437ce204849ad7275d15993fcdc1b16bb0ba299b458579611670ffebc0e8dc": "1.11a",
    "376129a5a15ad7017fcc3f0473e75e43f4b368d50089a487b02d6a9e49dad105": "1.11b",
    "9cb3d8dd0ffac92c164ba2a29f358d17fb372380abdcc15f871831f262de09fa": "1.12a",
    "74fe9c092a521f7710392548c82f81544e531107db2358617e83818874db40a2": "1.13c",
    "6ca6f345c11f47eaf6dc629457ec2ea0020fa7fba4aa9bb2248f911b66870ddd": "1.13d",
    "c99e3067e6a7eef7800680ac6bed2beb1a50cc285933166bcd7fbe4f394446a6": "1.14a",
    "0680e266b1fbbc8e7815b0a7c4f67267de38fd9063fceeae2da0306389a52178": "1.14b",
    "ad13296ae56b921987f1088e22d01d4edd4a56c0bd15af186549de87a03af29c": "1.14c",
    "631066c1649c4ea9ffe48bf97e24c00bca1f7a6759c21150f1a79982589adaaf": "1.14d",
}


def calculate_file_hash(filepath: Path, algorithms: List[str] = None) -> Dict[str, str]:
    """
    Calculate hash(es) of a file using specified algorithms.
    
    Args:
        filepath: Path to the file
        algorithms: List of hash algorithms to use (default: ['sha256'])
    
    Returns:
        Dictionary with algorithm names as keys and hex digests as values
    """
    if algorithms is None:
        algorithms = ['sha256']
    
    hashers = {algo: hashlib.new(algo) for algo in algorithms}
    
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                for hasher in hashers.values():
                    hasher.update(chunk)
        
        return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
    except (IOError, OSError) as e:
        return {algo: f"ERROR: {str(e)}" for algo in algorithms}


def get_file_info(filepath: Path, extract_pe: bool = True) -> Dict[str, Any]:
    """
    Get comprehensive file information including size and hashes.
    
    Args:
        filepath: Path to the file
        extract_pe: Whether to extract PE version info for executables
    
    Returns:
        Dictionary with file metadata
    """
    try:
        stat = filepath.stat()
        hashes = calculate_file_hash(filepath)
        
        info = {
            "filename": filepath.name,
            "size_bytes": stat.st_size,
            "size_readable": format_size(stat.st_size),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "sha256": hashes.get('sha256', ''),
        }
        
        # Extract PE version for executables and DLLs
        if extract_pe and filepath.suffix.lower() in ['.exe', '.dll']:
            pe_info = extract_pe_version(filepath)
            if pe_info:
                info["pe_version"] = pe_info.get("version_string", "")
                info["pe_version_raw"] = pe_info.get("raw_file_version", "")
        
        return info
    except (IOError, OSError) as e:
        return {
            "filename": filepath.name,
            "error": str(e)
        }


def format_size(size_bytes: int) -> str:
    """Format bytes into human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def extract_pe_version(filepath: Path) -> Optional[Dict[str, Any]]:
    """
    Extract version information from a Windows PE executable.
    
    Reads the PE header and VERSION_INFO resource to get the embedded
    version numbers that Diablo 2 uses to identify game versions.
    
    Args:
        filepath: Path to the .exe or .dll file
        
    Returns:
        Dictionary with version info or None if extraction fails:
        {
            "file_version": (major, minor, build, private),
            "product_version": (major, minor, build, private),
            "version_string": "1.10",
            "full_version_string": "1.10a",
            "raw_file_version": "1, 0, 10, 39"
        }
    """
    try:
        with open(filepath, 'rb') as f:
            # Check DOS header magic
            if f.read(2) != b'MZ':
                return None
            
            # Get PE header offset
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]
            
            # Check PE signature
            f.seek(pe_offset)
            if f.read(4) != b'PE\x00\x00':
                return None
            
            # Read COFF header
            machine = struct.unpack('<H', f.read(2))[0]
            num_sections = struct.unpack('<H', f.read(2))[0]
            f.read(12)  # Skip timestamp, symbol table ptr, symbol count
            optional_header_size = struct.unpack('<H', f.read(2))[0]
            f.read(2)  # Skip characteristics
            
            if optional_header_size == 0:
                return None
            
            # Read optional header
            optional_header_start = f.tell()
            magic = struct.unpack('<H', f.read(2))[0]
            
            # Determine if PE32 or PE32+
            if magic == 0x10b:  # PE32
                f.seek(optional_header_start + 92)  # Data directory offset for PE32
                num_rva_sizes = struct.unpack('<I', f.read(4))[0]
                data_dir_offset = optional_header_start + 96
            elif magic == 0x20b:  # PE32+
                f.seek(optional_header_start + 108)  # Data directory offset for PE32+
                num_rva_sizes = struct.unpack('<I', f.read(4))[0]
                data_dir_offset = optional_header_start + 112
            else:
                return None
            
            # Get resource directory RVA (index 2 in data directories)
            if num_rva_sizes < 3:
                return None
            f.seek(data_dir_offset + 2 * 8)  # Each entry is 8 bytes
            resource_rva = struct.unpack('<I', f.read(4))[0]
            resource_size = struct.unpack('<I', f.read(4))[0]
            
            if resource_rva == 0:
                return None
            
            # Read section headers to find resource section
            section_header_offset = optional_header_start + optional_header_size
            f.seek(section_header_offset)
            
            resource_file_offset = None
            for _ in range(num_sections):
                name = f.read(8).rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack('<I', f.read(4))[0]
                virtual_addr = struct.unpack('<I', f.read(4))[0]
                raw_size = struct.unpack('<I', f.read(4))[0]
                raw_ptr = struct.unpack('<I', f.read(4))[0]
                f.read(16)  # Skip rest of section header
                
                if virtual_addr <= resource_rva < virtual_addr + max(virtual_size, raw_size):
                    resource_file_offset = raw_ptr + (resource_rva - virtual_addr)
                    break
            
            if resource_file_offset is None:
                return None
            
            # Navigate resource directory to find VERSION_INFO (type 16)
            def read_resource_dir(offset, level=0):
                f.seek(offset)
                f.read(12)  # Skip characteristics, timestamp, version
                num_named = struct.unpack('<H', f.read(2))[0]
                num_id = struct.unpack('<H', f.read(2))[0]
                
                entries = []
                for i in range(num_named + num_id):
                    name_id = struct.unpack('<I', f.read(4))[0]
                    data_offset = struct.unpack('<I', f.read(4))[0]
                    entries.append((name_id, data_offset))
                return entries
            
            # Find RT_VERSION (16) in root directory
            root_entries = read_resource_dir(resource_file_offset)
            version_entry = None
            for name_id, data_offset in root_entries:
                if name_id == 16:  # RT_VERSION
                    version_entry = data_offset
                    break
            
            if version_entry is None:
                return None
            
            # Navigate to version data (follow the tree)
            if version_entry & 0x80000000:
                subdir_offset = resource_file_offset + (version_entry & 0x7FFFFFFF)
                sub_entries = read_resource_dir(subdir_offset)
                if sub_entries:
                    _, data_offset = sub_entries[0]
                    if data_offset & 0x80000000:
                        subdir2_offset = resource_file_offset + (data_offset & 0x7FFFFFFF)
                        sub2_entries = read_resource_dir(subdir2_offset)
                        if sub2_entries:
                            _, data_offset = sub2_entries[0]
            
            # Read data entry
            if data_offset & 0x80000000:
                return None  # Still a directory, unexpected
            
            data_entry_offset = resource_file_offset + data_offset
            f.seek(data_entry_offset)
            data_rva = struct.unpack('<I', f.read(4))[0]
            data_size = struct.unpack('<I', f.read(4))[0]
            
            # Calculate file offset for version data
            version_data_offset = resource_file_offset + (data_rva - resource_rva)
            f.seek(version_data_offset)
            version_data = f.read(min(data_size, 1024))
            
            # Parse VS_FIXEDFILEINFO structure
            # Look for signature 0xFEEF04BD
            sig_offset = version_data.find(b'\xBD\x04\xEF\xFE')
            if sig_offset < 0:
                return None
            
            f.seek(version_data_offset + sig_offset)
            signature = struct.unpack('<I', f.read(4))[0]
            if signature != 0xFEEF04BD:
                return None
            
            struct_version = struct.unpack('<I', f.read(4))[0]
            file_version_ms = struct.unpack('<I', f.read(4))[0]
            file_version_ls = struct.unpack('<I', f.read(4))[0]
            product_version_ms = struct.unpack('<I', f.read(4))[0]
            product_version_ls = struct.unpack('<I', f.read(4))[0]
            
            # Extract version components
            file_major = (file_version_ms >> 16) & 0xFFFF
            file_minor = file_version_ms & 0xFFFF
            file_build = (file_version_ls >> 16) & 0xFFFF
            file_private = file_version_ls & 0xFFFF
            
            prod_major = (product_version_ms >> 16) & 0xFFFF
            prod_minor = product_version_ms & 0xFFFF
            prod_build = (product_version_ls >> 16) & 0xFFFF
            prod_private = product_version_ls & 0xFFFF
            
            # Construct version strings
            # Pre-1.14: version is in file_build (e.g., 1.0.10.39 = 1.10)
            # 1.14+: different format (1.14.3.71)
            if file_major == 1 and file_minor == 0 and file_build <= 13:
                # Pre-1.14 format
                version_num = f"1.{file_build:02d}"
            else:
                # 1.14+ format
                version_num = f"{file_major}.{file_minor}.{file_build}"
            
            # Map build number to sub-version letter
            # This is approximate - the relationship varies by version
            sub_version_map = {
                # 1.00-1.03 range
                0: 'a', 1: 'a', 2: 'a',
                # 1.04+ uses build number to distinguish
            }
            
            return {
                "file_version": (file_major, file_minor, file_build, file_private),
                "product_version": (prod_major, prod_minor, prod_build, prod_private),
                "version_string": version_num,
                "raw_file_version": f"{file_major}, {file_minor}, {file_build}, {file_private}",
                "file_version_ms": file_version_ms,
                "file_version_ls": file_version_ls,
            }
            
    except Exception as e:
        return None


def parse_folder_name(folder_name: str) -> Dict[str, str]:
    """
    Parse Diablo 2 folder naming convention.
    
    Expected formats in VersionChanger project:
    - Classic/1.14d -> Classic version 1.14d
    - LoD/1.10 -> LoD version 1.10
    - NoCD/Classic/1.09b -> NoCD Classic version 1.09b
    
    Also supports legacy format:
    - Diablo2-C114d -> Classic version 1.14d
    - Diablo2-L114d -> LoD version 1.14d
    
    Args:
        folder_name: Name of the folder (or path segment)
    
    Returns:
        Dictionary with parsed information
    """
    result = {
        "folder_name": folder_name,
        "game_type": "unknown",
        "version": "unknown",
        "sub_version": "",
        "is_lod": None,
    }
    
    # Check for version-only format (e.g., "1.14d", "1.09b", "1.10 Beta 1")
    version_pattern = r'^(\d+\.\d+[a-z]?)(\s+Beta\s+\d+)?$'
    match = re.match(version_pattern, folder_name)
    if match:
        version = match.group(1)
        beta = match.group(2) or ""
        result["version"] = version
        result["full_version"] = folder_name
        return result
    
    # Pattern: Diablo2-C114d or Diablo2-L109b (legacy format)
    pattern = r'^Diablo2-([CL])(\d{3})([a-z])?$'
    match = re.match(pattern, folder_name)
    
    if match:
        game_type_char = match.group(1)
        version_num = match.group(2)
        sub_version = match.group(3) or ""
        
        result["game_type"] = "Classic" if game_type_char == "C" else "Lord of Destruction"
        result["is_lod"] = game_type_char == "L"
        
        # Convert 114 to 1.14
        if len(version_num) == 3:
            major = version_num[0]
            minor = version_num[1:]
            result["version"] = f"{major}.{minor}"
        else:
            result["version"] = version_num
        
        result["sub_version"] = sub_version
        result["full_version"] = result["version"] + sub_version
    elif folder_name in ["Diablo2", "Diablo2-old"]:
        result["game_type"] = "Modded/Custom"
        result["version"] = "custom"
    elif re.match(r'^Diablo2-[a-zA-Z]$', folder_name):
        result["game_type"] = "Variant"
        result["version"] = folder_name.split('-')[1]
    elif folder_name in ["Classic", "LoD"]:
        result["game_type"] = folder_name
        result["is_lod"] = folder_name == "LoD"
    
    return result


def parse_version_path(path: Path) -> Dict[str, str]:
    """
    Parse version information from a path in the VersionChanger structure.
    
    Args:
        path: Path like VersionChanger/Classic/1.09b or VersionChanger/NoCD/LoD/1.10
    
    Returns:
        Dictionary with game_type, version, is_lod, etc.
    """
    parts = path.parts
    result = {
        "path": str(path),
        "game_type": "unknown",
        "version": "unknown",
        "is_lod": None,
        "is_nocd": False,
    }
    
    # Find VersionChanger in path
    try:
        vc_idx = list(parts).index("VersionChanger")
    except ValueError:
        return result
    
    remaining = parts[vc_idx + 1:]
    
    if len(remaining) >= 2:
        if remaining[0] == "NoCD":
            result["is_nocd"] = True
            if len(remaining) >= 3:
                game_type = remaining[1]
                version = remaining[2]
                result["game_type"] = game_type
                result["is_lod"] = game_type == "LoD"
                result["version"] = version
                result["full_version"] = version
        else:
            game_type = remaining[0]
            version = remaining[1]
            result["game_type"] = game_type
            result["is_lod"] = game_type == "LoD"
            result["version"] = version
            result["full_version"] = version
    
    return result


def scan_folder(folder_path: Path, include_subdirs: bool = False, folder_info: Dict = None) -> Dict[str, Any]:
    """
    Scan a folder and collect file information with hashes.
    
    Args:
        folder_path: Path to the folder to scan
        include_subdirs: Whether to include subdirectory files
        folder_info: Pre-parsed folder info (for VersionChanger structure)
    
    Returns:
        Dictionary with folder scan results
    """
    if folder_info is None:
        folder_info = parse_folder_name(folder_path.name)
    
    result = {
        "folder_path": str(folder_path),
        "folder_name": folder_path.name,
        "folder_info": folder_info,
        "scan_time": datetime.now().isoformat(),
        "files": {},
        "file_count": 0,
        "total_size": 0,
        "extracted_version": None,
    }
    
    files_to_scan = []
    
    if include_subdirs:
        for item in folder_path.rglob('*'):
            if item.is_file():
                rel_path = item.relative_to(folder_path)
                files_to_scan.append((item, str(rel_path)))
    else:
        for item in folder_path.iterdir():
            if item.is_file():
                files_to_scan.append((item, item.name))
    
    for filepath, rel_name in files_to_scan:
        file_info = get_file_info(filepath)
        result["files"][rel_name] = file_info
        if "size_bytes" in file_info:
            result["total_size"] += file_info["size_bytes"]
    
    result["file_count"] = len(result["files"])
    result["total_size_readable"] = format_size(result["total_size"])
    
    # Extract version from Game.exe PE header if present
    game_exe_path = folder_path / "Game.exe"
    if game_exe_path.exists():
        pe_version = extract_pe_version(game_exe_path)
        if pe_version:
            result["extracted_version"] = pe_version
            # Add extracted version info to folder_info for comparison
            result["folder_info"]["extracted_pe_version"] = pe_version.get("version_string")
            result["folder_info"]["raw_pe_version"] = pe_version.get("raw_file_version")
            # Also store as tuple for verification logic
            result["folder_info"]["pe_version"] = pe_version.get("file_version")
            result["folder_info"]["pe_version_string"] = pe_version.get("version_string")
        
        # Look up community version from Game.exe hash
        game_exe_info = result["files"].get("Game.exe", {})
        game_exe_hash = game_exe_info.get("sha256", "")
        if game_exe_hash and game_exe_hash in GAME_EXE_VERSION_LOOKUP:
            result["folder_info"]["community_version"] = GAME_EXE_VERSION_LOOKUP[game_exe_hash]
    
    return result


def verify_version(folder_scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify if a folder's files match the expected version.
    
    Args:
        folder_scan: Scan results from scan_folder()
    
    Returns:
        Verification report with discrepancies
    """
    folder_info = folder_scan["folder_info"]
    expected_version = folder_info.get("full_version", folder_info.get("version", "unknown"))
    game_type = "L" if folder_info.get("is_lod") else "C" if folder_info.get("is_lod") is False else "X"
    
    # Get extracted PE version info
    pe_version = folder_info.get("pe_version")
    pe_version_string = folder_info.get("pe_version_string")
    
    report = {
        "folder_name": folder_scan["folder_name"],
        "expected_version": expected_version,
        "pe_version": pe_version,
        "pe_version_string": pe_version_string,
        "game_type": folder_info.get("game_type", "unknown"),
        "game_type_code": game_type,
        "is_lod": folder_info.get("is_lod"),
        "verification_status": "UNKNOWN",
        "issues": [],
        "warnings": [],
        "core_files_present": [],
        "core_files_missing": [],
        "detected_game_exe_size": None,
        "expected_game_exe_size": None,
    }
    
    files = folder_scan["files"]
    
    # Check for core files
    for core_file in CORE_VERSION_FILES:
        # Case-insensitive check
        found = False
        for filename in files:
            if filename.lower() == core_file.lower():
                found = True
                report["core_files_present"].append(filename)
                break
        if not found:
            report["core_files_missing"].append(core_file)
    
    # Check Game.exe size against known sizes
    game_exe_info = None
    for filename, info in files.items():
        if filename.lower() == "game.exe":
            game_exe_info = info
            break
    
    if game_exe_info and "size_bytes" in game_exe_info:
        size = game_exe_info["size_bytes"]
        report["detected_game_exe_size"] = size
        
        # Check if size matches expected version using (game_type, version) tuple
        lookup_key = (game_type, expected_version)
        if lookup_key in KNOWN_GAME_EXE_SIZES:
            expected_size = KNOWN_GAME_EXE_SIZES[lookup_key]
            report["expected_game_exe_size"] = expected_size
            if size != expected_size:
                report["issues"].append({
                    "type": "size_mismatch",
                    "file": "Game.exe",
                    "expected_size": expected_size,
                    "actual_size": size,
                    "message": f"Game.exe size ({size} bytes) doesn't match expected for {game_type} version {expected_version} ({expected_size} bytes)"
                })
        else:
            # Version not in known database - this is informational, not an error
            report["warnings"].append({
                "type": "unknown_reference",
                "message": f"No reference size available for {game_type} version {expected_version}"
            })
    
    # Check if LoD files are present/absent as expected
    lod_specific_files = ["d2exp.mpq", "D2xMusic.mpq", "d2xtalk.mpq", "D2xVideo.mpq"]
    has_lod_files = any(
        any(filename.lower() == lod.lower() for filename in files)
        for lod in lod_specific_files
    )
    
    if folder_info.get("is_lod") is True and not has_lod_files:
        report["issues"].append({
            "type": "missing_lod_files",
            "message": "Folder is marked as LoD but missing expansion MPQ files"
        })
    elif folder_info.get("is_lod") is False and has_lod_files:
        report["warnings"].append({
            "type": "unexpected_lod_files",
            "message": "Folder is marked as Classic but contains expansion MPQ files"
        })
    
    # Verify PE version matches folder version
    if pe_version and expected_version not in ("unknown", "custom"):
        # Parse expected version from folder name
        # Extract major.minor from expected_version (e.g., "1.14d" -> (1, 14))
        version_match = re.match(r'(\d+)\.(\d+)([a-z])?', expected_version)
        if version_match:
            expected_major = int(version_match.group(1))
            expected_minor = int(version_match.group(2))
            expected_letter = version_match.group(3) or ""
            
            # pe_version is tuple like (1, 0, 10, 39) for pre-1.14 or (1, 14, 3, 71) for 1.14+
            pe_major = pe_version[0]
            
            # Pre-1.14 format: (1, 0, version, build) where version = minor
            # 1.14+ format: (1, 14, subver, build)
            if len(pe_version) >= 3:
                if pe_version[1] == 0:
                    # Pre-1.14 format
                    pe_minor = pe_version[2]  # e.g., 10 for 1.10
                else:
                    # 1.14+ format
                    pe_minor = pe_version[1]  # e.g., 14 for 1.14
                
                version_matches = (expected_major == pe_major and expected_minor == pe_minor)
                
                if not version_matches:
                    report["issues"].append({
                        "type": "pe_version_mismatch",
                        "expected_version": expected_version,
                        "detected_pe_version": pe_version_string,
                        "message": f"PE version ({pe_version_string}) doesn't match folder version ({expected_version})"
                    })
                else:
                    # Version matches - add as info
                    report["pe_version_verified"] = True
    elif pe_version is None and expected_version not in ("unknown", "custom"):
        report["warnings"].append({
            "type": "no_pe_version",
            "message": "Could not extract version from Game.exe - file may be missing or corrupt"
        })
    
    # Determine verification status
    if len(report["issues"]) == 0:
        if expected_version == "unknown" or expected_version == "custom":
            report["verification_status"] = "UNVERIFIABLE"
        else:
            report["verification_status"] = "PASSED"
    else:
        report["verification_status"] = "FAILED"
    
    if report["warnings"]:
        if not report["verification_status"].startswith("FAILED"):
            report["verification_status"] += "_WITH_WARNINGS"
    
    return report


def compare_folders(folders: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compare files across multiple folder scans to find differences.
    
    Args:
        folders: List of folder scan results
    
    Returns:
        Comparison report
    """
    if len(folders) < 2:
        return {"error": "Need at least 2 folders to compare"}
    
    comparison = {
        "compared_folders": [f["folder_name"] for f in folders],
        "comparison_time": datetime.now().isoformat(),
        "files_analysis": {},
        "summary": {
            "files_identical_across_all": [],
            "files_with_variations": [],
            "files_unique_to_folders": defaultdict(list),
        }
    }
    
    # Collect all unique filenames across all folders
    all_files = set()
    for folder in folders:
        all_files.update(folder["files"].keys())
    
    for filename in sorted(all_files):
        file_analysis = {
            "filename": filename,
            "present_in": [],
            "missing_from": [],
            "variations": [],
            "is_identical": True,
        }
        
        # Track hashes to detect variations
        hash_groups = defaultdict(list)
        
        for folder in folders:
            folder_name = folder["folder_name"]
            if filename in folder["files"]:
                file_info = folder["files"][filename]
                file_analysis["present_in"].append(folder_name)
                
                if "sha256" in file_info and not file_info["sha256"].startswith("ERROR"):
                    hash_key = file_info["sha256"]
                    hash_groups[hash_key].append({
                        "folder": folder_name,
                        "size": file_info.get("size_bytes", 0),
                        "md5": file_info.get("md5", ""),
                    })
            else:
                file_analysis["missing_from"].append(folder_name)
        
        # Analyze variations
        if len(hash_groups) > 1:
            file_analysis["is_identical"] = False
            for hash_val, occurrences in hash_groups.items():
                file_analysis["variations"].append({
                    "sha256": hash_val,
                    "folders": [o["folder"] for o in occurrences],
                    "size": occurrences[0]["size"],
                })
            comparison["summary"]["files_with_variations"].append(filename)
        elif len(hash_groups) == 1 and len(file_analysis["missing_from"]) == 0:
            comparison["summary"]["files_identical_across_all"].append(filename)
        
        # Track unique files
        if len(file_analysis["present_in"]) < len(folders):
            for folder_name in file_analysis["present_in"]:
                if len(file_analysis["present_in"]) == 1:
                    comparison["summary"]["files_unique_to_folders"][folder_name].append(filename)
        
        comparison["files_analysis"][filename] = file_analysis
    
    # Convert defaultdict to regular dict for JSON serialization
    comparison["summary"]["files_unique_to_folders"] = dict(comparison["summary"]["files_unique_to_folders"])
    
    return comparison


def build_reference_database(scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a reference hash database from folder scans.
    
    This creates a database of expected file hashes for each version,
    which can be used to verify other installations.
    
    Args:
        scans: List of folder scan results
    
    Returns:
        Reference database structure
    """
    database = {
        "generated": datetime.now().isoformat(),
        "description": "Reference hash database for Diablo 2 version verification",
        "versions": {},
    }
    
    for scan in scans:
        folder_info = scan["folder_info"]
        version = folder_info.get("full_version", folder_info.get("version", "unknown"))
        game_type = "L" if folder_info.get("is_lod") else "C" if folder_info.get("is_lod") is False else "X"
        
        if version == "unknown" or version == "custom":
            continue
        
        version_key = f"{game_type}_{version}"
        
        if version_key not in database["versions"]:
            database["versions"][version_key] = {
                "game_type": folder_info.get("game_type"),
                "game_type_code": game_type,
                "version": version,
                "is_lod": folder_info.get("is_lod"),
                "source_folder": scan["folder_name"],
                "core_files": {},
                "data_files": {},
            }
        
        version_entry = database["versions"][version_key]
        
        # Store hashes for core files
        for filename, file_info in scan["files"].items():
            if "sha256" not in file_info or file_info["sha256"].startswith("ERROR"):
                continue
            
            file_entry = {
                "size_bytes": file_info.get("size_bytes", 0),
                "md5": file_info.get("md5", ""),
                "sha256": file_info.get("sha256", ""),
            }
            
            # Categorize as core or data file
            is_core = any(filename.lower() == cf.lower() for cf in CORE_VERSION_FILES)
            is_data = any(filename.lower() == df.lower() for df in DATA_FILES)
            
            if is_core:
                version_entry["core_files"][filename] = file_entry
            elif is_data:
                version_entry["data_files"][filename] = file_entry
    
    return database


def verify_against_reference(folder_scan: Dict[str, Any], reference_db: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify a folder against a reference hash database.
    
    Args:
        folder_scan: Scan results from scan_folder()
        reference_db: Reference database from build_reference_database()
    
    Returns:
        Detailed verification report
    """
    folder_info = folder_scan["folder_info"]
    version = folder_info.get("full_version", folder_info.get("version", "unknown"))
    game_type = "L" if folder_info.get("is_lod") else "C" if folder_info.get("is_lod") is False else "X"
    version_key = f"{game_type}_{version}"
    
    report = {
        "folder_name": folder_scan["folder_name"],
        "expected_version": version,
        "game_type": game_type,
        "reference_found": False,
        "files_verified": 0,
        "files_matched": 0,
        "files_mismatched": 0,
        "files_missing_from_reference": 0,
        "mismatches": [],
        "verification_status": "UNKNOWN",
    }
    
    if version_key not in reference_db.get("versions", {}):
        report["verification_status"] = "NO_REFERENCE"
        return report
    
    report["reference_found"] = True
    ref_version = reference_db["versions"][version_key]
    
    # Check all files against reference
    ref_files = {**ref_version.get("core_files", {}), **ref_version.get("data_files", {})}
    
    for filename, file_info in folder_scan["files"].items():
        if "sha256" not in file_info or file_info["sha256"].startswith("ERROR"):
            continue
        
        # Find matching reference file (case-insensitive)
        ref_file = None
        ref_filename = None
        for ref_fn, ref_fi in ref_files.items():
            if ref_fn.lower() == filename.lower():
                ref_file = ref_fi
                ref_filename = ref_fn
                break
        
        if ref_file is None:
            report["files_missing_from_reference"] += 1
            continue
        
        report["files_verified"] += 1
        
        if file_info["sha256"] == ref_file["sha256"]:
            report["files_matched"] += 1
        else:
            report["files_mismatched"] += 1
            report["mismatches"].append({
                "filename": filename,
                "expected_sha256": ref_file["sha256"],
                "actual_sha256": file_info["sha256"],
                "expected_size": ref_file.get("size_bytes"),
                "actual_size": file_info.get("size_bytes"),
            })
    
    # Determine verification status
    if report["files_mismatched"] == 0 and report["files_verified"] > 0:
        report["verification_status"] = "VERIFIED"
    elif report["files_mismatched"] > 0:
        report["verification_status"] = "MISMATCHED"
    else:
        report["verification_status"] = "INSUFFICIENT_DATA"
    
    return report


def find_version_folders(project_root: Path) -> List[Tuple[Path, Dict]]:
    """
    Find all version folders in the VersionChanger project structure.
    
    Returns:
        List of (folder_path, folder_info) tuples
    """
    results = []
    vc_dir = project_root / "VersionChanger"
    
    # Scan Classic and LoD patch folders
    for game_type in ["Classic", "LoD"]:
        game_dir = vc_dir / game_type
        if not game_dir.exists():
            continue
        
        for version_dir in sorted(game_dir.iterdir()):
            if not version_dir.is_dir():
                continue
            
            folder_info = {
                "folder_name": version_dir.name,
                "game_type": game_type,
                "is_lod": game_type == "LoD",
                "version": version_dir.name,
                "full_version": version_dir.name,
                "is_nocd": False,
            }
            results.append((version_dir, folder_info))
    
    # Scan NoCD folders
    nocd_dir = vc_dir / "NoCD"
    if nocd_dir.exists():
        for game_type in ["Classic", "LoD"]:
            game_dir = nocd_dir / game_type
            if not game_dir.exists():
                continue
            
            for version_dir in sorted(game_dir.iterdir()):
                if not version_dir.is_dir():
                    continue
                
                folder_info = {
                    "folder_name": f"NoCD-{game_type}-{version_dir.name}",
                    "game_type": game_type,
                    "is_lod": game_type == "LoD",
                    "version": version_dir.name,
                    "full_version": version_dir.name,
                    "is_nocd": True,
                }
                results.append((version_dir, folder_info))
    
    return results


def generate_reports(base_path: Path = None, output_dir: Path = None) -> Dict[str, Path]:
    """
    Generate all reports for Diablo 2 installation folders.
    
    Args:
        base_path: Path to the project root (default: auto-detect from script location)
        output_dir: Optional output directory for reports (default: base_path/reports)
    
    Returns:
        Dictionary with paths to generated report files
    """
    if base_path is None:
        base_path = get_project_root()
    
    if output_dir is None:
        output_dir = base_path / "reports"
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    report_files = {}
    
    # Find all version folders in the project structure
    version_folders = find_version_folders(base_path)
    
    print(f"Found {len(version_folders)} version folders to analyze...")
    
    # Scan all folders
    all_scans = []
    all_verifications = []
    
    for folder, folder_info in version_folders:
        print(f"  Scanning: {folder_info['folder_name']}...")
        scan = scan_folder(folder, include_subdirs=False, folder_info=folder_info)
        all_scans.append(scan)
        
        verification = verify_version(scan)
        all_verifications.append(verification)
    
    # Generate individual folder hash reports
    data_dir = output_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    hash_report_path = data_dir / "d2_folder_hashes.json"
    with open(hash_report_path, 'w', encoding='utf-8') as f:
        json.dump({
            "report_type": "folder_hashes",
            "generated": datetime.now().isoformat(),
            "base_path": str(base_path),
            "folders": {scan["folder_info"]["folder_name"]: scan for scan in all_scans}
        }, f, indent=2)
    report_files["folder_hashes"] = hash_report_path
    print(f"  Created: {hash_report_path}")
    
    # Generate verification report
    verification_report_path = data_dir / "d2_version_verification.json"
    issues_found = sum(len(v["issues"]) for v in all_verifications)
    warnings_found = sum(len(v.get("warnings", [])) for v in all_verifications)
    
    with open(verification_report_path, 'w', encoding='utf-8') as f:
        json.dump({
            "report_type": "version_verification",
            "generated": datetime.now().isoformat(),
            "summary": {
                "total_folders": len(all_verifications),
                "passed": sum(1 for v in all_verifications if v["verification_status"].startswith("PASSED")),
                "failed": sum(1 for v in all_verifications if v["verification_status"].startswith("FAILED")),
                "unverifiable": sum(1 for v in all_verifications if v["verification_status"].startswith("UNVERIFIABLE")),
                "total_issues": issues_found,
                "total_warnings": warnings_found,
            },
            "verifications": all_verifications
        }, f, indent=2)
    report_files["verification"] = verification_report_path
    print(f"  Created: {verification_report_path}")
    
    # Group folders by version type for comparison
    version_groups = defaultdict(list)
    for scan in all_scans:
        folder_info = scan["folder_info"]
        version = folder_info.get("full_version", folder_info.get("version", "unknown"))
        game_type = "L" if folder_info.get("is_lod") else "C" if folder_info.get("is_lod") is False else "X"
        group_key = f"{game_type}_{version}"
        version_groups[group_key].append(scan)
    
    # Generate comparison reports
    print("  Generating comparison reports...")
    
    # Compare all version folders together
    if len(all_scans) >= 2:
        full_comparison = compare_folders(all_scans)
        full_comparison_path = data_dir / "d2_full_comparison.json"
        with open(full_comparison_path, 'w', encoding='utf-8') as f:
            json.dump(full_comparison, f, indent=2)
        report_files["full_comparison"] = full_comparison_path
        print(f"  Created: {full_comparison_path}")
    
    # Build reference hash database
    print("  Building reference hash database...")
    reference_db = build_reference_database(all_scans)
    reference_db_path = data_dir / "d2_reference_hashes.json"
    with open(reference_db_path, 'w', encoding='utf-8') as f:
        json.dump(reference_db, f, indent=2)
    report_files["reference_database"] = reference_db_path
    print(f"  Created: {reference_db_path}")
    
    # Verify all folders against the reference database
    print("  Verifying folders against reference database...")
    reference_verifications = []
    for scan in all_scans:
        ref_verification = verify_against_reference(scan, reference_db)
        reference_verifications.append(ref_verification)
    
    ref_verification_path = data_dir / "d2_reference_verification.json"
    with open(ref_verification_path, 'w', encoding='utf-8') as f:
        json.dump({
            "report_type": "reference_verification",
            "generated": datetime.now().isoformat(),
            "description": "Verification of each folder against the reference hash database",
            "verifications": reference_verifications,
        }, f, indent=2)
    report_files["reference_verification"] = ref_verification_path
    print(f"  Created: {ref_verification_path}")
    
    # Generate human-readable summary
    summary_path = output_dir / "d2_analysis_summary.txt"
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("DIABLO 2 VERSION CHANGER - FILE ANALYSIS SUMMARY\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("FOLDER OVERVIEW:\n")
        f.write("-" * 40 + "\n")
        for scan in all_scans:
            info = scan["folder_info"]
            pe_ver = info.get('extracted_pe_version', '')
            pe_str = f" [PE: {pe_ver}]" if pe_ver else ""
            nocd_str = " (NoCD)" if info.get('is_nocd') else ""
            f.write(f"  {info.get('folder_name', scan['folder_name']):30} | {info.get('game_type', 'unknown'):10} | v{info.get('full_version', info.get('version', '?')):15}{pe_str}{nocd_str} | {scan['file_count']} files | {scan['total_size_readable']}\n")
        
        f.write("\n\nVERSION VERIFICATION:\n")
        f.write("-" * 40 + "\n")
        for v in all_verifications:
            status_icon = "✓" if v["verification_status"].startswith("PASSED") else "✗" if v["verification_status"].startswith("FAILED") else "?"
            pe_verified = "✓" if v.get("pe_version_verified") else ""
            pe_info = f" [PE: {v.get('pe_version_string', '?')}{pe_verified}]" if v.get('pe_version_string') else ""
            f.write(f"  [{status_icon}] {v['folder_name']:30} | {v['verification_status']}{pe_info}\n")
            for issue in v["issues"]:
                f.write(f"      ⚠ ISSUE: {issue.get('message', issue.get('type', 'Unknown issue'))}\n")
            for warning in v.get("warnings", []):
                f.write(f"      ⚡ WARNING: {warning.get('message', warning.get('type', 'Unknown warning'))}\n")
        
        if len(all_scans) >= 2:
            f.write("\n\nFILE COMPARISON SUMMARY:\n")
            f.write("-" * 40 + "\n")
            
            comparison = compare_folders(all_scans)
            f.write(f"  Files identical across ALL folders: {len(comparison['summary']['files_identical_across_all'])}\n")
            f.write(f"  Files with variations: {len(comparison['summary']['files_with_variations'])}\n")
            
            if comparison['summary']['files_with_variations']:
                f.write("\n  FILES THAT DIFFER BETWEEN VERSIONS:\n")
                for filename in sorted(comparison['summary']['files_with_variations']):
                    file_info = comparison['files_analysis'][filename]
                    f.write(f"    • {filename}\n")
                    for var in file_info.get("variations", []):
                        f.write(f"        Size: {format_size(var['size']):>12} in: {', '.join(var['folders'])}\n")
        
        f.write("\n\n" + "=" * 80 + "\n")
        f.write("See JSON files in reports/data/ for detailed hash information.\n")
    
    report_files["summary"] = summary_path
    print(f"  Created: {summary_path}")
    
    # Generate No-CD Detection Report
    print("  Running No-CD patch detection...")
    nocd_results = detect_nocd_patches(base_path)
    nocd_report_path = data_dir / "d2_nocd_detection.json"
    with open(nocd_report_path, 'w', encoding='utf-8') as f:
        json.dump(nocd_results, f, indent=2)
    report_files["nocd_detection"] = nocd_report_path
    print(f"  Created: {nocd_report_path}")
    
    # Print no-CD summary
    summary = nocd_results.get("summary", {})
    if summary.get("patched_nocd", 0) > 0:
        print(f"\n  ⚠️  Found {summary['patched_nocd']} NoCD patched files")
    
    return report_files


# ============================================================================
# NO-CD PATCH DETECTION
# ============================================================================

# CD check byte patterns in Storm.dll
# The CD validation uses GetDriveTypeA and compares with DRIVE_CDROM (5)
NOCD_PATTERNS = {
    # Original patterns (CD check intact)
    "cmp_eax_5_ja": (bytes([0x83, 0xF8, 0x05, 0x77]), "CMP EAX,5; JA - Original CD check", False),
    
    # Patched patterns (no-CD modifications)
    "cmp_eax_5_jmp_short": (bytes([0x83, 0xF8, 0x05, 0xEB]), "CMP EAX,5; JMP - Patched (short jmp)", True),
    "cmp_eax_5_nop": (bytes([0x83, 0xF8, 0x05, 0x90, 0x90]), "CMP EAX,5; NOP NOP - Patched (NOPed)", True),
    "nop_replacing_cmp": (bytes([0x90, 0x90, 0x90, 0x77]), "NOP NOP NOP; JA - CMP replaced with NOPs", True),
    "xor_eax_eax_nop_ja": (bytes([0x33, 0xC0, 0x90, 0x77]), "XOR EAX,EAX; NOP; JA - Drive type zeroed", True),
}


def analyze_storm_for_nocd(filepath: Path, folder_info: Dict = None) -> Dict[str, Any]:
    """
    Analyze a Storm.dll file for no-CD patches.
    
    Args:
        filepath: Path to Storm.dll
        folder_info: Pre-parsed folder info
        
    Returns:
        Dictionary with analysis results
    """
    result = {
        "filepath": str(filepath),
        "filename": filepath.name,
        "folder": filepath.parent.name,
        "size": filepath.stat().st_size,
        "hash": calculate_file_hash(filepath).get('sha256', ''),
        "version": None,
        "cd_check_status": "unknown",
        "patterns_found": [],
        "requires_cd": None,
        "notes": []
    }
    
    # Get version from folder_info if provided
    if folder_info:
        result["version"] = folder_info.get("version")
        result["game_type"] = folder_info.get("game_type")
    else:
        # Parse version from folder name (legacy format or try to extract)
        folder = result["folder"]
        match = re.search(r'(\d+\.\d+[a-z]?)$', folder)
        if match:
            result["version"] = match.group(1)
        else:
            # Legacy format: C109b or L110a
            match = re.search(r'[CL]1(\d{2})([a-z])?$', folder)
            if match:
                minor_ver = match.group(1)
                letter = match.group(2) or ''
                result["version"] = f"1.{minor_ver}{letter}"
    
    # Determine if this version requires CD (pre-1.12)
    if result["version"]:
        ver_match = re.match(r'(\d+)\.(\d+)', result["version"])
        if ver_match:
            major, minor = int(ver_match.group(1)), int(ver_match.group(2))
            result["requires_cd"] = major == 1 and minor < 12
    
    # Read file and search for patterns
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        for name, (pattern, desc, is_patched) in NOCD_PATTERNS.items():
            count = data.count(pattern)
            if count > 0:
                offsets = []
                pos = 0
                while len(offsets) < 5:
                    idx = data.find(pattern, pos)
                    if idx == -1:
                        break
                    offsets.append(f"0x{idx:X}")
                    pos = idx + 1
                
                result["patterns_found"].append({
                    "name": name,
                    "description": desc,
                    "is_patched_pattern": is_patched,
                    "count": count,
                    "offsets": offsets
                })
        
        # Determine CD check status
        has_original = any(p["name"] == "cmp_eax_5_ja" for p in result["patterns_found"])
        has_patched = any(p["is_patched_pattern"] for p in result["patterns_found"])
        
        if result["requires_cd"] == False:
            result["cd_check_status"] = "removed_officially"
            result["notes"].append("Version 1.12+ - CD check officially removed by Blizzard")
        elif has_patched:
            result["cd_check_status"] = "patched"
            result["notes"].append("No-CD patch detected! File has been modified.")
        elif has_original:
            result["cd_check_status"] = "original"
            result["notes"].append("Original CD check intact - requires CD to run")
        else:
            result["cd_check_status"] = "unknown"
            result["notes"].append("Could not determine CD check status")
            
    except Exception as e:
        result["error"] = str(e)
        result["cd_check_status"] = "error"
    
    return result


def detect_nocd_patches(base_path: Path = None) -> Dict[str, Any]:
    """
    Detect no-CD patches in all Storm.dll files under base_path.
    
    Args:
        base_path: Path to project root (default: auto-detect)
        
    Returns:
        Dictionary with detection results and summary
    """
    if base_path is None:
        base_path = get_project_root()
    
    results = []
    
    # Find all Storm.dll files in VersionChanger structure
    vc_dir = base_path / "VersionChanger"
    storm_files = []
    
    # Check NoCD folders first (most likely to have Storm.dll)
    nocd_dir = vc_dir / "NoCD"
    if nocd_dir.exists():
        for game_type in ["Classic", "LoD"]:
            game_dir = nocd_dir / game_type
            if not game_dir.exists():
                continue
            for version_dir in game_dir.iterdir():
                if version_dir.is_dir():
                    storm_path = version_dir / "Storm.dll"
                    if storm_path.exists():
                        folder_info = {
                            "version": version_dir.name,
                            "game_type": game_type,
                            "is_nocd": True
                        }
                        storm_files.append((storm_path, folder_info))
    
    # Also check regular version folders
    for game_type in ["Classic", "LoD"]:
        game_dir = vc_dir / game_type
        if not game_dir.exists():
            continue
        for version_dir in game_dir.iterdir():
            if version_dir.is_dir():
                storm_path = version_dir / "Storm.dll"
                if storm_path.exists():
                    folder_info = {
                        "version": version_dir.name,
                        "game_type": game_type,
                        "is_nocd": False
                    }
                    storm_files.append((storm_path, folder_info))
    
    for filepath, folder_info in sorted(storm_files, key=lambda x: str(x[0])):
        result = analyze_storm_for_nocd(filepath, folder_info)
        results.append(result)
    
    # Build summary
    summary = {
        "total_files": len(results),
        "original_cd_check": sum(1 for r in results if r["cd_check_status"] == "original"),
        "patched_nocd": sum(1 for r in results if r["cd_check_status"] == "patched"),
        "official_nocd": sum(1 for r in results if r["cd_check_status"] == "removed_officially"),
        "unknown": sum(1 for r in results if r["cd_check_status"] == "unknown"),
        "errors": sum(1 for r in results if r["cd_check_status"] == "error"),
    }
    
    # List patched files
    patched_files = [r["filepath"] for r in results if r["cd_check_status"] == "patched"]
    
    return {
        "report_type": "nocd_detection",
        "generated": datetime.now().isoformat(),
        "summary": summary,
        "patched_files": patched_files,
        "files": results
    }


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Diablo 2 Version Changer - Hash & Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python d2_hash_tool.py                          # Analyze from project root
  python d2_hash_tool.py -p /path/to/project      # Specify project root
  python d2_hash_tool.py -o ./custom-reports      # Output to custom folder
        """
    )
    
    parser.add_argument(
        "-p", "--path",
        type=str,
        default=None,
        help="Path to D2VersionChanger project root (default: auto-detect)"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output directory for reports (default: <project_root>/reports)"
    )
    
    parser.add_argument(
        "--include-subdirs",
        action="store_true",
        help="Include files in subdirectories (Data, Save, etc.)"
    )
    
    args = parser.parse_args()
    
    # Determine project root
    if args.path:
        base_path = Path(args.path).resolve()
    else:
        base_path = get_project_root()
    
    output_path = Path(args.output).resolve() if args.output else base_path / "reports"
    
    if not base_path.exists():
        print(f"Error: Path does not exist: {base_path}")
        return 1
    
    # Verify this looks like a D2VersionChanger project
    vc_dir = base_path / "VersionChanger"
    if not vc_dir.exists():
        print(f"Warning: VersionChanger directory not found at {vc_dir}")
        print("This may not be a D2VersionChanger project root.")
    
    print(f"\nDiablo 2 Version Changer - Hash & Verification Tool")
    print("=" * 50)
    print(f"Project Root: {base_path}")
    print(f"Output:       {output_path}")
    print()
    
    try:
        reports = generate_reports(base_path, output_path)
        print(f"\n✓ Analysis complete! Generated {len(reports)} report files.")
        print("\nReport files:")
        for name, path in reports.items():
            print(f"  • {name}: {path}")
        return 0
    except Exception as e:
        print(f"\n✗ Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
