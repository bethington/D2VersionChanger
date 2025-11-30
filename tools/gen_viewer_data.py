#!/usr/bin/env python3
"""
Generate consolidated data for the D2 Report Viewer.

This creates optimized data structures for the three-panel viewer:
1. VERSIONS_DATA - Lightweight array for version navigation (Panel 1)
2. FOLDERS_DATA - Detailed file data per version (Panel 2)
3. FILE_HISTORY_DATA - File evolution across versions (Panel 3)
4. DIFFS_DATA - Version-to-version changes
5. FILE_CATEGORIES - File category mappings
"""
import json
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, OrderedDict
from typing import Dict, List, Any, Tuple

# Import from the main hash tool
import sys
sys.path.insert(0, str(Path(__file__).parent))

from d2_hash_tool import (
    get_project_root,
    find_version_folders,
    scan_folder,
    extract_pe_exports,
)

# File categories for grouping and display
FILE_CATEGORIES = {
    "Game Logic": {
        "color": "#00FF00",  # Set green
        "files": ["D2Game.dll", "D2Common.dll", "D2Client.dll", "D2Lang.dll"]
    },
    "Graphics": {
        "color": "#6969FF",  # Magic blue
        "files": ["D2gfx.dll", "D2DDraw.dll", "D2Direct3D.dll", "D2Glide.dll", "D2Gdi.dll"]
    },
    "Audio": {
        "color": "#A59263",  # Muted gold
        "files": ["D2sound.dll", "binkw32.dll", "SmackW32.dll"]
    },
    "Network": {
        "color": "#FF6600",  # Crafted orange
        "files": ["D2Net.dll", "D2MCPClient.dll", "D2Multi.dll", "Bnclient.dll"]
    },
    "Launcher": {
        "color": "#FFFF00",  # Rare yellow
        "files": ["D2Launch.dll", "D2Win.dll", "Game.exe", "Diablo II.exe", "D2VidTst.exe"]
    },
    "MPQ": {
        "color": "#C7B377",  # Unique gold
        "files": []  # Will match by extension instead
    },
    "Utility": {
        "color": "#808080",  # Normal gray
        "files": ["Fog.dll", "Storm.dll", "ijl11.dll", "D2CMP.dll", "D2.LNG"]
    }
}


def get_file_category(filename: str) -> Tuple[str, str]:
    """Get category name and color for a file."""
    base_name = filename.split(' (')[0]  # Handle "Game.exe (NoCD)" format
    base_name_lower = base_name.lower()

    # Check for MPQ files by extension
    if base_name_lower.endswith('.mpq'):
        return "MPQ", FILE_CATEGORIES["MPQ"]["color"]

    # Check other categories by filename (case-insensitive)
    for category, info in FILE_CATEGORIES.items():
        for cat_file in info["files"]:
            if base_name_lower == cat_file.lower():
                return category, info["color"]
    return "Other", "#FFFFFF"


def detect_nocd_status(folder_info: Dict) -> str:
    """
    Detect NoCD status for a folder.
    
    Returns:
        'official_nocd' - Version 1.12+ with official no-CD support
        'nocd' - In NoCD folder (patched)
        'original' - Original (CD check likely intact)
    """
    # Check if in NoCD folder structure
    if folder_info.get('is_nocd'):
        return 'nocd'
    
    version = folder_info.get('full_version', folder_info.get('version', ''))
    
    # Check if it's an official no-CD version (1.12+)
    try:
        ver_clean = version.replace('Beta', '').strip().split()[0]
        parts = ver_clean.split('.')
        if len(parts) >= 2:
            major = int(parts[0])
            minor_str = ''.join(c for c in parts[1] if c.isdigit())
            minor = int(minor_str) if minor_str else 0
            if major >= 1 and minor >= 12:
                return 'official_nocd'
    except (ValueError, IndexError):
        pass
    
    return 'original'


def get_canonical_key(folder_info: Dict, folder_name: str) -> str:
    """
    Get canonical key for grouping versions (game_type + version).
    
    E.g., 'Classic/1.09b' and 'NoCD/Classic/1.09b' both become 'Classic/1.09b'
    """
    game_type = folder_info.get('game_type', 'Unknown')
    
    # Extract version from folder_name
    version = folder_name.split('/')[-1] if '/' in folder_name else folder_name
    
    return f"{game_type}/{version}"


def build_versions_data(all_scans: List[Dict]) -> List[Dict]:
    """
    Build lightweight versions table data, merging same version/type together.
    
    Returns array of version summary objects for the table.
    """
    # Group scans by canonical key (game_type + version)
    grouped = defaultdict(list)
    
    for scan in all_scans:
        info = scan.get('folder_info', {})
        folder_name = scan.get('folder_name', '')
        key = get_canonical_key(info, folder_name)
        grouped[key].append(scan)
    
    versions = []
    
    for key, scans in grouped.items():
        # Use first scan for base info, merge file counts and sizes
        first_scan = scans[0]
        info = first_scan.get('folder_info', {})
        
        # Extract version from key
        version = key.split('/')[-1] if '/' in key else key
        
        # Merge file counts and sizes
        total_files = sum(s.get('file_count', 0) for s in scans)
        total_bytes = sum(s.get('total_size', 0) for s in scans)
        
        # Determine nocd_status - if any scan has nocd, show it
        nocd_statuses = [detect_nocd_status(s.get('folder_info', {})) for s in scans]
        if 'nocd' in nocd_statuses:
            nocd_status = 'nocd'
        elif 'official_nocd' in nocd_statuses:
            nocd_status = 'official_nocd'
        else:
            nocd_status = 'original'
        
        versions.append({
            'folder_name': key,  # Use canonical key as folder_name
            'game_type': info.get('game_type', 'Unknown'),
            'is_lod': info.get('is_lod'),
            'version': version,
            'raw_pe_version': info.get('raw_pe_version', ''),
            'file_count': total_files,
            'total_size_readable': format_size(total_bytes),
            'nocd_status': nocd_status,
        })
    
    return versions


def format_size(size_bytes: int) -> str:
    """Format bytes to human readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def build_folders_data(all_scans: List[Dict], hash_to_community_id: Dict[str, str]) -> Dict[str, Any]:
    """
    Build folder file data with pre-computed hash matching.
    Merges files from same version/type together (e.g., original + NoCD).

    Returns dict keyed by canonical key (game_type/version) containing merged files.
    """
    # Group scans by canonical key
    grouped = defaultdict(list)
    for scan in all_scans:
        info = scan.get('folder_info', {})
        folder_name = scan.get('folder_name', '')
        key = get_canonical_key(info, folder_name)
        grouped[key].append(scan)

    # First pass: build hash-to-canonical-keys map for comparison
    # Uses canonical keys instead of raw folder names
    hash_map = defaultdict(lambda: defaultdict(set))  # filename -> sha256 -> {canonical_keys}

    for key, scans in grouped.items():
        for scan in scans:
            for filename, file_info in scan.get('files', {}).items():
                sha256 = file_info.get('sha256', '')
                if sha256:
                    hash_map[filename][sha256].add(key)

    # Second pass: build folders data with merged files
    folders_data = {}

    for key, scans in grouped.items():
        # Merge files from all scans with the same canonical key
        merged_files = {}

        for scan in scans:
            folder_name = scan.get('folder_name', '')
            is_nocd = scan.get('folder_info', {}).get('is_nocd', False)

            for filename, file_info in scan.get('files', {}).items():
                sha256 = file_info.get('sha256', '')

                # Create a unique key for files that might differ (original vs nocd)
                # If same filename with different hash exists, prefix with source
                file_key = filename
                if filename in merged_files:
                    existing_hash = merged_files[filename].get('sha256', '')
                    if existing_hash and sha256 and existing_hash != sha256:
                        # Different file content - add source prefix
                        source = 'NoCD' if is_nocd else 'Original'
                        file_key = f"{filename} ({source})"
                        # Also rename the existing one if not already renamed
                        if filename in merged_files and not filename.endswith(')'):
                            old_file = merged_files.pop(filename)
                            old_source = 'NoCD' if old_file.get('is_nocd') else 'Original'
                            merged_files[f"{filename} ({old_source})"] = old_file

                # Get matching canonical keys (excluding self)
                matching = []
                if sha256 and filename in hash_map:
                    matching = sorted([k for k in hash_map[filename].get(sha256, set()) if k != key])

                # Get category
                category, category_color = get_file_category(file_key)

                # Get community ID
                community_id = hash_to_community_id.get(sha256, '')

                merged_files[file_key] = {
                    'filename': file_key,
                    'size_readable': file_info.get('size_readable', ''),
                    'size_bytes': file_info.get('size_bytes', 0),
                    'sha256': sha256,
                    'pe_version': file_info.get('pe_version'),
                    'pe_version_raw': file_info.get('pe_version_raw'),
                    'matching_folders': matching,
                    'is_nocd': is_nocd,
                    'source_folder': folder_name,
                    'category': category,
                    'category_color': category_color,
                    'community_id': community_id,
                }

        folders_data[key] = {
            'folder_name': key,
            'files': merged_files,
        }

    return folders_data


def parse_version_for_sort(version_str: str) -> Tuple[int, int, str, int]:
    """Parse version string for sorting. Returns (major, minor, letter, beta)."""
    # Handle beta versions like "1.10 Beta 1"
    beta_match = re.match(r'^(\d+)\.(\d+)\s*Beta\s*(\d+)$', version_str, re.I)
    if beta_match:
        return (int(beta_match.group(1)), int(beta_match.group(2)), '', int(beta_match.group(3)))

    # Handle regular versions like "1.09b", "1.10", "1.14d"
    match = re.match(r'^(\d+)\.(\d+)([a-z])?$', version_str, re.I)
    if match:
        return (int(match.group(1)), int(match.group(2)), match.group(3) or '', 999)

    return (0, 0, version_str, 999)


def get_sorted_version_keys(grouped: Dict) -> List[str]:
    """Get version keys sorted by version number."""
    def sort_key(key):
        # key is like "Classic/1.09b" or "LoD/1.10"
        parts = key.split('/')
        game_type = parts[0] if len(parts) > 1 else 'Unknown'
        version = parts[-1]

        # Sort by game type (Classic first), then by version
        game_order = 0 if game_type == 'Classic' else 1
        version_tuple = parse_version_for_sort(version)
        return (version_tuple[0], version_tuple[1], version_tuple[3], version_tuple[2], game_order)

    return sorted(grouped.keys(), key=sort_key)


def build_file_history_data(all_scans: List[Dict]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Build file evolution history data and community version IDs.

    Returns:
        - FILE_HISTORY_DATA: Per-file evolution across versions
        - hash_to_community_id: Mapping from hash to community version ID
    """
    # Group scans by canonical key
    grouped = defaultdict(list)
    for scan in all_scans:
        info = scan.get('folder_info', {})
        folder_name = scan.get('folder_name', '')
        key = get_canonical_key(info, folder_name)
        grouped[key].append(scan)

    # Get sorted version order
    sorted_keys = get_sorted_version_keys(grouped)

    # Build file -> hash -> versions mapping
    # filename -> {hash -> [versions in order]}
    file_hashes = defaultdict(lambda: defaultdict(list))
    file_info_cache = {}  # hash -> file info (size, pe_version, etc.)

    for key in sorted_keys:
        scans = grouped[key]
        for scan in scans:
            for filename, file_info in scan.get('files', {}).items():
                sha256 = file_info.get('sha256', '')
                if not sha256:
                    continue

                base_name = filename.split(' (')[0]  # Normalize filename

                if key not in file_hashes[base_name][sha256]:
                    file_hashes[base_name][sha256].append(key)

                # Cache file info
                if sha256 not in file_info_cache:
                    file_info_cache[sha256] = {
                        'size_bytes': file_info.get('size_bytes', 0),
                        'size_readable': file_info.get('size_readable', ''),
                        'pe_version': file_info.get('pe_version'),
                        'pe_version_raw': file_info.get('pe_version_raw'),
                    }

    # Build community version IDs and file history
    hash_to_community_id = {}
    file_history = {}

    for filename, hash_versions in file_hashes.items():
        # Sort hashes by first appearance
        sorted_hashes = sorted(
            hash_versions.items(),
            key=lambda x: sorted_keys.index(x[1][0]) if x[1] and x[1][0] in sorted_keys else 999
        )

        # First pass: count how many variants per base version
        base_version_counts = defaultdict(int)
        for sha256, versions in sorted_hashes:
            first_version = versions[0].split('/')[-1] if versions else 'unknown'
            base_version_counts[first_version] += 1

        # Second pass: assign revision numbers only when needed
        base_version_current = defaultdict(int)

        variants = []
        total_versions = len(sorted_keys)
        versions_with_file = set()
        prev_size = None

        for sha256, versions in sorted_hashes:
            first_version = versions[0].split('/')[-1] if versions else 'unknown'
            last_version = versions[-1].split('/')[-1] if versions else ''

            # Create version range for display
            if len(versions) == 1:
                version_range = first_version
            elif first_version == last_version:
                version_range = first_version
            else:
                version_range = f"{first_version}-{last_version}"

            # Option C: Game Version as Base, Dot Revision (only if multiple variants for same base)
            # Format: {first_seen_version} or {first_seen_version}.{N} if multiple variants
            base_version_current[first_version] += 1
            if base_version_counts[first_version] > 1:
                # Multiple variants for this base version - add revision number
                community_id = f"{first_version}.{base_version_current[first_version]}"
            else:
                # Only one variant for this base version - no revision needed
                community_id = first_version

            community_id_full = community_id
            origin_tag = version_range

            hash_to_community_id[sha256] = community_id

            # Get cached file info
            info = file_info_cache.get(sha256, {})
            curr_size = info.get('size_bytes', 0)

            # Calculate size delta from previous variant
            size_delta = None
            size_delta_readable = None
            if prev_size is not None and curr_size > 0:
                size_delta = curr_size - prev_size
                if size_delta >= 0:
                    size_delta_readable = f"+{format_size(abs(size_delta))}"
                else:
                    size_delta_readable = f"-{format_size(abs(size_delta))}"

            variants.append({
                'hash': sha256,
                'community_id': community_id,
                'community_id_full': community_id_full,
                'origin_tag': origin_tag,
                'first_seen': versions[0] if versions else '',
                'last_seen': versions[-1] if versions else '',
                'versions': versions,
                'version_count': len(versions),
                'size_bytes': curr_size,
                'size_readable': info.get('size_readable', ''),
                'size_delta': size_delta,
                'size_delta_readable': size_delta_readable,
                'pe_version': info.get('pe_version'),
            })

            versions_with_file.update(versions)
            prev_size = curr_size

        # Calculate stability score
        stability = len(sorted_keys) - len(variants) + 1
        stability_pct = round((stability / len(sorted_keys)) * 100) if sorted_keys else 0

        category, category_color = get_file_category(filename)

        file_history[filename] = {
            'filename': filename,
            'category': category,
            'category_color': category_color,
            'variant_count': len(variants),
            'stability_pct': stability_pct,
            'variants': variants,
        }

    return file_history, hash_to_community_id


def build_diffs_data(all_scans: List[Dict]) -> Dict[str, Any]:
    """
    Build version-to-version diff data.

    Returns dict with changes between adjacent versions.
    """
    # Group scans by canonical key
    grouped = defaultdict(list)
    for scan in all_scans:
        info = scan.get('folder_info', {})
        folder_name = scan.get('folder_name', '')
        key = get_canonical_key(info, folder_name)
        grouped[key].append(scan)

    # Get sorted version order - separate Classic and LoD
    classic_keys = [k for k in grouped.keys() if k.startswith('Classic/')]
    lod_keys = [k for k in grouped.keys() if k.startswith('LoD/')]

    classic_sorted = get_sorted_version_keys({k: grouped[k] for k in classic_keys})
    lod_sorted = get_sorted_version_keys({k: grouped[k] for k in lod_keys})

    diffs = {}

    def compute_diff(prev_key: str, curr_key: str) -> Dict:
        """Compute diff between two versions."""
        prev_files = {}
        curr_files = {}

        for scan in grouped[prev_key]:
            for filename, info in scan.get('files', {}).items():
                base_name = filename.split(' (')[0]
                if base_name not in prev_files:
                    prev_files[base_name] = info

        for scan in grouped[curr_key]:
            for filename, info in scan.get('files', {}).items():
                base_name = filename.split(' (')[0]
                if base_name not in curr_files:
                    curr_files[base_name] = info

        added = []
        removed = []
        modified = []
        unchanged = []

        all_files = set(prev_files.keys()) | set(curr_files.keys())

        for filename in all_files:
            prev_info = prev_files.get(filename)
            curr_info = curr_files.get(filename)

            if prev_info is None:
                category, color = get_file_category(filename)
                added.append({
                    'filename': filename,
                    'size_bytes': curr_info.get('size_bytes', 0),
                    'size_readable': curr_info.get('size_readable', ''),
                    'category': category,
                })
            elif curr_info is None:
                category, color = get_file_category(filename)
                removed.append({
                    'filename': filename,
                    'category': category,
                })
            elif prev_info.get('sha256') != curr_info.get('sha256'):
                category, color = get_file_category(filename)
                prev_size = prev_info.get('size_bytes', 0)
                curr_size = curr_info.get('size_bytes', 0)
                modified.append({
                    'filename': filename,
                    'prev_size': prev_size,
                    'curr_size': curr_size,
                    'size_delta': curr_size - prev_size,
                    'category': category,
                })
            else:
                unchanged.append(filename)

        return {
            'from': prev_key,
            'to': curr_key,
            'added': added,
            'removed': removed,
            'modified': modified,
            'unchanged_count': len(unchanged),
            'change_count': len(added) + len(removed) + len(modified),
        }

    # Compute diffs for Classic versions
    for i in range(1, len(classic_sorted)):
        prev_key = classic_sorted[i - 1]
        curr_key = classic_sorted[i]
        diffs[curr_key] = compute_diff(prev_key, curr_key)

    # Compute diffs for LoD versions
    for i in range(1, len(lod_sorted)):
        prev_key = lod_sorted[i - 1]
        curr_key = lod_sorted[i]
        diffs[curr_key] = compute_diff(prev_key, curr_key)

    return diffs


def build_exports_data(version_folders: List[Tuple[Path, Dict]], sorted_version_keys: List[str]) -> Dict[str, Any]:
    """
    Build export table data for DLLs/EXEs across all versions.

    Returns:
        Dictionary mapping filename to export data:
        {
            "D2Client.dll": {
                "versions": ["Classic/1.00", "Classic/1.01", ...],
                "exports": {
                    "10001": {  # ordinal as string key
                        "name": "FunctionName" or null,
                        "addresses": {
                            "Classic/1.00": "0x00001234",
                            "Classic/1.01": "0x00001234",
                            ...
                        }
                    },
                    ...
                }
            }
        }
    """
    # Group folders by canonical key
    grouped = defaultdict(list)
    for folder, folder_info in version_folders:
        game_type = folder_info.get('game_type', 'Unknown')
        version = folder_info.get('version', folder.name)
        key = f"{game_type}/{version}"
        grouped[key].append((folder, folder_info))

    exports_data = {}

    # Collect all PE files across versions
    pe_files = set()
    for key in sorted_version_keys:
        if key not in grouped:
            continue
        for folder, folder_info in grouped[key]:
            for item in folder.iterdir():
                if item.is_file() and item.suffix.lower() in ['.dll', '.exe']:
                    pe_files.add(item.name)

    print(f"  Found {len(pe_files)} PE files to analyze for exports")

    # For each PE file, collect exports across all versions
    for pe_filename in sorted(pe_files):
        file_exports = {
            'versions': [],
            'exports': {}
        }

        for key in sorted_version_keys:
            if key not in grouped:
                continue

            for folder, folder_info in grouped[key]:
                pe_path = folder / pe_filename
                if not pe_path.exists():
                    # Try case-insensitive match
                    for item in folder.iterdir():
                        if item.is_file() and item.name.lower() == pe_filename.lower():
                            pe_path = item
                            break

                if not pe_path.exists():
                    continue

                exports = extract_pe_exports(pe_path)
                if not exports:
                    continue

                # Record this version has the file
                if key not in file_exports['versions']:
                    file_exports['versions'].append(key)

                # Record each export's address for this version
                for exp in exports:
                    ordinal_key = str(exp['ordinal'])

                    if ordinal_key not in file_exports['exports']:
                        file_exports['exports'][ordinal_key] = {
                            'ordinal': exp['ordinal'],
                            'name': exp.get('name'),
                            'addresses': {}
                        }

                    # Update name if we find one (some versions may have names, others not)
                    if exp.get('name') and not file_exports['exports'][ordinal_key]['name']:
                        file_exports['exports'][ordinal_key]['name'] = exp['name']

                    file_exports['exports'][ordinal_key]['addresses'][key] = exp['address']

        # Only include files that have exports
        if file_exports['exports']:
            exports_data[pe_filename] = file_exports
            print(f"    {pe_filename}: {len(file_exports['exports'])} exports across {len(file_exports['versions'])} versions")

    return exports_data


def generate_viewer_data(base_path: Path = None, output_dir: Path = None) -> Dict[str, Path]:
    """Generate consolidated viewer data for three-panel viewer."""
    if base_path is None:
        base_path = get_project_root()

    if output_dir is None:
        output_dir = base_path / 'reports'

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Generating consolidated viewer data...")
    print(f"Project root: {base_path}")

    # Find and scan all version folders
    version_folders = find_version_folders(base_path)
    print(f"Found {len(version_folders)} version folders")

    all_scans = []
    for folder, folder_info in version_folders:
        print(f"  Scanning: {folder_info['folder_name']}...")
        scan = scan_folder(folder, include_subdirs=False, folder_info=folder_info)
        all_scans.append(scan)

    # Build file history first (needed for community IDs)
    print("Building FILE_HISTORY_DATA...")
    file_history_data, hash_to_community_id = build_file_history_data(all_scans)

    # Build consolidated data
    print("Building VERSIONS_DATA...")
    versions_data = build_versions_data(all_scans)

    print("Building FOLDERS_DATA...")
    folders_data = build_folders_data(all_scans, hash_to_community_id)

    print("Building DIFFS_DATA...")
    diffs_data = build_diffs_data(all_scans)

    # Build sorted version keys for exports
    print("Building EXPORTS_DATA...")
    # Get sorted version keys from versions_data
    sorted_version_keys = []
    for v in versions_data:
        sorted_version_keys.append(v['folder_name'])
    exports_data = build_exports_data(version_folders, sorted_version_keys)

    # Add change counts to versions_data
    for version in versions_data:
        key = version['folder_name']
        if key in diffs_data:
            version['change_count'] = diffs_data[key]['change_count']
        else:
            version['change_count'] = 0

    # Generate JavaScript file
    js_content = f"""// Auto-generated by gen_viewer_data.py
// Generated: {datetime.now().isoformat()}
// Three-panel viewer data for D2 Version Archive

// File categories with D2 item rarity colors
const FILE_CATEGORIES = {json.dumps(FILE_CATEGORIES, separators=(',', ':'))};

// Lightweight version summaries for Panel 1
const VERSIONS_DATA = {json.dumps(versions_data, separators=(',', ':'))};

// Detailed folder/file data for Panel 2
const FOLDERS_DATA = {json.dumps(folders_data, separators=(',', ':'))};

// File evolution history for Panel 3
const FILE_HISTORY_DATA = {json.dumps(file_history_data, separators=(',', ':'))};

// Version-to-version diffs
const DIFFS_DATA = {json.dumps(diffs_data, separators=(',', ':'))};

// PE Export tables for DLLs/EXEs (ordinal -> address per version)
const EXPORTS_DATA = {json.dumps(exports_data, separators=(',', ':'))};
"""

    js_path = output_dir / 'd2_data.js'
    with open(js_path, 'w', encoding='utf-8') as f:
        f.write(js_content)

    print(f"\nGenerated {js_path}")
    print(f"  VERSIONS_DATA: {len(versions_data)} versions")
    print(f"  FOLDERS_DATA: {len(folders_data)} folders")
    print(f"  FILE_HISTORY_DATA: {len(file_history_data)} files tracked")
    print(f"  DIFFS_DATA: {len(diffs_data)} version diffs")
    print(f"  EXPORTS_DATA: {len(exports_data)} PE files with exports")

    return {'js': js_path}


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate consolidated viewer data")
    parser.add_argument("-p", "--path", type=str, help="Project root path")
    parser.add_argument("-o", "--output", type=str, help="Output directory")
    
    args = parser.parse_args()
    
    base_path = Path(args.path).resolve() if args.path else None
    output_path = Path(args.output).resolve() if args.output else None
    
    try:
        generate_viewer_data(base_path, output_path)
        return 0
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit(main())
