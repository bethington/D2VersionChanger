#!/usr/bin/env python3
"""
Generate consolidated data for the D2 Report Viewer.

This creates TWO optimized data structures:
1. VERSIONS_DATA - Lightweight array for the main versions table
2. FOLDERS_DATA - Detailed file data with pre-computed hash matching

This replaces the 6 separate JSON files with 2 focused datasets.
"""
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any

# Import from the main hash tool
import sys
sys.path.insert(0, str(Path(__file__).parent))

from d2_hash_tool import (
    get_project_root,
    find_version_folders,
    scan_folder,
)


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


def build_folders_data(all_scans: List[Dict]) -> Dict[str, Any]:
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
                }
        
        folders_data[key] = {
            'folder_name': key,
            'files': merged_files,
        }
    
    return folders_data


def generate_viewer_data(base_path: Path = None, output_dir: Path = None) -> Dict[str, Path]:
    """Generate consolidated viewer data."""
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
    
    # Build consolidated data
    print("Building VERSIONS_DATA...")
    versions_data = build_versions_data(all_scans)
    
    print("Building FOLDERS_DATA...")
    folders_data = build_folders_data(all_scans)
    
    # Generate JavaScript file
    js_content = f"""// Auto-generated by gen_viewer_data.py
// Generated: {datetime.now().isoformat()}
// Consolidated data for D2 Report Viewer

// Lightweight version summaries for the main table
const VERSIONS_DATA = {json.dumps(versions_data, separators=(',', ':'))};

// Detailed folder/file data with pre-computed hash matching
const FOLDERS_DATA = {json.dumps(folders_data, separators=(',', ':'))};
"""
    
    js_path = output_dir / 'd2_data.js'
    with open(js_path, 'w', encoding='utf-8') as f:
        f.write(js_content)
    
    print(f"\n✓ Generated {js_path}")
    print(f"  VERSIONS_DATA: {len(versions_data)} versions")
    print(f"  FOLDERS_DATA: {len(folders_data)} folders")
    
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
