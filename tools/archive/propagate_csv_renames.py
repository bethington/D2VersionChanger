#!/usr/bin/env python3
"""
Propagate CSV renames across all LoD versions.
Uses cross-version function matching to apply 1.10 renames to other versions.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional

REPORTS_PATH = Path("reports")
FUNCTION_INDEX_PATH = Path("data/function_index")

# CSV renames already applied
CSV_RENAMES = {
    "LoD": {
        "1.10": {
            "D2Common": [
                ("0x6FDA6790", "MONSTERS_ApplyClassicScaling"),
                ("0x6FDAC270", "PATH_ComputePathOrSlideAlongObstacles"),
                ("0x6FDABAC0", "PATH_FindSubpathWithoutObstacles"),
                ("0x6FDAC170", "PATH_SimplifyToLines"),
            ],
            "D2Game": [
                ("0x6FC34A80", "EVENT_FreeEventQueue"),
                ("0x6FC36280", "GAME_ReceiveDatabaseCharacter"),
            ],
            "D2Win": [
                ("0x6F8AFDC0", "D2Win_10043_TEXTBOX_Destroy"),
            ],
        },
        "1.13c": {
            "D2Common": [
                ("0x6FD5DDC0", "D2Common_10231_Impl"),
                ("0x6FD51250", "DATATBLS_GetSkillsTxtRecord"),
                ("0x6FDA3780", "DATATBLS_NewTreasureClassEx"),
                ("0x6FDA4430", "DATATBLS_ParseTreasureClassItem"),
                ("0x6FDCB220", "PATH_AStar_PopBestScoreForVisit"),
                ("0x6FDCB2C0", "PATH_AStar_TargetLocationHasEnoughRoom"),
                ("0x6FDC0650", "PATH_IDAStar_FlushNodeToDynamicPath"),
                ("0x6FDC0BB0", "PATH_IdaStar_ComputePathWithRooms"),
                ("0x6FD85E00", "PATH_PreparePathTargetForPathUpdate"),
                ("0x6FD5DC80", "PATH_StopMovement"),
                ("0x6FD7FAC0", "UNITS_AnimModeAllowsAnimSpeed"),
                ("0x6FD80BD0", "UNITS_CanAnimModeUseAttackRate"),
                ("0x6FD7EF90", "UNITS_IsAnimModeBlocking"),
                ("0x6FD7EFC0", "UNITS_IsAnimModeGetHit"),
                ("0x6FD7F010", "UNITS_IsAnimModeKnockBack"),
                ("0x6FD80B80", "UNITS_IsSeqAnimSpeedModulatedByFCR"),
                ("0x6FD5CEB0", "sub_6FD5CEB0"),
                ("0x6FD5DB70", "sub_6FD5DB70"),
                ("0x6FDC0840", "sub_6FDC0840"),
            ],
            "D2Game": [
                ("0x6FCAE540", "EVENT_AllocateTimer"),
                ("0x6FC89B00", "OBJMODE_GetToHitPercentage"),
            ],
        },
    },
    "Classic": {
        "1.00": {
            "D2Game": [
                ("0x100056D0", "GAME_ReceiveDatabaseCharacter"),
            ],
        }
    }
}


def find_function_in_index(func_data: Dict, target_address: str) -> Tuple[Optional[Dict], int]:
    """Find function by address in index data."""
    functions = func_data.get("functions", [])
    for idx, func in enumerate(functions):
        if func.get("address") == target_address:
            return func, idx
    return None, -1


def apply_rename_to_version(module: str, game_type: str, version: str, address: str, new_name: str) -> Tuple[bool, str]:
    """Apply a single rename to a specific version."""
    file_path = FUNCTION_INDEX_PATH / game_type / version / f"{module}.dll.json"

    if not file_path.exists():
        return False, f"File not found: {file_path}"

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Find function by address
        func, idx = find_function_in_index(data, address)
        if func is None:
            return False, f"Function not found at {address}"

        # Apply rename
        old_name = func.get("name")
        data["functions"][idx]["name"] = new_name
        data["functions"][idx]["display_name"] = new_name

        # Write back
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        return True, f"Renamed {old_name} -> {new_name}"

    except Exception as e:
        return False, f"Error: {str(e)}"


def propagate_renames_using_matcher(module: str, source_version: str, source_address: str,
                                     new_name: str, game_type: str = "LoD") -> Dict:
    """
    Propagate a rename across all versions using cross-version matcher results.
    """
    # Load cross-version index
    index_file = REPORTS_PATH / "cross_version_function_index.json"
    if not index_file.exists():
        return {
            "success": False,
            "error": "Cross-version index not found. Run cross_version_function_matcher.py first."
        }

    with open(index_file, 'r', encoding='utf-8') as f:
        cross_index = json.load(f)

    propagation = {
        "source_module": module,
        "source_version": source_version,
        "source_address": source_address,
        "new_name": new_name,
        "game_type": game_type,
        "versions_attempted": 0,
        "versions_succeeded": 0,
        "versions_failed": 0,
        "results": {}
    }

    # Load 1.10 index to find source function
    v110_file = FUNCTION_INDEX_PATH / game_type / source_version / f"{module}.dll.json"
    with open(v110_file, 'r', encoding='utf-8') as f:
        v110_data = json.load(f)

    source_func, _ = find_function_in_index(v110_data, source_address)
    if source_func is None:
        propagation["success"] = False
        propagation["error"] = f"Source function not found at {source_address}"
        return propagation

    source_name = source_func.get("name")
    source_api = source_func.get("indexes", {}).get("API")
    source_mne = source_func.get("indexes", {}).get("MNE")

    # Get matching functions from cross-version index
    if module not in cross_index.get("modules", {}):
        propagation["success"] = False
        propagation["error"] = f"Module {module} not in cross-version index"
        return propagation

    # Find this specific function's matches
    matches = None
    for func_match in cross_index["modules"][module].get("functions", []):
        if func_match.get("source_address") == source_address:
            matches = func_match.get("matches", {})
            break

    if matches is None:
        propagation["success"] = False
        propagation["error"] = f"Function matches not found in cross-version index"
        return propagation

    # Apply rename to matching versions
    for target_version, match_info in matches.items():
        if target_version == source_version:
            continue  # Already renamed in source

        propagation["versions_attempted"] += 1
        target_address = match_info.get("address")
        match_type = match_info.get("match_type")

        if not target_address:
            propagation["results"][target_version] = {
                "success": False,
                "reason": "No address match found"
            }
            propagation["versions_failed"] += 1
            continue

        # Only apply to high-confidence matches
        confidence = match_info.get("confidence")
        if confidence not in ["high", "medium"]:
            propagation["results"][target_version] = {
                "success": False,
                "reason": f"Low confidence match ({confidence})"
            }
            propagation["versions_failed"] += 1
            continue

        # Apply rename
        success, message = apply_rename_to_version(module, game_type, target_version, target_address, new_name)

        if success:
            propagation["results"][target_version] = {
                "success": True,
                "address": target_address,
                "match_type": match_type,
                "message": message
            }
            propagation["versions_succeeded"] += 1
        else:
            propagation["results"][target_version] = {
                "success": False,
                "reason": message
            }
            propagation["versions_failed"] += 1

    propagation["success"] = propagation["versions_succeeded"] > 0
    return propagation


def main():
    """Propagate all CSV renames across versions."""
    print("="*70)
    print("Propagating CSV Renames Across LoD Versions")
    print("="*70)

    all_propagations = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "baseline_version": "1.10",
        "propagations": [],
        "summary": {
            "total_renames": 0,
            "successful_propagations": 0,
            "failed_propagations": 0,
            "versions_updated": set()
        }
    }

    # Process each CSV rename
    total_renames = 0
    for game_type, versions in CSV_RENAMES.items():
        for base_version, modules in versions.items():
            for module, renames in modules.items():
                for address, new_name in renames:
                    total_renames += 1

    print(f"Found {total_renames} CSV renames to propagate\n")

    rename_count = 0
    for game_type, versions in CSV_RENAMES.items():
        for base_version, modules in versions.items():
            for module, renames in modules.items():
                for address, new_name in renames:
                    rename_count += 1
                    print(f"[{rename_count}/{total_renames}] Propagating {module}:{address} -> {new_name}")

                    prop = propagate_renames_using_matcher(module, base_version, address, new_name, game_type)
                    all_propagations["propagations"].append(prop)

                    if prop.get("success"):
                        print(f"  [OK] Propagated to {prop['versions_succeeded']} versions")
                        all_propagations["summary"]["successful_propagations"] += 1
                    else:
                        print(f"  [FAIL] Failed: {prop.get('error', 'Unknown error')}")
                        all_propagations["summary"]["failed_propagations"] += 1

                    # Track updated versions
                    for version in prop.get("results", {}).keys():
                        if prop["results"][version].get("success"):
                            all_propagations["summary"]["versions_updated"].add(version)

    # Convert set to sorted list for JSON serialization
    all_propagations["summary"]["versions_updated"] = sorted(list(all_propagations["summary"]["versions_updated"]))
    all_propagations["summary"]["total_renames"] = total_renames

    # Save propagation report
    output_file = REPORTS_PATH / "csv_rename_propagation_report.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_propagations, f, indent=2)

    print("\n" + "="*70)
    print("PROPAGATION SUMMARY")
    print("="*70)
    print(f"Total Renames: {total_renames}")
    print(f"Successful: {all_propagations['summary']['successful_propagations']}")
    print(f"Failed: {all_propagations['summary']['failed_propagations']}")
    print(f"Versions Updated: {', '.join(all_propagations['summary']['versions_updated'])}")
    print(f"\nReport saved to {output_file}")


if __name__ == "__main__":
    main()
