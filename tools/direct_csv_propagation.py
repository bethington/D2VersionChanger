#!/usr/bin/env python3
"""
Direct CSV rename propagation using generated 1.10 mappings.
Uses the 1_10_*_complete_mapping.json files to find target addresses.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPORTS_PATH = Path("reports")
FUNCTION_INDEX_PATH = Path("data/function_index")

# CSV renames to propagate (source: 1.10)
CSV_RENAMES_SOURCE = {
    "D2Common": [
        ("0x6FDA6790", "MONSTERS_ApplyClassicScaling"),
        ("0x6FDAC270", "PATH_ComputePathOrSlideAlongObstacles"),
        ("0x6FDABAC0", "PATH_FindSubpathWithoutObstacles"),
        ("0x6FDAC170", "PATH_SimplifyToLines"),
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
        ("0x6FC34A80", "EVENT_FreeEventQueue"),
        ("0x6FC36280", "GAME_ReceiveDatabaseCharacter"),
        ("0x6FCAE540", "EVENT_AllocateTimer"),
        ("0x6FC89B00", "OBJMODE_GetToHitPercentage"),
    ],
    "D2Win": [
        ("0x6F8AFDC0", "D2Win_10043_TEXTBOX_Destroy"),
    ],
}


def load_mapping_file(module: str) -> Optional[Dict]:
    """Load the 1.10 cross-version mapping for a module."""
    file_path = REPORTS_PATH / f"1_10_{module.lower()}_complete_mapping.json"
    if not file_path.exists():
        print(f"  Warning: Mapping file not found: {file_path}")
        return None

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"  Error loading mapping: {e}")
        return None


def find_function_by_address(func_data: Dict, address: str) -> Tuple[Optional[Dict], int]:
    """Find function by address."""
    functions = func_data.get("functions", [])
    for idx, func in enumerate(functions):
        if func.get("address") == address:
            return func, idx
    return None, -1


def apply_rename(module: str, game_type: str, version: str, address: str, new_name: str) -> Tuple[bool, str]:
    """Apply rename to a specific version."""
    file_path = FUNCTION_INDEX_PATH / game_type / version / f"{module}.dll.json"

    if not file_path.exists():
        return False, "File not found"

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        func, idx = find_function_by_address(data, address)
        if func is None:
            return False, "Function not found at address"

        old_name = func.get("name")
        data["functions"][idx]["name"] = new_name
        data["functions"][idx]["display_name"] = new_name

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        return True, f"{old_name} -> {new_name}"

    except Exception as e:
        return False, str(e)


def propagate_csv_rename(module: str, v110_address: str, new_name: str) -> Dict:
    """
    Propagate a single CSV rename across versions using mapping data.
    """
    result = {
        "module": module,
        "v110_address": v110_address,
        "new_name": new_name,
        "versions": {},
        "summary": {
            "total_versions": 0,
            "successful": 0,
            "failed": 0,
        }
    }

    # Load mapping
    mapping = load_mapping_file(module)
    if not mapping:
        result["error"] = "Could not load mapping"
        return result

    # Find function in mapping
    target_func = None
    for func in mapping.get("functions", []):
        if func.get("version_addresses", {}).get("1.10", {}).get("address") == v110_address:
            target_func = func
            break

    if not target_func:
        result["error"] = f"Function not found at {v110_address}"
        return result

    # Get addresses from all versions
    version_addresses = target_func.get("version_addresses", {})

    # Apply rename to each version
    for version in sorted(version_addresses.keys()):
        if version == "1.10":
            # Already renamed in source
            result["versions"][version] = {
                "status": "source_baseline",
                "new_name": new_name
            }
            result["summary"]["successful"] += 1
            result["summary"]["total_versions"] += 1
            continue

        address_info = version_addresses.get(version)
        if not address_info or not address_info.get("address"):
            result["versions"][version] = {
                "status": "no_match",
            }
            result["summary"]["failed"] += 1
            result["summary"]["total_versions"] += 1
            continue

        target_address = address_info.get("address")
        success, message = apply_rename(module, "LoD", version, target_address, new_name)

        result["versions"][version] = {
            "status": "success" if success else "failed",
            "address": target_address,
            "message": message,
        }

        if success:
            result["summary"]["successful"] += 1
        else:
            result["summary"]["failed"] += 1

        result["summary"]["total_versions"] += 1

    return result


def main():
    """Main execution."""
    print("="*70)
    print("Direct CSV Rename Propagation")
    print("="*70)

    all_results = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "baseline_version": "1.10",
        "propagations": [],
        "summary": {
            "total_renames": 0,
            "successful_renames": 0,
            "failed_renames": 0,
            "versions_affected": set(),
        }
    }

    total_renames = sum(len(addrs) for addrs in CSV_RENAMES_SOURCE.values())
    rename_count = 0

    for module, renames in CSV_RENAMES_SOURCE.items():
        print(f"\n{module}: {len(renames)} renames")
        for address, new_name in renames:
            rename_count += 1
            print(f"  [{rename_count}/{total_renames}] {address} -> {new_name}")

            prop = propagate_csv_rename(module, address, new_name)
            all_results["propagations"].append(prop)

            if "error" in prop:
                print(f"    [ERROR] {prop['error']}")
                all_results["summary"]["failed_renames"] += 1
            else:
                success_count = prop["summary"]["successful"]
                total_count = prop["summary"]["total_versions"]
                print(f"    [{success_count}/{total_count}] versions updated")

                if success_count > 0:
                    all_results["summary"]["successful_renames"] += 1
                else:
                    all_results["summary"]["failed_renames"] += 1

                # Track versions
                for version in prop.get("versions", {}).keys():
                    if prop["versions"][version].get("status") == "success":
                        all_results["summary"]["versions_affected"].add(version)

    # Convert set to sorted list
    all_results["summary"]["versions_affected"] = sorted(list(all_results["summary"]["versions_affected"]))
    all_results["summary"]["total_renames"] = total_renames

    # Save report
    output_file = REPORTS_PATH / "csv_rename_propagation_report.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2)

    # Print summary
    print("\n" + "="*70)
    print("PROPAGATION SUMMARY")
    print("="*70)
    print(f"Total Renames: {total_renames}")
    print(f"Successful: {all_results['summary']['successful_renames']}")
    print(f"Failed: {all_results['summary']['failed_renames']}")
    print(f"Versions Updated: {len(all_results['summary']['versions_affected'])}")
    if all_results['summary']['versions_affected']:
        print(f"  {', '.join(all_results['summary']['versions_affected'])}")
    print(f"\nReport saved to {output_file}")


if __name__ == "__main__":
    main()
