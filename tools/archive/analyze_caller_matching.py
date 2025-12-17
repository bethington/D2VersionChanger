#!/usr/bin/env python3
"""
Caller-based matching analysis.

Theory: If function X calls function A in version V1, and we've already matched X to version V2,
then whatever X calls in V2 at similar positions is likely the same as A.

This is especially useful across compiler boundaries where the CALLEE's code changes
but the CALLER's relationship to it remains stable.
"""

import json
from pathlib import Path
from collections import defaultdict


def load_version(version_path: Path, dll: str) -> dict:
    """Load function data for a DLL in a specific version."""
    json_file = version_path / f"{dll}.json"
    if not json_file.exists():
        return {}
    with open(json_file) as f:
        data = json.load(f)
    return {func["address"]: func for func in data.get("functions", [])}


def build_callers_map(functions: dict) -> dict:
    """Build a reverse map: callee_name -> list of caller addresses."""
    callers = defaultdict(list)
    for addr, func in functions.items():
        for callee in func.get("api_calls", []):
            callers[callee].append(addr)
    return dict(callers)


def analyze_validate_region():
    """Analyze ValidateRegionWithAlternative caller patterns."""
    base = Path("data/function_index")

    # Load 1.09d
    funcs_09d = load_version(base / "LoD" / "1.09d", "D2Common.dll")
    callers_09d = build_callers_map(funcs_09d)

    # Load 1.10
    funcs_110 = load_version(base / "LoD" / "1.10", "D2Common.dll")
    callers_110 = build_callers_map(funcs_110)

    # The function we're trying to match
    target_name = "ValidateRegionWithAlternative"
    target_09d_addr = "0x6FD438F0"
    target_110_addr = "0x6FD44FF0"  # Expected match

    print(f"Analyzing: {target_name}")
    print(f"  1.09d address: {target_09d_addr}")
    print(f"  1.10 expected: {target_110_addr}")
    print()

    # Find callers of ValidateRegionWithAlternative in 1.09d
    callers_of_target = callers_09d.get(target_name, [])
    print(f"Callers in 1.09d ({len(callers_of_target)}):")

    for caller_addr in callers_of_target[:10]:
        caller = funcs_09d.get(caller_addr, {})
        caller_name = caller.get("name", "unnamed")
        print(f"  {caller_name} @ {caller_addr}")

        # Check what this caller calls
        callees = caller.get("api_calls", [])
        print(f"    Callees: {callees[:5]}...")

    print()

    # Now check if any named callers exist in 1.10 with the same name
    print("Tracking callers to 1.10:")
    for caller_addr in callers_of_target:
        caller = funcs_09d.get(caller_addr, {})
        caller_name = caller.get("name", "unnamed")

        if caller_name.startswith("FUN_"):
            continue

        # Find this caller in 1.10 by name
        caller_110 = None
        for addr, func in funcs_110.items():
            if func.get("name") == caller_name:
                caller_110 = func
                break

        if caller_110:
            print(f"\n  {caller_name}:")
            print(f"    1.09d: {caller_addr}")
            print(f"    1.10:  {caller_110.get('address')}")

            # What does this caller call in 1.10?
            callees_110 = caller_110.get("api_calls", [])
            print(f"    1.10 callees: {callees_110}")

            # Check if any callee looks like our target
            if target_110_addr in str(callees_110).lower():
                print(f"    *** FOUND! Calls {target_110_addr} ***")

            # Check for ordinals or FUN_ functions at similar positions
            for i, callee in enumerate(callees_110):
                if "Ordinal" in callee or callee.startswith("FUN_"):
                    # This is a candidate for the renamed function
                    orig_callees = caller.get("api_calls", [])
                    if i < len(orig_callees) and orig_callees[i] == target_name:
                        print(f"    Position match! {target_name} -> {callee}")


def analyze_call_patterns():
    """
    More comprehensive analysis: For unmatched functions with good callees,
    can we use caller matching?
    """
    base = Path("data/function_index")

    # Load both versions
    funcs_09d = load_version(base / "LoD" / "1.09d", "D2Common.dll")
    funcs_110 = load_version(base / "LoD" / "1.10", "D2Common.dll")

    # Build name -> addr maps
    name_to_addr_09d = {
        f.get("name"): addr for addr, f in funcs_09d.items() if f.get("name")
    }
    name_to_addr_110 = {
        f.get("name"): addr for addr, f in funcs_110.items() if f.get("name")
    }

    print("\n" + "=" * 70)
    print("CALL GRAPH MATCHING ANALYSIS")
    print("=" * 70)

    # For each named function in 1.09d that doesn't have a direct name match in 1.10
    unmatched_count = 0
    matchable_by_caller = 0

    for addr, func in funcs_09d.items():
        name = func.get("name", "")
        if not name or name.startswith("FUN_"):
            continue

        # Check if there's a direct name match in 1.10
        if name in name_to_addr_110:
            continue  # Already matchable by name

        unmatched_count += 1

        # Find callers of this function in 1.09d
        callers = []
        for caller_addr, caller_func in funcs_09d.items():
            if name in caller_func.get("api_calls", []):
                callers.append((caller_addr, caller_func))

        # Check if any callers have name matches in 1.10
        matched_callers = []
        for caller_addr, caller_func in callers:
            caller_name = caller_func.get("name", "")
            if (
                caller_name
                and not caller_name.startswith("FUN_")
                and caller_name in name_to_addr_110
            ):
                matched_callers.append((caller_name, caller_addr))

        if matched_callers:
            matchable_by_caller += 1
            print(f"\n{name} @ {addr}:")
            print(
                f"  Has {len(callers)} callers, {len(matched_callers)} are named & matched to 1.10"
            )
            for cn, ca in matched_callers[:3]:
                print(f"    Caller: {cn}")

    print(f"\n\nSummary:")
    print(
        f"  Named functions in 1.09d without direct 1.10 name match: {unmatched_count}"
    )
    print(f"  Of these, matchable by caller analysis: {matchable_by_caller}")


if __name__ == "__main__":
    analyze_validate_region()
    analyze_call_patterns()
