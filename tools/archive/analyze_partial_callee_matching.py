#!/usr/bin/env python3
"""
Analyze partial callee matching for functions that changed across compiler boundaries.

The key insight is that even if the callee SET changed, the COMMON callees
(especially domain-specific ones like ClearMapCellFlagRadius, ApplyTileAttributePattern)
can still provide strong matching signals when combined with other factors.
"""

import json
from collections import defaultdict


def normalize_callee_set(callees: list) -> set:
    """Extract callee names, ignoring ordinals and FUN_ prefixes."""
    named = set()
    ordinals = set()
    funs = set()

    for c in callees:
        if c.startswith("Ordinal_"):
            ordinals.add(c)
        elif c.startswith("FUN_"):
            funs.add(c)
        else:
            named.add(c)

    return named, ordinals, funs


def analyze_function_pair():
    """Analyze the ValidateRegionWithAlternative case."""

    data_09d = json.load(open("data/function_index/LoD/1.09d/D2Common.dll.json"))
    data_110 = json.load(open("data/function_index/LoD/1.10/D2Common.dll.json"))

    # Find ValidateRegionWithAlternative in 1.09d
    func_09d = [f for f in data_09d["functions"] if f.get("address") == "0x6FD438F0"][0]

    # Find FUN_6fd44ff0 in 1.10
    func_110 = [f for f in data_110["functions"] if f.get("address") == "0x6FD44FF0"][0]

    print("=" * 70)
    print("ValidateRegionWithAlternative (1.09d) vs FUN_6fd44ff0 (1.10)")
    print("=" * 70)

    # Callees
    callees_09d = func_09d.get("api_calls", [])
    callees_110 = func_110.get("api_calls", [])

    print(f"\n1.09d callees: {callees_09d}")
    print(f"1.10 callees:  {callees_110}")

    named_09d, ord_09d, fun_09d = normalize_callee_set(callees_09d)
    named_110, ord_110, fun_110 = normalize_callee_set(callees_110)

    print(f"\nNamed callees in 1.09d: {named_09d}")
    print(f"Named callees in 1.10:  {named_110}")

    common_named = named_09d & named_110
    print(f"\nCommon named callees: {common_named}")

    # Size comparison
    size_09d = func_09d.get("size", 0)
    size_110 = func_110.get("size", 0)
    size_ratio = (
        min(size_09d, size_110) / max(size_09d, size_110)
        if max(size_09d, size_110) > 0
        else 0
    )

    print(f"\nSize: 1.09d={size_09d}, 1.10={size_110}, ratio={size_ratio:.2%}")

    # Now let's see how UNIQUE these common callees are
    print("\n" + "-" * 70)
    print("How unique are ClearMapCellFlagRadius + ApplyTileAttributePattern?")
    print("-" * 70)

    # Find all functions in 1.10 that call both
    callers_of_both = []
    for f in data_110["functions"]:
        callees = f.get("api_calls", [])
        if (
            "ClearMapCellFlagRadius" in callees
            and "ApplyTileAttributePattern" in callees
        ):
            callers_of_both.append((f.get("address"), f.get("name"), f.get("size")))

    print(
        f"\nFunctions in 1.10 calling both ClearMapCellFlagRadius AND ApplyTileAttributePattern:"
    )
    for addr, name, size in callers_of_both:
        print(f"  {addr}: {name} (size {size})")

    # Now check which of these has the closest size to 1.09d
    print("\n" + "-" * 70)
    print("Size-based ranking of candidates:")
    print("-" * 70)

    candidates = []
    for addr, name, size in callers_of_both:
        if size and size_09d:
            ratio = min(size, size_09d) / max(size, size_09d)
            candidates.append((ratio, addr, name, size))

    for ratio, addr, name, size in sorted(candidates, reverse=True):
        print(f"  {ratio:.1%} match: {addr} {name} (size {size})")

    # Signature comparison
    print("\n" + "-" * 70)
    print("Signature analysis:")
    print("-" * 70)
    print(f"1.09d signature: {func_09d.get('signature')}")
    print(f"1.10 signature:  {func_110.get('signature')}")


def propose_matching_strategy():
    """Propose an enhanced matching strategy."""

    print("\n" + "=" * 70)
    print("PROPOSED MATCHING STRATEGY")
    print("=" * 70)

    print(
        """
For functions that fail the normal 80% callee overlap threshold,
add a "domain callee" matching tier:

1. Extract NAMED (non-ordinal, non-FUN_) callees from both functions
2. If 2+ named callees match AND they're relatively unique in the codebase:
   - Weight = 0.4 (moderate confidence)
   
3. Combine with size proximity:
   - If size ratio >= 0.7: +0.2
   - If size ratio >= 0.8: +0.3
   
4. Combined score can reach 0.6-0.7, enough to suggest as a candidate

For ValidateRegionWithAlternative:
- Common named callees: ClearMapCellFlagRadius, ApplyTileAttributePattern (2 matches)
- Size ratio: 454/536 = 84.7%
- Proposed score: 0.4 (domain callees) + 0.3 (size) = 0.7

This would be enough to at least SUGGEST the match, even if not auto-apply it.
"""
    )


if __name__ == "__main__":
    analyze_function_pair()
    propose_matching_strategy()
