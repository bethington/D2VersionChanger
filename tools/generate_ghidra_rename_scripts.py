#!/usr/bin/env python3
"""
Generate Ghidra batch rename scripts for all-version functions.
Creates scripts for each module and version to apply cross-version naming.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple

REPORTS_PATH = Path("reports")
FUNCTION_INDEX_PATH = Path("data/function_index")
GHIDRA_SCRIPTS_PATH = Path("ghidra_scripts")

LOD_VERSIONS = ["1.07", "1.08", "1.09", "1.09b", "1.09d", "1.10", "1.11", "1.11b", "1.12a", "1.13c", "1.13d"]
MODULES = ["D2Game", "D2Client", "D2Common", "D2Win", "Storm", "Fog"]


def load_unified_index() -> Dict:
    """Load unified function index."""
    index_file = REPORTS_PATH / "unified_function_index.json"
    with open(index_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_priority_tiers() -> Dict:
    """Load priority tier information."""
    tiers_file = REPORTS_PATH / "renaming_priority_tiers.json"
    with open(tiers_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_all_version_functions_for_module(unified: Dict, module: str) -> List[Dict]:
    """Get all-version functions for a specific module."""
    module_data = unified.get("modules", {}).get(module, {})
    all_version_funcs = []

    for func in module_data.get("functions", []):
        if func.get("consistency_level") == 11:
            all_version_funcs.append(func)

    return sorted(all_version_funcs, key=lambda x: x["name"])


def generate_java_script_header(module: str, version: str, total_renames: int) -> str:
    """Generate header for Ghidra Java script."""
    return f"""// Auto-generated Ghidra rename script
// Module: {module}
// Version: {version}
// Generated: Cross-version renaming (Phase 4)
// Total renames: {total_renames}
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply {module} {version} Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class Rename{module}{version} extends GhidraScript {{

    @Override
    protected void run() throws Exception {{
        if (currentProgram == null) {{
            println("No program loaded");
            return;
        }}

        int successCount = 0;
        int failureCount = 0;

        Listing listing = currentProgram.getListing();

"""


def generate_java_rename_statement(address: str, new_name: str) -> str:
    """Generate a single rename statement for Java script."""
    return f"""        try {{
            Address addr = currentProgram.getAddressFactory().getAddress("{address}");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {{
                func.setName("{new_name}", SourceType.USER_DEFINED);
                successCount++;
            }} else {{
                println("  WARNING: No function at {address}");
                failureCount++;
            }}
        }} catch (Exception e) {{
            println("  ERROR at {address}: " + e.getMessage());
            failureCount++;
        }}
"""


def generate_java_script_footer(module: str, version: str) -> str:
    """Generate footer for Ghidra Java script."""
    return f"""
        println("");
        println("{module} {version} Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }}
}}
"""


def generate_module_version_script(module: str, version: str, renames: List[Tuple[str, str]]) -> str:
    """Generate complete rename script for a module/version combination."""
    script = generate_java_script_header(module, version, len(renames))

    for address, new_name in renames:
        script += generate_java_rename_statement(address, new_name)

    script += generate_java_script_footer(module, version)

    return script


def generate_all_scripts(unified: Dict) -> Dict:
    """Generate Ghidra scripts for all modules and versions."""
    print("="*70)
    print("Generating Ghidra Rename Scripts")
    print("="*70)

    GHIDRA_SCRIPTS_PATH.mkdir(exist_ok=True)

    generated_scripts = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "scripts": [],
        "summary": {
            "total_scripts": 0,
            "total_renames": 0,
            "by_module": {}
        }
    }

    # Generate script for each module
    for module in MODULES:
        print(f"\nGenerating scripts for {module}...")

        # Get all-version functions for this module
        all_version_funcs = get_all_version_functions_for_module(unified, module)

        if not all_version_funcs:
            print(f"  No all-version functions found for {module}")
            continue

        module_renames_total = 0

        # Generate script for each version
        for version in LOD_VERSIONS:
            # Find addresses for this version
            renames = []
            for func in all_version_funcs:
                addresses = func.get("addresses", {})
                if version in addresses:
                    address = addresses[version]
                    func_name = func.get("name")
                    renames.append((address, func_name))

            if renames:
                # Generate script
                script_content = generate_module_version_script(module, version, renames)

                # Save script
                script_name = f"D2VersionChanger_Rename{module}_{version.replace('.', '_')}"
                script_file = GHIDRA_SCRIPTS_PATH / f"{script_name}.java"

                with open(script_file, 'w', encoding='utf-8') as f:
                    f.write(script_content)

                print(f"  Generated {script_file.name} ({len(renames)} renames)")

                generated_scripts["scripts"].append({
                    "module": module,
                    "version": version,
                    "script_file": script_file.name,
                    "renames": len(renames)
                })

                generated_scripts["summary"]["total_scripts"] += 1
                module_renames_total += len(renames)
                generated_scripts["summary"]["total_renames"] += len(renames)

        if module_renames_total > 0:
            generated_scripts["summary"]["by_module"][module] = {
                "scripts": len([s for s in generated_scripts["scripts"] if s["module"] == module]),
                "total_renames": module_renames_total
            }

    return generated_scripts


def generate_master_batch_script() -> str:
    """Generate a master script that applies all renames sequentially."""
    script = """// Master D2VersionChanger Rename Script
// This script applies all all-version function renames
// Run individual module/version scripts in sequence

import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class D2VersionChanger_MasterRename extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("ERROR: No program loaded");
            return;
        }

        println("========================================");
        println("D2VersionChanger Master Rename Script");
        println("========================================");
        println("");
        println("USAGE: Run individual scripts:");
        println("  1. Open your target D2 binary in Ghidra");
        println("  2. Use Script Manager (Window > Script Manager)");
        println("  3. Find D2VersionChanger_Rename scripts");
        println("  4. Run the appropriate script for your module/version");
        println("");
        println("Available Scripts:");
        println("  - D2VersionChanger_RenameD2Game_*");
        println("  - D2VersionChanger_RenameD2Client_*");
        println("  - D2VersionChanger_RenameD2Common_*");
        println("  - D2VersionChanger_RenameD2Win_*");
        println("  - D2VersionChanger_RenameStorm_*");
        println("  - D2VersionChanger_RenameFog_*");
        println("");
        println("For versions: 1_07, 1_08, 1_09, 1_09b, 1_09d, 1_10,");
        println("              1_11, 1_11b, 1_12a, 1_13c, 1_13d");
        println("");
        println("Example: D2VersionChanger_RenameD2Client_1_10.java");
        println("  This applies all all-version D2Client function names to v1.10");
    }
}
"""
    return script


def main():
    """Main execution."""
    print("="*70)
    print("Phase 4: Ghidra Script Generation")
    print("="*70)

    # Load unified index
    print("\nLoading unified function index...")
    unified = load_unified_index()

    # Generate scripts
    print("\nGenerating Ghidra scripts...")
    results = generate_all_scripts(unified)

    # Generate master script
    print("\nGenerating master script...")
    master_script = generate_master_batch_script()
    master_file = GHIDRA_SCRIPTS_PATH / "D2VersionChanger_MasterRename.java"
    with open(master_file, 'w', encoding='utf-8') as f:
        f.write(master_script)
    print(f"Generated {master_file.name}")

    # Save results
    results_file = REPORTS_PATH / "ghidra_scripts_generated.json"
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    # Print summary
    print("\n" + "="*70)
    print("GHIDRA SCRIPT GENERATION SUMMARY")
    print("="*70)
    print(f"\nTotal Scripts Generated: {results['summary']['total_scripts']}")
    print(f"Total Rename Statements: {results['summary']['total_renames']}")

    print("\nBy Module:")
    print("-"*70)
    for module in sorted(results["summary"]["by_module"].keys()):
        mod_info = results["summary"]["by_module"][module]
        print(f"  {module:12} | {mod_info['scripts']:2} scripts | {mod_info['total_renames']:4} renames")

    print("\nAll-Version Functions in Each Module:")
    print("-"*70)
    for module in MODULES:
        all_version_funcs = get_all_version_functions_for_module(unified, module)
        print(f"  {module:12} | {len(all_version_funcs):3} all-version functions")

    print("\n" + "="*70)
    print("SCRIPT DEPLOYMENT READY")
    print("="*70)
    print(f"\nScripts Location: {GHIDRA_SCRIPTS_PATH}")
    print(f"\nTo use these scripts:")
    print("  1. Copy all generated .java files to your Ghidra scripts folder")
    print("  2. In Ghidra, open Window > Script Manager")
    print("  3. Find and run the appropriate script for your module/version")
    print(f"\nGenerated report: {results_file}")


if __name__ == "__main__":
    main()
