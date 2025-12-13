// Master D2VersionChanger Rename Script
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
