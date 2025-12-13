// Auto-generated Ghidra rename script
// Module: D2Game
// Version: 1.13c
// Generated: Cross-version renaming (Phase 4)
// Total renames: 84
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Game 1.13c Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Game1.13c extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("No program loaded");
            return;
        }

        int successCount = 0;
        int failureCount = 0;

        Listing listing = currentProgram.getListing();

        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A30A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A30A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A30A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A646");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearField0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A646");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A646: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AF6A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearImageDimensions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AF6A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AF6A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B210");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B210");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B210: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A562");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractAndClearValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A562");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A562: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD16246");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23263", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD16246");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD16246: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD16352");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23386", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD16352");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD16352: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD163B9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23482", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD163B9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD163B9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AAF6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AAF6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AAF6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A4FC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A4FC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A4FC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AE74");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemDataByCode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AE74");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AE74: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AFB2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AFB2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AFB2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B3CC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetParsedItemCountPtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B3CC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B3CC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AF8E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathPointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AF8E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AF8E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AEBC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AEBC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AEBC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B00C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B00C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B00C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AC70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AC70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AC70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AB3E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AB3E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AB3E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AB4A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AB4A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AB4A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A79C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A79C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A79C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AB56");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitGfxUnk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AB56");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AB56: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B23A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B23A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B23A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AB5C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AB5C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AB5C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A628");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A628");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A628: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A616");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A616");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A616: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B1FE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MultiplyValuesBy5", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B1FE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B1FE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC729F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10002", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC729F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC729F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4CFD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10003", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4CFD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4CFD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC74400");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10004", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC74400");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC74400: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4E1E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10008", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4E1E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4E1E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCFB860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10010", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCFB860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCFB860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC49AE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10011", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC49AE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC49AE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4A6D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10012", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4A6D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4A6D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4B160");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10014", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4B160");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4B160: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC72390");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10015", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC72390");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC72390: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A376");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10016", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A376");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A376: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A382");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10017", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A382");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A382: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC58D40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10018", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC58D40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC58D40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AF5E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10019", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AF5E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AF5E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC72650");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10021", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC72650");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC72650: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC49B10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10022", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC49B10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC49B10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4DF10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4DF10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4DF10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC53970");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10027", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC53970");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC53970: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4AD80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4AD80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4AD80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AA12");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10029", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AA12");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AA12: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4AE40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10033", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4AE40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4AE40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4A370");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10037", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4A370");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4A370: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4D4B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10038", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4D4B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4D4B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC72140");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10039", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC72140");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC72140: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4E460");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10040", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4E460");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4E460: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC58BC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10042", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC58BC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC58BC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B1EC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10043", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B1EC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B1EC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4C570");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10044", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4C570");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4C570: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4B7C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10045", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4B7C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4B7C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4A9A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10047", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4A9A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4A9A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4A330");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10048", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4A330");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4A330: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A994");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10050", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A994");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A994: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC4A1F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10052", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC4A1F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC4A1F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC722D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10056", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC722D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC722D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AC82");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AC82");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AC82: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A26E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A26E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A26E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A27A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A27A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A27A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A8AA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnsZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A8AA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A8AA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B006");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B006");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B006: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A658");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_SetGfxSelected", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A658");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A658: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD16050");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__CallSettingFrame@12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD16050");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD16050: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC278BD");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__NLG_Notify1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC278BD");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC278BD: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD16CC2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD16CC2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD16CC2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2789A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__abnormal_termination", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2789A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2789A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD144B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__alldiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD144B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD144B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD16458");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD16458");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD16458: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC22A4D");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC22A4D");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC22A4D: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1613D");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1613D");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1613D: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2326B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2326B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2326B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC29D61");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC29D61");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC29D61: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC25F4C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC25F4C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC25F4C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC22E10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__strrev", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC22E10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC22E10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC25F78");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC25F78");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC25F78: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC27400");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC27400");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC27400: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC27460");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC27460");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC27460: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC23520");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC23520");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC23520: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC22E50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC22E50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC22E50: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Game 1.13c Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
