// Auto-generated Ghidra rename script
// Module: D2Game
// Version: 1.11b
// Generated: Cross-version renaming (Phase 4)
// Total renames: 84
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Game 1.11b Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Game1.11b extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A312");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A312");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A312: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AA8C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearField0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AA8C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AA8C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A92A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearImageDimensions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A92A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A92A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A4F8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A4F8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A4F8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AA9E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractAndClearValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AA9E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AA9E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD15956");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23263", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD15956");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD15956: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD15A5E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23386", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD15A5E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD15A5E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD15AC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23482", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD15AC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD15AC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AB2E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AB2E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AB2E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A558");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A558");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A558: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A6D8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemDataByCode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A6D8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A6D8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A7C8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A7C8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A7C8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B32C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetParsedItemCountPtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B32C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B32C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2ADBC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathPointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2ADBC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2ADBC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AAE6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AAE6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AAE6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AB70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AB70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AB70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AA02");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AA02");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AA02: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AC54");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AC54");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AC54: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2ACF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2ACF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2ACF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A8EE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A8EE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A8EE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B368");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitGfxUnk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B368");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B368: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AD02");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AD02");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AD02: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AA20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AA20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AA20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A40E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A40E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A40E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A3FC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A3FC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A3FC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A882");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MultiplyValuesBy5", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A882");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A882: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B1B2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10002", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B1B2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B1B2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD05C10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10003", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD05C10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD05C10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD039E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10004", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD039E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD039E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD036B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10008", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD036B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD036B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC90720");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10010", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC90720");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC90720: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AE46");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10011", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AE46");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AE46: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC90870");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10012", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC90870");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC90870: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD070C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10014", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD070C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD070C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD050B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10015", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD050B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD050B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD03980");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10016", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD03980");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD03980: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD04DB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10017", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD04DB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD04DB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD08310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10018", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD08310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD08310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD07B90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10019", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD07B90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD07B90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC91970");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10021", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC91970");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC91970: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD03A10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10022", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD03A10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD03A10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A35A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A35A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A35A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AAE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10027", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AAE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AAE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD07970");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD07970");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD07970: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AA38");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10029", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AA38");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AA38: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD05520");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10033", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD05520");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD05520: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD06BE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10037", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD06BE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD06BE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC92290");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10038", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC92290");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC92290: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC917E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10039", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC917E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC917E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B44C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10040", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B44C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B44C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD05DB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10042", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD05DB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD05DB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD04380");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10043", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD04380");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD04380: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC918E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10044", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC918E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC918E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B2D2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10045", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B2D2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B2D2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD04EC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10047", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD04EC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD04EC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC92090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10048", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC92090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC92090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD063A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10050", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD063A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD063A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC91A30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10052", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC91A30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC91A30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD05700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10056", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD05700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD05700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AF0C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AF0C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AF0C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A25E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A25E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A25E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A26A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A26A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A26A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A318");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A318");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A318: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B0F2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnsZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B0F2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B0F2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AB6A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AB6A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AB6A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AAA4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_SetGfxSelected", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AAA4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AAA4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD15760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__CallSettingFrame@12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD15760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD15760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC26D25");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__NLG_Notify1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC26D25");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC26D25: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD163A8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD163A8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD163A8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC26D02");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__abnormal_termination", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC26D02");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC26D02: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD13BC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__alldiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD13BC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD13BC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A080");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A080");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A080: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD15B5A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD15B5A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD15B5A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC229AE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC229AE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC229AE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1584D");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1584D");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1584D: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2351F");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2351F");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2351F: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2982E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2982E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2982E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC24F79");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC24F79");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC24F79: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC22C00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__strrev", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC22C00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC22C00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC24FA5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC24FA5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC24FA5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC28670");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC28670");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC28670: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC27100");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC27100");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC27100: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC22A30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC22A30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC22A30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC22A70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC22A70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC22A70: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Game 1.11b Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
