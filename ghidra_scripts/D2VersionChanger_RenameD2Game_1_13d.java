// Auto-generated Ghidra rename script
// Module: D2Game
// Version: 1.13d
// Generated: Cross-version renaming (Phase 4)
// Total renames: 84
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Game 1.13d Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Game1.13d extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A2F8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A2F8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A2F8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B180");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearField0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B180");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B180: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B288");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearImageDimensions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B288");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B288: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A9D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A9D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A9D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B0AE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractAndClearValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B0AE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B0AE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD163F6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23263", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD163F6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD163F6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD164FE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23386", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD164FE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD164FE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD16560");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23482", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD16560");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD16560: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A4BA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A4BA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A4BA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A4AE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A4AE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A4AE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A508");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemDataByCode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A508");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A508: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A82C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A82C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A82C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B3AE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetParsedItemCountPtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B3AE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B3AE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AACC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathPointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AACC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AACC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B28E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B28E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B28E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AAAE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AAAE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AAAE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AA66");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AA66");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AA66: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A52C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A52C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A52C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A88C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A88C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A88C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AADE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AADE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AADE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B228");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitGfxUnk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B228");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B228: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A892");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A892");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A892: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A730: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A9E2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A9E2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A9E2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A988");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MultiplyValuesBy5", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A988");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A988: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCB92D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10002", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCB92D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCB92D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCE6900");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10003", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCE6900");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCE6900: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCF02F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10004", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCF02F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCF02F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDDA00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10008", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDDA00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDDA00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDD3A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10010", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDD3A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDD3A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC59D00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10011", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC59D00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC59D00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDBF30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10012", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDBF30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDBF30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCA2C60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10014", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCA2C60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCA2C60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCEAC70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10015", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCEAC70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCEAC70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDF520");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10016", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDF520");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDF520: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDCC00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10017", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDCC00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDCC00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDC0B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10018", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDC0B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDC0B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDEC30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10019", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDEC30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDEC30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDD940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10021", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDD940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDD940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDD260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10022", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDD260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDD260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B24C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B24C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B24C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCA2C70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10027", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCA2C70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCA2C70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDFED0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDFED0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDFED0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDFBC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10029", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDFBC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDFBC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCE61E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10033", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCE61E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCE61E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCE6560");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10037", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCE6560");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCE6560: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDC6B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10038", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDC6B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDC6B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCE6050");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10039", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCE6050");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCE6050: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCEAD20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10040", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCEAD20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCEAD20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCE6150");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10042", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCE6150");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCE6150: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCEAE70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10043", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCEAE70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCEAE70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2ACB2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10044", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2ACB2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2ACB2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDD2E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10045", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDD2E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDD2E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDCF70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10047", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDCF70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDCF70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCE0050");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10048", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCE0050");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCE0050: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCEADF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10050", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCEADF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCEADF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDCDF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10052", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDCDF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDCDF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDF110");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10056", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDF110");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDF110: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AB56");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A2FE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A2FE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A2FE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2ABE6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnsZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2ABE6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2ABE6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AAA8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AAA8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AAA8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B192");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_SetGfxSelected", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B192");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B192: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD16200");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__CallSettingFrame@12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD16200");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD16200: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC26D35");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__NLG_Notify1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC26D35");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC26D35: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD16E48");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD16E48");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD16E48: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC26D12");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__abnormal_termination", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC26D12");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC26D12: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD14660");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__alldiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD14660");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD14660: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD165FA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD165FA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD165FA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC22B1C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC22B1C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC22B1C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD162ED");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD162ED");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD162ED: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC231AB");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC231AB");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC231AB: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC299E2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC299E2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC299E2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC23EC1");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC23EC1");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC23EC1: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC22820");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__strrev", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC22820");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC22820: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC23EED");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC23EED");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC23EED: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC286B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC286B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC286B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC27C70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC27C70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC27C70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC22DB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC22DB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC22DB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC22860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC22860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC22860: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Game 1.13d Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
