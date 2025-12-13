// Auto-generated Ghidra rename script
// Module: D2Game
// Version: 1.07
// Generated: Cross-version renaming (Phase 4)
// Total renames: 84
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Game 1.07 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Game1.07 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20304");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20304");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20304: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FDFA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearField0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FDFA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FDFA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20244");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearImageDimensions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20244");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20244: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F968");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F968");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F968: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FDBE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractAndClearValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FDBE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FDBE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD23263");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23263", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD23263");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD23263: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD23386");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23386", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD23386");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD23386: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD23482");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FUN_6fd23482", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD23482");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD23482: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FDE8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FDE8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FDE8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F818");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F818");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F818: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F5B4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemDataByCode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F5B4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F5B4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F614");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F614");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F614: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F5AE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetParsedItemCountPtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F5AE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F5AE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD2011E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathPointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD2011E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD2011E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FE00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FE00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FE00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F85A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F85A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F85A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F9EC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F9EC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F9EC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FA22");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FA22");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FA22: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F1B8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F1B8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F1B8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F9FE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F9FE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F9FE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FD2E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitGfxUnk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FD2E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FD2E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FA40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FA40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FA40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F1BE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F1BE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F1BE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F5FC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F5FC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F5FC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F992");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F992");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F992: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FA6A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MultiplyValuesBy5", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FA6A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FA6A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC65480");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10002", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC65480");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC65480: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC680B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10003", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC680B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC680B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC68920");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10004", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC68920");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC68920: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC6ABB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10008", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC6ABB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC6ABB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD2027A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10010", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD2027A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD2027A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10011", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20274");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10012", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20274");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20274: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD2026E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10014", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD2026E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD2026E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD2024A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10015", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD2024A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD2024A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20262");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10016", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20262");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20262: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC69EF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10017", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC69EF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC69EF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC6A4B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10018", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC6A4B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC6A4B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20250");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10019", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20250");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20250: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20256");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10021", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20256");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20256: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC6A900");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10022", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC6A900");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC6A900: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC67600");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC67600");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC67600: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCE5940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10027", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCE5940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCE5940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCE59A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCE59A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCE59A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCAB390");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10029", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCAB390");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCAB390: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCDB830");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10033", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCDB830");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCDB830: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCB3400");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10037", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCB3400");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCB3400: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FCB3440");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10038", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FCB3440");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FCB3440: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC6FDC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10039", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC6FDC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC6FDC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC6FDE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10040", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC6FDE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC6FDE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC700D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10042", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC700D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC700D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC70280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10043", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC70280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC70280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC70380");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10044", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC70380");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC70380: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC70460");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10045", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC70460");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC70460: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC657C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10047", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC657C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC657C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD00AE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10048", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD00AE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD00AE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC65410");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10050", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC65410");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC65410: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC69800");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10052", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC69800");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC69800: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC657A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10056", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC657A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC657A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FFE6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FFE6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FFE6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD29720");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD29720");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD29720: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20316");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20316");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20316: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD202F8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD202F8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD202F8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1F4B2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnsZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1F4B2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1F4B2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FF56");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FF56");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FF56: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD1FDF4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_SetGfxSelected", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD1FDF4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD1FDF4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD226B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__CallSettingFrame@12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD226B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD226B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20BAD");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__NLG_Notify1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20BAD");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20BAD: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD28792");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD28792");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD28792: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20B8A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__abnormal_termination", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20B8A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20B8A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20480");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__alldiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20480");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20480: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20530");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20530");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20530: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD23515");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD23515");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD23515: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD2038A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD2038A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD2038A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD23225");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD23225");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD23225: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20FE1");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20FE1");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20FE1: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD27248");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD27248");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD27248: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD22EE3");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD22EE3");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD22EE3: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD20EB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__strrev", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD20EB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD20EB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD22ED1");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD22ED1");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD22ED1: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD271F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD271F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD271F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD25080");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD25080");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD25080: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD207C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD207C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD207C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD206C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD206C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD206C0: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Game 1.07 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
