// Auto-generated Ghidra rename script
// Module: D2Common
// Version: 1.11b
// Generated: Cross-version renaming (Phase 4)
// Total renames: 93
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Common 1.11b Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Common1.11b extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59206");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AllocPoolMemoryTracked", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59206");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59206: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59F10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AndDwordValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59F10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59F10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD77CE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ApplyTileAttributePattern", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD77CE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD77CE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59266");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("BinarySearchTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59266");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59266: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59EE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59EE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59EE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59296");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59296");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59296: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BC90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearField0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BC90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BC90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6B960");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearImageDimensions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6B960");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6B960: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD77B40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearMapCellFlagRadius", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD77B40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD77B40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD591EE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareStringsIgnoreCase", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD591EE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD591EE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB1B50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ComputeLinearIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB1B50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB1B50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB1A80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ComputeScaledAttribute", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB1A80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB1A80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB1B00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CoordToMapIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB1B00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB1B00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDAFD20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDAFD20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDAFD20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59254");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnterCriticalSectionWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59254");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59254: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD87ED0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractAndClearValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD87ED0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD87ED0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB1B60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractBitFields32", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB1B60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB1B60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD1170");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD1170");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD1170: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5920C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemoryTracked", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5920C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5920C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD7AA30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD7AA30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD7AA30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDCCC00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetD2ComState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDCCC00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDCCC00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB67A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDirectionIndexFromCoords", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB67A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB67A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6DEF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameStateAndResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6DEF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6DEF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDC5140");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirement", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDC5140");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDC5140: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDC5D20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirementWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDC5D20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDC5D20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD92F00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemDataByCode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD92F00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD92F00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8E180");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8E180");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8E180: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8E2A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetObjectDataPtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8E2A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8E2A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BEC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathPointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BEC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BEC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BCA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BCA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BCA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD1160");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD1160");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD1160: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB6AF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPrimaryDir8FromDeltas", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB6AF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB6AF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BFC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BFC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BFC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BEF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BEF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BEF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8E150");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetSeedHi", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8E150");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8E150: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BD80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListBaseStatValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BD80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BD80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BBE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListFlag4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BBE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BBE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD1150");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD1150");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD1150: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD663A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStringIdFromSlotIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD663A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD663A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BAE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructField54", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BAE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BAE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BF00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BF00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BF00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BF60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField88", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BF60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BF60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BAF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BAF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BAF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BC50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlag2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BC50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BC50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBBF50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBBF50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBBF50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BB50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitGfxUnk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BB50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BB50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BB00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BB00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BB00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BEE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitSeedHi", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BEE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BEE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BB30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BB30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BB30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8E190");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8E190");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8E190: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8E1A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8E1A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8E1A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8D500");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidUnitType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8D500");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8D500: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD78BE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ModifyTileAttributesFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD78BE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD78BE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDAA560");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MultiplyValuesBy5", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDAA560");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDAA560: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD51F28");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileReadShare", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD51F28");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD51F28: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD51ECC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileWithPermissions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD51ECC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD51ECC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BE90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BE90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BE90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD591E2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD591E2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD591E2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BCC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("STATLIST_GetRoom", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BCC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BCC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5929C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5929C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5929C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8E170");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCoordPair", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8E170");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8E170: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59F30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetDwordValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59F30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59F30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59F20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFlagsOnValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59F20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59F20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA6D20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalValue11103", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA6D20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA6D20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5D740");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAllocatedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5D740");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5D740: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6B900");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAnimData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6B900");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6B900: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BF10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BF10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BF10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BBF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BBF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BBF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59EF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetValueIfEmpty", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59EF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59EF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA6D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownLogFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA6D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA6D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBC610");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBC610");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBC610: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBBEB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBBEB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBBEB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD1100");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD1100");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD1100: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BF90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetUnitStat84", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BF90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BF90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD6BC20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_SetGfxSelected", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD6BC20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD6BC20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB1B20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnpackBitFields", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB1B20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB1B20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB1BB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnpackStatIdentifier", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB1BB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB1BB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD592D2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ValidateStringId", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD592D2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD592D2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59F00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("XorDwordInPlace", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59F00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59F00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD82D8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD82D8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD82D8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD54D90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD54D90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD54D90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD7B48");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD7B48");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD7B48: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD51B1E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD51B1E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD51B1E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD783B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD783B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD783B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5208E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5208E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5208E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD58C05");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD58C05");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD58C05: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD55F72");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD55F72");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD55F72: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD531DE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__seh_longjmp_unwind@4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD531DE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD531DE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD55F9E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD55F9E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD55F9E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD580F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD580F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD580F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD56680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD56680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD56680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD582A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD582A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD582A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD51B40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD51B40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD51B40: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Common 1.11b Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
