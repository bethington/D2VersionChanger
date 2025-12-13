// Auto-generated Ghidra rename script
// Module: D2Common
// Version: 1.09b
// Generated: Cross-version renaming (Phase 4)
// Total renames: 93
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Common 1.09b Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Common1.09b extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3978");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AllocPoolMemoryTracked", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3978");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3978: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD66AA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AndDwordValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD66AA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD66AA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD42550");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ApplyTileAttributePattern", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD42550");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD42550: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB39B4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("BinarySearchTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB39B4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB39B4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD66AD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD66AD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD66AD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3A38");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3A38");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3A38: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C3B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearField0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C3B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C3B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C950");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearImageDimensions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C950");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C950: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD42E00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearMapCellFlagRadius", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD42E00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD42E00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareStringsIgnoreCase", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83250");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ComputeLinearIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD83250");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD83250: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83320");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ComputeScaledAttribute", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD83320");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD83320: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83290");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CoordToMapIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD83290");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD83290: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB2D50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB2D50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB2D50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB39F6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnterCriticalSectionWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB39F6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB39F6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD76F70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractAndClearValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD76F70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD76F70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83130");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractBitFields32", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD83130");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD83130: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB32E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB32E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB32E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB397E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemoryTracked", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB397E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB397E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDACE10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDACE10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDACE10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD4A470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetD2ComState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD4A470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD4A470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9DB50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDirectionIndexFromCoords", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9DB50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9DB50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD578E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameStateAndResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD578E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD578E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8B940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirement", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8B940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8B940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8BF90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirementWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8BF90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8BF90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD4EE60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemDataByCode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD4EE60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD4EE60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0A30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA0A30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA0A30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD7D860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetObjectDataPtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD7D860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD7D860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C190");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathPointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C190");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C190: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C3A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C3A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C3A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3340");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3340");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3340: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9DC20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPrimaryDir8FromDeltas", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9DC20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9DC20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C0A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C0A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C0A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C170");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C170");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C170: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0A60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetSeedHi", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA0A60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA0A60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C2D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListBaseStatValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C2D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C2D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C450");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListFlag4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C450");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C450: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C2A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C2A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C2A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD97DC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStringIdFromSlotIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD97DC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD97DC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C7F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructField54", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C7F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C7F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C160");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C160");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C160: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C100");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField88", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C100");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C100: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C7A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C7A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C7A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C3E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlag2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C3E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C3E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA3780");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA3780");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA3780: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C5C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitGfxUnk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C5C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C5C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C770");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C770");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C770: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C180");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitSeedHi", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C180");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C180: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C740");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C740");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C740: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0A20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA0A20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA0A20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA09E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA09E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA09E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD44F60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidUnitType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD44F60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD44F60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD43B20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ModifyTileAttributesFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD43B20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD43B20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD7E020");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MultiplyValuesBy5", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD7E020");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD7E020: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3D84");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileReadShare", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3D84");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3D84: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3D53");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileWithPermissions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3D53");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3D53: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C1C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C1C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C1C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBC9BE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBC9BE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBC9BE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C380");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("STATLIST_GetRoom", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C380");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C380: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3A32");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3A32");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3A32: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0A40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCoordPair", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA0A40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA0A40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C2B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetDwordValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C2B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C2B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD66A90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFlagsOnValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD66A90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD66A90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD974A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalValue11103", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD974A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD974A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD47950");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAllocatedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD47950");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD47950: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C9B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAnimData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C9B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C9B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C130");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C130");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C130: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C420");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C420");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C420: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD66AC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetValueIfEmpty", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD66AC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD66AC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD97770");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownLogFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD97770");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD97770: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0B80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA0B80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA0B80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA4660");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA4660");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA4660: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3360");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3360");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3360: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C0D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetUnitStat84", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C0D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C0D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C3F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_SetGfxSelected", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C3F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C3F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnpackBitFields", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD83260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD83260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83100");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnpackStatIdentifier", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD83100");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD83100: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3966");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ValidateStringId", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3966");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3966: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD66AB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("XorDwordInPlace", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD66AB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD66AB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBB2C3");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBB2C3");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBB2C3: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB4C10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB4C10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB4C10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB61DA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB61DA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB61DA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3AAC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3AAC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3AAC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB5EEA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB5EEA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB5EEA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3BCE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3BCE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3BCE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBA0EC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBA0EC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBA0EC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB779B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB779B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB779B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB8E4D");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__seh_longjmp_unwind@4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB8E4D");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB8E4D: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB7789");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB7789");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB7789: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB9870");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB9870");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB9870: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB9680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB9680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB9680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB9700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB9700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB9700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB4470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB4470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB4470: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Common 1.09b Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
