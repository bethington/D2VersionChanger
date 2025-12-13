// Auto-generated Ghidra rename script
// Module: D2Common
// Version: 1.09d
// Generated: Cross-version renaming (Phase 4)
// Total renames: 93
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Common 1.09d Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Common1.09d extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3A88");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AllocPoolMemoryTracked", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3A88");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3A88: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD66AB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AndDwordValue", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3AC4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("BinarySearchTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3AC4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3AC4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD66AE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD66AE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD66AE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3B48");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3B48");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3B48: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C410");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearField0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C410");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C410: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C9B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearImageDimensions", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3EB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareStringsIgnoreCase", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3EB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3EB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ComputeLinearIndex", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83330");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ComputeScaledAttribute", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD83330");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD83330: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD832A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CoordToMapIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD832A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD832A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB2E50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB2E50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB2E50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3B06");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnterCriticalSectionWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3B06");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3B06: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD76F80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractAndClearValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD76F80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD76F80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83140");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractBitFields32", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD83140");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD83140: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB33E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB33E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB33E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3A8E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemoryTracked", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3A8E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3A8E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDACF10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDACF10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDACF10: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9DBB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDirectionIndexFromCoords", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9DBB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9DBB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD578F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameStateAndResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD578F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD578F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8B910");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirement", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8B910");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8B910: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8BF60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirementWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8BF60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8BF60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD4EE70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemDataByCode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD4EE70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD4EE70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0A90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA0A90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA0A90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD7D870");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetObjectDataPtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD7D870");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD7D870: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C160");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathPointData", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C400");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C400");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C400: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3450");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3450");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3450: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9DC80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPrimaryDir8FromDeltas", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9DC80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9DC80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C070");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C070");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C070: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C140");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C140");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C140: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0AC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetSeedHi", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA0AC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA0AC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C330");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListBaseStatValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C330");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C330: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C4B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListFlag4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C4B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C4B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3410");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3410");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3410: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD97D90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStringIdFromSlotIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD97D90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD97D90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C850");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructField54", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C850");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C850: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C130");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructFlag0x20", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C0D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField88", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C800");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C800");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C800: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C440");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlag2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C440");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C440: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA37E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA37E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA37E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C620");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitGfxUnk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C620");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C620: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C7D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C7D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C7D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C150");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitSeedHi", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C150");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C150: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C7A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0A80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA0A80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA0A80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0A40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD7E030");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MultiplyValuesBy5", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD7E030");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD7E030: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3E94");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileReadShare", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3E94");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3E94: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3E63");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileWithPermissions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3E63");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3E63: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C190");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBCAC8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBCAC8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBCAC8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C3E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("STATLIST_GetRoom", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3B42");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3B42");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3B42: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0AA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCoordPair", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA0AA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA0AA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetDwordValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD66AA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFlagsOnValue", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD97470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalValue11103", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD97470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD97470: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9CA10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAnimData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9CA10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9CA10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C100");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag0x20", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C480");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C480");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C480: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD66AD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetValueIfEmpty", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD97740");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownLogFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD97740");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD97740: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA0BE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA0BE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA0BE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDA46C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDA46C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDA46C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C0A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetUnitStat84", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C450");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_SetGfxSelected", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83270");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnpackBitFields", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD83270");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD83270: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD83110");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnpackStatIdentifier", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD83110");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD83110: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3A76");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ValidateStringId", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3A76");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3A76: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD66AC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("XorDwordInPlace", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBB3A3");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBB3A3");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBB3A3: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB4D20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB4D20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB4D20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB62BF");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB62BF");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB62BF: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3BBC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3BBC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3BBC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB5FCF");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB5FCF");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB5FCF: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB3CDE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB3CDE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB3CDE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBA1CC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBA1CC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBA1CC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB7880");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB7880");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB7880: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB8F31");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__seh_longjmp_unwind@4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB8F31");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB8F31: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB786E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB786E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB786E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB9950");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB9950");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB9950: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB9760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB9760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB9760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB97E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB97E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB97E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB4580");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB4580");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB4580: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Common 1.09d Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
