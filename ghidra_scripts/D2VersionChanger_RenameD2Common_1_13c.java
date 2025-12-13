// Auto-generated Ghidra rename script
// Module: D2Common
// Version: 1.13c
// Generated: Cross-version renaming (Phase 4)
// Total renames: 93
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Common 1.13c Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Common1.13c extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59222");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AllocPoolMemoryTracked", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59222");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59222: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86C00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AndDwordValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86C00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86C00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9BE90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ApplyTileAttributePattern", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9BE90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9BE90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59240");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("BinarySearchTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59240");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59240: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86BD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86BD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86BD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD592AC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD592AC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD592AC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84A00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearField0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84A00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84A00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD846D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearImageDimensions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD846D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD846D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9BCF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearMapCellFlagRadius", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9BCF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9BCF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59204");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareStringsIgnoreCase", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59204");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59204: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD95830");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ComputeLinearIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD95830");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD95830: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD95760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ComputeScaledAttribute", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD95760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD95760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD957E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CoordToMapIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD957E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD957E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8D280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8D280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8D280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD592D6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnterCriticalSectionWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD592D6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD592D6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59DD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractAndClearValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59DD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59DD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD95840");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractBitFields32", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD95840");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD95840: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD68260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD68260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD68260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD58E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemoryTracked", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD58E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD58E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD62000");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD62000");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD62000: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDCE480");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetD2ComState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDCE480");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDCE480: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8E190");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDirectionIndexFromCoords", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBC7D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameStateAndResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBC7D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBC7D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD76190");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirement", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD76190");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD76190: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD76DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirementWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD76DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD76DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDC1940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemDataByCode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDC1940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDC1940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86730: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8B250");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetObjectDataPtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8B250");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8B250: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84C30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathPointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84C30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84C30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD87D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD87D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD87D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84AE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84AE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84AE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8E5F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPrimaryDir8FromDeltas", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8E5F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8E5F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84C60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84C60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84C60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetSeedHi", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84AF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListBaseStatValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84AF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84AF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8B220");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListFlag4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8B220");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8B220: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD68240");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD68240");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD68240: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD7C9C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStringIdFromSlotIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD7C9C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD7C9C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84850");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructField54", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84850");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84850: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84C70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84C70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84C70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84CD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField88", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84CD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84CD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD849C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlag2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD849C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD849C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9DE40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9DE40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9DE40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD848C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitGfxUnk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD848C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD848C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84870");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84870");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84870: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84C50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitSeedHi", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84C50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84C50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD848A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD848A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD848A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86740");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86740");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86740: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86750");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86750");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86750: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD937C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidUnitType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD937C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD937C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9CD90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ModifyTileAttributesFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9CD90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9CD90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D8A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MultiplyValuesBy5", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D8A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D8A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD52043");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileReadShare", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD52043");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD52043: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD51FE7");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileWithPermissions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD51FE7");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD51FE7: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84C00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84C00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84C00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD591FE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD591FE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD591FE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD87D50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("STATLIST_GetRoom", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD87D50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD87D50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD592B2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD592B2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD592B2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86720");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCoordPair", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86720");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86720: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86C20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetDwordValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86C20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86C20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86C10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFlagsOnValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86C10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86C10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD62A90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalValue11103", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD62A90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD62A90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDAD750");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAllocatedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDAD750");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDAD750: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84670");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAnimData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84670");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84670: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84C80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84C80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84C80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84960");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84960");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84960: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86BE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetValueIfEmpty", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86BE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86BE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD62AA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownLogFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD62AA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD62AA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDC0F70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDC0F70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDC0F70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9DDA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9DDA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9DDA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD681F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD681F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD681F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84D00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetUnitStat84", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84D00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84D00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD84990");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_SetGfxSelected", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD84990");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD84990: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD95800");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnpackBitFields", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD95800");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD95800: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD95890");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnpackStatIdentifier", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD95890");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD95890: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD592E8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ValidateStringId", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD592E8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD592E8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD86BF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("XorDwordInPlace", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD86BF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD86BF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD7C92");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD7C92");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD7C92: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD53750");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD53750");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD53750: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD74E6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD74E6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD74E6: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD71CB");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD71CB");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD71CB: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD521A9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD521A9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD521A9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD58DC5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD58DC5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD58DC5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD55F53");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD55F53");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD55F53: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD55F7F");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD55F7F");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD55F7F: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD56A60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD56A60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD56A60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD56B50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD56B50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD56B50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD56CE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD56CE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD56CE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD526F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD526F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD526F0: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Common 1.13c Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
