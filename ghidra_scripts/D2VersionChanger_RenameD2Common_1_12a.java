// Auto-generated Ghidra rename script
// Module: D2Common
// Version: 1.12a
// Generated: Cross-version renaming (Phase 4)
// Total renames: 93
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Common 1.12a Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Common1.12a extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59216");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AllocPoolMemoryTracked", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59216");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59216: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD89FE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AndDwordValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD89FE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD89FE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD69940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ApplyTileAttributePattern", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD69940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD69940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD59228");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("BinarySearchTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD59228");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD59228: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD89FB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD89FB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD89FB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD592CA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD592CA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD592CA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D180");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearField0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D180");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D180: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9CE50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearImageDimensions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9CE50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9CE50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD697A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearMapCellFlagRadius", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD697A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD697A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5920A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareStringsIgnoreCase", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5920A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5920A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD62FC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ComputeLinearIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD62FC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD62FC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD62EF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ComputeScaledAttribute", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD62EF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD62EF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD62F70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CoordToMapIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD62F70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD62F70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD90AD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD90AD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD90AD0: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD70AD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractAndClearValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD70AD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD70AD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD62FD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExtractBitFields32", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD62FD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD62FD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C730: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5B490");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5B490");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5B490: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDBB4B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetD2ComState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDBB4B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDBB4B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD82950");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDirectionIndexFromCoords", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD82950");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD82950: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDC3520");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameStateAndResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDC3520");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDC3520: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD7B860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirement", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD7B860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD7B860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD7C470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirementWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD7C470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD7C470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDAC920");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemDataByCode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDAC920");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDAC920: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9EEB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9EEB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9EEB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB7000");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetObjectDataPtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB7000");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB7000: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D3B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathPointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D3B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D3B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D190");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D190");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D190: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD82D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPrimaryDir8FromDeltas", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD82D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD82D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D4B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D4B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D4B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D3E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D3E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D3E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9EE80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetSeedHi", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9EE80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9EE80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D270");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListBaseStatValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D270");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D270: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D0D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListFlag4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D0D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D0D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C710");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C710");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C710: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD89610");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStringIdFromSlotIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD89610");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD89610: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9CFD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructField54", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9CFD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9CFD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D3F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D3F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D3F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D450");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField88", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D450");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D450: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9CFE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9CFE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9CFE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D140");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlag2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D140");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D140: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5BFC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5BFC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5BFC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D040");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitGfxUnk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D040");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D040: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9CFF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9CFF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9CFF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D3D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitSeedHi", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D3D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D3D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D020");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D020");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D020: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9EEC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9EEC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9EEC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9EED0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9EED0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9EED0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDC0E60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidUnitType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDC0E60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDC0E60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD69F60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ModifyTileAttributesFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD69F60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD69F60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDABC80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MultiplyValuesBy5", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDABC80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDABC80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD52287");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileReadShare", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD52287");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD52287: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5222B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileWithPermissions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5222B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5222B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D380");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D380");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D380: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D1B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("STATLIST_GetRoom", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D1B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D1B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD592D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD592D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD592D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9EEA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCoordPair", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9EEA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9EEA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD8A000");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetDwordValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD8A000");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD8A000: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD89FF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFlagsOnValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD89FF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD89FF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5A140");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalValue11103", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5A140");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5A140: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD90D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAllocatedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD90D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD90D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9CDF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAnimData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9CDF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9CDF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D400");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D400");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D400: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D0E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D0E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D0E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD89FC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetValueIfEmpty", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD89FC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD89FC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5A150");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownLogFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5A150");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5A150: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB7350");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB7350");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB7350: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDB7310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDB7310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDB7310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9C6C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9C6C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9C6C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D480");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetUnitStat84", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D480");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D480: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD9D110");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_SetGfxSelected", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD9D110");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD9D110: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD62F90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnpackBitFields", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD62F90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD62F90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD63020");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnpackStatIdentifier", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD63020");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD63020: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD592E2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ValidateStringId", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD592E2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD592E2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD89FD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("XorDwordInPlace", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD89FD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD89FD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD7B52");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD7B52");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD7B52: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD53300");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD53300");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD53300: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD73A6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD73A6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD73A6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD51C83");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD51C83");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD51C83: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FDD708B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FDD708B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FDD708B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD523ED");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD523ED");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD523ED: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD56523");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD56523");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD56523: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5376E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__seh_longjmp_unwind@4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5376E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5376E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD5654F");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD5654F");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD5654F: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD563C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD563C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD563C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD56570");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD56570");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD56570: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD56700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD56700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD56700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FD51FE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FD51FE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FD51FE0: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Common 1.12a Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
