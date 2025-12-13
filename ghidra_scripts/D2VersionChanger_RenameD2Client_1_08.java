// Auto-generated Ghidra rename script
// Module: D2Client
// Version: 1.08
// Generated: Cross-version renaming (Phase 4)
// Total renames: 225
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Client 1.08 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Client1.08 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB010B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AutomapPlayerIconLine_SetField24", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB010B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB010B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFDFE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("BackupKeyBindingsAndReinitialize", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFDFE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFDFE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB00D50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CTRL_SetUpdateFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB00D50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB00D50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB901D8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CacheMarkSmsCategoriesForCopy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB901D8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB901D8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB25750");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CalculateMenuPanelYPosition", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB25750");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB25750: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF5090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CalculateWindowBorders", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF5090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF5090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB77130");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CancelScreenFade", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB77130");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB77130: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB59690");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CheckTimeoutElapsed50ms", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB59690");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB59690: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB695C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CheckValueAndProcessData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB695C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB695C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90291");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupAndDelete", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90291");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90291: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADEBD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupPlayerSlots", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADEBD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADEBD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE3940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupPlayerSlotsWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE3940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE3940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB818D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB818D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB818D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB634F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearItemSlots", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB634F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB634F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB05F40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearPopupDialogResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB05F40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB05F40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8E778");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearResetFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8E778");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8E778: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADB830");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearTargetingState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADB830");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADB830: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB58900");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearUnitSelectionState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB58900");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB58900: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB900E2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB900E2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB900E2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F23A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F23A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F23A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F282");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateWaypointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F282");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F282: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB010E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DecrementObjectCounter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB010E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB010E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF5070");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DecrementWindowBorderY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF5070");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF5070: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB900DC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DeleteFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB900DC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB900DC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9006A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DestroyDataArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9006A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9006A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90268");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DestructorWithCleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90268");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90268: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB902E8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DispatchJumpTableEntry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB902E8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB902E8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB01250");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DispatchVtableMethod34", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB01250");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB01250: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB58910");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnableVideoInitialization", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB58910");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB58910: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB979C5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExceptionCleanupAndExit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB979C5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB979C5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD8C50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExceptionHandlerLogAndCleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD8C50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD8C50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB995C9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExecuteInventoryCallback", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB995C9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB995C9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FF7A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FindPaletteIndexForColor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FF7A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FF7A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFCFD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ForceCalculateWindowBorders", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFCFD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFCFD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F462");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F462");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F462: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8EA24");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8EA24");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8EA24: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB4F680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GameDataCollectionDestructor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB4F680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB4F680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FF98");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCurrentFontProperty", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FF98");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FF98: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD8120");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDefaultCameraScale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD8120");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD8120: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5E250");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameContextUnitStat", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5E250");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5E250: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB28080");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameModeFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB28080");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB28080: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90142");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90142");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90142: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F7DA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F7DA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F7DA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8EF94");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirementWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8EF94");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8EF94: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8EC76");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8EC76");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8EC76: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F4A4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetMissileTargetY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F4A4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F4A4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F624");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F624");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F624: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F24C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F24C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F24C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE7A20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetQuestSystemInitialized", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE7A20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE7A20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8ECCA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8ECCA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8ECCA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8ED5A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8ED5A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8ED5A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F222");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F222");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F222: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F0B4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStringIdFromSlotIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F0B4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F0B4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F34E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F34E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F34E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F510");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F510");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F510: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8EBA4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8EBA4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8EBA4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F516");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F516");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F516: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8E8D4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8E8D4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8E8D4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1A650");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetViewportFieldAt12DF8", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1A650");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1A650: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE49D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetViewportYOffsetAdjusted", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE49D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE49D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB812E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetWindowModeIfExpansion", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB812E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB812E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90244");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCandidateListA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90244");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90244: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9024A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCandidateListCountA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9024A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9024A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90232");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCompositionStringA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90232");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90232: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90238");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90238");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90238: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90250");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetConversionStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90250");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90250: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9022C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetOpenStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9022C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9022C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9023E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmIsIME", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9023E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9023E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90226");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmReleaseContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90226");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90226: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9025C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSetConversionStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9025C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9025C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90262");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSetOpenStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90262");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90262: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90256");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSimulateHotKey", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90256");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90256: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF5080");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IncreaseWindowBorderY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF5080");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF5080: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8E916");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8E916");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8E916: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8EA54");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8EA54");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8EA54: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1F8C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeCharacterInventoryDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1F8C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1F8C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5ACC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeDialogBox", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5ACC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5ACC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2F800");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2F800");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2F800: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB84DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameObjectState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB84DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB84DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2B0E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameStateFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2B0E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2B0E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB12030");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameUIState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB12030");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB12030: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2B210");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameViewportConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2B210");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2B210: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFC090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGlobalCounters", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFC090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFC090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD2770");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGlobalStateFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD2770");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD2770: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB54550");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeInventorySlotCounters", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB54550");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB54550: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD11F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeLanguageSupport", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD11F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD11F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB30480");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeMenuState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB30480");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB30480: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFD570");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeMouseButtonCallbacks", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFD570");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFD570: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE5890");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializePlayerStatistics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE5890");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE5890: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE7A00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeQuestClassTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE7A00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE7A00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2B1F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeRandomSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2B1F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2B1F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1F980");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeServerDialogStateHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1F980");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1F980: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1F8F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeServerSocketDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1F8F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1F8F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB28000");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeSliderCursor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB28000");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB28000: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB80980");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeStructureFields", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB80980");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB80980: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1F890");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeUIDialogConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1F890");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1F890: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB56B20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeViewportWindow", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB56B20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB56B20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB4F620");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeVtablePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB4F620");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB4F620: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FF1A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsDSoundWaveEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FF1A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FF1A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB54860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsGameModeInPlayableState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB54860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB54860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB037C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsInventoryOpen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB037C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB037C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8ED42");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsMonsterBossType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8ED42");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8ED42: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB14AB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsObjectTypeMonster", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB14AB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB14AB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB14A90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsObjectTypeValid", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB14A90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB14A90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADAA40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsRemoteSessionHandlingReady", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADAA40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADAA40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADAA80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsRemoteSessionSupported", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADAA80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADAA80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F8EE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsStateLevelFourOrHigher", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F8EE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F8EE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB59810");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsTargetingEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB59810");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB59810: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADAB10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidRemoteDesktopSession", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADAB10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADAB10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F750");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidUnitType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F750");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F750: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD1C10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsVideoInitializationEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD1C10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD1C10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1A880");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LB_DelegateVtbl13", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1A880");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1A880: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1A890");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ListboxDelegateInnerVtableMethod14", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1A890");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1A890: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB30BC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LoadBlendedShadowsSetting", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB30BC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB30BC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FE0C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10000", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FE0C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FE0C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FE2A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10001", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FE2A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FE2A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F7BC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10002", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F7BC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F7BC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FE24");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10004", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FE24");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FE24: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FE00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10005", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FE00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FE00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FFC2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10006", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FFC2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FFC2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FF0E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10007", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FF0E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FF0E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FDFA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10008", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FDFA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FDFA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FDD6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10010", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FDD6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FDD6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FEE4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10014", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FEE4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FEE4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F7E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10018", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F7E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F7E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F8CA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10019", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F8CA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F8CA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F876");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10020", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F876");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F876: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FE18");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10023", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FE18");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FE18: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F852");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F852");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F852: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FE12");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10026", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FE12");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FE12: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F846");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F846");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F846: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FE42");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10029", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FE42");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FE42: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F7CE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10034", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F7CE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F7CE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F79E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10036", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F79E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F79E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F7B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10046", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F7B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F7B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F86A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10050", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F86A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F86A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FEFC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10057", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FEFC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FEFC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F88E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10060", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F88E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F88E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FF20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10064", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FF20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FF20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F89A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10067", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F89A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F89A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F810");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10070", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F810");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F810: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F8AC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10074", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F8AC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F8AC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F828");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10082", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F828");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F828: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8ED78");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8ED78");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8ED78: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB82DB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PlayVideoAndConfigureGraphics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB82DB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB82DB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB809F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PlayVideoFromStructure", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB809F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB809F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD6660");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessCompressionObjects", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD6660");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD6660: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F31E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessInventoryItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F31E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F31E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5D5A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessInventoryItemWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5D5A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5D5A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB582D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUIStateChange", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB582D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB582D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5D830");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUnitCoordinateData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5D830");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5D830: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6D9B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUnitStats", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6D9B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6D9B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90202");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("QueryRegistryUlong", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90202");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90202: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90160");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterCmdDef", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90160");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90160: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FFA4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RenderUnicodeTextWithLineHeight", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FFA4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FFA4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB30440");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetGameModeFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB30440");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB30440: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9A650");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9A650");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9A650: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90154");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90154");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90154: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD1170");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SafeDelete", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD1170");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD1170: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD1D90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SaveDefaultCommandLineToRegistry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD1D90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD1D90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FF08");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAutomapCentersEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FF08");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FF08: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF6FA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAutomapUpdateThrottle", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF6FA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF6FA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB30B90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBlendedShadowsMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB30B90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB30B90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB06760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCancelConfirmedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB06760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB06760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1F9E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCharacterInventoryDialogState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1F9E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1F9E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB900D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePointerWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB900D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB900D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8E7CC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGameMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8E7CC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8E7CC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD2780");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalState4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD2780");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD2780: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB12750");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalState6", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB12750");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB12750: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8E9A6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetMissileDataField2C", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8E9A6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8E9A6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB901F6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetRegistryDword", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB901F6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB901F6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90172");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetRegistryStringValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90172");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90172: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB010A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetSliderControlWidth", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB010A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB010A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD2790");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetStateLevelFive", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD2790");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD2790: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD27B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetStateLevelSeven", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD27B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD27B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD5D90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetTimeout500Ms", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD5D90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD5D90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8E90A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAllocatedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8E90A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8E90A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F348");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F348");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F348: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F7D4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetWindowVisibility", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F7D4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F7D4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB92739");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetupExceptionHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB92739");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB92739: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB033E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownAutomapRendering", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB033E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB033E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADD6E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownCompressionService", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADD6E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADD6E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD1310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownLanguageManager", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD1310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD1310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90058");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90058");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90058: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FFAA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SumCharacterValues", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FFAA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FFAA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB00D60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("TEXT_ClearSelectionState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB00D60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB00D60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8F210");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8F210");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8F210: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8E874");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetRoom", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8E874");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8E874: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB8FCD1");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnlinkListNode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB8FCD1");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB8FCD1: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9A9A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba41fe", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9A9A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9A9A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9A9E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba4368", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9A9E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9A9E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9AA2A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba4400", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9AA2A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9AA2A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB58920");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdateTimeoutValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB58920");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB58920: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9638B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteErrorMessage", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9638B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9638B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB92500");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__CallSettingFrame@12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB92500");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB92500: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90661");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__NLG_Notify1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90661");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90661: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB997A9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB997A9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB997A9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9063E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__abnormal_termination", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9063E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9063E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB95B70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB95B70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB95B70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB919EA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__amsg_exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB919EA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB919EA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB92BB8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB92BB8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB92BB8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB906C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB906C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB906C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB928C8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB928C8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB928C8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90E19");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90E19");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90E19: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB98118");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB98118");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB98118: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB945F4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB945F4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB945F4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB977B9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__seh_longjmp_unwind@4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB977B9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB977B9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB91710");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__strrev", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB91710");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB91710: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB945E2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB945E2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB945E2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB980C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB980C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB980C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB91C60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strcmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB91C60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB91C60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB94010");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB94010");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB94010: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB98530");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB98530");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB98530: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB90A50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB90A50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB90A50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB75EF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB75EF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB75EF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB76110");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_10", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB76110");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB76110: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB76150");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_11", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB76150");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB76150: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB75AB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB75AB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB75AB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB75B40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_3", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB75B40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB75B40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB75BD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB75BD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB75BD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB75D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_6", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB75D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB75D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB75DD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_7", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB75DD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB75DD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB75F00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_9", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB75F00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB75F00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB75E60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_a", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB75E60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB75E60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB75F60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_d", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB75F60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB75F60: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Client 1.08 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
