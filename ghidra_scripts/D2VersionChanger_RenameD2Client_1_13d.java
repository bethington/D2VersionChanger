// Auto-generated Ghidra rename script
// Module: D2Client
// Version: 1.13d
// Generated: Cross-version renaming (Phase 4)
// Total renames: 225
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Client 1.13d Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Client1.13d extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC3830");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AutomapPlayerIconLine_SetField24", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC3830");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC3830: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEC470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("BackupKeyBindingsAndReinitialize", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEC470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEC470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC3BE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CTRL_SetUpdateFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC3BE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC3BE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE88");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CacheMarkSmsCategoriesForCopy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE88");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE88: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7DFC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CalculateMenuPanelYPosition", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7DFC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7DFC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB21FC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CalculateWindowBorders", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB21FC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB21FC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6EB70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CancelScreenFade", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6EB70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6EB70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC79C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CheckTimeoutElapsed50ms", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC79C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC79C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB01DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CheckValueAndProcessData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB01DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB01DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB400B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupAndDelete", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB400B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB400B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB52350");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupPlayerSlots", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB52350");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB52350: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB33DE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupPlayerSlotsWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB33DE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB33DE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3F280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3F280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3F280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB69660");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearItemSlots", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB69660");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB69660: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB14960");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearPopupDialogResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB14960");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB14960: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC02C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearResetFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC02C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC02C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF2C10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearTargetingState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF2C10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF2C10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3FCC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearUnitSelectionState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3FCC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3FCC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBF24");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBF24");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBF24: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC91A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC91A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC91A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCDA6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateWaypointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCDA6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCDA6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC37F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DecrementObjectCounter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC37F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC37F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB20730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DecrementWindowBorderY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB20730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB20730: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBF36");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DeleteFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBF36");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBF36: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBF6C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DestroyDataArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBF6C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBF6C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB3FC5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DestructorWithCleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB3FC5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB3FC5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7B2C1");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DispatchJumpTableEntry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7B2C1");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7B2C1: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC3730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DispatchVtableMethod34", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC3730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC3730: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6EB60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnableVideoInitialization", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6EB60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6EB60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7CBAD");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExceptionCleanupAndExit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7CBAD");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7CBAD: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF34E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExceptionHandlerLogAndCleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF34E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF34E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7D46D");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExecuteInventoryCallback", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7D46D");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7D46D: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD2BC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FindPaletteIndexForColor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD2BC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD2BC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEC710");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ForceCalculateWindowBorders", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEC710");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEC710: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC92C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC92C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC92C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC43A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC43A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC43A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB2F60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GameDataCollectionDestructor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB2F60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB2F60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD2C8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCurrentFontProperty", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD2C8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD2C8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFA8B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDefaultCameraScale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFA8B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFA8B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB11A10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameContextUnitStat", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB11A10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB11A10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1C620");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameModeFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1C620");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1C620: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB71BE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB71BE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB71BE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADBCF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADBCF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADBCF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC70A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirementWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC70A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC70A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC632");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC632");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC632: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCC4A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetMissileTargetY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCC4A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCC4A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCEC6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCEC6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCEC6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC93E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC93E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC93E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB36010");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetQuestSystemInitialized", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB36010");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB36010: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC88A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC88A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC88A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCD9A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCD9A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCD9A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC932");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC932");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC932: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC8D8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStringIdFromSlotIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC8D8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC8D8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCB8A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCB8A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCB8A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC5A2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC5A2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC5A2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC5C6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC5C6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC5C6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC5A8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC5A8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC5A8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB69580");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB69580");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB69580: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB66E70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetViewportFieldAt12DF8", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB66E70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB66E70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0BC10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetViewportYOffsetAdjusted", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0BC10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0BC10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB72700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetWindowModeIfExpansion", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB72700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB72700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD44");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCandidateListA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD44");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD44: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCandidateListCountA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD62");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCompositionStringA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD62");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD62: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD4A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD4A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD4A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD7A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetConversionStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD7A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD7A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetOpenStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD56");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmIsIME", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD56");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD56: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD5C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmReleaseContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD5C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD5C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD68");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSetConversionStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD68");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD68: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD6E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSetOpenStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD6E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD6E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD74");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSimulateHotKey", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD74");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD74: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB20740");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IncreaseWindowBorderY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB20740");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB20740: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC3B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC3B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC3B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC3AA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC3AA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC3AA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2B920");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeCharacterInventoryDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2B920");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2B920: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEEC40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeDialogBox", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEEC40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEEC40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3FE70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3FE70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3FE70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD65E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameObjectState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD65E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD65E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1C4C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameStateFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1C4C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1C4C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3FEA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameUIState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3FEA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3FEA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB36780");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameViewportConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB36780");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB36780: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60060");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGlobalCounters", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60060");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60060: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3EED0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGlobalStateFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3EED0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3EED0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC1F20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeInventorySlotCounters", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC1F20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC1F20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFA730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeLanguageSupport", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFA730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFA730: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3B330");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeMenuState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3B330");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3B330: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEC050");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeMouseButtonCallbacks", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEC050");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEC050: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC6850");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializePlayerStatistics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC6850");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC6850: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB32C00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeQuestClassTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB32C00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB32C00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB367A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeRandomSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB367A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB367A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2EE90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeServerDialogStateHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2EE90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2EE90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2EEC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeServerSocketDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2EEC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2EEC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1C770");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeSliderCursor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1C770");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1C770: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB1FE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeStructureFields", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB1FE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB1FE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2B950");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeUIDialogConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2B950");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2B950: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC7C80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeViewportWindow", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC7C80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC7C80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB676C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeVtablePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB676C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB676C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD1FC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsDSoundWaveEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD1FC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD1FC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB40100");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsGameModeInPlayableState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB40100");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB40100: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB39130");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsInventoryOpen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB39130");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB39130: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCBA2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsMonsterBossType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCBA2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCBA2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3FAD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsObjectTypeMonster", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3FAD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3FAD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3FAE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsObjectTypeValid", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3FAE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3FAE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF3180");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsRemoteSessionHandlingReady", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF3180");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF3180: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF3130");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsRemoteSessionSupported", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF3130");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF3130: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD0F4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsStateLevelFourOrHigher", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD0F4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD0F4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB71310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsTargetingEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB71310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB71310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF30D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidRemoteDesktopSession", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF30D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF30D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC524");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidUnitType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC524");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC524: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB53A20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsVideoInitializationEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB53A20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB53A20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB66D40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LB_DelegateVtbl13", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB66D40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB66D40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB66D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ListboxDelegateInnerVtableMethod14", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB66D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB66D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB71BF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LoadBlendedShadowsSetting", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB71BF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB71BF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD154");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10000", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD154");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD154: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10001", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB35FD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10002", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB35FD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB35FD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD10C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10004", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD10C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD10C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD17E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10005", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD17E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD17E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD09A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10006", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD09A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD09A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD262");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10007", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD262");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD262: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD106");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10008", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD106");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD106: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD2C2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10010", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD2C2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD2C2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCFB6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10014", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCFB6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCFB6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD028");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10018", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD028");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD028: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD1CC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10019", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD1CC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD1CC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10020", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC0D4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10023", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC0D4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC0D4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD16C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD16C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD16C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD27A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10026", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD27A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD27A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD208");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD208");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD208: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD214");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10029", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD214");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD214: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD322");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10034", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD322");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD322: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD142");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10036", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD142");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD142: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCFF2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10046", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCFF2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCFF2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCF68");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10050", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCF68");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCF68: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD1E4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10057", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD1E4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD1E4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD23E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10060", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD23E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD23E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC03E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10064", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC03E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC03E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD1C6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10067", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD1C6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD1C6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD0DC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10070", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD0DC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD0DC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC1CA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10074", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC1CA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC1CA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD082");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10082", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD082");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD082: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCCFE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCCFE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCCFE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEC460");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PlayVideoAndConfigureGraphics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEC460");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEC460: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB64370");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PlayVideoFromStructure", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB64370");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB64370: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFAA60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessCompressionObjects", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFAA60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFAA60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCB90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessInventoryItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCB90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCB90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1A850");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessInventoryItemWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1A850");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1A850: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACC190");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUIStateChange", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACC190");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACC190: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB11380");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUnitCoordinateData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB11380");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB11380: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB00BE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUnitStats", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB00BE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB00BE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD9E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("QueryRegistryUlong", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD9E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD9E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE1C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterCmdDef", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE1C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE1C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD298");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RenderUnicodeTextWithLineHeight", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD298");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD298: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3B020");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetGameModeFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3B020");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3B020: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD3E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD3E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD3E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD98");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD98");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD98: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB1000");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SafeDelete", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB1000");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB1000: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADBD10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SaveDefaultCommandLineToRegistry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADBD10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADBD10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD21A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAutomapCentersEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD21A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD21A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1FF40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAutomapUpdateThrottle", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1FF40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1FF40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB71C20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBlendedShadowsMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB71C20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB71C20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB14860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCancelConfirmedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB14860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB14860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2CB90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCharacterInventoryDialogState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2CB90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2CB90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBF1E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePointerWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBF1E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBF1E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC074");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGameMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC074");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC074: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3EEC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalState4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3EEC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3EEC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3EEA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalState6", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3EEA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3EEA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC3F2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetMissileDataField2C", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC3F2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC3F2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBD86");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetRegistryDword", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBD86");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBD86: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE04");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetRegistryStringValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE04");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE04: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC3840");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetSliderControlWidth", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC3840");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC3840: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3EEB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetStateLevelFive", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3EEB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3EEB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3FE00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetStateLevelSeven", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3FE00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3FE00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC3050");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetTimeout500Ms", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC3050");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC3050: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCD70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAllocatedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCD70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCD70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCAA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCAA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCAA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD0D6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetWindowVisibility", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD0D6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD0D6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB2B20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetupExceptionHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB2B20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB2B20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB599D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownAutomapRendering", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB599D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB599D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB36120");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownCompressionService", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB36120");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB36120: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFA700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownLanguageManager", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFA700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFA700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB66FF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB66FF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB66FF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD292");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SumCharacterValues", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD292");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD292: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC3BB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("TEXT_ClearSelectionState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC3BB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC3BB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC944");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC944");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC944: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC2A8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetRoom", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC2A8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC2A8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB67660");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnlinkListNode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB67660");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB67660: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7D94C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba41fe", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7D94C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7D94C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7DAD1");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba4368", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7DAD1");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7DAD1: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7DB28");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba4400", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7DB28");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7DB28: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC7BD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdateTimeoutValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC7BD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC7BD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB8E23");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteErrorMessage", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB8E23");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB8E23: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7C400");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__CallSettingFrame@12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7C400");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7C400: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB92CD");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__NLG_Notify1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB92CD");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB92CD: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7CBE6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7CBE6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7CBE6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB92AA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__abnormal_termination", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB92AA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB92AA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB6F80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB6F80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB6F80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB46C2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__amsg_exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB46C2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB46C2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7BA1A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7BA1A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7BA1A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB9A120");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB9A120");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB9A120: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7B70D");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7B70D");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7B70D: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB381C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB381C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB381C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBA4F");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBA4F");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBA4F: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB5697");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB5697");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB5697: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB53DE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__seh_longjmp_unwind@4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB53DE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB53DE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB3F90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__strrev", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB3F90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB3F90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB56C3");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB56C3");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB56C3: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABAB80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABAB80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABAB80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB8680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strcmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB8680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB8680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB8150");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB8150");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB8150: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABAE60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABAE60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABAE60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB3A30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB3A30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB3A30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB19C10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB19C10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB19C10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFCCC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_10", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFCCC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFCCC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFDDA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_11", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFDDA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFDDA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFC950");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFC950");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFC950: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFCC10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_3", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFCC10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFCC10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3CAD2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3CAD2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3CAD2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFCEA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_6", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFCEA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFCEA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFCE10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_7", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFCE10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFCE10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFD960");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_9", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFD960");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFD960: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFCD80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_a", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFCD80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFCD80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFE260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_d", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFE260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFE260: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Client 1.13d Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
