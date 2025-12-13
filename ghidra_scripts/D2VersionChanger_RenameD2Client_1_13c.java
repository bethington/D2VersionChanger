// Auto-generated Ghidra rename script
// Module: D2Client
// Version: 1.13c
// Generated: Cross-version renaming (Phase 4)
// Total renames: 225
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Client 1.13c Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Client1.13c extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB16B20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AutomapPlayerIconLine_SetField24", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB16B20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB16B20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEA6D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("BackupKeyBindingsAndReinitialize", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEA6D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEA6D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE82D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CTRL_SetUpdateFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE82D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE82D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBF44");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CacheMarkSmsCategoriesForCopy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBF44");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBF44: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7DD90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CalculateMenuPanelYPosition", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7DD90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7DD90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB108D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CalculateWindowBorders", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB108D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB108D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6C3D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CancelScreenFade", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6C3D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6C3D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6DFC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CheckTimeoutElapsed50ms", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6DFC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6DFC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB62980");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CheckValueAndProcessData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB62980");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB62980: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB312A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupAndDelete", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB312A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB312A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB4E280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupPlayerSlots", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB4E280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB4E280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5D8E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupPlayerSlotsWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5D8E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5D8E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFF7C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFF7C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFF7C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB31B30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearItemSlots", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB31B30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB31B30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB211C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearPopupDialogResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB211C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB211C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC142");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearResetFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC142");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC142: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF1BC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearTargetingState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF1BC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF1BC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6E310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearUnitSelectionState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6E310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6E310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC02E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC02E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC02E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCAD2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCAD2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCAD2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC574");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateWaypointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC574");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC574: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE7EE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DecrementObjectCounter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE7EE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE7EE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0FB30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DecrementWindowBorderY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0FB30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0FB30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC040");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DeleteFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC040");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC040: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC004");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DestroyDataArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC004");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC004: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB30E4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DestructorWithCleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB30E4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB30E4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7AE1A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DispatchJumpTableEntry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7AE1A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7AE1A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE7E20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DispatchVtableMethod34", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE7E20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE7E20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6E300");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnableVideoInitialization", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6E300");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6E300: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7C729");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExceptionCleanupAndExit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7C729");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7C729: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF2470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExceptionHandlerLogAndCleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF2470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF2470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7D00D");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExecuteInventoryCallback", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7D00D");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7D00D: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD390");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FindPaletteIndexForColor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD390");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD390: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEA690");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ForceCalculateWindowBorders", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEA690");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEA690: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCAE4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCAE4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCAE4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCCE8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCCE8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCCE8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB2CA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GameDataCollectionDestructor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB2CA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB2CA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD38A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCurrentFontProperty", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD38A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD38A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2FC60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDefaultCameraScale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2FC60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2FC60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB55480");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameContextUnitStat", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB55480");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB55480: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD6500");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameModeFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD6500");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD6500: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB13570");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB13570");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB13570: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEC9F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEC9F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEC9F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC8AA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirementWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC8AA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC8AA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC4AE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC4AE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC4AE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC406");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetMissileTargetY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC406");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC406: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCFE8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCFE8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCFE8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCAF6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCAF6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCAF6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB12E20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetQuestSystemInitialized", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB12E20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB12E20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC496");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC496");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC496: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCC6A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCC6A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCC6A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCAEA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCAEA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCAEA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCE26");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStringIdFromSlotIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCE26");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCE26: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC6BE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC6BE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC6BE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD006");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD006");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD006: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC628");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC628");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC628: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD00C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD00C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD00C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6E230");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6E230");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6E230: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB170F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetViewportFieldAt12DF8", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB170F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB170F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEF6B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetViewportYOffsetAdjusted", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEF6B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEF6B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB143E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetWindowModeIfExpansion", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB143E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB143E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE24");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCandidateListA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE24");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE24: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCandidateListCountA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE42");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCompositionStringA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE42");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE42: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE2A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE2A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE2A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE5A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetConversionStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE5A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE5A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetOpenStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE36");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmIsIME", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE36");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE36: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE3C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmReleaseContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE3C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE3C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE48");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSetConversionStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE48");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE48: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE4E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSetOpenStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE4E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE4E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE54");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSimulateHotKey", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE54");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE54: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0FB40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IncreaseWindowBorderY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0FB40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0FB40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC3B2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC3B2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC3B2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC634");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC634");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC634: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF9030");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeCharacterInventoryDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF9030");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF9030: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5A170");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeDialogBox", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5A170");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5A170: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3BB60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3BB60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3BB60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB38D70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameObjectState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB38D70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB38D70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD6410");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameStateFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD6410");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD6410: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3BBF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameUIState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3BBF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3BBF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB27A30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameViewportConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB27A30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB27A30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1EBD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGlobalCounters", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1EBD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1EBD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0A910");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGlobalStateFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0A910");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0A910: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB095B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeInventorySlotCounters", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB095B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB095B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB12CC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeLanguageSupport", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB12CC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB12CC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACC8E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeMenuState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACC8E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACC8E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEA3A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeMouseButtonCallbacks", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEA3A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEA3A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB01050");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializePlayerStatistics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB01050");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB01050: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5C090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeQuestClassTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5C090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5C090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB251D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeRandomSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB251D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB251D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFBE10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeServerDialogStateHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFBE10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFBE10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFBE40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeServerSocketDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFBE40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFBE40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD6650");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeSliderCursor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD6650");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD6650: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB20D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeStructureFields", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB20D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB20D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF9060");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeUIDialogConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF9060");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF9060: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6E430");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeViewportWindow", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6E430");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6E430: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB17940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeVtablePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB17940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB17940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD2F4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsDSoundWaveEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD2F4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD2F4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3BDE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsGameModeInPlayableState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3BDE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3BDE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0AD60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsInventoryOpen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0AD60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0AD60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC6DC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsMonsterBossType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC6DC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC6DC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3B750");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsObjectTypeMonster", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3B750");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3B750: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3B760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsObjectTypeValid", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3B760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3B760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF20E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsRemoteSessionHandlingReady", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF20E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF20E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF2090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsRemoteSessionSupported", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF2090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF2090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD1BC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsStateLevelFourOrHigher", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD1BC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD1BC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6E3F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsTargetingEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6E3F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6E3F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF2030");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidRemoteDesktopSession", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF2030");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF2030: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCBC2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidUnitType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCBC2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCBC2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF1930");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsVideoInitializationEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF1930");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF1930: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB16FC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LB_DelegateVtbl13", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB16FC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB16FC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB16FB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ListboxDelegateInnerVtableMethod14", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB16FB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB16FB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB13580");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LoadBlendedShadowsSetting", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB13580");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB13580: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCCB2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10000", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCCB2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCCB2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD198");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10001", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD198");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD198: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB12DE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10002", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB12DE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB12DE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD21C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10004", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD21C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD21C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD3CC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10005", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD3CC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD3CC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD336");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10006", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD336");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD336: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCE4A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10007", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCE4A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCE4A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD3F6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10008", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD3F6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD3F6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD102");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10010", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD102");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD102: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD354");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10014", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD354");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD354: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD2AC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10018", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD2AC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD2AC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD228");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10019", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD228");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD228: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD300");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10020", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD300");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD300: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD2D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10023", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD2D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD2D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD40E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD40E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD40E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD33C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10026", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD33C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD33C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD318");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD318");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD318: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD1C2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10029", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD1C2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD1C2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD276");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10034", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD276");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD276: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC136");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10036", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC136");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC136: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD126");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10046", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD126");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD126: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD330");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10050", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD330");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD330: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD34E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10057", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD34E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD34E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC0D6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10060", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC0D6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC0D6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC790");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10064", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC790");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC790: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCFEE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10067", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCFEE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCFEE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD360");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10070", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD360");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD360: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD1B6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10074", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD1B6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD1B6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB13560");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10082", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB13560");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB13560: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC6F4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC6F4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC6F4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0EF50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PlayVideoAndConfigureGraphics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0EF50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0EF50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0D110");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PlayVideoFromStructure", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0D110");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0D110: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB302F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessCompressionObjects", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB302F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB302F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC784");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessInventoryItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC784");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC784: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB54D80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessInventoryItemWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB54D80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB54D80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB72790");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUIStateChange", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB72790");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB72790: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB54D20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUnitCoordinateData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB54D20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB54D20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB617C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUnitStats", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB617C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB617C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE8A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("QueryRegistryUlong", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE8A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE8A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBF14");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterCmdDef", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBF14");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBF14: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD37E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RenderUnicodeTextWithLineHeight", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD37E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD37E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACC720");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetGameModeFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACC720");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACC720: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE1E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE1E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE1E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBE6C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBE6C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBE6C: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC08E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SaveDefaultCommandLineToRegistry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC08E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC08E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD312");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAutomapCentersEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD312");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD312: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0F230");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAutomapUpdateThrottle", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0F230");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0F230: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB135B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBlendedShadowsMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB135B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB135B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB210C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCancelConfirmedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB210C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB210C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFA210");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCharacterInventoryDialogState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFA210");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFA210: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC028");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePointerWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC028");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC028: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC0B8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGameMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC0B8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC0B8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0A900");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalState4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0A900");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0A900: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0A8E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalState6", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0A8E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0A8E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC2C8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetMissileDataField2C", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC2C8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC2C8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBEF6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetRegistryDword", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBEF6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBEF6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBEB4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetRegistryStringValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBEB4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBEB4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE7F30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetSliderControlWidth", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE7F30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE7F30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB0A8F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetStateLevelFive", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB0A8F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB0A8F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3BAF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetStateLevelSeven", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3BAF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3BAF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC0EA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetTimeout500Ms", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC0EA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC0EA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCE5C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAllocatedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCE5C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCE5C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC670");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC670");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC670: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD1D4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetWindowVisibility", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD1D4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD1D4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB2B40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetupExceptionHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB2B40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB2B40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE58E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownAutomapRendering", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE58E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE58E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FC10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownCompressionService", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FC10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FC10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB12C90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownLanguageManager", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB12C90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB12C90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB17270");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB17270");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB17270: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABD35A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SumCharacterValues", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABD35A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABD35A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE82A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("TEXT_ClearSelectionState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE82A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE82A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABCAFC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABCAFC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABCAFC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABC1F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetRoom", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABC1F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABC1F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB178E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnlinkListNode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB178E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB178E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7D520");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba41fe", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7D520");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7D520: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7D64B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba4368", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7D64B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7D64B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7D6D8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba4400", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7D6D8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7D6D8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6E2E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdateTimeoutValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6E2E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6E2E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB8ECE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteErrorMessage", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB8ECE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB8ECE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7BF60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__CallSettingFrame@12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7BF60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7BF60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB91E9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__NLG_Notify1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB91E9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB91E9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7C762");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7C762");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7C762: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB91C6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__abnormal_termination", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB91C6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB91C6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB75D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB75D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB75D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB46DA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__amsg_exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB46DA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB46DA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7B581");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7B581");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7B581: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB7B266");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB7B266");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB7B266: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB3857");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB3857");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB3857: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABBB2B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABBB2B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABBB2B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB7D33");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB7D33");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB7D33: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB4A3E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__seh_longjmp_unwind@4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB4A3E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB4A3E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB4090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__strrev", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB4090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB4090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB7D5F");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB7D5F");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB7D5F: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABA9F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABA9F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABA9F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB4A60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strcmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB4A60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB4A60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB6FF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB6FF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB6FF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FABB0D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FABB0D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FABB0D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB3AC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB3AC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB3AC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB02D00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB02D00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB02D00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD4CD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_10", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD4CD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD4CD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD5D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_11", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD5D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD5D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD4870");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD4870");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD4870: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD4AE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_3", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD4AE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD4AE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD4FA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD4FA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD4FA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD4E30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_6", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD4E30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD4E30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD4DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_7", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD4DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD4DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD58F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_9", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD58F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD58F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD4D10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_a", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD4D10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD4D10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD61F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_d", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD61F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD61F0: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Client 1.13c Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
