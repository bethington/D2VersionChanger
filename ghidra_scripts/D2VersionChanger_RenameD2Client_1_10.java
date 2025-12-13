// Auto-generated Ghidra rename script
// Module: D2Client
// Version: 1.10
// Generated: Cross-version renaming (Phase 4)
// Total renames: 225
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Client 1.10 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Client1.10 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD7F80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AutomapPlayerIconLine_SetField24", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD7F80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD7F80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD4EC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("BackupKeyBindingsAndReinitialize", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD4EC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD4EC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD7C10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CTRL_SetUpdateFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD7C10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD7C10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60224");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CacheMarkSmsCategoriesForCopy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60224");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60224: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFC240");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CalculateMenuPanelYPosition", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFC240");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFC240: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACB6E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CalculateWindowBorders", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACB6E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACB6E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB49910");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CancelScreenFade", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB49910");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB49910: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB24660");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CheckTimeoutElapsed50ms", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB24660");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB24660: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB32CB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CheckValueAndProcessData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB32CB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB32CB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60295");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupAndDelete", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60295");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60295: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAAF260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupPlayerSlots", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAAF260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAAF260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB3DF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupPlayerSlotsWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB3DF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB3DF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB53800");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB53800");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB53800: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2E680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearItemSlots", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2E680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2E680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADC6D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearPopupDialogResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADC6D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADC6D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A878");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearResetFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A878");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A878: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAABF60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearTargetingState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAABF60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAABF60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB23890");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearUnitSelectionState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB23890");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB23890: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A776");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A776");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A776: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B2AA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B2AA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B2AA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B304");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateWaypointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B304");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B304: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD7FB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DecrementObjectCounter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD7FB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD7FB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACB6C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DecrementWindowBorderY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACB6C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACB6C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A770");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DeleteFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A770");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A770: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A6FE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DestroyDataArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A6FE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A6FE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6026C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DestructorWithCleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6026C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6026C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB602EC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DispatchJumpTableEntry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB602EC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB602EC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD8180");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DispatchVtableMethod34", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD8180");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD8180: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB238A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnableVideoInitialization", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB238A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB238A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB67B33");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExceptionCleanupAndExit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB67B33");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB67B33: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA9420");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExceptionHandlerLogAndCleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA9420");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA9420: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB69739");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExecuteInventoryCallback", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB69739");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB69739: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BF8E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FindPaletteIndexForColor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BF8E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BF8E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD3E30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ForceCalculateWindowBorders", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD3E30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD3E30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B28C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B28C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B28C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6AB24");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6AB24");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6AB24: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1A6D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GameDataCollectionDestructor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1A6D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1A6D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BFAC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCurrentFontProperty", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BFAC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BFAC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA88B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDefaultCameraScale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA88B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA88B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB29370");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameContextUnitStat", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB29370");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB29370: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFE9F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameModeFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFE9F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFE9F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BEF2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BEF2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BEF2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B7F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B7F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B7F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B03A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirementWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B03A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B03A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6ADA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6ADA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6ADA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B4C6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetMissileTargetY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B4C6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B4C6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B688");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B688");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B688: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B2BC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B2BC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B2BC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB8EE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetQuestSystemInitialized", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB8EE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB8EE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6ADE2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6ADE2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6ADE2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6AE54");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6AE54");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6AE54: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B292");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B292");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B292: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B160");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStringIdFromSlotIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B160");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B160: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B3CA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B3CA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B3CA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B57A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B57A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B57A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6ACD4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6ACD4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6ACD4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B580");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B580");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B580: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A9B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A9B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A9B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF10A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetViewportFieldAt12DF8", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF10A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF10A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB58A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetViewportYOffsetAdjusted", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB58A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB58A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB53230");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetWindowModeIfExpansion", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB53230");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB53230: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A80C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCandidateListA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A80C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A80C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A812");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCandidateListCountA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A812");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A812: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A7FA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCompositionStringA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A7FA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A7FA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A800");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A800");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A800: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A818");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetConversionStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A818");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A818: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A7F4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetOpenStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A7F4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A7F4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A806");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmIsIME", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A806");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A806: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A7EE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmReleaseContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A7EE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A7EE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A824");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSetConversionStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A824");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A824: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A82A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSetOpenStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A82A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A82A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A81E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSimulateHotKey", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A81E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A81E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACB6D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IncreaseWindowBorderY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACB6D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACB6D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A9EC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A9EC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A9EC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6AB6C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6AB6C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6AB6C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF6440");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeCharacterInventoryDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF6440");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF6440: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB25BC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeDialogBox", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB25BC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB25BC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB19D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB19D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB19D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB56AA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameObjectState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB56AA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB56AA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB01B20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameStateFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB01B20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB01B20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE8F10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameUIState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE8F10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE8F10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB01C50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameViewportConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB01C50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB01C50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD2F60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGlobalCounters", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD2F60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD2F60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA2870");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGlobalStateFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA2870");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA2870: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1F370");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeInventorySlotCounters", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1F370");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1F370: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA11E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeLanguageSupport", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA11E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA11E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB06D60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeMenuState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB06D60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB06D60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFDC60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeMouseButtonCallbacks", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFDC60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFDC60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB6A50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializePlayerStatistics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB6A50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB6A50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB8EC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeQuestClassTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB8EC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB8EC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB01C30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeRandomSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB01C30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB01C30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF6500");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeServerDialogStateHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF6500");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF6500: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF6470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeServerSocketDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF6470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF6470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFE970");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeSliderCursor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFE970");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFE970: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB528D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeStructureFields", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB528D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB528D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF6410");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeUIDialogConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF6410");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF6410: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB21970");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeViewportWindow", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB21970");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB21970: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1A670");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeVtablePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1A670");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1A670: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BF2E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsDSoundWaveEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BF2E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BF2E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1F680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsGameModeInPlayableState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1F680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1F680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADA710");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsInventoryOpen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADA710");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADA710: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B3AC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsMonsterBossType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B3AC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B3AC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEB930");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsObjectTypeMonster", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEB930");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEB930: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEB910");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsObjectTypeValid", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEB910");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEB910: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAAB250");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsRemoteSessionHandlingReady", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAAB250");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAAB250: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAAB290");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsRemoteSessionSupported", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAAB290");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAAB290: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B904");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsStateLevelFourOrHigher", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B904");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B904: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB247E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsTargetingEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB247E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB247E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADAB00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidRemoteDesktopSession", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADAB00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADAB00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B772");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidUnitType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B772");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B772: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB06EE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsVideoInitializationEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB06EE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB06EE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF12A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LB_DelegateVtbl13", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF12A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF12A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD81A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ListboxDelegateInnerVtableMethod14", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD81A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD81A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB074D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LoadBlendedShadowsSetting", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB074D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB074D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BE14");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10000", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BE14");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BE14: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BE32");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10001", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BE32");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BE32: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B7CC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10002", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B7CC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B7CC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BF5E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10004", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BF5E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BF5E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BF88");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10005", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BF88");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BF88: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BFD6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10006", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BFD6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BFD6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BF22");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10007", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BF22");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BF22: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BE02");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10008", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BE02");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BE02: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BEC8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10010", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BEC8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BEC8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BEF8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10014", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BEF8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BEF8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B7F6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10018", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B7F6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B7F6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BED4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10019", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BED4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BED4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BECE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10020", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BECE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BECE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BF16");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10023", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BF16");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BF16: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B868");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B868");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B868: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BE1A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10026", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BE1A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BE1A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BFD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BFD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BFD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BE56");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10029", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BE56");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BE56: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B7E4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10034", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B7E4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B7E4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B7AE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10036", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B7AE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B7AE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B7C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10046", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B7C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B7C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B880");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10050", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B880");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B880: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BF10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10057", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BF10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BF10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BF46");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10060", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BF46");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BF46: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BF34");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10064", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BF34");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BF34: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B8B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10067", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B8B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B8B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B826");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10070", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B826");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B826: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B8C2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10074", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B8C2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B8C2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B83E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10082", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B83E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B83E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6ACAA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6ACAA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6ACAA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB54CB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PlayVideoAndConfigureGraphics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB54CB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB54CB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB52940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PlayVideoFromStructure", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB52940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB52940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA6AB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessCompressionObjects", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA6AB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA6AB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6ACDA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessInventoryItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6ACDA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6ACDA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB4C940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessInventoryItemWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB4C940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB4C940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB23260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUIStateChange", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB23260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB23260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB286A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUnitCoordinateData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB286A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB286A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3D880");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUnitStats", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3D880");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3D880: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6024E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("QueryRegistryUlong", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6024E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6024E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB601AC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterCmdDef", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB601AC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB601AC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BFB8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RenderUnicodeTextWithLineHeight", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BFB8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BFB8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB06D20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetGameModeFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB06D20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB06D20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A7E8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A7E8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A7E8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB601A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB601A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB601A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA1160");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SafeDelete", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA1160");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA1160: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA1E80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SaveDefaultCommandLineToRegistry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA1E80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA1E80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BF1C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAutomapCentersEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BF1C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BF1C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACD650");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAutomapUpdateThrottle", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACD650");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACD650: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB074A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBlendedShadowsMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB074A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB074A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADCEF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCancelConfirmedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADCEF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADCEF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF6560");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCharacterInventoryDialogState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF6560");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF6560: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A764");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePointerWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A764");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A764: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A8CC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGameMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A8CC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A8CC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA2880");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalState4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA2880");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA2880: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA28A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalState6", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA28A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA28A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6AAA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetMissileDataField2C", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6AAA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6AAA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60242");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetRegistryDword", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60242");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60242: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB601BE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetRegistryStringValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB601BE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB601BE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD7F70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetSliderControlWidth", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD7F70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD7F70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA2890");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetStateLevelFive", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA2890");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA2890: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE9620");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetStateLevelSeven", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE9620");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE9620: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA61F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetTimeout500Ms", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA61F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA61F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A9E6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAllocatedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A9E6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A9E6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B3C4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B3C4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B3C4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B7EA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetWindowVisibility", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B7EA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B7EA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB629C9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetupExceptionHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB629C9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB629C9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FADA320");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownAutomapRendering", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FADA320");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FADA320: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAADC70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownCompressionService", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAADC70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAADC70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA1300");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownLanguageManager", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA1300");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA1300: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD7F60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD7F60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD7F60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BFBE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SumCharacterValues", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BFBE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BFBE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD7C20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("TEXT_ClearSelectionState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD7C20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD7C20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A968");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetRoom", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A968");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A968: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6BCD3");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnlinkListNode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6BCD3");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6BCD3: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6C3E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba41fe", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6C3E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6C3E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6C420");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba4368", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6C420");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6C420: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6C46A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba4400", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6C46A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6C46A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB238B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdateTimeoutValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB238B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB238B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB665DB");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteErrorMessage", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB665DB");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB665DB: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB62790");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__CallSettingFrame@12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB62790");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB62790: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60665");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__NLG_Notify1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60665");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60665: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB69919");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB69919");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB69919: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60642");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__abnormal_termination", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60642");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60642: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB618C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB618C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB618C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB61CBA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__amsg_exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB61CBA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB61CBA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB62E48");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB62E48");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB62E48: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB606C4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB606C4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB606C4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB62B58");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB62B58");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB62B58: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60E19");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60E19");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60E19: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB68288");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB68288");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB68288: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB64884");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB64884");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB64884: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB619F5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__seh_longjmp_unwind@4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB619F5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB619F5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB61900");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__strrev", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB61900");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB61900: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB64872");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB64872");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB64872: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB68230");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB68230");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB68230: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB61EF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strcmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB61EF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB61EF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB642A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB642A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB642A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB686A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB686A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB686A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60A50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60A50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60A50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB48100");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB48100");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB48100: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB48350");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_10", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB48350");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB48350: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB48390");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_11", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB48390");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB48390: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB47BF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB47BF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB47BF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB47CA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_3", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB47CA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB47CA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB47D50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB47D50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB47D50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB47EE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_6", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB47EE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB47EE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB47FA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_7", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB47FA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB47FA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB48110");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_9", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB48110");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB48110: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB48050");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_a", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB48050");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB48050: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB48180");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_d", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB48180");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB48180: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Client 1.10 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
