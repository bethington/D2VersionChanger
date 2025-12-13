// Auto-generated Ghidra rename script
// Module: D2Client
// Version: 1.09
// Generated: Cross-version renaming (Phase 4)
// Total renames: 225
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Client 1.09 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Client1.09 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD1570");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AutomapPlayerIconLine_SetField24", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD1570");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD1570: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACE4A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("BackupKeyBindingsAndReinitialize", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACE4A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACE4A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD1210");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CTRL_SetUpdateFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD1210");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD1210: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60ACC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CacheMarkSmsCategoriesForCopy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60ACC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60ACC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF5AE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CalculateMenuPanelYPosition", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF5AE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF5AE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC53D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CalculateWindowBorders", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC53D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC53D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB479C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CancelScreenFade", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB479C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB479C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB29D00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CheckTimeoutElapsed50ms", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB29D00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB29D00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB39E40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CheckValueAndProcessData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB39E40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB39E40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B85");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupAndDelete", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B85");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B85: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAAECC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupPlayerSlots", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAAECC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAAECC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB3AF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CleanupPlayerSlotsWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB3AF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB3AF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB521D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB521D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB521D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB33CD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearItemSlots", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB33CD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB33CD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD6580");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearPopupDialogResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD6580");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD6580: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F078");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearResetFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F078");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F078: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAAB920");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearTargetingState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAAB920");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAAB920: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB28F70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearUnitSelectionState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB28F70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB28F70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB609D6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB609D6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB609D6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FB28");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreatePoolObject", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FB28");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FB28: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FB70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateWaypointData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FB70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FB70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD15A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DecrementObjectCounter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD15A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD15A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC53B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DecrementWindowBorderY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC53B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC53B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB609D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DeleteFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB609D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB609D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6095E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DestroyDataArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6095E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6095E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B5C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DestructorWithCleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B5C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B5C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60BDC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DispatchJumpTableEntry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60BDC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60BDC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD1710");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DispatchVtableMethod34", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD1710");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD1710: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB28F80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnableVideoInitialization", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB28F80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB28F80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB683D5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExceptionCleanupAndExit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB683D5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB683D5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA8D00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExceptionHandlerLogAndCleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA8D00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA8D00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB69FD9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ExecuteInventoryCallback", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB69FD9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB69FD9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6086E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FindPaletteIndexForColor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6086E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6086E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACD3F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ForceCalculateWindowBorders", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACD3F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACD3F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FD4A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreePoolMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FD4A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FD4A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F330");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FreeTrackedPoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F330");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F330: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1FBA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GameDataCollectionDestructor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1FBA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1FBA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6088C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCurrentFontProperty", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6088C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6088C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA81D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDefaultCameraScale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA81D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA81D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2E8A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameContextUnitStat", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2E8A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2E8A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF8410");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameModeFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF8410");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF8410: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60A36");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60A36");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60A36: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB600CE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB600CE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB600CE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F88E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemAffixLevelRequirementWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F88E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F88E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F588");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetItemRandSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F588");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F588: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FD8C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetMissileTargetY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FD8C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FD8C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FF12");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathTargetUnit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FF12");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FF12: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FB3A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetPathX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FB3A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FB3A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB7BB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetQuestSystemInitialized", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB7BB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB7BB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F5DC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRoomNext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F5DC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F5DC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F666");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetRosterUnitXPos", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F666");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F666: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FB10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStatListOwnerType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FB10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FB10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F9A8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStringIdFromSlotIndex", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F9A8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F9A8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FC3C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetStructFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FC3C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FC3C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FDF8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitField91", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FDF8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FDF8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F4B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F4B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F4B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FDFE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitStatList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FDFE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FDFE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F1D4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetUnitX", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F1D4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F1D4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEA9E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetViewportFieldAt12DF8", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEA9E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEA9E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB4B70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetViewportYOffsetAdjusted", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB4B70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB4B70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB51BE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetWindowModeIfExpansion", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB51BE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB51BE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B38");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCandidateListA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B38");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B38: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B3E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCandidateListCountA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B3E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B3E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B26");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetCompositionStringA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B26");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B26: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B2C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B2C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B2C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B44");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetConversionStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B44");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B44: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmGetOpenStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B32");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmIsIME", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B32");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B32: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B1A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmReleaseContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B1A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B1A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSetConversionStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B56");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSetOpenStatus", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B56");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B56: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60B4A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImmSimulateHotKey", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60B4A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60B4A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC53C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IncreaseWindowBorderY", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC53C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC53C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F216");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitRngSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F216");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F216: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F360");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitTimerState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F360");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F360: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEFCB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeCharacterInventoryDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEFCB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEFCB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2B310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeDialogBox", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2B310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2B310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFFC60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFFC60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFFC60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB556A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameObjectState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB556A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB556A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFB540");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameStateFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFB540");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFB540: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE2380");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameUIState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE2380");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE2380: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFB670");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameViewportConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFB670");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFB670: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACC4A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGlobalCounters", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACC4A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACC4A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA2820");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGlobalStateFlags", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA2820");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA2820: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB24AA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeInventorySlotCounters", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB24AA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB24AA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA11F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeLanguageSupport", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA11F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA11F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB35420");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeMenuState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB35420");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB35420: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FACDA30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeMouseButtonCallbacks", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FACDA30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FACDA30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB5A30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializePlayerStatistics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB5A30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB5A30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAB7B90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeQuestClassTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAB7B90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAB7B90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAFB650");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeRandomSeed", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAFB650");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAFB650: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEFD70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeServerDialogStateHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEFD70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEFD70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEFCE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeServerSocketDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEFCE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEFCE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAF8390");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeSliderCursor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAF8390");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAF8390: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB51280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeStructureFields", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB51280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB51280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEFC80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeUIDialogConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEFC80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEFC80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB27190");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeViewportWindow", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB27190");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB27190: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB1FB40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeVtablePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB1FB40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB1FB40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6080E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsDSoundWaveEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6080E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6080E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB24DB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsGameModeInPlayableState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB24DB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB24DB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD3C80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsInventoryOpen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD3C80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD3C80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F64E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsMonsterBossType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F64E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F64E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE4E20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsObjectTypeMonster", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE4E20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE4E20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE4E00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsObjectTypeValid", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE4E00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE4E00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAAAB30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsRemoteSessionHandlingReady", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAAAB30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAAAB30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAAAB70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsRemoteSessionSupported", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAAAB70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAAAB70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB601E2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsStateLevelFourOrHigher", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB601E2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB601E2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB29E80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsTargetingEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB29E80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB29E80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAAAC00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidRemoteDesktopSession", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAAAC00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAAAC00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6003E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsValidUnitType", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6003E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6003E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA1CC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsVideoInitializationEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA1CC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA1CC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEAC10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LB_DelegateVtbl13", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEAC10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEAC10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEAC20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ListboxDelegateInnerVtableMethod14", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEAC20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEAC20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB01020");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LoadBlendedShadowsSetting", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB01020");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB01020: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10000", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6071E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10001", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6071E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6071E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB600AA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10002", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB600AA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB600AA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6083E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10004", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6083E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6083E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB606F4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10005", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB606F4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB606F4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB608B6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10006", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB608B6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB608B6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60802");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10007", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60802");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60802: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB606EE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10008", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB606EE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB606EE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB606CA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10010", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB606CA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB606CA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB607D8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10014", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB607D8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB607D8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB600D4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10018", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB600D4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB600D4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB601BE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10019", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6016A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10020", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6016A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6016A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6070C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10023", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6070C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6070C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60146");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60146");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60146: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60706");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10026", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60706");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60706: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6013A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6013A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6013A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60736");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10029", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60736");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60736: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB600C2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10034", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB600C2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB600C2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6008C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10036", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6008C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6008C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6009E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10046", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6009E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6009E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6015E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10050", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6015E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6015E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB607F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10057", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB607F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB607F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60182");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10060", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60182");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60182: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60814");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10064", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60814");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60814: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6018E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10067", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6018E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6018E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60104");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10070", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60104");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60104: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB601A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10074", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6011C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10082", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6011C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6011C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F684");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PATH_GetDirection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F684");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F684: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB536B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PlayVideoAndConfigureGraphics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB536B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB536B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB512F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("PlayVideoFromStructure", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB512F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB512F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA6710");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessCompressionObjects", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA6710");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA6710: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FC0C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessInventoryItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FC0C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FC0C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2DBF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessInventoryItemWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2DBF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2DBF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB28940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUIStateChange", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB28940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB28940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB2DE80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUnitCoordinateData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB2DE80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB2DE80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB3E230");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessUnitStats", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB3E230");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB3E230: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60AF6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("QueryRegistryUlong", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60AF6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60AF6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60A54");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterCmdDef", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60A54");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60A54: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60898");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RenderUnicodeTextWithLineHeight", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60898");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60898: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB008A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetGameModeFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB008A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB008A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6AF50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6AF50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6AF50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60A48");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60A48");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60A48: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA1170");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SafeDelete", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA1170");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA1170: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA1E40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SaveDefaultCommandLineToRegistry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA1E40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA1E40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB607FC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAutomapCentersEnabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB607FC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB607FC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAC72E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAutomapUpdateThrottle", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAC72E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAC72E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB00FF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBlendedShadowsMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB00FF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB00FF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD6DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCancelConfirmedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD6DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD6DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEFDD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCharacterInventoryDialogState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEFDD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEFDD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB609C4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePointerWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB609C4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB609C4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F0CC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGameMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F0CC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F0CC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA2830");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalState4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA2830");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA2830: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAE2AA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalState6", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAE2AA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAE2AA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F2B2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetMissileDataField2C", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F2B2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F2B2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60AEA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetRegistryDword", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60AEA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60AEA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60A66");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetRegistryStringValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60A66");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60A66: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD1560");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetSliderControlWidth", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD1560");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD1560: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA2840");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetStateLevelFive", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA2840");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA2840: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA2860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetStateLevelSeven", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA2860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA2860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA5E40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetTimeout500Ms", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA5E40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA5E40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F20A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitAllocatedFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F20A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F20A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FC36");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetUnitFlag0x20", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FC36");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FC36: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB600C8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetWindowVisibility", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB600C8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB600C8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB63139");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetupExceptionHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB63139");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB63139: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD38A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownAutomapRendering", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD38A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD38A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAAD7D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownCompressionService", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAAD7D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAAD7D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAA1310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownLanguageManager", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAA1310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAA1310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAEA800");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubReturnZero", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAEA800");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAEA800: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6089E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SumCharacterValues", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6089E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6089E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FAD1220");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("TEXT_ClearSelectionState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FAD1220");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FAD1220: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5FAFE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetField08", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5FAFE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5FAFE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB5F174");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UNITS_GetRoom", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB5F174");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB5F174: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB605C5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnlinkListNode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB605C5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB605C5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B2A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba41fe", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B2A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B2A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B2E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba4368", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B2E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B2E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6B32A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Unwind@6fba4400", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6B32A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6B32A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB28F90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdateTimeoutValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB28F90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB28F90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB66D9B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteErrorMessage", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB66D9B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB66D9B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB62F00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__CallSettingFrame@12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB62F00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB62F00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60F55");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__NLG_Notify1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60F55");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60F55: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB6A1B9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB6A1B9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB6A1B9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB60F32");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__abnormal_termination", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB60F32");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB60F32: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB66330");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB66330");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB66330: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB623EA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__amsg_exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB623EA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB623EA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB635B8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB635B8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB635B8: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB632C8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB632C8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB632C8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB61709");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB61709");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB61709: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB68B28");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB68B28");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB68B28: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB64FF4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB64FF4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB64FF4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB681C9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__seh_longjmp_unwind@4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB681C9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB681C9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB62110");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__strrev", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB62110");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB62110: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB64FE2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB64FE2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB64FE2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB68AD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB68AD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB68AD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB62660");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strcmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB62660");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB62660: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB64A10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB64A10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB64A10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB68F40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB68F40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB68F40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB61340");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB61340");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB61340: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB46760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_1", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB46760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB46760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB46980");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_10", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB46980");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB46980: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB469C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_11", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB469C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB469C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB46320");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB46320");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB46320: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB463B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_3", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB463B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB463B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB46440");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_4", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB46440");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB46440: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB465A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_6", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB465A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB465A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB46640");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_7", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB46640");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB46640: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB46770");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_9", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB46770");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB46770: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB466D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_a", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB466D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB466D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FB467D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("caseD_d", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FB467D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FB467D0: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Client 1.09 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
