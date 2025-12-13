// Auto-generated Ghidra rename script
// Module: D2Win
// Version: 1.07
// Generated: Cross-version renaming (Phase 4)
// Total renames: 58
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Win 1.07 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Win1.07 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913D46");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearCelGraphicsCache", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913D46");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913D46: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90DDE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ConvertCharToUnicodeAndProcess", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90DDE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90DDE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F909CC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ConvertCharToUnicodeAndSetEditData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F909CC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F909CC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F9142C2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F9142C2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F9142C2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F91694B");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DisplayRuntimeError", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F91694B");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F91694B: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F909D10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EditData_SetString", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F909D10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F909D10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913D1C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCelFrameCount", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913D1C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913D1C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F910260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDataTableEntry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F910260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F910260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90FE30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90FE30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90FE30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913D40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameStructureSelector", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913D40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913D40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913D76");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913D76");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913D76: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F91C4DE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitializedState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F91C4DE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F91C4DE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F91C4D8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetMusicOptions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F91C4D8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F91C4D8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913D58");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeAndCleanupQueues", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913D58");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913D58: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913D4C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeCompressedGameData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913D4C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913D4C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90E6F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameEngine", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90E6F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90E6F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90E720");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGraphics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90E720");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90E720: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913D52");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGraphicsSystem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913D52");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913D52: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90B470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsCharAlpha", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90B470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90B470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90B450");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsCharDigit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90B450");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90B450: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90EF50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsPointInRect", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90EF50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90EF50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90DE60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ListAddItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90DE60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90DE60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90E860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10006", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90E860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90E860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913DE2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913DE2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913DE2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913DB2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10030", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913DB2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913DB2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913DA6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10032", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913DA6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913DA6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913DAC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10033", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913DAC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913DAC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F91C4CC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10034", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F91C4CC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F91C4CC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913E0C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10036", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913E0C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913E0C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913E12");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10038", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913E12");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913E12: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913DF4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10046", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913DF4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913DF4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913DBE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10047", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913DBE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913DBE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F913E06");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10052", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F913E06");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F913E06: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F91C4D2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessAudioQueue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F91C4D2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F91C4D2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F907620");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReleaseCelFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F907620");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F907620: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F914268");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReleasePoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F914268");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F914268: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90E710");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetInitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90E710");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90E710: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F91C4E4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F91C4E4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F91C4E4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90FE60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SafeDereferencePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90FE60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90FE60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F904D20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCelGlobals", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F904D20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F904D20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90E680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90E680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90E680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90FE40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetLastInventoryItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90FE40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90FE40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F91C4C6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetMusicVolume", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F91C4C6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F91C4C6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F907640");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShowInsertExpansionDiscDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F907640");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F907640: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90E8C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StopMessageLoop", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90E8C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90E8C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F90F940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdateMusicStateFromOptions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F90F940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F90F940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F91AC89");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F91AC89");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F91AC89: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F915E4E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F915E4E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F915E4E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F91437E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F91437E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F91437E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F915B5E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F915B5E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F915B5E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F9189A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F9189A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F9189A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F916B99");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F916B99");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F916B99: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F916B87");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F916B87");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F916B87: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F9172D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F9172D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F9172D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F916DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F916DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F916DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F916E20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F916E20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F916E20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F914570");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F914570");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F914570: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Win 1.07 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
