// Auto-generated Ghidra rename script
// Module: D2Win
// Version: 1.10
// Generated: Cross-version renaming (Phase 4)
// Total renames: 58
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Win 1.10 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Win1.10 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B2096");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearCelGraphicsCache", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B2096");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B2096: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8AC4F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ConvertCharToUnicodeAndProcess", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8AC4F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8AC4F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8A80F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ConvertCharToUnicodeAndSetEditData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8A80F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8A80F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B266E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B266E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B266E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B4AB9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DisplayRuntimeError", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B4AB9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B4AB9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8A8140");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EditData_SetString", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8A8140");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8A8140: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B206C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCelFrameCount", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B206C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B206C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8AE930");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDataTableEntry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8AE930");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8AE930: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B9292");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B9292");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B9292: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B2090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameStructureSelector", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B2090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B2090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B20C6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B20C6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B20C6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B92B6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitializedState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B92B6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B92B6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B92B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetMusicOptions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B92B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B92B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B20A8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeAndCleanupQueues", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B20A8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B20A8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B209C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeCompressedGameData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B209C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B209C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ACDB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameEngine", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ACDB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ACDB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ACDE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGraphics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ACDE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ACDE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B20A2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGraphicsSystem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B20A2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B20A2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8A9870");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsCharAlpha", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8A9870");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8A9870: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8A9850");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsCharDigit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8A9850");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8A9850: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8AD650");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsPointInRect", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8AD650");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8AD650: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8AC570");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ListAddItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8AC570");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8AC570: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ACF20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10006", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ACF20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ACF20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B20F6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B20F6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B20F6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8AE9F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8AE9F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8AE9F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B2108");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10030", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B2108");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B2108: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B20FC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10032", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B20FC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B20FC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B2102");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10033", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B2102");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B2102: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B92A4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10034", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B92A4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B92A4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B2162");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10036", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B2162");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B2162: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B2168");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10038", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B2168");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B2168: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B2614");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10046", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B2614");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B2614: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8AFE30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10047", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8AFE30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8AFE30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B215C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10052", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B215C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B215C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B92AA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessAudioQueue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B92AA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B92AA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8A5AE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReleaseCelFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8A5AE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8A5AE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B260E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReleasePoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B260E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B260E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ACDD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetInitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ACDD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ACDD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B92BC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B92BC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B92BC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8AE530");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SafeDereferencePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8AE530");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8AE530: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8A3360");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCelGlobals", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8A3360");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8A3360: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ACF50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ACF50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ACF50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8AE510");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetLastInventoryItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8AE510");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8AE510: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B929E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetMusicVolume", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B929E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B929E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8A5B40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShowInsertExpansionDiscDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8A5B40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8A5B40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ACF80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StopMessageLoop", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ACF80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ACF80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8AE020");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdateMusicStateFromOptions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8AE020");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8AE020: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B8381");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B8381");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B8381: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B3FBC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B3FBC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B3FBC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B26C4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B26C4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B26C4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B3CCC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B3CCC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B3CCC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B6540");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B6540");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B6540: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B4D07");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B4D07");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B4D07: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B4CF5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B4CF5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B4CF5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B5430");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B5430");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B5430: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B4F00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B4F00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B4F00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B4F80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B4F80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B4F80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8B28C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8B28C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8B28C0: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Win 1.10 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
