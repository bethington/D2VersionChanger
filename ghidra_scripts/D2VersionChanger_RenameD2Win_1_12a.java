// Auto-generated Ghidra rename script
// Module: D2Win
// Version: 1.12a
// Generated: Cross-version renaming (Phase 4)
// Total renames: 58
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Win 1.12a Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Win1.12a extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E779A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearCelGraphicsCache", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E779A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E779A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EE190");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ConvertCharToUnicodeAndProcess", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EE190");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EE190: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EADD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ConvertCharToUnicodeAndSetEditData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EADD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EADD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E76F2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E76F2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E76F2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E37AC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DisplayRuntimeError", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E37AC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E37AC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EAD50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EditData_SetString", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EAD50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EAD50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7764");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCelFrameCount", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7764");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7764: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E8FC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDataTableEntry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E8FC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E8FC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E77EE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E77EE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E77EE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7794");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameStructureSelector", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7794");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7794: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7854");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7854");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7854: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E773A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitializedState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E773A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E773A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E772E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetMusicOptions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E772E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E772E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7776");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeAndCleanupQueues", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7776");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7776: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7782");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeCompressedGameData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7782");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7782: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ECB80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameEngine", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ECB80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ECB80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ECB30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGraphics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ECB30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ECB30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E777C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGraphicsSystem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E777C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E777C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E94C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsCharAlpha", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E94C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E94C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E94F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsCharDigit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E94F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E94F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EC7F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsPointInRect", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EC7F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EC7F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EE030");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ListAddItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EE030");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EE030: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EDD30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10006", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EDD30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EDD30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7806");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7806");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7806: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F1110");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F1110");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F1110: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7FC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10030", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7FC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7FC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E784E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10032", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E784E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E784E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E93B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10033", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E93B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E93B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E96A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10034", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E96A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E96A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F13B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10036", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F13B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F13B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F4340");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10038", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F4340");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F4340: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F3030");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10046", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F3030");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F3030: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E8690");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10047", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E8690");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E8690: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F3060");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10052", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F3060");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F3060: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7722");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessAudioQueue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7722");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7722: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E8A50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReleaseCelFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E8A50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E8A50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E76C2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReleasePoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E76C2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E76C2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ECB70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetInitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ECB70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ECB70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E763E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E763E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E763E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EC250");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SafeDereferencePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EC250");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EC250: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F30A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCelGlobals", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F30A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F30A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ECBA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ECBA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ECBA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EC260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetLastInventoryItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EC260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EC260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7728");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetMusicVolume", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7728");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7728: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E8A30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShowInsertExpansionDiscDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E8A30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E8A30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ECA50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StopMessageLoop", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ECA50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ECA50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ECCA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdateMusicStateFromOptions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ECCA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ECCA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F93E9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F93E9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F93E9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F8C3D");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F8C3D");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F8C3D: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E11B7");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E11B7");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E11B7: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F8922");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F8922");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F8922: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E71D2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E71D2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E71D2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E3AF8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E3AF8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E3AF8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E3B24");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E3B24");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E3B24: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E48E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E48E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E48E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E4D10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E4D10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E4D10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E5060");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E5060");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E5060: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E11E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E11E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E11E0: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Win 1.12a Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
