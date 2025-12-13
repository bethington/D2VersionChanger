// Auto-generated Ghidra rename script
// Module: D2Win
// Version: 1.13d
// Generated: Cross-version renaming (Phase 4)
// Total renames: 58
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Win 1.13d Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Win1.13d extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7764");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearCelGraphicsCache", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F81B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ConvertCharToUnicodeAndProcess", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F81B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F81B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F0700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ConvertCharToUnicodeAndSetEditData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F0700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F0700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E37BC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("DisplayRuntimeError", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E37BC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E37BC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F0680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EditData_SetString", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F0680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F0680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7722");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCelFrameCount", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F8590");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDataTableEntry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F8590");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F8590: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7830");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7830");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7830: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E775E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameStructureSelector", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E775E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E775E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E77B8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitFlag", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E77B8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E77B8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7704");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitializedState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7704");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7704: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E76F8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetMusicOptions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E76F8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E76F8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7746");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeAndCleanupQueues", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7746");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7746: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7752");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeCompressedGameData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7752");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7752: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EDE00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameEngine", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EDE00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EDE00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EDDB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGraphics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EDDB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EDDB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E774C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGraphicsSystem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E774C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E774C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EEDF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsCharAlpha", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EEDF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EEDF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EEE20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsCharDigit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EEE20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EEE20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EDB20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsPointInRect", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EDB20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EDB20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F8050");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ListAddItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F8050");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F8050: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F1C70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10006", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F1C70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F1C70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E8520");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E8520");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E8520: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F1D80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F1D80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F1D80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F63A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10030", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F63A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F63A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E8370");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10032", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E8370");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E8370: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F1A10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10033", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F1A10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F1A10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F8980");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10034", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F8980");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F8980: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F4F50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10036", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F4F50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F4F50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EBDB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10038", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EBDB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EBDB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F7B50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10046", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F7B50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F7B50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F3B70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10047", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F3B70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F3B70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F6700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10052", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F6700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F6700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E76EC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessAudioQueue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E76EC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E76EC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ECF10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReleaseCelFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ECF10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ECF10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E766E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReleasePoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E766E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E766E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EDDF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetInitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EDDF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EDDF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E760E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E760E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E760E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ED3B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SafeDereferencePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ED3B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ED3B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E8EB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCelGlobals", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E8EB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E8EB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EDE20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EDE20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EDE20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ED3C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetLastInventoryItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ED3C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ED3C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E76F2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetMusicVolume", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ECEF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShowInsertExpansionDiscDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ECEF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ECEF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EDD40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StopMessageLoop", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EDD40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EDD40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EDF20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdateMusicStateFromOptions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EDF20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EDF20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F9697");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F9697");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F9697: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F8F07");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F8F07");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F8F07: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E120F");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E120F");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E120F: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F8BFA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F8BFA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F8BFA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E6C82");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E6C82");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E6C82: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E3FE6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E3FE6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E3FE6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E4012");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E4012");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E4012: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E5030");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E5030");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E5030: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E3EE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E3EE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E3EE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E56E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E56E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E56E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E1230");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E1230");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E1230: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Win 1.13d Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
