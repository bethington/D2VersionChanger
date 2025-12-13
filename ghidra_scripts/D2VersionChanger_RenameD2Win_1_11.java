// Auto-generated Ghidra rename script
// Module: D2Win
// Version: 1.11
// Generated: Cross-version renaming (Phase 4)
// Total renames: 58
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply D2Win 1.11 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameD2Win1.11 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7728");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearCelGraphicsCache", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F3B50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ConvertCharToUnicodeAndProcess", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F3B50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F3B50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E98C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ConvertCharToUnicodeAndSetEditData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E98C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E98C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E76D4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E76D4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E76D4: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E9840");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EditData_SetString", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E9840");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E9840: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E773A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCelFrameCount", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F0F90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDataTableEntry", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F0F90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F0F90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E77D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E77D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E77D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7722");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetGameStructureSelector", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E777C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitFlag", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E770A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetInitializedState", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E770A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E770A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E76FE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetMusicOptions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E76FE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E76FE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E775E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeAndCleanupQueues", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E776A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeCompressedGameData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E776A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E776A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EB740");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGameEngine", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EB740");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EB740: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EB6F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGraphics", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EB6F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EB6F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7764");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeGraphicsSystem", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7FB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsCharAlpha", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7FB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7FB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7FE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsCharDigit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7FE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7FE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EB420");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsPointInRect", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EB420");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EB420: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F39F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ListAddItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F39F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F39F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EE470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10006", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EE470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EE470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E77E8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10024", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E77E8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E77E8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8ED8A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10028", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8ED8A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8ED8A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EB440");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10030", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EB440");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EB440: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F82A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10032", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F82A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F82A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F5AD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10033", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F5AD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F5AD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EDFB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10034", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EDFB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EDFB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F1B70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10036", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F1B70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F1B70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E77C4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10038", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E77C4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E77C4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EAD30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10046", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EAD30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EAD30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EDFD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10047", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EDFD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EDFD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EB830");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("Ordinal_10052", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EB830");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EB830: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E76F2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ProcessAudioQueue", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F8280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReleaseCelFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F8280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F8280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E7674");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReleasePoolAllocation", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E7674");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E7674: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EB730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetInitMode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EB730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EB730: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EAF40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SafeDereferencePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EAF40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EAF40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F4880");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetCelGlobals", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F4880");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F4880: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EB760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EB760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EB760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EAF50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetLastInventoryItem", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EAF50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EAF50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E76F8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetMusicVolume", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F8260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShowInsertExpansionDiscDialog", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F8260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F8260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EB680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StopMessageLoop", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EB680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EB680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8EB860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdateMusicStateFromOptions", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8EB860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8EB860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F92E7");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F92E7");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F92E7: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F8B57");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F8B57");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F8B57: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E1220");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E1220");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E1220: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8F884A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8F884A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8F884A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E71AA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E71AA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E71AA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E4323");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E4323");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E4323: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E434F");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E434F");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E434F: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E41C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E41C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E41C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E46B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E46B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E46B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E4A00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E4A00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E4A00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6F8E1240");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6F8E1240");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6F8E1240: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("D2Win 1.11 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
