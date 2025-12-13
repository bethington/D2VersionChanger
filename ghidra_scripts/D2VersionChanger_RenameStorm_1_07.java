// Auto-generated Ghidra rename script
// Module: Storm
// Version: 1.07
// Generated: Cross-version renaming (Phase 4)
// Total renames: 52
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply Storm 1.07 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameStorm1.07 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC2860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AcquireGlobalLock", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC2860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC2860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFE0430");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AullDiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFE0430");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFE0430: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC20C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClosePaletteWindow", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC20C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC20C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFCD550");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareMemoryBytes", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFCD550");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFCD550: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFE03F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CopyMemoryBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFE03F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFE03F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC04D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EndDialogWithResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC04D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC04D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDFBC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FillMemoryWithByte", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDFBC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDFBC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF7F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FindLongestMatch", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF7F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF7F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDFC30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FlushBitWriteBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDFC30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDFC30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFCAEA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FlushFileWriteBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFCAEA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFCAEA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDA920");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GameDataCollectionDestructor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDA920");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDA920: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFBA910");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDebugReturnStringEnd", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFBA910");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFBA910: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC1BB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDirectDrawInterfaces", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC1BB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC1BB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFB86B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetEntryValueById", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFB86B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFB86B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC79E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetExecutableDirectoryPath", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC79E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC79E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF2C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetFileVersionInfoSizeA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF2C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF2C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDBA20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetLastError", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDBA20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDBA20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFB8690");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("HasEntryById", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFB8690");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFB8690: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDFCB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImplodeBuildSortTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDFCB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDFCB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImplodeEncodeBlock", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFB9160");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitCommandLineParsing", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFB9160");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFB9160: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF2D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitCompressContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF2D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF2D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDA950");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeVtablePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDA950");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDA950: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC5A00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeWorkerThread", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC5A00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC5A00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDD610");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsHandleInCodecList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDD610");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDD610: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFCD5E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MoveMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFCD5E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFCD5E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFB87B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ParseCommandLineArgs", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFB87B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFB87B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC9000");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadArchiveFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC9000");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC9000: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFBE450");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterDialogClasses", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFBE450");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFBE450: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC3990");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterEventHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC3990");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC3990: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFCDD30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterExceptionFilter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFCDD30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFCDD30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC30E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReportHandleLeak", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC30E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC30E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFCC8C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFCC8C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFCC8C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDAAA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SStrCopy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDAAA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDAAA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC94F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetErrorHandlingDisabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC94F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC94F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC9770");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalConfigByte2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC9770");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC9770: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC9760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalUshortConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC9760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC9760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC0C80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetLocale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC0C80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC0C80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDACA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownStubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDACA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDACA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFD15F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StoreVersionFromContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFD15F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFD15F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDB920");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StringToUpper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDB920");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDB920: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFD2040");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFD2040");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFD2040: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC97C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnlinkListNode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC97C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC97C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC16E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdatePaletteAndMarkRealized", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC16E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC16E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC20E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdatePaletteAndRealize", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC20E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC20E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDFB30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteBitsToBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDFB30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDFB30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFBC650");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteBitsToStream", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFBC650");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFBC650: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFE04A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFE04A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFE04A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC2D20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__break", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC2D20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC2D20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF2A8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strupr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF2A8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF2A8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF288");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("memmove", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF288");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF288: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF26A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("setlocale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF26A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF26A: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("Storm 1.07 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
