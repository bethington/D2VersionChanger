// Auto-generated Ghidra rename script
// Module: Storm
// Version: 1.12a
// Generated: Cross-version renaming (Phase 4)
// Total renames: 52
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply Storm 1.12a Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameStorm1.12a extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC04C20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AcquireGlobalLock", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC04C20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC04C20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2CC30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AullDiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2CC30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2CC30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC19C90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClosePaletteWindow", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC19C90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC19C90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC24360");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareMemoryBytes", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC24360");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC24360: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC24330");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CopyMemoryBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC24330");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC24330: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0D9A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EndDialogWithResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0D9A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0D9A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFBC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FillMemoryWithByte", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFBC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFBC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFF7F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FindLongestMatch", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFF7F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFF7F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFC30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FlushBitWriteBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFC30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFC30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC15000");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FlushFileWriteBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC15000");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC15000: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF23B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GameDataCollectionDestructor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF23B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF23B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC24930");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDebugReturnStringEnd", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC24930");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC24930: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC19DE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDirectDrawInterfaces", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC19DE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC19DE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2B9E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetEntryValueById", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2B9E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2B9E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC00840");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetExecutableDirectoryPath", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC00840");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC00840: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFEC02");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetFileVersionInfoSizeA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFEC02");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFEC02: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC28DC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetLastError", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC28DC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC28DC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2BA20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("HasEntryById", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2BA20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2BA20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFCB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImplodeBuildSortTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFCB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFCB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFF470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImplodeEncodeBlock", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFF470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFF470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2C400");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitCommandLineParsing", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2C400");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2C400: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFF2D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitCompressContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFF2D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFF2D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF2260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeVtablePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF2260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF2260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC035C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeWorkerThread", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC035C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC035C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0C140");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsHandleInCodecList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0C140");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0C140: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC242E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MoveMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC242E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC242E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2C300");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ParseCommandLineArgs", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2C300");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2C300: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC03610");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadArchiveFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC03610");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC03610: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC120A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterDialogClasses", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC120A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC120A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC14B70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterEventHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC14B70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC14B70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC32960");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterExceptionFilter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC32960");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC32960: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC05640");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReportHandleLeak", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC05640");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC05640: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A060");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A060");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A060: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC05FC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SStrCopy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC05FC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC05FC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC04BC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetErrorHandlingDisabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC04BC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC04BC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFD70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalConfigByte2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFD70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFD70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFD80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalUshortConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFD80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFD80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0D860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetLocale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0D860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0D860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF1020");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownStubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF1020");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF1020: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC1C7D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StoreVersionFromContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC1C7D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC1C7D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC057A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StringToUpper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC057A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC057A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC1C7A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC1C7A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC1C7A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF1FE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnlinkListNode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF1FE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF1FE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC1A2E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdatePaletteAndMarkRealized", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC1A2E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC1A2E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC1A060");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdatePaletteAndRealize", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC1A060");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC1A060: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFB30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteBitsToBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFB30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFB30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF3DB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteBitsToStream", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF3DB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF3DB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFE920");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFE920");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFE920: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC04C60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__break", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC04C60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC04C60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF7234");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strupr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF7234");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF7234: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF5AE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("memmove", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF5AE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF5AE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF70DA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("setlocale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF70DA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF70DA: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("Storm 1.12a Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
