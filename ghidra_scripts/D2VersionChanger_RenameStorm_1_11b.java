// Auto-generated Ghidra rename script
// Module: Storm
// Version: 1.11b
// Generated: Cross-version renaming (Phase 4)
// Total renames: 52
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply Storm 1.11b Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameStorm1.11b extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC26EC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AcquireGlobalLock", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC26EC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC26EC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2CBC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AullDiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2CBC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2CBC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A550");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClosePaletteWindow", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A550");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A550: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFDC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareMemoryBytes", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFDC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFDC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFD90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CopyMemoryBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFD90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFD90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC1D470");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EndDialogWithResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC1D470");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC1D470: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFB70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FillMemoryWithByte", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFB70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFB70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFF760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FindLongestMatch", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFF760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFF760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFBE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FlushBitWriteBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFBE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFBE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC097B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FlushFileWriteBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC097B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC097B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF32A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GameDataCollectionDestructor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF32A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF32A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC288E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDebugReturnStringEnd", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC288E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC288E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A870");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDirectDrawInterfaces", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A870");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A870: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0D150");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetEntryValueById", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0D150");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0D150: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC01D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetExecutableDirectoryPath", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC01D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC01D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFEBAA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetFileVersionInfoSizeA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFEBAA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFEBAA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC26EA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetLastError", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC26EA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC26EA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0D190");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("HasEntryById", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0D190");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0D190: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFC60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImplodeBuildSortTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFC60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFC60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFF3E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImplodeEncodeBlock", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFF3E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFF3E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0DB70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitCommandLineParsing", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0DB70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0DB70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFF240");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitCompressContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFF240");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFF240: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF3150");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeVtablePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF3150");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF3150: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC04A30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeWorkerThread", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC04A30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC04A30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC19FA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsHandleInCodecList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC19FA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC19FA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFD40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MoveMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFD40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFD40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0DA70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ParseCommandLineArgs", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0DA70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0DA70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC04A80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadArchiveFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC04A80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC04A80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC21B70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterDialogClasses", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC21B70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC21B70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC26C20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterEventHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC26C20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC26C20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC328A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterExceptionFilter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC328A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC328A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC27960");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReportHandleLeak", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC27960");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC27960: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC23350");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC23350");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC23350: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC00C30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SStrCopy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC00C30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC00C30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC26E60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetErrorHandlingDisabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC26E60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC26E60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC011E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalConfigByte2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC011E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC011E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC011F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalUshortConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC011F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC011F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC1D330");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetLocale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC1D330");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC1D330: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0DCA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StoreVersionFromContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0DCA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0DCA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFDF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StringToUpper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFDF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFDF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0DC70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0DC70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0DC70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF4E20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnlinkListNode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF4E20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF4E20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2ABA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdatePaletteAndMarkRealized", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2ABA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2ABA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2AAF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdatePaletteAndRealize", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2AAF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2AAF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFAA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteBitsToBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFAA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFAA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF16F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteBitsToStream", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF16F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF16F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFE720");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFE720");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFE720: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC26F30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__break", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC26F30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC26F30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF73F2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strupr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF73F2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF73F2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF6F20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("memmove", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF6F20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF6F20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF6634");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("setlocale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF6634");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF6634: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("Storm 1.11b Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
