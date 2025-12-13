// Auto-generated Ghidra rename script
// Module: Storm
// Version: 1.11
// Generated: Cross-version renaming (Phase 4)
// Total renames: 52
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply Storm 1.11 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameStorm1.11 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC29C50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AcquireGlobalLock", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC29C50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC29C50: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFD60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClosePaletteWindow", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFD60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFD60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC06130");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareMemoryBytes", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC06130");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC06130: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC06100");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CopyMemoryBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC06100");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC06100: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC20DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EndDialogWithResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC20DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC20DA0: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC1EC00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FlushFileWriteBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC1EC00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC1EC00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF2600");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GameDataCollectionDestructor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF2600");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF2600: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC04570");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDebugReturnStringEnd", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC04570");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC04570: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFFE50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDirectDrawInterfaces", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFFE50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFFE50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC06460");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetEntryValueById", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC06460");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC06460: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC1A740");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetExecutableDirectoryPath", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC1A740");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC1A740: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFEBB2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetFileVersionInfoSizeA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFEBB2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFEBB2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC29C30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetLastError", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC29C30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC29C30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC064A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("HasEntryById", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC064A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC064A0: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC06E80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitCommandLineParsing", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC06E80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC06E80: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF24B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeVtablePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF24B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF24B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC1D440");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeWorkerThread", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC1D440");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC1D440: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC25A90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsHandleInCodecList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC25A90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC25A90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC060B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MoveMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC060B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC060B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC06D80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ParseCommandLineArgs", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC06D80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC06D80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC1D490");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadArchiveFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC1D490");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC1D490: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC254A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterDialogClasses", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC254A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC254A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0CF30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterEventHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0CF30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0CF30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC32870");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterExceptionFilter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC32870");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC32870: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC2A6F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReportHandleLeak", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC2A6F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC2A6F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC180B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC180B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC180B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0C590");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SStrCopy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0C590");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0C590: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC29BF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetErrorHandlingDisabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC29BF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC29BF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC19BF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalConfigByte2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC19BF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC19BF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC19C00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalUshortConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC19C00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC19C00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC20C60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetLocale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC20C60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC20C60: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0D240");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StoreVersionFromContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0D240");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0D240: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0B750");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StringToUpper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0B750");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0B750: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC0D210");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC0D210");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC0D210: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF4560");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnlinkListNode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF4560");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF4560: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC004C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdatePaletteAndMarkRealized", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC004C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC004C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC001E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdatePaletteAndRealize", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC001E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC001E0: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF1460");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteBitsToStream", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF1460");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF1460: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBFE8D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBFE8D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBFE8D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FC29CC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__break", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FC29CC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FC29CC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF73DD");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strupr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF73DD");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF73DD: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF6A30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("memmove", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF6A30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF6A30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FBF68CC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("setlocale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FBF68CC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FBF68CC: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("Storm 1.11 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
