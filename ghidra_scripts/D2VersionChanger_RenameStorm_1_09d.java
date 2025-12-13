// Auto-generated Ghidra rename script
// Module: Storm
// Version: 1.09d
// Generated: Cross-version renaming (Phase 4)
// Total renames: 52
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply Storm 1.09d Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameStorm1.09d extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC2940");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AcquireGlobalLock", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC2940");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC2940: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFE0A10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AullDiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFE0A10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFE0A10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC21A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClosePaletteWindow", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC21A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC21A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFCDC40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareMemoryBytes", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFCDC40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFCDC40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFE01A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CopyMemoryBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFE01A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFE01A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC05B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EndDialogWithResult", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC05B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC05B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFE01E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FillMemoryWithByte", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFE01E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFE01E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDFDD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FindLongestMatch", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDFDD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDFDD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFE0250");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FlushBitWriteBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFE0250");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFE0250: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFCB590");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("FlushFileWriteBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFCB590");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFCB590: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDAEE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GameDataCollectionDestructor", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDAEE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDAEE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFBA980");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDebugReturnStringEnd", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFBA980");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFBA980: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC1C90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetDirectDrawInterfaces", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC1C90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC1C90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFB8720");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetEntryValueById", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFB8720");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFB8720: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC7D80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetExecutableDirectoryPath", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC7D80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC7D80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF8A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetFileVersionInfoSizeA", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF8A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF8A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDC000");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetLastError", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDC000");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDC000: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFB8700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("HasEntryById", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFB8700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFB8700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFE02D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImplodeBuildSortTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFE02D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFE02D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDFA50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ImplodeEncodeBlock", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDFA50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDFA50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFB91D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitCommandLineParsing", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFB91D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFB91D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF8B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitCompressContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF8B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF8B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDAF10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeVtablePointer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDAF10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDAF10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC5AF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeWorkerThread", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC5AF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC5AF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDDBF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IsHandleInCodecList", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDDBF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDDBF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFCDCD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("MoveMemory", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFCDCD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFCDCD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFB8820");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ParseCommandLineArgs", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFB8820");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFB8820: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC9580");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadArchiveFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC9580");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC9580: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFBE530");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterDialogClasses", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFBE530");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFBE530: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC3A70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterEventHandler", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC3A70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC3A70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFCE420");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterExceptionFilter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFCE420");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFCE420: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC31C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReportHandleLeak", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC31C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC31C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFCCFB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFCCFB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFCCFB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDB060");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SStrCopy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDB060");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDB060: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC9B30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetErrorHandlingDisabled", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC9B30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC9B30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC9DB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalConfigByte2", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC9DB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC9DB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC9DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetGlobalUshortConfig", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC9DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC9DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC0D60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetLocale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC0D60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC0D60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDB260");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ShutdownStubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDB260");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDB260: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFD1CE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StoreVersionFromContext", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFD1CE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFD1CE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDBF00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StringToUpper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDBF00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDBF00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFD2730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFD2730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFD2730: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFD97F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UnlinkListNode", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFD97F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFD97F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC17C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdatePaletteAndMarkRealized", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC17C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC17C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC21C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("UpdatePaletteAndRealize", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC21C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC21C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFE0110");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteBitsToBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFE0110");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFE0110: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFBC740");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteBitsToStream", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFBC740");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFBC740: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFE0A80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFE0A80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFE0A80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFC2E00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__break", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFC2E00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFC2E00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF888");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strupr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF888");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF888: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF862");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("memmove", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF862");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF862: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FFDF84A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("setlocale", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FFDF84A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FFDF84A: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("Storm 1.09d Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
