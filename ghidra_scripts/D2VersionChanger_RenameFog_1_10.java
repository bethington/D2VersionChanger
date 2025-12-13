// Auto-generated Ghidra rename script
// Module: Fog
// Version: 1.10
// Generated: Cross-version renaming (Phase 4)
// Total renames: 60
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply Fog 1.10 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameFog1.10 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5A720");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AtomicExchange64", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5A720");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5A720: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5A740");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AtomicRead64", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5A740");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5A740: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF53370");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF53370");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF53370: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF63280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CloseHandleWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF63280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF63280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF659F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareStringsIgnoreCase", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF659F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF659F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF632D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateStormThread", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF632D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF632D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF632F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateTcpConnection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF632F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF632F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51B40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EncodeVarInt2Byte", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51B40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51B40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5DC40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnterCriticalSectionWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5DC40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5DC40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51DF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCosineFromTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51DF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51DF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51AD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetField0x110", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51AD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51AD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF54920");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetField880", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF54920");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF54920: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5DF20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetFogStatePtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5DF20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5DF20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51E10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetSineValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51E10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51E10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5A5B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetTickCount", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5A5B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5A5B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61A70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IffCreate", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61A70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61A70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61AE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IffDestroy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61AE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61AE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61C50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeLogManager", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61C50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61C50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF63760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LeaveSocketCriticalSection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF63760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF63760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5E6A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LogMessage", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5E6A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5E6A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF64466");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileWithDefaultArchive", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF64466");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF64466: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF64460");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadArchiveFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF64460");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF64460: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61620");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadFileAsync", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61620");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61620: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61C70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterExceptionFilter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61C70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61C70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5A580");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetPerformanceAccumulators", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5A580");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5A580: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF70B14");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF70B14");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF70B14: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF643D6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemAlloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF643D6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF643D6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF643D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF643D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF643D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF578F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SendSocketData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF578F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF578F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61650");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAsyncFileHandle", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61650");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61650: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF53320");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF53320");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF53320: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61710");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePointerWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61710");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61710: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6446C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePosition", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6446C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6446C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66D85");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFpuControlWord", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66D85");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66D85: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF57410");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF57410");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF57410: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF57620");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubOrdinal10183", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF57620");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF57620: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF53E20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("TitleCaseString", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF53E20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF53E20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5DC60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ValidateCriticalSection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5DC60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5DC60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF632C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WSACleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF632C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF632C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF616F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF616F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF616F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF67C14");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteStringToBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF67C14");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF67C14: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF70B0E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__WSAFDIsSet", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF70B0E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF70B0E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F5CA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F5CA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F5CA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF64BB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__alldiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF64BB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF64BB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF65730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF65730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF65730: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF668B4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF668B4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF668B4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF644C8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF644C8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF644C8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF665C4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF665C4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF665C4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF65B18");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF65B18");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF65B18: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66DB5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fload_withFB", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66DB5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66DB5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6C8B8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6C8B8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6C8B8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF69AE9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__frnd", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF69AE9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF69AE9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF650B9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF650B9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF650B9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66D27");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__startOneArgErrorHandling", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66D27");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66D27: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF650A7");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF650A7");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF650A7: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6C860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6C860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6C860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6BA50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6BA50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6BA50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6D950");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6D950");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6D950: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF65770");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF65770");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF65770: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("Fog 1.10 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
