// Auto-generated Ghidra rename script
// Module: Fog
// Version: 1.09
// Generated: Cross-version renaming (Phase 4)
// Total renames: 60
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply Fog 1.09 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameFog1.09 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF595C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AtomicExchange64", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF595C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF595C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF595E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AtomicRead64", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF595E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF595E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61060");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CloseHandleWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61060");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61060: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF63200");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareStringsIgnoreCase", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF63200");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF63200: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5F7F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5F7F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5F7F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF610B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateStormThread", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF610B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF610B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF610D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateTcpConnection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF610D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF610D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51A70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EncodeVarInt2Byte", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51A70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51A70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5C750");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnterCriticalSectionWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5C750");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5C750: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51D10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCosineFromTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51D10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51D10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51A00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetField0x110", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51A00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51A00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF533A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetField880", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF533A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF533A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5CA20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetFogStatePtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5CA20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5CA20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetSineValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF59440");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetTickCount", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF59440");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF59440: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5FBB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IffCreate", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5FBB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5FBB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5FC20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IffDestroy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5FC20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5FC20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5FD90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeLogManager", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5FD90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5FD90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61550");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LeaveSocketCriticalSection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61550");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61550: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5D140");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LogMessage", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5D140");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5D140: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61CE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileWithDefaultArchive", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61CE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61CE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61CDA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadArchiveFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61CDA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61CDA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5F790");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadFileAsync", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5F790");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5F790: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5FDB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterExceptionFilter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5FDB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5FDB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF59410");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetPerformanceAccumulators", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF59410");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF59410: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6DF04");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6DF04");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6DF04: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61C56");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemAlloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61C56");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61C56: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61C50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF56590");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SendSocketData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF56590");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF56590: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5F7C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAsyncFileHandle", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5F7C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5F7C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51D50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51D50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51D50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5F880");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePointerWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5F880");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5F880: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61CE6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePosition", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61CE6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61CE6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF64135");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFpuControlWord", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF64135");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF64135: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF560D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF560D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF560D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF562E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubOrdinal10183", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF562E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF562E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF52890");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("TitleCaseString", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF52890");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF52890: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5C770");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ValidateCriticalSection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5C770");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5C770: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF610A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WSACleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF610A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF610A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5F860");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5F860");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5F860: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF64FC4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteStringToBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF64FC4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF64FC4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6DEFE");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__WSAFDIsSet", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6DEFE");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6DEFE: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6C9BA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6C9BA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6C9BA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF62390");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__alldiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF62390");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF62390: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF62F10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF62F10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF62F10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF63C5C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF63C5C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF63C5C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61D42");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61D42");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61D42: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6396C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6396C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6396C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6338A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6338A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6338A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF64165");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fload_withFB", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF64165");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF64165: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF69CF8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF69CF8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF69CF8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66F89");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__frnd", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66F89");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66F89: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF62899");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF62899");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF62899: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF640D7");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__startOneArgErrorHandling", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF640D7");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF640D7: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF62887");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF62887");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF62887: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF69CA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF69CA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF69CA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF68E90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF68E90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF68E90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6AC40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6AC40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6AC40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF62F50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF62F50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF62F50: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("Fog 1.09 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
