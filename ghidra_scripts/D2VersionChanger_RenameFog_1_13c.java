// Auto-generated Ghidra rename script
// Module: Fog
// Version: 1.13c
// Generated: Cross-version renaming (Phase 4)
// Total renames: 60
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply Fog 1.13c Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameFog1.13c extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6C9C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AtomicExchange64", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6C9C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6C9C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6C9A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AtomicRead64", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6C9A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6C9A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF64040");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF64040");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF64040: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF67D90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CloseHandleWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF67D90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF67D90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5CE72");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareStringsIgnoreCase", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5CE72");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5CE72: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF67DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF67DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF67DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66DD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateStormThread", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66DD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66DD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66B10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateTcpConnection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66B10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66B10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF68090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EncodeVarInt2Byte", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF68090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF68090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF617C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnterCriticalSectionWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF617C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF617C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCosineFromTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66730: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6E340");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetField0x110", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6E340");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6E340: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5D020");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetField880", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5D020");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5D020: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF605D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetFogStatePtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF605D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF605D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66710");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetSineValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66710");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66710: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5FB80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetTickCount", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5FB80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5FB80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF67140");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IffCreate", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF67140");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF67140: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF67130");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IffDestroy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF67130");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF67130: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF74B60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeLogManager", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF74B60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF74B60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF668E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LeaveSocketCriticalSection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF668E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF668E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5FD70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LogMessage", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5FD70");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5FD70: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5CE36");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileWithDefaultArchive", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5CE36");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5CE36: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5CE30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadArchiveFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5CE30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5CE30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF67E00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadFileAsync", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF67E00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF67E00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF74BB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterExceptionFilter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF74BB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF74BB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5FB90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetPerformanceAccumulators", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5FB90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5FB90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5CD2E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5CD2E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5CD2E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5CDC4");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemAlloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5CDC4");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5CDC4: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5CDCA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5CDCA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5CDCA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF70180");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SendSocketData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF70180");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF70180: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF67E40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAsyncFileHandle", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF67E40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF67E40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF64090");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF64090");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF64090: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF67D20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePointerWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF67D20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF67D20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF67DD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePosition", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF67DD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF67DD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF743A5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFpuControlWord", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF743A5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF743A5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6E310");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6E310");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6E310: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5FCD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubOrdinal10183", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5FCD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5FCD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F910");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("TitleCaseString", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F910");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F910: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61690");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ValidateCriticalSection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61690");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61690: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF668F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WSACleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF668F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF668F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF67D60");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF67D60");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF67D60: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF540E8");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteStringToBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF540E8");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF540E8: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5CD88");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__WSAFDIsSet", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5CD88");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5CD88: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5C11D");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5C11D");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5C11D: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF714F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__alldiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF714F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF714F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF59CD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF59CD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF59CD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5B897");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5B897");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5B897: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF51BBA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF51BBA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF51BBA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5B57C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5B57C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5B57C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF52BBF");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF52BBF");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF52BBF: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF743D5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fload_withFB", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF743D5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF743D5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5B1E6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5B1E6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5B1E6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF5ACD1");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__frnd", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF5ACD1");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF5ACD1: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF52099");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF52099");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF52099: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF74347");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__startOneArgErrorHandling", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF74347");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF74347: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF520C5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF520C5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF520C5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF58680");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF58680");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF58680: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF56690");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF56690");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF56690: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF590C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF590C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF590C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF52D90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF52D90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF52D90: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("Fog 1.13c Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
