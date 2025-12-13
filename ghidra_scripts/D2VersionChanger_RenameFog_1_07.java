// Auto-generated Ghidra rename script
// Module: Fog
// Version: 1.07
// Generated: Cross-version renaming (Phase 4)
// Total renames: 60
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply Fog 1.07 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameFog1.07 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF695B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AtomicExchange64", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF695B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF695B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF695D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AtomicRead64", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF695D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF695D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ClearBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F7A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CloseHandleWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F7A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F7A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF73170");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareStringsIgnoreCase", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF73170");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF73170: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F760");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F760");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F760: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71020");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateStormThread", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71020");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71020: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71040");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateTcpConnection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71040");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71040: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61A70");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EncodeVarInt2Byte", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6C730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnterCriticalSectionWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6C730");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6C730: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61D10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetCosineFromTable", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61D10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61D10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61A00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetField0x110", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61A00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61A00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF63350");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetField880", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF63350");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF63350: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6CA20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetFogStatePtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6CA20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6CA20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61D30");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetSineValue", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61D30");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61D30: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF69420");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetTickCount", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF69420");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF69420: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6FB20");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IffCreate", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6FB20");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6FB20: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6FB90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IffDestroy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6FB90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6FB90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6FCD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeLogManager", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6FCD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6FCD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF714C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LeaveSocketCriticalSection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF714C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF714C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6D120");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LogMessage", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6D120");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6D120: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71C3E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileWithDefaultArchive", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71C3E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71C3E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71C4A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadArchiveFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71C4A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71C4A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F700");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadFileAsync", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F700");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F700: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6CE80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterExceptionFilter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6CE80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6CE80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF693F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetPerformanceAccumulators", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF693F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF693F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF7DE7E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF7DE7E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF7DE7E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71BC6");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemAlloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71BC6");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71BC6: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71BC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71BC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71BC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66530");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SendSocketData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66530");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66530: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F6E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAsyncFileHandle", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F6E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F6E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61D50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetBitInArray", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61D50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61D50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F7F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePointerWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F7F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F7F0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71C56");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePosition", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71C56");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71C56: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF740A5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFpuControlWord", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF740A5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF740A5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF61D00");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF61D00");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF61D00: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66280");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubOrdinal10183", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66280");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66280: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF62830");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("TitleCaseString", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF62830");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF62830: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6C770");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ValidateCriticalSection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6C770");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6C770: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71010");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WSACleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71010");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71010: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F7D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F7D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F7D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF74F09");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteStringToBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF74F09");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF74F09: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF7DE78");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__WSAFDIsSet", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF7DE78");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF7DE78: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF7C90A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF7C90A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF7C90A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF72300");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__alldiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF72300");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF72300: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF72E80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF72E80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF72E80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF73BCC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF73BCC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF73BCC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71CB2");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71CB2");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71CB2: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF738DC");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF738DC");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF738DC: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF732FA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF732FA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF732FA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF740D5");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fload_withFB", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF740D5");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF740D5: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF79C48");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF79C48");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF79C48: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF76ED9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__frnd", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF76ED9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF76ED9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF72809");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF72809");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF72809: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF74047");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__startOneArgErrorHandling", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF74047");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF74047: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF727F7");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF727F7");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF727F7: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF79BF0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF79BF0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF79BF0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF78DE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF78DE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF78DE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF7AB90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF7AB90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF7AB90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF72EC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF72EC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF72EC0: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("Fog 1.07 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
