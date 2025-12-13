// Auto-generated Ghidra rename script
// Module: Fog
// Version: 1.08
// Generated: Cross-version renaming (Phase 4)
// Total renames: 60
// Description: Applies consistent function names across all versions

//@author D2VersionChanger
//@category Search.Functions
//@keybinding
//@menupath Tools.D2VersionChanger.Apply Fog 1.08 Renames
//@toolbar

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.app.script.GhidraScript;

public class RenameFog1.08 extends GhidraScript {

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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF69570");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AtomicExchange64", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF69570");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF69570: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF69590");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("AtomicRead64", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF69590");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF69590: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF70F90");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CloseHandleWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF70F90");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF70F90: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF73130");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CompareStringsIgnoreCase", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF73130");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF73130: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F720");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F720");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F720: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF70FE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateStormThread", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF70FE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF70FE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71000");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("CreateTcpConnection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71000");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71000: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6C710");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("EnterCriticalSectionWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6C710");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6C710: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6C9E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetFogStatePtr", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6C9E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6C9E0: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF693D0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("GetTickCount", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF693D0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF693D0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6FAE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IffCreate", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6FAE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6FAE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6FB50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("IffDestroy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6FB50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6FB50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6FCC0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("InitializeLogManager", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6FCC0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6FCC0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71480");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LeaveSocketCriticalSection", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71480");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71480: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6D0E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("LogMessage", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6D0E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6D0E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71C10");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("OpenFileWithDefaultArchive", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71C10");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71C10: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71C0A");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadArchiveFile", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71C0A");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71C0A: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F6C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ReadFileAsync", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F6C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F6C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6FCE0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RegisterExceptionFilter", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6FCE0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6FCE0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF693A0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ResetPerformanceAccumulators", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF693A0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF693A0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF7DE3E");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("RtlUnwind", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF7DE3E");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF7DE3E: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71B86");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemAlloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71B86");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71B86: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71B80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SMemFree", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71B80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71B80: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66520");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SendSocketData", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66520");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66520: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F6F0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetAsyncFileHandle", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F6F0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F6F0: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F7B0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePointerWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F7B0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F7B0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71C16");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFilePosition", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71C16");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71C16: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF74065");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("SetFpuControlWord", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF74065");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF74065: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF693E0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubNoOp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF693E0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF693E0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF66270");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("StubOrdinal10183", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF66270");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF66270: " + e.getMessage());
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6C730");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("ValidateCriticalSection", SourceType.USER_DEFINED);
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
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF70FD0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WSACleanup", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF70FD0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF70FD0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF6F790");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteFileWrapper", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF6F790");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF6F790: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF74EC9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("WriteStringToBuffer", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF74EC9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF74EC9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF7DE38");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__WSAFDIsSet", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF7DE38");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF7DE38: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF7C8CA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("___add_12", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF7C8CA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF7C8CA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF722C0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__alldiv", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF722C0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF722C0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF72E40");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__allmul", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF72E40");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF72E40: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF73B8C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__cfltcvt", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF73B8C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF73B8C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF71C72");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__exit", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF71C72");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF71C72: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF7389C");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fassign", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF7389C");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF7389C: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF732BA");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fclose_lk", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF732BA");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF732BA: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF74095");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fload_withFB", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF74095");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF74095: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF79C08");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__fptrap", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF79C08");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF79C08: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF76E99");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__frnd", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF76E99");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF76E99: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF727C9");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__nh_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF727C9");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF727C9: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF74007");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("__startOneArgErrorHandling", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF74007");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF74007: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF727B7");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_malloc", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF727B7");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF727B7: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF79BB0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_memset", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF79BB0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF79BB0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF78DA0");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strlen", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF78DA0");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF78DA0: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF7AB50");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncmp", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF7AB50");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF7AB50: " + e.getMessage());
            failureCount++;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress("0x6FF72E80");
            Function func = listing.getFunctionAt(addr);
            if (func != null) {
                func.setName("_strncpy", SourceType.USER_DEFINED);
                successCount++;
            } else {
                println("  WARNING: No function at 0x6FF72E80");
                failureCount++;
            }
        } catch (Exception e) {
            println("  ERROR at 0x6FF72E80: " + e.getMessage());
            failureCount++;
        }

        println("");
        println("Fog 1.08 Rename Summary:");
        println("  Successful: " + successCount);
        println("  Failed: " + failureCount);
        println("  Total: " + (successCount + failureCount));
    }
}
