// Auto-generated from function_registry_v2.json
// Generated: 2025-12-15T15:44:29.888678
// Functions for PD2_EXT.dll
// Versions: LoD/PD2

var FUNCTIONS_PD2_EXT_dll = {
  "versions": [
    "LoD/PD2"
  ],
  "functions": {
    "PD2_EXT_MNE_541190143a3a": {
      "addresses": {
        "LoD/PD2": "0x7B331050"
      },
      "rvas": {
        "LoD/PD2": "0x1050"
      },
      "sizes": {
        "LoD/PD2": 42
      },
      "name": "InitializeAndClearData",
      "signature": "void InitializeAndClearData(byte * pDataArray, byte nFlag)",
      "calling_convention": "__stdcall",
      "comment": "Initializes data array and clears first byte if allocation succeeds.\n\nAlgorithm:\n1. Call data initialization function with array pointer and flag parameter\n2. Test if initialization returned valid pointer (non-null check)\n3. If pointer is null, exit function\n4. If pointer is valid, zero the first byte of returned data\n5. Call data initialization function again with same parameters\n6. Return to caller\n\nParameters:\npDataArray - Pointer to 16-byte data array to initialize\nnFlag - Configuration flag passed to initialization function\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nMagic Numbers: 0x0 is null pointer sentinel value\nThe function zeroes offset [0] which typically indicates a cleared/uninitialized state\nDouble initialization with conditional first-byte clearing suggests lazy initialization pattern",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:541190143a3ab7e12d55d20c423b370d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "541190143a3ab7e12d55d20c423b370d",
        "CFG": "bc042e4f56c5c862716dd36277cac9ef",
        "PRO": "416e2a238d1f53a62e632e2f6f17dd97"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_STR_f7788545959f": {
      "addresses": {
        "LoD/PD2": "0x7B331080"
      },
      "rvas": {
        "LoD/PD2": "0x1080"
      },
      "sizes": {
        "LoD/PD2": 316
      },
      "name": "ApplyCodePatches",
      "signature": "void ApplyCodePatches(void)",
      "calling_convention": "__stdcall",
      "comment": "Applies runtime code patches to game executable and Fog.dll module.\nThis function modifies code in memory by changing memory protection settings,\nwriting patch instructions (JMP opcodes with offsets), and restoring protection.\nIt targets specific addresses in the main executable and Fog.dll module.\n\nAlgorithm:\n1. Initialize stack cookie for buffer overflow protection\n2. Patch instruction at 0x0040763f with 5-byte JMP to relative address 0x7af299bc\n3. Patch 33 bytes at 0x004083ef with NOP instructions (0x90909090 pattern)\n4. Check if Fog.dll module is loaded with expected signature bytes at offsets 0xff5f and 0xff63\n5. If Fog.dll has matching signatures (0x5e0cc483 at +0xff5f, 0xc314c483 at +0xff63), patch address at +0x17ea7\n6. Invoke callback function at 0x7b346340 for additional initialization\n7. Verify stack cookie integrity and return\n\nParameters: None\n\nReturns: void\n\nSpecial Cases:\n- If Fog.dll is not loaded or signatures don't match, skips Fog.dll patching\n- Uses stack cookie protection to detect buffer overflows\n- All memory patches use VirtualProtect to temporarily allow write access\n\nStructure Layout:\nAll patches are JMP instructions with 5-byte encoding:\n- Byte 0: 0xE8 (CALL opcode, or can be JMP)\n- Bytes 1-4: Relative offset (little-endian)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:f7788545959fa9cab34dfc89f7128ee6",
      "indexes": {
        "EXP": null,
        "STR": "f7788545959fa9cab34dfc89f7128ee6",
        "API": null,
        "MNE": "4fd68c5993cb56126ea7d3b2bd60c04b",
        "CFG": "809bca52eaccd9c02a2e095b3e34845d",
        "PRO": "886b7b104a46f394d874ea62be1efbb0"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_0e2d971e7387": {
      "addresses": {
        "LoD/PD2": "0x7B3311C0"
      },
      "rvas": {
        "LoD/PD2": "0x11C0"
      },
      "sizes": {
        "LoD/PD2": 130
      },
      "name": "PatchCodeOnLoadOrUnload",
      "signature": "int PatchCodeOnLoadOrUnload(HINSTANCE__ * hInstance, int notifyReason)",
      "calling_convention": "__stdcall",
      "comment": "Applies or removes code patches during DLL load/unload.\n\nThis function modifies executable code at a target address (0x004082DD) to install or remove a code hook. During DLL_PROCESS_ATTACH (notifyReason==1), it patches 5 bytes of code to redirect execution. During DLL_PROCESS_DETACH (notifyReason==0), the patch is removed.\n\nAlgorithm:\n1. Calculate XOR guard value from global canary and stack frame pointer\n2. If notifyReason == 1 (DLL_PROCESS_ATTACH):\n   a. Save current memory protection of target code\n   b. Change protection to PAGE_EXECUTE_READWRITE (0x40)\n   c. Write 0xE8 opcode (CALL instruction) at 0x004082DD\n   d. Calculate offset to hook target (0x7b331080 - 0x4082E2)\n   e. Restore original protection\n   f. Store computed hook target address in global DAT_7b346340\n3. Call security verification function with guard XOR\n4. Return status code\n\nParameters:\n- hInstance (HINSTANCE*): DLL module handle (not used in function)\n- notifyReason (int): DLL notification reason (1=ATTACH, 0=DETACH)\n\nReturns:\n- int: Status code (0 for success, non-zero for failure)\n\nSpecial Cases:\n- Only patches code when notifyReason==1; skips patch when notifyReason==0\n- Uses XOR canary from DAT_7b345000 for stack overflow protection\n- Target patch location is in another module (address 0x004082DD)\n- Computed hook target is relative offset: (0x7b331080 - 0x4082E2)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0e2d971e7387755a27a5a4eb39f31468",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0e2d971e7387755a27a5a4eb39f31468",
        "CFG": "075135080bbbd8ff3b9b0305147b5d54",
        "PRO": "a4a166be7730bf1973bd4f90dd397475"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_4efdd923a388": {
      "addresses": {
        "LoD/PD2": "0x7B331242"
      },
      "rvas": {
        "LoD/PD2": "0x1242"
      },
      "sizes": {
        "LoD/PD2": 14
      },
      "name": "ValidateStackCookie",
      "signature": "void ValidateStackCookie(uint cookieValue)",
      "calling_convention": "__fastcall",
      "comment": "Validates the stack cookie value against the global cookie to detect stack buffer overflows.\n\nAlgorithm:\n1. Compare the provided stack cookie value (in ECX) with the global cookie value at DAT_7b345000\n2. If values match, return immediately (no corruption detected)\n3. If values differ, jump to error handler at cookie_invalid_error (stack overflow detected)\n4. Error handler calls FUN_7b3315db to abort execution\n\nParameters:\ncookieValue (ECX) - uint: The stack cookie value to validate against the global cookie\n\nReturns: void (no return value; either returns normally if valid or aborts if invalid)\n\nSpecial Cases:\n- Used extensively throughout the binary for security checks\n- Part of Visual C++ stack overflow protection mechanism\n- Called from functions like ApplyCodePatches with XOR'd cookie values\n- If validation fails, execution is terminated via FUN_7b3315db (abort/TerminateProcess)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4efdd923a388be710585d381cbbbfb83",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4efdd923a388be710585d381cbbbfb83",
        "CFG": "74c44fff4d24f318587f22fc1085febb",
        "PRO": "412130ac6f9477a35fd15037b1e2ac3d"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_b3faaa54e614": {
      "addresses": {
        "LoD/PD2": "0x7B331250"
      },
      "rvas": {
        "LoD/PD2": "0x1250"
      },
      "sizes": {
        "LoD/PD2": 83
      },
      "name": "dllmain_crt_dispatch",
      "signature": "int dllmain_crt_dispatch(HINSTANCE__ * param_1, ulong param_2, void * param_3)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n int __stdcall dllmain_crt_dispatch(struct HINSTANCE__ * const,unsigned long,void * const)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b3faaa54e614fd38955b32ddce3fe396",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b3faaa54e614fd38955b32ddce3fe396",
        "CFG": "ffc212cf0cc73a31e9b7aa13b24a4473",
        "PRO": "2a1c1ffdf2772f7f599b724da58d6961"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_813902e79b8b": {
      "addresses": {
        "LoD/PD2": "0x7B3312A3"
      },
      "rvas": {
        "LoD/PD2": "0x12A3"
      },
      "sizes": {
        "LoD/PD2": 250
      },
      "name": "dllmain_crt_process_attach",
      "signature": "int dllmain_crt_process_attach(HINSTANCE__ * param_1, void * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl dllmain_crt_process_attach(struct HINSTANCE__ * const,void * const)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:813902e79b8b4c3f1e839bd5ac54ccd1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "813902e79b8b4c3f1e839bd5ac54ccd1",
        "CFG": "43ed1f8975afc6ad6b976a0e849204d9",
        "PRO": "0eb913c280572016b91d73e0d644845c"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_5f97d76a7bf7": {
      "addresses": {
        "LoD/PD2": "0x7B33143F"
      },
      "rvas": {
        "LoD/PD2": "0x143F"
      },
      "sizes": {
        "LoD/PD2": 10
      },
      "name": "ReleaseStartupLock",
      "signature": "void ReleaseStartupLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the C Runtime startup lock during DLL initialization.\n\nAlgorithm:\n1. Push the startup lock token from local storage onto the stack\n2. Call ___scrt_release_startup_lock to release the CRT initialization lock\n3. Return to caller (___scrt_release_startup_lock performs cleanup)\n\nParameters:\nNone\n\nReturns:\nvoid\n\nSpecial Cases:\n- This function is part of the Visual C++ CRT initialization sequence\n- Called from dllmain_crt_process_attach during DLL process attach\n- The startup lock token is obtained from [EBP + -0x1d] during DLL entry\n- This ensures thread-safe initialization of global state\n\nContext:\nThis is a lightweight wrapper function in the CRT startup sequence that\ncoordinates the release of the startup lock acquired during DLL process\nattachment. It enables other threads to proceed with their initialization\nonce the primary thread completes its startup phase.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5f97d76a7bf7bad4437ec948fbad99b7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5f97d76a7bf7bad4437ec948fbad99b7",
        "CFG": null,
        "PRO": "3af54882954c3fea013c00f9af30f6ea"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_7816046ec43e": {
      "addresses": {
        "LoD/PD2": "0x7B3313AA"
      },
      "rvas": {
        "LoD/PD2": "0x13AA"
      },
      "sizes": {
        "LoD/PD2": 154
      },
      "name": "dllmain_crt_process_detach",
      "signature": "int dllmain_crt_process_detach(bool param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl dllmain_crt_process_detach(bool)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7816046ec43e929854fe8a047b0b3cda",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7816046ec43e929854fe8a047b0b3cda",
        "CFG": "1f0b199d876f44740208617600255ae3",
        "PRO": "e046abbc1e92106a0e98812d7809c9c0"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_e7313d19d2f1": {
      "addresses": {
        "LoD/PD2": "0x7B33144C"
      },
      "rvas": {
        "LoD/PD2": "0x144C"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "CallInitializationRoutine",
      "signature": "void CallInitializationRoutine(void)",
      "calling_convention": "__stdcall",
      "comment": "Calls an initialization routine during program startup/shutdown.\n\nAlgorithm:\n1. Call initialization/cleanup function at 0x7b3318e0\n2. Return to caller\n\nReturns:\nvoid - No return value\n\nNotes:\nThin wrapper function that delegates to another initialization routine. Called during DLL process detach phase.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e7313d19d2f1b94221ec63dffd5562f1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e7313d19d2f1b94221ec63dffd5562f1",
        "CFG": null,
        "PRO": "cafb7a061851ddb77a31ab9264ccc6aa"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_ea9bbbf8bef4": {
      "addresses": {
        "LoD/PD2": "0x7B33145A"
      },
      "rvas": {
        "LoD/PD2": "0x145A"
      },
      "sizes": {
        "LoD/PD2": 231
      },
      "name": "dllmain_dispatch",
      "signature": "int dllmain_dispatch(HINSTANCE__ * param_1, ulong param_2, void * param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl dllmain_dispatch(struct HINSTANCE__ * const,unsigned long,void * const)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ea9bbbf8bef4ef26b3e4c98bd2475e75",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ea9bbbf8bef4ef26b3e4c98bd2475e75",
        "CFG": "42aae10500d98c4ac73e788bf936bce7",
        "PRO": "083226d4633d943b436ad5d79dac1822"
      },
      "basic_block_counts": {
        "LoD/PD2": 18
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_b29ba1c1091b": {
      "addresses": {
        "LoD/PD2": "0x7B331565"
      },
      "rvas": {
        "LoD/PD2": "0x1565"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "dllmain_raw",
      "signature": "int dllmain_raw(HINSTANCE__ * param_1, ulong param_2, void * param_3)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n int __stdcall dllmain_raw(struct HINSTANCE__ * const,unsigned long,void * const)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b29ba1c1091b500c21215b5dad4c7b51",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b29ba1c1091b500c21215b5dad4c7b51",
        "CFG": "ea03c6407b4d091868dce8d0baf95212",
        "PRO": "d07ec5ac8efade03ee8465977ba73e3d"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_221794ffc10f": {
      "addresses": {
        "LoD/PD2": "0x7B331590"
      },
      "rvas": {
        "LoD/PD2": "0x1590"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "method": "MNE",
      "index": "MNE:221794ffc10f5780ac30dfceea10155b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "221794ffc10f5780ac30dfceea10155b",
        "CFG": "d525801d8d00f8589c4fa0f08b524029",
        "PRO": "84caeb7f6cadbe42e93c2f62bffeff20"
      },
      "display_name": "MNE_221794ffc10f5780",
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_25e9db5cf2bb": {
      "addresses": {
        "LoD/PD2": "0x7B3315B3"
      },
      "rvas": {
        "LoD/PD2": "0x15B3"
      },
      "sizes": {
        "LoD/PD2": 40
      },
      "name": "TerminateProcessOnException",
      "signature": "void TerminateProcessOnException(_EXCEPTION_POINTERS * pExceptionInfo)",
      "calling_convention": "__cdecl",
      "comment": "Terminates the current process in response to an unhandled exception.\n\nThis is a critical exception handler that ensures the application exits cleanly when an unhandled exception occurs. It performs the following operations:\n\nAlgorithm:\n1. Clear any existing top-level exception filter by setting it to NULL, ensuring no recursive exception handling\n2. Pass the exception information to the default Windows exception filter for standard processing\n3. Set the exit code to STATUS_NONCONTINUABLE_EXCEPTION (0xc0000409), indicating a fatal error\n4. Obtain a handle to the current process\n5. Terminate the current process with the non-continuable exception exit code\n6. Function never returns as TerminateProcess halts execution immediately\n\nParameters:\n  pExceptionInfo (_EXCEPTION_POINTERS *): Pointer to the exception information structure containing the exception record and thread context at the time of the exception\n\nReturns:\n  void (never returns - process terminates)\n\nSpecial Cases:\n  - Magic number 0xc0000409 is STATUS_NONCONTINUABLE_EXCEPTION, a Windows NTSTATUS code indicating a fatal non-continuable exception\n  - SetUnhandledExceptionFilter(NULL) disables the current exception filter before processing\n  - The function is designed to prevent infinite exception handling loops by clearing the filter first\n  - Typically registered as the top-level exception handler via SetUnhandledExceptionFilter at application startup",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:25e9db5cf2bb0c2a07b05ef3a9da54bb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "25e9db5cf2bb0c2a07b05ef3a9da54bb",
        "CFG": null,
        "PRO": "9f331c678610c3875624e2af3bd7a065"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_bb70ec70f335": {
      "addresses": {
        "LoD/PD2": "0x7B3315DB"
      },
      "rvas": {
        "LoD/PD2": "0x15DB"
      },
      "sizes": {
        "LoD/PD2": 250
      },
      "name": "InitializeExceptionContext",
      "signature": "void InitializeExceptionContext(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes exception context structure for Windows SEH handler.\n\nAlgorithm:\n1. Check processor feature 0x17 (likely AVX or SSE support)\n2. If feature present, invoke INT 0x29 to get extended CPU state\n3. Save all general purpose registers (EBX, ESI, EDI, EAX, ECX, EDX)\n4. Save all segment registers (SS, CS, DS, ES, FS, GS)\n5. Save processor flags (EFLAGS) including IF, TF, AF, ZF, SF, CF, OF\n6. Save stack frame base pointer (EBP) and return address\n7. Populate exception context global structure at 0x7b345a00-0x7b345a28\n8. Set exception record at 0x7b345910 with code 0xc0000409 (STATUS_STACK_OVERFLOW)\n9. Store exception dispatch info (flags, nest count) at 0x7b345960, 0x7b345914, 0x7b345920, 0x7b345924\n10. Call TerminateProcessOnException with exception pointers to exit process\n\nParameters:\nNone - operates on implicit processor state and stack frame\n\nReturns:\nvoid - function does not return normally; calls TerminateProcessOnException\n\nSpecial Cases:\n- Processor feature check determines CPU capability level\n- INT 0x29 is undocumented CPU instruction for extended state\n- Exception code 0xc0000409 is STACK_OVERFLOW exception\n- Global exception structure enables SEH handler to identify stack corruption\n- Function never returns; always terminates process via TerminateProcessOnException\n\nStructure Layout:\n0x7b345a00: EBX (saved register)\n0x7b345a04: ESI (saved register)\n0x7b345a08: EDX (saved register)\n0x7b345a0c: ECX (saved register)\n0x7b345a10: EAX (saved register)\n0x7b345a14: EBP (saved base pointer)\n0x7b345a18: Return address from caller\n0x7b345a1c: CS (code segment)\n0x7b345a20: EFLAGS (processor flags)\n0x7b345a24: Pointer to stack arguments\n0x7b345a28: SS (stack segment)\n0x7b345910: Exception code (0xc0000409 = STACK_OVERFLOW)\n0x7b345914: Exception flags (1 = continuous)\n0x7b345920: Nesting depth (1)\n0x7b345924: Reserved field (2)\n0x7b345960: Dispatch flags (0x10001)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bb70ec70f33544c83c2933604761b819",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bb70ec70f33544c83c2933604761b819",
        "CFG": "7bfefc8801c3c6b6816629c969d6bde0",
        "PRO": "a325ad3e9ff440aaafda5e95e66d598d"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_3658f6e3181c": {
      "addresses": {
        "LoD/PD2": "0x7B3316D5"
      },
      "rvas": {
        "LoD/PD2": "0x16D5"
      },
      "sizes": {
        "LoD/PD2": 77
      },
      "name": "___get_entropy",
      "signature": "uint ___get_entropy(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___get_entropy\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3658f6e3181c1e09fd88490bb715e521",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3658f6e3181c1e09fd88490bb715e521",
        "CFG": null,
        "PRO": "c5dd24a6a7c6dbb1d27f032a07fbb393"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_d2995c856eb0": {
      "addresses": {
        "LoD/PD2": "0x7B331722"
      },
      "rvas": {
        "LoD/PD2": "0x1722"
      },
      "sizes": {
        "LoD/PD2": 75
      },
      "name": "___security_init_cookie",
      "signature": "void ___security_init_cookie(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___security_init_cookie\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d2995c856eb0be51cc6f663a49375b96",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d2995c856eb0be51cc6f663a49375b96",
        "CFG": "fbea47b737f9cded99d3ac1117fd0429",
        "PRO": "e46535eefaef60fbc723d6946d76a33f"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_fde18f840643": {
      "addresses": {
        "LoD/PD2": "0x7B33176D"
      },
      "rvas": {
        "LoD/PD2": "0x176D"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "InitializeThreadSafeList",
      "signature": "void InitializeThreadSafeList(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes thread-safe singly-linked list during DLL initialization.\\n\\nAlgorithm:\\n1. Push list header address onto stack\\n2. Call InitializeSListHead API to initialize list\\n\\nParameters:\\nNone\\n\\nReturns:\\nvoid\\n\\nSpecial Cases:\\n- Called during CRT process attach phase\\n- Initializes global thread-safe list header at 0x7b345c30\\n- Part of Visual Studio 2019 CRT initialization sequence",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fde18f840643d8d99756120348d7717e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fde18f840643d8d99756120348d7717e",
        "CFG": null,
        "PRO": "bdc16783bc1ef6a02ca7312960c0fb9b"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_bba6787b3ee5": {
      "addresses": {
        "LoD/PD2": "0x7B331779"
      },
      "rvas": {
        "LoD/PD2": "0x1779"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "__scrt_uninitialize_type_info",
      "signature": "void __scrt_uninitialize_type_info(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl __scrt_uninitialize_type_info(void)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bba6787b3ee574ab1a3904a4931976c2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bba6787b3ee574ab1a3904a4931976c2",
        "CFG": null,
        "PRO": "fe7a0f3a77e3705529ca04b6812e7acb"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_7b4de9f0cf35": {
      "addresses": {
        "LoD/PD2": "0x7B33A921"
      },
      "rvas": {
        "LoD/PD2": "0xA921"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetStdioConfigPointer",
      "signature": "void * GetStdioConfigPointer(void)",
      "calling_convention": "__cdecl",
      "comment": "Retrieves pointer to static stdio configuration structure.\n\nAlgorithm:\n1. Load address of static stdio configuration data into EAX\n2. Return pointer to caller\n\nReturns:\nvoid * - Pointer to stdio configuration structure at 0x7b345c38\n\nCalled by:\n___scrt_initialize_default_local_stdio_options (MSVC C Runtime)\n\nPurpose:\nGetter function for C Runtime initialization. Returns reference to static\nstdio configuration data used during default stdio options setup.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "eeb03a2ce7d7c1a61d4503a71c5b7efc"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_cf4bcddf67ac": {
      "addresses": {
        "LoD/PD2": "0x7B331791"
      },
      "rvas": {
        "LoD/PD2": "0x1791"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "___scrt_initialize_default_local_stdio_options",
      "signature": "undefined ___scrt_initialize_default_local_stdio_options(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___scrt_initialize_default_local_stdio_options\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cf4bcddf67ac9e17aa89769203bfea57",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cf4bcddf67ac9e17aa89769203bfea57",
        "CFG": null,
        "PRO": "6ba79451faca0fe02a1deeb6f0e82c39"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_54240c086691": {
      "addresses": {
        "LoD/PD2": "0x7B3317AE"
      },
      "rvas": {
        "LoD/PD2": "0x17AE"
      },
      "sizes": {
        "LoD/PD2": 68
      },
      "name": "find_pe_section",
      "signature": "_IMAGE_SECTION_HEADER * find_pe_section(uchar * param_1, uint param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n struct _IMAGE_SECTION_HEADER * __cdecl find_pe_section(unsigned char * const,unsigned int)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:54240c08669162934f897c557f4f39c4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "54240c08669162934f897c557f4f39c4",
        "CFG": "a8d36b0ca5ed1975934c1a8015201c3a",
        "PRO": "0c7493b02e6ab3526ddf682cec86ced2"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_6d1054d982f1": {
      "addresses": {
        "LoD/PD2": "0x7B3317F2"
      },
      "rvas": {
        "LoD/PD2": "0x17F2"
      },
      "sizes": {
        "LoD/PD2": 50
      },
      "name": "___scrt_acquire_startup_lock",
      "signature": "undefined4 ___scrt_acquire_startup_lock(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___scrt_acquire_startup_lock\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6d1054d982f12d7786c3ee992c573f3b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6d1054d982f12d7786c3ee992c573f3b",
        "CFG": "d8e234c1afd075bd3612cb5632926224",
        "PRO": "c631f5712ca91c8815d902e55765019a"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_c5ed9fc94c31": {
      "addresses": {
        "LoD/PD2": "0x7B331824"
      },
      "rvas": {
        "LoD/PD2": "0x1824"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "___scrt_dllmain_after_initialize_c",
      "signature": "undefined4 ___scrt_dllmain_after_initialize_c(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___scrt_dllmain_after_initialize_c\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c5ed9fc94c31ba047222fa7af95d9b83",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c5ed9fc94c31ba047222fa7af95d9b83",
        "CFG": "dc0623423d93fb21da8f1c1461d32590",
        "PRO": "19dc95aa0b20db33c4672067b685ed64"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_494831ecedeb": {
      "addresses": {
        "LoD/PD2": "0x7B33184F"
      },
      "rvas": {
        "LoD/PD2": "0x184F"
      },
      "sizes": {
        "LoD/PD2": 14
      },
      "name": "___scrt_dllmain_before_initialize_c",
      "signature": "bool ___scrt_dllmain_before_initialize_c(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___scrt_dllmain_before_initialize_c\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:494831ecedeb44bb307191f6a9f972d0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "494831ecedeb44bb307191f6a9f972d0",
        "CFG": null,
        "PRO": "3bcc9e25ee57bf38856ce81963bf6ce3"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_0f7f0612760a": {
      "addresses": {
        "LoD/PD2": "0x7B33217D"
      },
      "rvas": {
        "LoD/PD2": "0x217D"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "___scrt_dllmain_crt_thread_attach",
      "signature": "undefined1 ___scrt_dllmain_crt_thread_attach(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___scrt_dllmain_crt_thread_attach\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0f7f0612760a750cf668844686b49619",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0f7f0612760a750cf668844686b49619",
        "CFG": "d550e8e8abf2e6c7bc4606c0c80e2b95",
        "PRO": "1bd6690134ab3875957602f26064abc1"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_eb59560942d3": {
      "addresses": {
        "LoD/PD2": "0x7B33187C"
      },
      "rvas": {
        "LoD/PD2": "0x187C"
      },
      "sizes": {
        "LoD/PD2": 13
      },
      "name": "___scrt_dllmain_crt_thread_detach",
      "signature": "undefined1 ___scrt_dllmain_crt_thread_detach(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___scrt_dllmain_crt_thread_detach\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:eb59560942d31215fd937048597cce9f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "eb59560942d31215fd937048597cce9f",
        "CFG": null,
        "PRO": "d19d01dc63cdfb6824b96cb8466f8413"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_9d9882837604": {
      "addresses": {
        "LoD/PD2": "0x7B331889"
      },
      "rvas": {
        "LoD/PD2": "0x1889"
      },
      "sizes": {
        "LoD/PD2": 52
      },
      "name": "___scrt_dllmain_exception_filter",
      "signature": "undefined ___scrt_dllmain_exception_filter(undefined4 param_1, int param_2, undefined4 param_3, undefined * param_4, int param_5, undefined4 param_6)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___scrt_dllmain_exception_filter\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9d9882837604aa71830e9f2b201a0a63",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9d9882837604aa71830e9f2b201a0a63",
        "CFG": "8bbfe2737ef55f3a9a35ae1b43be54c6",
        "PRO": "71f3bcd1241ea112e2b0e5881d3d2ae1"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "PD2_EXT_MNE_a6edb326ee32": {
      "addresses": {
        "LoD/PD2": "0x7B3318BD"
      },
      "rvas": {
        "LoD/PD2": "0x18BD"
      },
      "sizes": {
        "LoD/PD2": 50
      },
      "name": "InitializeOrCleanupCRT",
      "signature": "void InitializeOrCleanupCRT(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes or cleans up CRT resources based on UCRT DLL availability.\n\nAlgorithm:\n1. Check if UCRT (Universal C Runtime) DLL is loaded in the current process\n2. If UCRT is available, call cleanup routine FUN_7b334e16 to perform UCRT-specific cleanup\n3. If UCRT is not available, call alternative cleanup FUN_7b3347d8\n4. If alternative cleanup returns non-zero (error), exit early\n5. Otherwise, call resource initialization FUN_7b3345ff with parameters (0, 0, 1)\n6. Return to caller\n\nPurpose: This function is part of the CRT initialization/cleanup sequence called during DLL detachment (dllmain_crt_process_detach). It ensures proper resource management by choosing the appropriate cleanup path based on whether the UCRT is available in the current environment.\n\nReturn: void",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a6edb326ee323224096e5775dc4e42b2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a6edb326ee323224096e5775dc4e42b2",
        "CFG": "cb8eff8eb27b04d335095ce75c22ce5f",
        "PRO": "b942908d7f9c1aa600a15a992c402dd3"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_c43768f4d0dd": {
      "addresses": {
        "LoD/PD2": "0x7B3318E0"
      },
      "rvas": {
        "LoD/PD2": "0x18E0"
      },
      "sizes": {
        "LoD/PD2": 13
      },
      "name": "Uninit_ProcessExit",
      "signature": "void Uninit_ProcessExit(void)",
      "calling_convention": "__stdcall",
      "comment": "Process exit and cleanup handler\n\nInitiates program termination by uninitializing critical runtime components and\ntransferring control to the continuation cleanup routine. This function is called\nduring the process shutdown sequence as part of the initialization/cleanup chain.\n\nAlgorithm:\n1. Push parameter (0x0) onto stack for ACRT uninitialize call\n2. Call ACRT critical section uninitialize function\n3. Pop return value from stack into ECX register\n4. Jump to cleanup_and_continue routine to complete shutdown\n\nParameters:\nNone\n\nReturns:\nDoes not return; transfers control to cleanup_and_continue routine\n\nCalling Convention:\n__stdcall - Stack-based parameters with callee cleanup (RET 0x0)\n\nSpecial Cases:\n- Function does not use standard RET instruction; instead uses JMP to next handler\n- This is part of a cleanup chain called by CallInitializationRoutine\n- The pushed 0x0 value may be a parameter or placeholder for ACRT function\n- Execution continues at cleanup_and_continue without returning to caller",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c43768f4d0ddaf780c3b3e66819b4b76",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c43768f4d0ddaf780c3b3e66819b4b76",
        "CFG": null,
        "PRO": "0746fd3a87463857b7c1f19bdf637d26"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_8ee2644d27cb": {
      "addresses": {
        "LoD/PD2": "0x7B3318ED"
      },
      "rvas": {
        "LoD/PD2": "0x18ED"
      },
      "sizes": {
        "LoD/PD2": 57
      },
      "name": "___scrt_initialize_crt",
      "signature": "undefined4 ___scrt_initialize_crt(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___scrt_initialize_crt\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8ee2644d27cbe7b06992437e07f34de8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8ee2644d27cbe7b06992437e07f34de8",
        "CFG": "285d09a7e9b985b0b82a1cfce0632509",
        "PRO": "98805f012a8b96a5bed1058dab0479ae"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_a8a10b422712": {
      "addresses": {
        "LoD/PD2": "0x7B331926"
      },
      "rvas": {
        "LoD/PD2": "0x1926"
      },
      "sizes": {
        "LoD/PD2": 135
      },
      "name": "___scrt_initialize_onexit_tables",
      "signature": "undefined4 ___scrt_initialize_onexit_tables(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___scrt_initialize_onexit_tables\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a8a10b422712da4bbd9cb3a7439bbfa5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a8a10b422712da4bbd9cb3a7439bbfa5",
        "CFG": "9837f335a7f4c852d4923098d737e51d",
        "PRO": "edc48dc70fbc80691b5aefe1ba462157"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_8987f08d1294": {
      "addresses": {
        "LoD/PD2": "0x7B3319AD"
      },
      "rvas": {
        "LoD/PD2": "0x19AD"
      },
      "sizes": {
        "LoD/PD2": 126
      },
      "name": "___scrt_is_nonwritable_in_current_image",
      "signature": "undefined4 ___scrt_is_nonwritable_in_current_image(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___scrt_is_nonwritable_in_current_image\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8987f08d1294583acadd46f1f102f5ad",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8987f08d1294583acadd46f1f102f5ad",
        "CFG": "d790950703572277ff9cc2fe99997fd3",
        "PRO": "bad8a4a7cbcd15bb403bd0a7a6d5049b"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_f7e6c19e50a3": {
      "addresses": {
        "LoD/PD2": "0x7B331A41"
      },
      "rvas": {
        "LoD/PD2": "0x1A41"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "___scrt_release_startup_lock",
      "signature": "int ___scrt_release_startup_lock(char param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___scrt_release_startup_lock\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f7e6c19e50a30f46926a4d1218a196eb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f7e6c19e50a30f46926a4d1218a196eb",
        "CFG": "5f8eaafe0358964f49953899a86b0609",
        "PRO": "7239d333172d44ca4fb78de82efccd6c"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_1fcd22518b09": {
      "addresses": {
        "LoD/PD2": "0x7B331A5E"
      },
      "rvas": {
        "LoD/PD2": "0x1A5E"
      },
      "sizes": {
        "LoD/PD2": 40
      },
      "name": "___scrt_uninitialize_crt",
      "signature": "undefined4 ___scrt_uninitialize_crt(char param_1, char param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___scrt_uninitialize_crt\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1fcd22518b091651f16739ae56625ad9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1fcd22518b091651f16739ae56625ad9",
        "CFG": "59064043b32d878adeb9b6c7844d59e3",
        "PRO": "26890f8b5b445e6a2162ad028ce9c861"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_6caddc40c023": {
      "addresses": {
        "LoD/PD2": "0x7B331A8C"
      },
      "rvas": {
        "LoD/PD2": "0x1A8C"
      },
      "sizes": {
        "LoD/PD2": 277
      },
      "name": "InitializeExceptionHandling",
      "signature": "void InitializeExceptionHandling(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes CRT exception handling by setting up a fake exception context for security checks.\n\nAlgorithm:\n1. Check if processor supports feature 0x17 (AVX/SSE support). If yes, execute SWI 0x29 instruction.\n2. Call FUN_7b331ba1 to perform additional initialization (passes argument 3).\n3. Create a fake CONTEXT record (0x2cc bytes) and initialize it to zero.\n4. Set context flags to 0x10001 (context_full with extended registers).\n5. Create an EXCEPTION_RECORD structure and initialize it to zero (0x50 bytes).\n6. Set exception code to 0x40000015 (custom security exception) and flags to 1.\n7. Build EXCEPTION_POINTERS structure linking the record and context.\n8. Call SetUnhandledExceptionFilter(NULL) to clear any existing handler.\n9. Call UnhandledExceptionFilter() with the fake exception pointers.\n10. If filter returned 0 and no debugger is present, call FUN_7b331ba1 again (passes argument 3).\n11. Return.\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nvoid - no return value\n\nSpecial Cases:\n- This is a CRT initialization function called during DLL process attach/detach\n- The fake exception context simulates an exception state for security validation\n- Different behavior based on debugger presence (IsDebuggerPresent check)\n- AVX/SSE support detection may trigger special CPU instruction execution",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6caddc40c023313bf4c19c93a633030d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6caddc40c023313bf4c19c93a633030d",
        "CFG": "dee5ae6c78f147ea962923b86462b4d9",
        "PRO": "289d4b0b0f5053db57f9f70355ed7716"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_0bc0597c449e": {
      "addresses": {
        "LoD/PD2": "0x7B331BA1"
      },
      "rvas": {
        "LoD/PD2": "0x1BA1"
      },
      "sizes": {
        "LoD/PD2": 8
      },
      "name": "ClearSecurityCookie",
      "signature": "void ClearSecurityCookie(void)",
      "calling_convention": "__stdcall",
      "comment": "Clears the global security cookie flag during exception handling initialization.\n\nAlgorithm:\n1. Clear the DWORD at address 0x7b345c6c to 0 using AND instruction\n2. Return to caller\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nvoid - no return value\n\nSpecial Cases:\n- Called twice in CRT exception initialization: once unconditionally and once conditionally based on debugger presence\n- Part of Visual Studio CRT exception handling chain\n- Security-related: clears validation cookie during exception filter setup\n- Used in both exception report fault handling and exception initialization\n\nContext:\nThis function is part of the CRT's exception handling initialization and is called from:\n1. InitializeExceptionHandling - CRT initialization routine\n2. ___acrt_call_reportfault - Exception reporting handler\nCalled conditionally when not in a debugger or when param_1 != -1",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0bc0597c449eb3f95856ba1dd6da8aef",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0bc0597c449eb3f95856ba1dd6da8aef",
        "CFG": null,
        "PRO": "0a876bc4ec49359e9b45a08f0bcb16d9"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_1f330ff9b893": {
      "addresses": {
        "LoD/PD2": "0x7B331BD5"
      },
      "rvas": {
        "LoD/PD2": "0x1BD5"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "__RTC_Initialize",
      "signature": "undefined __RTC_Initialize(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __RTC_Initialize\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1f330ff9b89359cdf6cadeb488a2e714",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1f330ff9b89359cdf6cadeb488a2e714",
        "CFG": "ddcab2040c8318c24b007a99f0f62124",
        "PRO": "d22c4a4be5792ab02a62f5fef091dc16"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_aa114f8324e6": {
      "addresses": {
        "LoD/PD2": "0x7B331C10"
      },
      "rvas": {
        "LoD/PD2": "0x1C10"
      },
      "sizes": {
        "LoD/PD2": 69
      },
      "name": "__SEH_prolog4",
      "signature": "undefined __SEH_prolog4(undefined4 param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __SEH_prolog4\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:aa114f8324e60bfaec362f5007b6b7c5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "aa114f8324e60bfaec362f5007b6b7c5",
        "CFG": null,
        "PRO": "d860c5b91f034e585ee3a75a6cf44b4e"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_576e71e58ac1": {
      "addresses": {
        "LoD/PD2": "0x7B331C55"
      },
      "rvas": {
        "LoD/PD2": "0x1C55"
      },
      "sizes": {
        "LoD/PD2": 3
      },
      "name": "guard_check_icall",
      "signature": "undefined guard_check_icall(void)",
      "calling_convention": "__cdecl",
      "comment": "guard_check_icall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:576e71e58ac12dc4dc652fb1f77bef85",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "576e71e58ac12dc4dc652fb1f77bef85",
        "CFG": null,
        "PRO": "4221cd66b7d1bf15a636664004a85178"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_604d43e5bcf6": {
      "addresses": {
        "LoD/PD2": "0x7B331C58"
      },
      "rvas": {
        "LoD/PD2": "0x1C58"
      },
      "sizes": {
        "LoD/PD2": 468
      },
      "name": "DetectCPUFeatures",
      "signature": "int DetectCPUFeatures(void)",
      "calling_convention": "__stdcall",
      "comment": "Detects CPU feature support including SSE, AVX, and AVX-512.\n\nThis function executes CPUID instructions to determine processor capabilities\nand sets global feature flags based on manufacturer, model, and extended\nfeature bits. It supports Intel processors and detects AVX and AVX-512 support\nwith proper OS context (XCR0) validation.\n\nAlgorithm:\n1. Check if CPUID instruction is supported via IsProcessorFeaturePresent(10)\n2. If not supported, skip detection and return\n3. Execute CPUID(0) to get processor signature and identify manufacturer\n4. Validate CPUID(1) version bits against known Intel models\n5. Check CPUID(7) availability (if CPUID(0) >= 7)\n6. If available, get extended features from CPUID(7) and check AVX-512 bit 0x200\n7. Check CPUID(1) ECX bit 20 for XGETBV instruction support\n8. If XGETBV available, check CPUID(1) ECX bits 27-28 for OSXSAVE/XCR0\n9. Read XCR0 register and validate bits 1-2 set (AVX register state)\n10. Check XCR0 bits 5-7 for upper AVX-512 state availability\n11. Set SIMD capability level in global DAT_7b345c70 (0=none, 2=SSE, 3=AVX, 5=AVX2, 6=AVX-512)\n12. Return 0\n\nReturns:\n0 - Always returns 0; actual results stored in DAT_7b345c70 and DAT_7b345c74",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:604d43e5bcf69eff6aa5413313c346d7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "604d43e5bcf69eff6aa5413313c346d7",
        "CFG": "6d806e30505702808d6989af53ecf95a",
        "PRO": "76491599a60dd1362d45f5dbe7b81447"
      },
      "basic_block_counts": {
        "LoD/PD2": 31
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_7ec409a9eaef": {
      "addresses": {
        "LoD/PD2": "0x7B331E2C"
      },
      "rvas": {
        "LoD/PD2": "0x1E2C"
      },
      "sizes": {
        "LoD/PD2": 4
      },
      "name": "InitializeStubReturn",
      "signature": "uint InitializeStubReturn(void)",
      "calling_convention": "__stdcall",
      "comment": "C Runtime initialization stub function that returns success status.\n\nAlgorithm:\n1. Clear EAX register using XOR (EAX = 0)\n2. Increment EAX to 1\n3. Return with success status\n\nReturns:\n- EAX = 1: Initialization successful (TRUE/success status code)\n\nPurpose:\nThis is a sentinel initialization function called during C Runtime startup\n(__scrt_dllmain_after_initialize_c). It serves as a checkpoint in the\ninitialization sequence, returning 1 to indicate successful completion.\nThe simple structure (return constant 1) suggests this is either a stub\nfor future functionality or a mandatory initialization sentinel.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7ec409a9eaefed77c043adece1ffae56",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7ec409a9eaefed77c043adece1ffae56",
        "CFG": null,
        "PRO": "c0006870c47ab8b75740ed203b0785a3"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_54eb44b5a73f": {
      "addresses": {
        "LoD/PD2": "0x7B331E30"
      },
      "rvas": {
        "LoD/PD2": "0x1E30"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "___scrt_is_ucrt_dll_in_use",
      "signature": "bool ___scrt_is_ucrt_dll_in_use(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___scrt_is_ucrt_dll_in_use\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:54eb44b5a73ff76965fb286f3a476751",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "54eb44b5a73ff76965fb286f3a476751",
        "CFG": null,
        "PRO": "8ba2043989a9093235cb9b0769474a7c"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_514cfd21368c": {
      "addresses": {
        "LoD/PD2": "0x7B331E40"
      },
      "rvas": {
        "LoD/PD2": "0x1E40"
      },
      "sizes": {
        "LoD/PD2": 311
      },
      "name": "FindCharacterInMemory",
      "signature": "pointer FindCharacterInMemory(pointer pBuffer, byte searchChar)",
      "calling_convention": "__cdecl",
      "comment": "Optimized character search in memory buffer with multiple algorithms\n\nAlgorithm:\n1. Check optimization flag (DAT_7b345c70) to determine search strategy\n2. If flag == 0: Use backward SCASB loop for string length, then SCASB reverse scan\n3. If flag == 1: Use SSE PCMPISTRI for aligned character search with boundary handling\n4. If flag >= 2: Use SIMD (SSE) vectorized search with null-byte and target detection\n   a. Extract alignment offset from buffer pointer (lowest 4 bits)\n   b. Create broadcast XMM register with replicated search character\n   c. Load 16-byte aligned chunk and compare with null bytes and target char\n   d. Extract bit masks using PMOVMSKB to find matches in current chunk\n   e. Continue scanning 16-byte chunks until null byte or character found\n   f. Use BSR (bit scan reverse) to find highest set bit in match mask\n\nParameters:\npBuffer: Pointer to buffer to search (may be unaligned to 16-byte boundary)\nsearchChar: Byte value to locate in buffer (searches until null terminator)\n\nReturns:\nEAX: Pointer to first occurrence of searchChar in buffer, or null if not found\n\nSpecial Cases:\n- Handles unaligned buffer pointers by masking initial matches\n- Supports three different optimization levels for SSE availability\n- Backward scan path (flag==0) reverses string direction\n- Character search (flag>=2 with non-zero searchChar) handles partial chunks",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:514cfd21368cfdcc0e00229d0ca3460c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "514cfd21368cfdcc0e00229d0ca3460c",
        "CFG": "1617b24cb38e9aa97b78ff9235d92468",
        "PRO": "abe77b871131bf611813be48ff233aed"
      },
      "basic_block_counts": {
        "LoD/PD2": 25
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_9d75cc89a17d": {
      "addresses": {
        "LoD/PD2": "0x7B331F80"
      },
      "rvas": {
        "LoD/PD2": "0x1F80"
      },
      "sizes": {
        "LoD/PD2": 50
      },
      "name": "_ValidateLocalCookies",
      "signature": "undefined _ValidateLocalCookies(int * param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _ValidateLocalCookies\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9d75cc89a17dcac8355f6ef97efd5751",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9d75cc89a17dcac8355f6ef97efd5751",
        "CFG": "4829319e2a49e5c4df0979448cd2dd26",
        "PRO": "9ca10b74f090b9afc622fe761a467cdc"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_17dd6baec15e": {
      "addresses": {
        "LoD/PD2": "0x7B331FC0"
      },
      "rvas": {
        "LoD/PD2": "0x1FC0"
      },
      "sizes": {
        "LoD/PD2": 350
      },
      "name": "__except_handler4",
      "signature": "undefined4 __except_handler4(PEXCEPTION_RECORD param_1, PVOID param_2, int param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __except_handler4\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:17dd6baec15e2db7fba918d73f3fb6ac",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "17dd6baec15e2db7fba918d73f3fb6ac",
        "CFG": "5f480d16e7ca428a0055a5d062059fea",
        "PRO": "91b3369df11f8feb11fafa98b6bc9d00"
      },
      "basic_block_counts": {
        "LoD/PD2": 23
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_99e8399ac83d": {
      "addresses": {
        "LoD/PD2": "0x7B33211E"
      },
      "rvas": {
        "LoD/PD2": "0x211E"
      },
      "sizes": {
        "LoD/PD2": 60
      },
      "name": "___std_type_info_compare",
      "signature": "uint ___std_type_info_compare(int param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___std_type_info_compare\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:99e8399ac83d2733bda29a6897eda555",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "99e8399ac83d2733bda29a6897eda555",
        "CFG": "32e15db7c5b22f7bb7a58182cedf6021",
        "PRO": "d6ccd103ef028882446901c26c684439"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_a993bd305991": {
      "addresses": {
        "LoD/PD2": "0x7B33215A"
      },
      "rvas": {
        "LoD/PD2": "0x215A"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "___std_type_info_destroy_list",
      "signature": "undefined ___std_type_info_destroy_list(PSLIST_HEADER param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___std_type_info_destroy_list\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a993bd3059910ca87071e597794b6a23",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a993bd3059910ca87071e597794b6a23",
        "CFG": "a76e0273b3e592eaee672793f78290ba",
        "PRO": "1eb4dca57ccbebcf434ae970ede20d52"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_ed23cc5d152d": {
      "addresses": {
        "LoD/PD2": "0x7B334FAC"
      },
      "rvas": {
        "LoD/PD2": "0x4FAC"
      },
      "sizes": {
        "LoD/PD2": 11
      },
      "name": "___vcrt_thread_attach",
      "signature": "bool ___vcrt_thread_attach(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___vcrt_thread_attach\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ed23cc5d152d612501ab985b6cd1180b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ed23cc5d152d612501ab985b6cd1180b",
        "CFG": null,
        "PRO": "eedad9422dc6248ae039abcb80d819f5"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_f23776c981f8": {
      "addresses": {
        "LoD/PD2": "0x7B334FB7"
      },
      "rvas": {
        "LoD/PD2": "0x4FB7"
      },
      "sizes": {
        "LoD/PD2": 8
      },
      "name": "HandleCrtThreadDetachCleanup",
      "signature": "bool HandleCrtThreadDetachCleanup(void)",
      "calling_convention": "__stdcall",
      "comment": "Handles CRT thread detachment cleanup operations.\n\nThis function is invoked during the CRT thread detachment initialization process \nas part of the thread-local storage (TLS) cleanup sequence. It serves as an error \nrecovery path when the primary thread attachment preparation fails.\n\nAlgorithm:\n1. Call FUN_7b332693 to perform thread-local storage cleanup and finalization\n2. Return 1 (true) to indicate successful cleanup completion\n\nParameters:\n(none)\n\nReturns:\nbool - Always returns 1 (true) indicating successful cleanup operation\n\nSpecial Cases:\n- Called only when thread attachment initialization encounters an error condition\n- Serves as cleanup handler for failed thread attachment scenarios\n- Part of CRT (C Runtime) thread management infrastructure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23776c981f88f2e44bd8f0f2628e6a8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23776c981f88f2e44bd8f0f2628e6a8",
        "CFG": null,
        "PRO": "e6e0f0a3e635c038e4bd479b72d929d1"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_cf4213f1c246": {
      "addresses": {
        "LoD/PD2": "0x7B3321AF"
      },
      "rvas": {
        "LoD/PD2": "0x21AF"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "___vcrt_uninitialize",
      "signature": "undefined4 ___vcrt_uninitialize(char param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___vcrt_uninitialize\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cf4213f1c24622ef19ecd49d55cefa47",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cf4213f1c24622ef19ecd49d55cefa47",
        "CFG": "4a19a33d654978a38a753d8c14f15e92",
        "PRO": "40d546ad1477b1a45840a6e0118966b8"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_f2c4a007044f": {
      "addresses": {
        "LoD/PD2": "0x7B3321CE"
      },
      "rvas": {
        "LoD/PD2": "0x21CE"
      },
      "sizes": {
        "LoD/PD2": 142
      },
      "name": "___DestructExceptionObject",
      "signature": "undefined ___DestructExceptionObject(int * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___DestructExceptionObject\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f2c4a007044f1c447116ccdb496863c9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f2c4a007044f1c447116ccdb496863c9",
        "CFG": "616269d69488c60ad6c06535f277e575",
        "PRO": "3fcbadf4582f7ea2da238028d74042a7"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_1afe32329822": {
      "addresses": {
        "LoD/PD2": "0x7B33226F"
      },
      "rvas": {
        "LoD/PD2": "0x226F"
      },
      "sizes": {
        "LoD/PD2": 13
      },
      "name": "_CallMemberFunction0",
      "signature": "void _CallMemberFunction0(void * param_1, void * param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n void __stdcall _CallMemberFunction0(void * const,void * const)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1afe32329822801a6e320d6c68dd5ad7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1afe32329822801a6e320d6c68dd5ad7",
        "CFG": null,
        "PRO": "86e2eb50bba3c410486856c9168ce909"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_2b7a28af6339": {
      "addresses": {
        "LoD/PD2": "0x7B33227C"
      },
      "rvas": {
        "LoD/PD2": "0x227C"
      },
      "sizes": {
        "LoD/PD2": 88
      },
      "name": "_FilterSetCurrentException",
      "signature": "ulong _FilterSetCurrentException(_EXCEPTION_POINTERS * param_1, uchar param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n unsigned long __cdecl _FilterSetCurrentException(struct _EXCEPTION_POINTERS *,unsigned char)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2b7a28af6339241c0af7c2338ab83d02",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2b7a28af6339241c0af7c2338ab83d02",
        "CFG": "f0e06b48e47d35f6214e4e8e701baba0",
        "PRO": "83224923afae6d95087d6877e861cef9"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_c3872d0240bc": {
      "addresses": {
        "LoD/PD2": "0x7B3322D4"
      },
      "rvas": {
        "LoD/PD2": "0x22D4"
      },
      "sizes": {
        "LoD/PD2": 38
      },
      "name": "__IsExceptionObjectToBeDestroyed",
      "signature": "undefined4 __IsExceptionObjectToBeDestroyed(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __IsExceptionObjectToBeDestroyed\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c3872d0240bc624f915f7473c768c6f2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c3872d0240bc624f915f7473c768c6f2",
        "CFG": "76db6c382c26eeeef0f0e1f77aac8844",
        "PRO": "8972a9f6914de74b4a74eee5a4784586"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_beefd4590b78": {
      "addresses": {
        "LoD/PD2": "0x7B3322FA"
      },
      "rvas": {
        "LoD/PD2": "0x22FA"
      },
      "sizes": {
        "LoD/PD2": 37
      },
      "name": "___AdjustPointer",
      "signature": "int ___AdjustPointer(int param_1, int * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___AdjustPointer\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:beefd4590b780cc5ab9452c4491d586f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "beefd4590b780cc5ab9452c4491d586f",
        "CFG": "dc31fd8ae2ce6da459435b7f021fe995",
        "PRO": "8dcd29da0e631801fbbcc27c9425f659"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_834de6ae16e0": {
      "addresses": {
        "LoD/PD2": "0x7B33231F"
      },
      "rvas": {
        "LoD/PD2": "0x231F"
      },
      "sizes": {
        "LoD/PD2": 86
      },
      "name": "___FrameUnwindFilter",
      "signature": "undefined4 ___FrameUnwindFilter(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___FrameUnwindFilter\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:834de6ae16e03b37748e9709014fa787",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "834de6ae16e03b37748e9709014fa787",
        "CFG": "0e45c9325a2dc9f2f6d991bb86ee35e4",
        "PRO": "25237ad0402b2d887dc4f4120ac52c90"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_fdad073544ac": {
      "addresses": {
        "LoD/PD2": "0x7B33CF70"
      },
      "rvas": {
        "LoD/PD2": "0xCF70"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "Unwind@7b332375",
      "signature": "undefined Unwind@7b332375(void)",
      "calling_convention": "__cdecl",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fdad073544ac1586678f808b3470f76a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fdad073544ac1586678f808b3470f76a",
        "CFG": null,
        "PRO": "f97f2445006c847e038b034fd580e1ab"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_b300650ab0d3": {
      "addresses": {
        "LoD/PD2": "0x7B332380"
      },
      "rvas": {
        "LoD/PD2": "0x2380"
      },
      "sizes": {
        "LoD/PD2": 346
      },
      "name": "_memset",
      "signature": "void * _memset(void * _Dst, int _Val, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memset\n\nLibraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b300650ab0d3880a59ed2b059ab57c68",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b300650ab0d3880a59ed2b059ab57c68",
        "CFG": "b9c82149cdd16061660dd363b4e6583f",
        "PRO": "20a5ac617918f2d5f9d43e4eaefe88bf"
      },
      "basic_block_counts": {
        "LoD/PD2": 24
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_4b130a7ddc52": {
      "addresses": {
        "LoD/PD2": "0x7B3324E0"
      },
      "rvas": {
        "LoD/PD2": "0x24E0"
      },
      "sizes": {
        "LoD/PD2": 159
      },
      "name": "UnwindExceptionCleanup",
      "signature": "void UnwindExceptionCleanup(uint * xorKeyPtr, int structPtr, uint rangeLimit)",
      "calling_convention": "__cdecl",
      "comment": "Unwwind exception cleanup handler for SEH exception traversal and validation.\n\nAlgorithm:\n1. Initialize SEH exception handling frame with XOR obfuscation security check\n2. Push exception handler address (LAB_7b332580) and set up exception list link\n3. Enter loop to process exception records:\n   a. Load current index from structPtr+0xc (0xfffffffe marks end)\n   b. If index == 0xfffffffe or (rangeLimit != 0xfffffffe AND index <= rangeLimit), exit loop\n   c. Calculate array element offset: ([structPtr+8] XOR *xorKeyPtr) + 0x10 + index*0xc\n   d. Load next index from current element and update structPtr+0xc\n   e. Validate element: if element[1] == 0, error (call __NLG_Notify(0x101) and FUN_7b332850)\n   f. Otherwise continue loop\n4. Restore exception list and return\n\nParameters:\n- xorKeyPtr: pointer to XOR key (typically stack-based obfuscation seed)\n- structPtr: pointer to exception structure with indices at offset 0xc and base at offset 0x8\n- rangeLimit: limit index for iteration (0xfffffffe = no limit)\n\nReturns: void\n\nSpecial Cases:\n- Magic value 0xfffffffe marks end of linked list iteration\n- Element validation: puVar1[1] == 0 indicates invalid/null element requiring error handler\n- XOR obfuscation: array pointer is obfuscated via XOR with key to defeat static analysis\n- Array stride: 0xc bytes per element (typical for 3-DWORD structures)\n- SEH security: local_20 stores XOR checksum with DAT_7b345000 for stack guard validation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4b130a7ddc52fcb9e62208c9e7cc7f42",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4b130a7ddc52fcb9e62208c9e7cc7f42",
        "CFG": "049fd204bbc6d6c1f4a8e9694396506f",
        "PRO": "063b198714a0df3ea2abf902bc836c85"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_93ee3e3eb2ce": {
      "addresses": {
        "LoD/PD2": "0x7B3325D0"
      },
      "rvas": {
        "LoD/PD2": "0x25D0"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "_EH4_CallFilterFunc",
      "signature": "undefined _EH4_CallFilterFunc(undefined * param_1)",
      "calling_convention": "__fastcall",
      "comment": "Library Function - Single Match\n @_EH4_CallFilterFunc@8\n\nLibrary: Visual Studio 2019 Release\n__fastcall _EH4_CallFilterFunc,8",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:93ee3e3eb2ce656cea811f30fb40d90f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "93ee3e3eb2ce656cea811f30fb40d90f",
        "CFG": null,
        "PRO": "a3aeaf905aa3ad7e698619e7e0a53ab0"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_e79230fb5d82": {
      "addresses": {
        "LoD/PD2": "0x7B3325F0"
      },
      "rvas": {
        "LoD/PD2": "0x25F0"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "_EH4_TransferToHandler",
      "signature": "undefined _EH4_TransferToHandler(undefined * UNRECOVERED_JUMPTABLE)",
      "calling_convention": "__fastcall",
      "comment": "Library Function - Single Match\n @_EH4_TransferToHandler@8\n\nLibrary: Visual Studio 2019 Release\n__fastcall _EH4_TransferToHandler,8",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e79230fb5d8226b2a60868c040f71dd0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e79230fb5d8226b2a60868c040f71dd0",
        "CFG": null,
        "PRO": "ba26c8d3bc1aaf79190445a6ba2f1688"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_f947813812ec": {
      "addresses": {
        "LoD/PD2": "0x7B332610"
      },
      "rvas": {
        "LoD/PD2": "0x2610"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "_EH4_GlobalUnwind2",
      "signature": "undefined _EH4_GlobalUnwind2(PVOID param_1, PEXCEPTION_RECORD param_2)",
      "calling_convention": "__fastcall",
      "comment": "Library Function - Single Match\n @_EH4_GlobalUnwind2@8\n\nLibrary: Visual Studio 2019 Release\n__fastcall _EH4_GlobalUnwind2,8",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f947813812ec93633c2fecc27752b1c2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f947813812ec93633c2fecc27752b1c2",
        "CFG": null,
        "PRO": "1157426f97106cda8d1b357c667aefd9"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_4e42bd50f35d": {
      "addresses": {
        "LoD/PD2": "0x7B332630"
      },
      "rvas": {
        "LoD/PD2": "0x2630"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "_EH4_LocalUnwind",
      "signature": "undefined _EH4_LocalUnwind(int param_1, uint param_2, undefined4 param_3, uint * param_4)",
      "calling_convention": "__fastcall",
      "comment": "Library Function - Single Match\n @_EH4_LocalUnwind@16\n\nLibrary: Visual Studio 2019 Release\n__fastcall _EH4_LocalUnwind,16",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4e42bd50f35d0553fe79ad066a458d16",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4e42bd50f35d0553fe79ad066a458d16",
        "CFG": null,
        "PRO": "8c24fd5686df2a16d005ca95ad500b54"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_ccf83ea34632": {
      "addresses": {
        "LoD/PD2": "0x7B332647"
      },
      "rvas": {
        "LoD/PD2": "0x2647"
      },
      "sizes": {
        "LoD/PD2": 48
      },
      "name": "___except_validate_context_record",
      "signature": "undefined ___except_validate_context_record(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___except_validate_context_record\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ccf83ea34632061926306461433c0d59",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ccf83ea34632061926306461433c0d59",
        "CFG": "2555e203409cbc2d4a46fa3a51b3c448",
        "PRO": "52046443c0c88f8adfeca30385ed3050"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_a0a473648b8f": {
      "addresses": {
        "LoD/PD2": "0x7B332677"
      },
      "rvas": {
        "LoD/PD2": "0x2677"
      },
      "sizes": {
        "LoD/PD2": 28
      },
      "name": "ValidateAndCleanupThreadLocalStorage",
      "signature": "void ValidateAndCleanupThreadLocalStorage(LPVOID pStorageHandle)",
      "calling_convention": "__stdcall",
      "comment": "Validates and cleans up thread-local storage.\n\nALGORITHM:\n1. Load storage handle from parameter (EBP+0x8)\n2. Test if handle is NULL; exit if NULL\n3. Compare handle to default sentinel value (0x7b345cb8); exit if equal\n4. If handle is valid, push it and call cleanup function\n5. Pop stack and return with 4-byte argument cleanup\n\nPARAMETERS:\n  pStorageHandle: LPVOID - Handle from thread local storage, may be NULL or sentinel\n\nRETURNS:\n  void - No return value\n\nSPECIAL CASES:\n  - NULL pointer: Silently skipped (valid condition)\n  - Sentinel value 0x7b345cb8: Skipped as it indicates uninitialized storage\n  - Valid non-NULL, non-sentinel pointers: Passed to cleanup handler function",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a0a473648b8f7515b3a6e14725dfec5f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a0a473648b8f7515b3a6e14725dfec5f",
        "CFG": "aed4449cad9c680425c75a8429257195",
        "PRO": "49fd19e1eb6aaeea7f7053a48ae51cab"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_800c356bcde4": {
      "addresses": {
        "LoD/PD2": "0x7B332693"
      },
      "rvas": {
        "LoD/PD2": "0x2693"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "CleanupThreadLocalStorage",
      "signature": "void CleanupThreadLocalStorage(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleans up thread-local storage for CRT upon thread detachment.\n\nAlgorithm:\n1. Load FLS (Fiber Local Storage) slot index from global DAT_7b345060\n2. Check if slot index is valid (not 0xffffffff uninitialized marker)\n3. If invalid, skip cleanup and return immediately\n4. If valid, call ___vcrt_FlsGetValue to retrieve thread's storage handle\n5. Call ___vcrt_FlsSetValue to clear the FLS slot with NULL\n6. Call ValidateAndCleanupThreadLocalStorage to perform validation and cleanup\n7. Return to caller\n\nParameters:\nNone - Function takes no parameters\n\nReturns:\nvoid - No return value, performs cleanup side effects only\n\nSpecial Cases:\n- If DAT_7b345060 contains 0xffffffff, the FLS slot is considered uninitialized and cleanup is skipped\n- The function is called during thread detachment (CRT cleanup phase)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:800c356bcde42f5553d0470b81df02a6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "800c356bcde42f5553d0470b81df02a6",
        "CFG": "ea03c6407b4d091868dce8d0baf95212",
        "PRO": "4e35888d97351da6af24e2c592a045c2"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_db025ad6cd47": {
      "addresses": {
        "LoD/PD2": "0x7B3326BE"
      },
      "rvas": {
        "LoD/PD2": "0x26BE"
      },
      "sizes": {
        "LoD/PD2": 14
      },
      "name": "___vcrt_getptd",
      "signature": "undefined ___vcrt_getptd(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___vcrt_getptd\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:db025ad6cd47be53d30ec8c7bca7f4bc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "db025ad6cd47be53d30ec8c7bca7f4bc",
        "CFG": "93b5915f2433b5c17d3d3c41471d9e68",
        "PRO": "15284545aff9eb335f28cfbdb13d2143"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_33151eb86bb1": {
      "addresses": {
        "LoD/PD2": "0x7B3326CC"
      },
      "rvas": {
        "LoD/PD2": "0x26CC"
      },
      "sizes": {
        "LoD/PD2": 146
      },
      "name": "___vcrt_getptd_noexit",
      "signature": "LPVOID ___vcrt_getptd_noexit(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___vcrt_getptd_noexit\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:33151eb86bb15e376506f8fd3f98f0a7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "33151eb86bb15e376506f8fd3f98f0a7",
        "CFG": "1b86eb4d0c96666303d04c2121496f71",
        "PRO": "af7cc1d12db923e774e0507640c2cd67"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_8a4000f8351a": {
      "addresses": {
        "LoD/PD2": "0x7B33275E"
      },
      "rvas": {
        "LoD/PD2": "0x275E"
      },
      "sizes": {
        "LoD/PD2": 51
      },
      "name": "___vcrt_initialize_ptd",
      "signature": "undefined4 ___vcrt_initialize_ptd(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___vcrt_initialize_ptd\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8a4000f8351a0aa341d88405e70888ae",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8a4000f8351a0aa341d88405e70888ae",
        "CFG": "bfa22c3fd387f22c29ee41d99ac17a74",
        "PRO": "eb965373977cb4f589d4e31834428093"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_5aebfd690502": {
      "addresses": {
        "LoD/PD2": "0x7B332791"
      },
      "rvas": {
        "LoD/PD2": "0x2791"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "___vcrt_uninitialize_ptd",
      "signature": "undefined4 ___vcrt_uninitialize_ptd(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___vcrt_uninitialize_ptd\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5aebfd690502582bb101c5c92e5b328b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5aebfd690502582bb101c5c92e5b328b",
        "CFG": "f09da8ab2298e4bafedfaee404f68269",
        "PRO": "f18d5be13588fc4b6a44f720df12c0d4"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_4e06e7380fc7": {
      "addresses": {
        "LoD/PD2": "0x7B3327AC"
      },
      "rvas": {
        "LoD/PD2": "0x27AC"
      },
      "sizes": {
        "LoD/PD2": 60
      },
      "name": "___vcrt_initialize_locks",
      "signature": "undefined4 ___vcrt_initialize_locks(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___vcrt_initialize_locks\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4e06e7380fc707b0ff36cbc7f3d9ce45",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4e06e7380fc707b0ff36cbc7f3d9ce45",
        "CFG": "eedaec691a4b94e5a795ce955c5fac49",
        "PRO": "38844b0d944b1d414e3a88fce91ffb29"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_a1b9b8f8fc7a": {
      "addresses": {
        "LoD/PD2": "0x7B3327E8"
      },
      "rvas": {
        "LoD/PD2": "0x27E8"
      },
      "sizes": {
        "LoD/PD2": 47
      },
      "name": "___vcrt_uninitialize_locks",
      "signature": "undefined4 ___vcrt_uninitialize_locks(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___vcrt_uninitialize_locks\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a1b9b8f8fc7ae83c82b85617ce060d2d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a1b9b8f8fc7ae83c82b85617ce060d2d",
        "CFG": "4e847b889984c71922568191fca6fba0",
        "PRO": "e67d380ffbab7cb66e361a2844d3e3ad"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_285fbf375b91": {
      "addresses": {
        "LoD/PD2": "0x7B332820"
      },
      "rvas": {
        "LoD/PD2": "0x2820"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "GetCallbackFunction",
      "signature": "pointer GetCallbackFunction(uint callbackId)",
      "calling_convention": "__fastcall",
      "comment": "Retrieves a callback function pointer from a global array based on callback ID.\n\nAlgorithm:\n1. Accept callback ID as parameter (passed in EDX via __fastcall)\n2. Load base address of global callback table (0x7b345070) into EBX\n3. Jump to continuation code for actual lookup operation\n4. Store retrieved function pointer in EAX for return\n\nParameters:\ncallbackId (EDX register): Callback identifier used to select function from table\n\nReturns:\nEAX: Function pointer to callback function\n\nSpecial Cases:\n- Global callback table base: 0x7b345070\n- Called by __CallSettingFrame@12 with special handling for ID 0x100 (remapped to 2)\n- Very simple wrapper for table lookup operation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:285fbf375b91db6a4aaef7c7ccdbe9ed",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "285fbf375b91db6a4aaef7c7ccdbe9ed",
        "CFG": null,
        "PRO": "17cd6c9a2888593fd4a9c48c3c4fbf56"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_8a66beed7791": {
      "addresses": {
        "LoD/PD2": "0x7B332830"
      },
      "rvas": {
        "LoD/PD2": "0x2830"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "__NLG_Notify",
      "signature": "void __NLG_Notify(ulong param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __NLG_Notify\n\nLibraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8a66beed7791df002b527959d711671a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8a66beed7791df002b527959d711671a",
        "CFG": "fdd5a1378d33d71c1b536e590571b410",
        "PRO": "6e196072d72f09449344725f5a3ddc96"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_92df3e3d5563": {
      "addresses": {
        "LoD/PD2": "0x7B332850"
      },
      "rvas": {
        "LoD/PD2": "0x2850"
      },
      "sizes": {
        "LoD/PD2": 3
      },
      "name": "InvokeErrorCleanupHandler",
      "signature": "void InvokeErrorCleanupHandler(void)",
      "calling_convention": "__stdcall",
      "comment": "Exception handler cleanup stub that invokes a cleanup handler.\n\nAlgorithm:\n1. Call the function pointer stored in EAX register\n2. Return to caller\n\nParameters:\n- EAX (implicit): Cleanup handler function pointer to invoke\n\nReturns:\nvoid - This function returns control via RET instruction after handler completes\n\nSpecial Cases:\n- Called exclusively from UnwindExceptionCleanup error handler at offset 0x7b332567\n- Triggered when exception validation fails (invalid element detected)\n- Handler pointer in EAX must be valid or execution will crash\n- This is a thin wrapper used to isolate error handler invocation\n- Used in SEH (Structured Exception Handling) cleanup sequences",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:92df3e3d5563806163f4fd65bc64473b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "92df3e3d5563806163f4fd65bc64473b",
        "CFG": null,
        "PRO": "ba95c5c19848da6c40263fb68139d805"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_3a904f51eaee": {
      "addresses": {
        "LoD/PD2": "0x7B332853"
      },
      "rvas": {
        "LoD/PD2": "0x2853"
      },
      "sizes": {
        "LoD/PD2": 110
      },
      "name": "FindRangeContainingValue",
      "signature": "void FindRangeContainingValue(uint * pOutputResult, uint resultValue1, int searchValue, uint resultValue2, void * pRangeArray, int searchDepth)",
      "calling_convention": "__cdecl",
      "comment": "Binary search algorithm to find a range containing the specified search value.\n\nAlgorithm:\n1. Initialize search variables: load range array metadata from pRangeArray\n2. Calculate first range element pointer using searchDepth to offset into array\n3. Enter search loop: iterate downward through range elements (stride 0x14)\n4. For each element, compare searchValue against range bounds (offsets -6 and -5)\n5. When matching range found (value within bounds) or bounds exceeded, record index\n6. Continue iteration until searchDepth reaches -1\n7. After loop completes, validate result: check if found index is within valid range\n8. If validation passes, populate pOutputResult with found indices and return\n9. If validation fails, call abort() to signal error condition\n\nParameters:\n- pOutputResult: Pointer to output structure receiving 4 uint fields: [0]=resultValue1, [4]=foundIndex, [8]=resultValue2, [12]=rangeIndex\n- resultValue1: Value to store in output[0], typically range data identifier\n- searchValue: The value to search for within range bounds (compared as int)\n- resultValue2: Value to store in output[8], typically range data identifier\n- pRangeArray: Pointer to sorted range array structure with metadata at +0xc (count) and +0x10 (base pointer)\n- searchDepth: Initial iteration count for search loop, defines search window size\n\nReturns:\n- None (void function); result written to pOutputResult structure\n- On error (no matching range found), calls abort()\n\nSpecial Cases:\n- Index -1 is sentinel indicating loop termination\n- Empty ranges (count=0) cause abort() call\n- Search value outside all range bounds causes abort() call\n- Algorithm assumes ranges are non-overlapping and sorted",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3a904f51eaee94334e6e398aa706763c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3a904f51eaee94334e6e398aa706763c",
        "CFG": "500af4ef03c3490703ea24166f346dc9",
        "PRO": "2685a2bbb939afce441c8e31e7195372"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "PD2_EXT_MNE_2feb9fafe29f": {
      "addresses": {
        "LoD/PD2": "0x7B3328C2"
      },
      "rvas": {
        "LoD/PD2": "0x28C2"
      },
      "sizes": {
        "LoD/PD2": 93
      },
      "name": "CallSettingFrameWithSEH",
      "signature": "undefined4 CallSettingFrameWithSEH(undefined4 param1, undefined4 param2, undefined4 param3, int param4, int param5)",
      "calling_convention": "__cdecl",
      "comment": "Sets up Structured Exception Handling (SEH) context and delegates to __CallSettingFrame for frame setup.\n\nAlgorithm:\n1. Initialize stack canary by XORing frame address with security value (DAT_7b345000)\n2. Save parameters into local variables for exception handler access\n3. Increment param4 and store as local (purpose unclear - may be frame counter)\n4. Set up exception return address pointer to FUN_7b332a92 exception handler\n5. Chain exception handler by saving current FS:[0] to prevExceptionList local\n6. Update FS:[0] to point to new exception frame at [EBP-0x18]\n7. Call __CallSettingFrame@12(param3, param1, param5) with frame context\n8. Restore FS:[0] to previous exception list\n9. Return result from __CallSettingFrame\n\nParameters:\nparam1 (undefined4): Frame/context parameter passed to __CallSettingFrame and saved\nparam2 (undefined4): Frame parameter value (saved but not used in visible flow)\nparam3 (undefined4): Primary parameter passed to __CallSettingFrame\nparam4 (int): Counter/flag value that is incremented before being saved\nparam5 (int): Secondary parameter passed to __CallSettingFrame\n\nReturns:\nundefined4: Result from __CallSettingFrame (typically status or value code)\n\nSpecial Cases:\n- Uses Microsoft Visual C++ SEH (Structured Exception Handling) mechanism\n- Security: Stack canary XOR value stored at DAT_7b345000\n- Exception handler chain: Maintains linked list via FS:[0] register\n- All parameters are preserved for exception handler access",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2feb9fafe29f5f6b422340d478154186",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2feb9fafe29f5f6b422340d478154186",
        "CFG": "2905a5f71956f3ea8f8249f7e990e9c6",
        "PRO": "ae08580d6cfbf25a3e28c561037c0d50"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_32dc407a777a": {
      "addresses": {
        "LoD/PD2": "0x7B33291F"
      },
      "rvas": {
        "LoD/PD2": "0x291F"
      },
      "sizes": {
        "LoD/PD2": 240
      },
      "name": "DispatchTranslatorGuardHandler",
      "signature": "int DispatchTranslatorGuardHandler(int * pExceptionInfo, int * pFilterAddress, int exceptionCode, int exceptionFlags, int exceptionRecord, int exceptionHandler, int contextRecord)",
      "calling_convention": "__cdecl",
      "comment": "SEH (Structured Exception Handling) filter dispatcher for translator guard handler.\\n\\nAlgorithm:\\n1. Check if pExceptionInfo equals magic value 0x123 (special termination signal)\\n   - If true: set output address to 0x7b3329e3 and return 1\\n2. Otherwise, establish SEH frame with guard protection:\\n   a. Save handler address and calculate XOR security token\\n   b. Link into exception chain via FS:[0] segment register\\n   c. Initialize local stack frame with exception parameters\\n   d. Call __filter_x86_sse2_floating_point_exception_default() to handle FPU exceptions\\n3. Retrieve current thread data via ___vcrt_getptd() to find guarded call handler\\n4. Guard-check the indirect function pointer before calling\\n5. Invoke handler with exception info and saved exception info copy\\n6. Check if exception was handled (exceptionHandled != 0):\\n   - If yes: restore previous exception frame from FS:[0] chain\\n   - If no: restore exception frame normally\\n7. Return filter result code (0=continue search, 1=execute handler, -1=continue)\\n\\nParameters:\\npExceptionInfo: int * - Pointer to exception information block\\npFilterAddress: int * - Output parameter: address to jump to if handler accepts\\nexceptionCode: int - Exception code from EXCEPTION_RECORD.ExceptionCode\\nexceptionFlags: int - Exception flags from EXCEPTION_RECORD.ExceptionFlags\\nexceptionRecord: int - Full exception record pointer\\nexceptionHandler: int - Exception handler address/context\\ncontextRecord: int - CPU context record pointer\\n\\nReturns:\\nint - Filter result: 1 if exception handled by guard, 0 otherwise\\n\\nSpecial Cases:\\n- Magic value 0x123 in pExceptionInfo triggers special cleanup path\\n- FPU exception handling integrated via SSE2 floating point filter\\n- SEH frame linked into global exception chain for nested exception handling\\n- Security XOR token prevents buffer overflow exploits\\n- Guard-checked indirect call prevents code execution attacks",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:32dc407a777a01489fe546082ca6cc2e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "32dc407a777a01489fe546082ca6cc2e",
        "CFG": "7f867d4d755682b4f1c250f388279fc7",
        "PRO": "1b9dee6481570558cfe7530efeeadb45"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "PD2_EXT_MNE_489067da1a2c": {
      "addresses": {
        "LoD/PD2": "0x7B332A0F"
      },
      "rvas": {
        "LoD/PD2": "0x2A0F"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "_JumpToContinuation",
      "signature": "void _JumpToContinuation(void * param_1, EHRegistrationNode * param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:489067da1a2c8cee5a3d2d9b9de565b4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "489067da1a2c8cee5a3d2d9b9de565b4",
        "CFG": null,
        "PRO": "3cc833536bdfd5ce9c6ea6051767a049"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_f0b1ace8a5f1": {
      "addresses": {
        "LoD/PD2": "0x7B332A3F"
      },
      "rvas": {
        "LoD/PD2": "0x2A3F"
      },
      "sizes": {
        "LoD/PD2": 83
      },
      "name": "_UnwindNestedFrames",
      "signature": "void _UnwindNestedFrames(EHRegistrationNode * param_1, EHExceptionRecord * param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *,struct EHExceptionRecord *)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f0b1ace8a5f12224e121b9af4d2c672b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f0b1ace8a5f12224e121b9af4d2c672b",
        "CFG": null,
        "PRO": "df093f47bb296618880a859e828a8e62"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_ebbf40cad4d9": {
      "addresses": {
        "LoD/PD2": "0x7B332A92"
      },
      "rvas": {
        "LoD/PD2": "0x2A92"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "ExceptionHandlerDispatch",
      "signature": "void ExceptionHandlerDispatch(EHExceptionRecord * pExceptionRecord, EHRegistrationNode * pRegNode, _CONTEXT * pContext)",
      "calling_convention": "__cdecl",
      "comment": "Dispatches exception handling by validating stack cookie and invoking C++ exception handler.\\n\\nAlgorithm:\\n1. Validate stack cookie using XOR of registration node pointer and cookie value stored at +0x8\\n2. Call ValidateStackCookie with computed cookie XOR result\\n3. Extract exception handler function information from registration node:\\n   - pExceptionNode from offset +0x10\\n   - pFuncInfo from offset +0xc\\n   - iEHExceptionLevel from offset +0x14\\n4. Invoke FUN_7b333c67 (main C++ exception dispatcher) with extracted parameters\\n5. Return to caller\\n\\nParameters:\\n- pExceptionRecord: EHExceptionRecord* - Exception information\\n- pRegNode: EHRegistrationNode* - Registration node containing exception handler metadata\\n- pContext: _CONTEXT* - CPU context at exception time\\n\\nReturns:\\nvoid - No return value\\n\\nSpecial Cases:\\n- Stack cookie validation uses XOR encoding for security (cookie XOR regnode_ptr)\\n- Registration node structure is embedded in stack frame\\n- Exception handler level indicates nested try/catch depth",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ebbf40cad4d99d238bac34c946af8450",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ebbf40cad4d99d238bac34c946af8450",
        "CFG": null,
        "PRO": "ad2539f2b40edf627725ffbf986ca76d"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_d8759df0db80": {
      "addresses": {
        "LoD/PD2": "0x7B332AC3"
      },
      "rvas": {
        "LoD/PD2": "0x2AC3"
      },
      "sizes": {
        "LoD/PD2": 36
      },
      "name": "__CreateFrameInfo",
      "signature": "undefined4 * __CreateFrameInfo(undefined4 * param_1, undefined4 param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __CreateFrameInfo\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d8759df0db80c469547839b319f42d0b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d8759df0db80c469547839b319f42d0b",
        "CFG": null,
        "PRO": "fc00fcf02377aae9fe4d46c5bf2d1a28"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_1bfde2ab6134": {
      "addresses": {
        "LoD/PD2": "0x7B332AE7"
      },
      "rvas": {
        "LoD/PD2": "0x2AE7"
      },
      "sizes": {
        "LoD/PD2": 71
      },
      "name": "__FindAndUnlinkFrame",
      "signature": "undefined __FindAndUnlinkFrame(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __FindAndUnlinkFrame\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1bfde2ab6134a2ce093522ed6335f84a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1bfde2ab6134a2ce093522ed6335f84a",
        "CFG": "733afd2a4616909da7683c7bc052e8e1",
        "PRO": "65d7d5ce6451a3d8d1573a8d6e5922ba"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_55960fbf9938": {
      "addresses": {
        "LoD/PD2": "0x7B332B2F"
      },
      "rvas": {
        "LoD/PD2": "0x2B2F"
      },
      "sizes": {
        "LoD/PD2": 152
      },
      "name": "FID_conflict:TranslatorGuardHandler",
      "signature": "undefined4 FID_conflict:TranslatorGuardHandler(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Multiple Matches With Different Base Names\n enum _EXCEPTION_DISPOSITION __cdecl TranslatorGuardHandler(struct EHExceptionRecord *,struct TranslatorGuardRN *,void *,void *)\n __TranslatorGuardHandler\n\nLibraries: Visual Studio 2012 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:55960fbf99384e3434ee365b023c8268",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "55960fbf99384e3434ee365b023c8268",
        "CFG": "950a535247ef24e3e2febcb81273d214",
        "PRO": "a15af6512a8a1aa05b6baf4a32aec904"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_c3e67f0f66e9": {
      "addresses": {
        "LoD/PD2": "0x7B332BCC"
      },
      "rvas": {
        "LoD/PD2": "0x2BCC"
      },
      "sizes": {
        "LoD/PD2": 54
      },
      "name": "FID_conflict:___CxxFrameHandler3",
      "signature": "undefined4 FID_conflict:___CxxFrameHandler3(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Multiple Matches With Different Base Names\n ___CxxFrameHandler\n ___CxxFrameHandler2\n ___CxxFrameHandler3\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c3e67f0f66e9fe1748a93603f0dc99e6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c3e67f0f66e9fe1748a93603f0dc99e6",
        "CFG": null,
        "PRO": "3eb11560c7bf6b9350f1ef50ba3c5660"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_7108372b66ec": {
      "addresses": {
        "LoD/PD2": "0x7B332C10"
      },
      "rvas": {
        "LoD/PD2": "0x2C10"
      },
      "sizes": {
        "LoD/PD2": 1047
      },
      "name": "CopyMemoryOptimized",
      "signature": "uint CopyMemoryOptimized(uint * pDestination, uint * pSource, uint numBytes)",
      "calling_convention": "__cdecl",
      "comment": "Optimized memory copy function with handling for overlapping regions and alignment optimization.\n\nAlgorithm:\n1. Check if regions overlap: if source < destination < source+numBytes, perform backward copy\n2. Forward copy (non-overlapping or source before destination):\n   a. For small copies (< 32 bytes): perform simple byte-by-byte or word-by-word copy\n   b. For medium copies (32-127 bytes): align destination to 4-byte boundary, then copy 32-bit words\n   c. For large copies (>= 128 bytes): use SSSE3 SIMD instructions for 128-bit aligned copying\n   d. Final cleanup: copy remainder bytes\n3. Backward copy (destination < source < destination+numBytes):\n   a. Start from end of buffers and copy backwards to avoid overwriting source data\n   b. Align to 16-byte boundary if SSSE3 support available\n   c. Use 128-bit SSE instructions for efficient bulk copying\n   d. Fallback to 32-bit or 8-bit copies for remainder\n\nParameters:\n- pDestination: uint * - Target memory address where data will be copied\n- pSource: uint * - Source memory address to copy from\n- numBytes: uint - Number of bytes to copy\n\nReturns:\n- uint - Original destination address (pDestination)\n\nSpecial Cases:\n- Overlapping regions: backward copy when destination overlaps with source region\n- Alignment optimization: uses SSSE3/SSE2 instructions when processor supports (checked via flag at 0x7b345050, 0x7b345c74)\n- Unaligned copies: adjusts strategy based on alignment of source/destination pointers",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7108372b66ecf751dc8d1b6817b95672",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7108372b66ecf751dc8d1b6817b95672",
        "CFG": "41cf389ae808dd634a76453cb4632e3a",
        "PRO": "19478db3a4835d3e3129152057a42b94"
      },
      "basic_block_counts": {
        "LoD/PD2": 67
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_ec5b4b642d4b": {
      "addresses": {
        "LoD/PD2": "0x7B333060"
      },
      "rvas": {
        "LoD/PD2": "0x3060"
      },
      "sizes": {
        "LoD/PD2": 283
      },
      "name": "ForwardCopySsse3Aligned",
      "signature": "size_t ForwardCopySsse3Aligned(void * pDestination, void * pSource, size_t nByteCount)",
      "calling_convention": "__cdecl",
      "comment": "Copies memory forward using SSE3 SIMD instructions, optimized for aligned 128-byte bulk transfers.\n\nAlgorithm:\n1. Check source alignment: if not 16-byte aligned, copy (16 - alignment) bytes\n   to align source, reducing remaining byte count\n2. For bulk 128-byte chunks: load 8 XMM registers (4 at source+0x00, 4 at\n   source+0x40), write to destination, advance 128 bytes, loop until done\n3. For remainder bytes (1-127): if >= 32 bytes, copy 32-byte chunks with MOVDQU\n   (unaligned move), advance 32 bytes each iteration\n4. For final < 32 bytes: copy dword-aligned chunks (4 bytes), then copy\n   remaining bytes (1-3) individually\n5. Return third parameter (byte count) as result\n\nParameters:\n  pDestination [EDI]: Destination memory buffer (must be writable)\n  pSource [ESI]: Source memory buffer (may be unaligned, data copied forward)\n  nByteCount [ECX on entry, param_3]: Number of bytes to copy\n\nReturns:\n  EAX = nByteCount (returns third parameter as result code)\n\nSpecial Cases:\n  - Unaligned source: copies alignment bytes individually to reach 16-byte\n    boundary, then uses MOVDQA for fast aligned SSE transfers\n  - Bulk copy: 128-byte stride with 8 concurrent XMM operations for\n    cache efficiency\n  - Remainder: handles any byte count via 32-byte, 4-byte, then 1-byte transfers",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ec5b4b642d4b85db434e2d3ccd54c2db",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ec5b4b642d4b85db434e2d3ccd54c2db",
        "CFG": "3adaf362770f882a81273e10cfe17469",
        "PRO": "34ce6eac616e3c8259738b56d338a799"
      },
      "basic_block_counts": {
        "LoD/PD2": 20
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_3a5203810764": {
      "addresses": {
        "LoD/PD2": "0x7B333184"
      },
      "rvas": {
        "LoD/PD2": "0x3184"
      },
      "sizes": {
        "LoD/PD2": 160
      },
      "name": "ResolveProcAddressWithCache",
      "signature": "int ResolveProcAddressWithCache(int functionOrdinal, LPCSTR functionName, int * pLibraryIndicesStart, int * pLibraryIndicesEnd)",
      "calling_convention": "__cdecl",
      "comment": "Resolves a procedure address from a set of candidate libraries with thread-safe caching.\n\nAlgorithm:\n1. Calculate cache entry address using functionOrdinal as array index into DAT_7b345d08\n2. Check if function is already cached (value != 0xFFFFFFFF and != 0)\n3. If cached with valid result, return immediately\n4. If cached with failure marker (0xFFFFFFFF), return NULL\n5. If not cached (value = 0), iterate through candidate libraries:\n   a. Get library index from pLibraryIndicesStart array\n   b. Fetch HMODULE from DAT_7b345cfc using library index\n   c. If HMODULE is NULL, attempt to load library via try_load_library_from_system_directory\n   d. Use atomic XCHG to cache loaded HMODULE, free old if needed\n   e. If HMODULE is invalid (0xFFFFFFFF), continue to next library\n   f. Call GetProcAddress to resolve functionName from current library\n   g. If found, atomically cache function pointer and return\n   h. If not found in this library, continue to next\n6. If not found in any library, atomically cache failure marker (0xFFFFFFFF) and return NULL\n\nParameters:\n  functionOrdinal - Index into function cache array (DAT_7b345d08)\n  functionName - Name of function to resolve (passed to GetProcAddress)\n  pLibraryIndicesStart - Pointer to array of library indices (ordinals)\n  pLibraryIndicesEnd - End of library indices array (loop condition)\n\nReturns:\n  Function pointer (FARPROC) if successfully resolved\n  NULL (0) if function not found in any candidate library\n\nSpecial Cases:\n  Cache value 0xFFFFFFFF indicates previous resolution failure\n  Multiple libraries checked in order until function is found\n  Thread synchronization via LOCK/UNLOCK for cache updates\n  Library handles cached in DAT_7b345cfc to avoid repeated loads",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3a52038107640b8eaffaa003a30df9b9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3a52038107640b8eaffaa003a30df9b9",
        "CFG": "2db1c7f6668c38a7026eb82118a6cdec",
        "PRO": "0614e89b7a9bcad21ea63e583b6624ca"
      },
      "basic_block_counts": {
        "LoD/PD2": 19
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_76ae5b440b5b": {
      "addresses": {
        "LoD/PD2": "0x7B333224"
      },
      "rvas": {
        "LoD/PD2": "0x3224"
      },
      "sizes": {
        "LoD/PD2": 75
      },
      "name": "try_load_library_from_system_directory",
      "signature": "HINSTANCE__ * try_load_library_from_system_directory(wchar_t * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n struct HINSTANCE__ * __cdecl try_load_library_from_system_directory(wchar_t const * const)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:76ae5b440b5b4eba709d28aaadc1e692",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "76ae5b440b5b4eba709d28aaadc1e692",
        "CFG": "d4a4f7f07eed1fb0c24bfad08eb98295",
        "PRO": "bde0d86e3f3b5fdee7d0ca5bdeb5fcc8"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_eb9855cfe307": {
      "addresses": {
        "LoD/PD2": "0x7B33326F"
      },
      "rvas": {
        "LoD/PD2": "0x326F"
      },
      "sizes": {
        "LoD/PD2": 59
      },
      "name": "___vcrt_FlsAlloc",
      "signature": "undefined ___vcrt_FlsAlloc(undefined4 param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___vcrt_FlsAlloc\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:eb9855cfe3079a68ada2b749c94de074",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "eb9855cfe3079a68ada2b749c94de074",
        "CFG": "3d7ac2c2df8a331cdbb21fa9dd404d13",
        "PRO": "5fc9dffb576987faa1780b5c4455c4ef"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_681a8ee97e4f": {
      "addresses": {
        "LoD/PD2": "0x7B3332E5"
      },
      "rvas": {
        "LoD/PD2": "0x32E5"
      },
      "sizes": {
        "LoD/PD2": 59
      },
      "name": "___vcrt_FlsFree",
      "signature": "undefined ___vcrt_FlsFree(DWORD param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___vcrt_FlsFree\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:681a8ee97e4f188190975f017117c4d4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "681a8ee97e4f188190975f017117c4d4",
        "CFG": "611b0a2738bc697e80a73ce4243ca126",
        "PRO": "51b628bb3397e4bcdaae0bae3cccc89d"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_75b65262791c": {
      "addresses": {
        "LoD/PD2": "0x7B333320"
      },
      "rvas": {
        "LoD/PD2": "0x3320"
      },
      "sizes": {
        "LoD/PD2": 62
      },
      "name": "___vcrt_FlsSetValue",
      "signature": "undefined ___vcrt_FlsSetValue(DWORD param_1, LPVOID param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___vcrt_FlsSetValue\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:75b65262791c6439417fa9c6957fb064",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "75b65262791c6439417fa9c6957fb064",
        "CFG": "f16ee01fce64ac425fc77137800a8352",
        "PRO": "b06c542b4c9143e5e97c419b4ffcbbc7"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_b76d7f5eef9a": {
      "addresses": {
        "LoD/PD2": "0x7B33335E"
      },
      "rvas": {
        "LoD/PD2": "0x335E"
      },
      "sizes": {
        "LoD/PD2": 71
      },
      "name": "___vcrt_InitializeCriticalSectionEx",
      "signature": "undefined ___vcrt_InitializeCriticalSectionEx(LPCRITICAL_SECTION param_1, DWORD param_2, undefined4 param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___vcrt_InitializeCriticalSectionEx\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b76d7f5eef9a248524bd260d012b6bb2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b76d7f5eef9a248524bd260d012b6bb2",
        "CFG": "e6239802a5b3e3dd1f1be91f0d5c374d",
        "PRO": "b5f3032f34ee37af43d77cb40f297169"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_61abeb07930a": {
      "addresses": {
        "LoD/PD2": "0x7B3333A5"
      },
      "rvas": {
        "LoD/PD2": "0x33A5"
      },
      "sizes": {
        "LoD/PD2": 308
      },
      "name": "BuildCatchObjectHelperInternal<class___FrameHandler3>",
      "signature": "int BuildCatchObjectHelperInternal<class___FrameHandler3>(EHExceptionRecord * param_1, void * param_2, _s_HandlerType * param_3, _s_CatchableType * param_4)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl BuildCatchObjectHelperInternal<class __FrameHandler3>(struct EHExceptionRecord *,void *,struct _s_HandlerType const *,struct _s_CatchableType const *)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:61abeb07930ad8551e5cc6f1e4544c2d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "61abeb07930ad8551e5cc6f1e4544c2d",
        "CFG": "fb5eb2e15522055ed8ddd75942e8883a",
        "PRO": "30085646aedcd72058f53c776c5b1b40"
      },
      "basic_block_counts": {
        "LoD/PD2": 33
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_44921dddb1f4": {
      "addresses": {
        "LoD/PD2": "0x7B3334E3"
      },
      "rvas": {
        "LoD/PD2": "0x34E3"
      },
      "sizes": {
        "LoD/PD2": 140
      },
      "name": "BuildCatchObjectInternal<class___FrameHandler3>",
      "signature": "void BuildCatchObjectInternal<class___FrameHandler3>(EHExceptionRecord * param_1, void * param_2, _s_HandlerType * param_3, _s_CatchableType * param_4)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl BuildCatchObjectInternal<class __FrameHandler3>(struct EHExceptionRecord *,void *,struct _s_HandlerType const *,struct _s_CatchableType const *)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:44921dddb1f497acc4651ae7fbab2c15",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "44921dddb1f497acc4651ae7fbab2c15",
        "CFG": "e68b7688884d68f20d908ef015201416",
        "PRO": "b68836da7a5821a841320b7026a0b840"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_ca8ecdc04eed": {
      "addresses": {
        "LoD/PD2": "0x7B33357C"
      },
      "rvas": {
        "LoD/PD2": "0x357C"
      },
      "sizes": {
        "LoD/PD2": 128
      },
      "name": "CatchIt<class___FrameHandler3>",
      "signature": "void CatchIt<class___FrameHandler3>(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4, _s_FuncInfo * param_5, _s_HandlerType * param_6, _s_CatchableType * param_7, _s_TryBlockMapEntry * param_8, int param_9, EHRegistrationNode * param_10, uchar param_11, uchar param_12)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl CatchIt<class __FrameHandler3>(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,struct _s_HandlerType const *,struct _s_CatchableType const *,struct _s_TryBlockMapEntry const *,int,struct EHRegistrationNode *,unsigned char,unsigned char)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ca8ecdc04eed2f8da196c568de3e4013",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ca8ecdc04eed2f8da196c568de3e4013",
        "CFG": "833dd2b2958695689b3c401989f44f23",
        "PRO": "19c51558fc5d698f613d0d97f23907ea"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "PD2_EXT_MNE_47d2251775f9": {
      "addresses": {
        "LoD/PD2": "0x7B3335FC"
      },
      "rvas": {
        "LoD/PD2": "0x35FC"
      },
      "sizes": {
        "LoD/PD2": 932
      },
      "name": "CxxFrameHandler3ProcessException",
      "signature": "int CxxFrameHandler3ProcessException(EHExceptionRecord * pException, EHRegistrationNode * pRN, _CONTEXT * pContext, void * pDispatcher, _s_FuncInfo * pFuncInfo, uchar isFirstHandler, int nestLevel, EHRegistrationNode * pEstablisherFrame)",
      "calling_convention": "__cdecl",
      "comment": "C++ Exception Handler (FrameHandler3) - processes exceptions and manages try-catch resolution\n\nAlgorithm:\n1. Validate exception record magic number (0xe06d7363) and version (3)\n2. Verify exception state is within valid range [-1, maxState)\n3. For C++ exceptions with valid records:\n   a. Retrieve current exception state using GetCurrentState\n   b. Access vcrt per-thread data to check for nested exception handling\n   c. If nested exception exists, process it recursively\n4. For foreign (non-C++) exceptions, search for matching handlers in try-catch blocks\n5. Iterate through try-catch block map entries that contain current execution state\n6. For each matching try block, iterate through handler types in nCatches\n7. Call TypeMatch to test each handler's exception type match\n8. If match found, call CatchIt to execute the handler and transfer control\n9. If no handlers match exception type, continue to next try block\n10. After handler search, check exception object destruction flag\n11. If destructor needed, call DestructExceptionObject\n12. Check for exception specification (EHFlags & 0x1fffffff > 0x19930520)\n13. For exception specifications, validate exception against type list using FUN_7b334084\n14. If validation succeeds and nested handling, set exception in thread context\n15. If validation fails or nested exception, call terminate() or throw std::bad_exception\n16. Unwind stack frames using UnwindNestedFrames to handler location\n17. Call FrameUnwindToEmptyState to restore frame to initial state\n18. Execute continuation handler via FUN_7b334141\n19. If no handlers match and not first handler, return early\n20. Invalid state or exception magic number triggers abort()\n\nParameters:\n  pException: EHExceptionRecord* - exception descriptor with magic (0xe06d7363), version (3), throw info\n  pRN: EHRegistrationNode* - registration node for current frame\n  pContext: _CONTEXT* - CPU context at exception point\n  pDispatcher: void* - dispatcher object for frame lookup\n  pFuncInfo: _s_FuncInfo* - function info with try block map and exception specifications\n  isFirstHandler: uchar - flag indicating if this is first handler in chain (0=nested, 1=first)\n  nestLevel: int - nesting level for recursive exception handling\n  pEstablisherFrame: EHRegistrationNode* - establisher frame for unwinding\n\nReturns:\n  int: EXCEPTION_CONTINUE_EXECUTION (0) if handled, EXCEPTION_CONTINUE_SEARCH (-1) if not handled,\n       EXCEPTION_EXECUTE_HANDLER (1) if handler executed and control transferred\n\nSpecial Cases:\n  - Magic number 0xe06d7363 identifies Microsoft C++ exceptions\n  - State values: -1=prolog, 0 to maxState-1=valid states, else=invalid\n  - Codes 0x19930520/0x19930521/0x19930522 represent C++ exception versions\n  - std::bad_exception replaces unmatched foreign exceptions\n  - Nested exceptions invoke recursive processing with vcrt per-thread storage\n  - ESTypeList structures enable exception specification validation\n  - Multiple try blocks in single function require iteration of all ranges\n\nStructure Layout:\n  EHExceptionRecord @ offset 0:\n    Offset  Size  Field                Type        Description\n    0x0     4     magicNumber          dword       Must be 0xe06d7363\n    0x4     4     reserved             dword       Reserved field\n    0x10    4     version              dword       Must be 3 for C++ exceptions\n    0x14    4     throwInfoPtr         dword       Pointer to _ThrowInfo structure\n    0x1c    4     handlerCount         dword       Number of handlers (typically 0)\n\n  _s_FuncInfo @ offset 0:\n    Offset  Size  Field                Type        Description\n    0x0     4     magicNumber_and_bbtFlags dword   Magic number & BBT flags\n    0x4     4     maxState             dword       Maximum possible state value\n    0xc     4     nTryBlocks           dword       Number of try-catch blocks\n    0x1c    4     pESTypeList          ESTypeList* Exception specification list\n    0x20    4     EHFlags              dword       Exception handling flags",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:47d2251775f9327aae3f0569123b6c7f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "47d2251775f9327aae3f0569123b6c7f",
        "CFG": "ff6512a542087483d7724aac8b77714b",
        "PRO": "1352a677397dc50633be999771698771"
      },
      "basic_block_counts": {
        "LoD/PD2": 68
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "PD2_EXT_MNE_bde4080e0ce1": {
      "addresses": {
        "LoD/PD2": "0x7B3339A1"
      },
      "rvas": {
        "LoD/PD2": "0x39A1"
      },
      "sizes": {
        "LoD/PD2": 309
      },
      "name": "FindHandlerForForeignException<class___FrameHandler3>",
      "signature": "void FindHandlerForForeignException<class___FrameHandler3>(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4, _s_FuncInfo * param_5, int param_6, int param_7, EHRegistrationNode * param_8)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl FindHandlerForForeignException<class __FrameHandler3>(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,int,int,struct EHRegistrationNode *)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bde4080e0ce192cbc3591ced7ae1526f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bde4080e0ce192cbc3591ced7ae1526f",
        "CFG": "8fe48d343214f9dfe1bfe33fdf7aebbe",
        "PRO": "1746fed340e053e07d4f9618fd56189d"
      },
      "basic_block_counts": {
        "LoD/PD2": 19
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "PD2_EXT_MNE_b697cde157c9": {
      "addresses": {
        "LoD/PD2": "0x7B333AD7"
      },
      "rvas": {
        "LoD/PD2": "0x3AD7"
      },
      "sizes": {
        "LoD/PD2": 142
      },
      "name": "FID_conflict:___TypeMatch",
      "signature": "undefined4 FID_conflict:___TypeMatch(byte * param_1, byte * param_2, byte * param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Multiple Matches With Different Base Names\n int __cdecl TypeMatchHelper<struct _s_HandlerType const >(struct _s_HandlerType const *,struct _s_CatchableType const *,struct _s_ThrowInfo const *)\n int __cdecl TypeMatchHelper<class __FrameHandler3>(struct _s_HandlerType const *,struct _s_CatchableType const *,struct _s_ThrowInfo const *)\n ___TypeMatch\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b697cde157c956c790fcdd1ebc023b57",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b697cde157c956c790fcdd1ebc023b57",
        "CFG": "75ae442b51ee3de06eb1d5e08cae1bb7",
        "PRO": "058c660cb9a40f87d3e37747f49323e6"
      },
      "basic_block_counts": {
        "LoD/PD2": 24
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_54dd8c60fb60": {
      "addresses": {
        "LoD/PD2": "0x7B333B65"
      },
      "rvas": {
        "LoD/PD2": "0x3B65"
      },
      "sizes": {
        "LoD/PD2": 258
      },
      "name": "__InternalCxxFrameHandler<class___FrameHandler3>",
      "signature": "_EXCEPTION_DISPOSITION __InternalCxxFrameHandler<class___FrameHandler3>(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4, _s_FuncInfo * param_5, int param_6, EHRegistrationNode * param_7, uchar param_8)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n enum _EXCEPTION_DISPOSITION __cdecl __InternalCxxFrameHandler<class __FrameHandler3>(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,int,struct EHRegistrationNode *,unsigned char)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:54dd8c60fb60e0a39eed9d6dc81f8511",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "54dd8c60fb60e0a39eed9d6dc81f8511",
        "CFG": "82041f95a9d6ce050d5a8f931ef72e6e",
        "PRO": "cf76cf36c1ad7a2facd2c6626ab8a642"
      },
      "basic_block_counts": {
        "LoD/PD2": 22
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "PD2_EXT_MNE_e2a98ca0d22e": {
      "addresses": {
        "LoD/PD2": "0x7B333C67"
      },
      "rvas": {
        "LoD/PD2": "0x3C67"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "CxxFrameHandlerThunk",
      "signature": "int CxxFrameHandlerThunk(EHExceptionRecord * pExceptionRecord, EHRegistrationNode * pRegistrationNode, _CONTEXT * pContext, void * pDispatcher, _s_FuncInfo * pFuncInfo, int param_6, EHRegistrationNode * pTargetFrame, uchar dispatcherContext)",
      "calling_convention": "__cdecl",
      "comment": "C++ exception handler thunk dispatcher.\n\nThis is a simple wrapper function that sets up the stack frame and forwards execution to the main exception handler. It is part of the Visual C++ exception handling infrastructure and is responsible for dispatching exceptions to the appropriate frame handler.\n\nAlgorithm:\n1. Push frame pointer to save current stack frame\n2. Set up new stack frame using current stack pointer\n3. Restore previous frame pointer\n4. Jump to main exception handler implementation\n\nParameters:\npExceptionRecord: Exception record containing exception details\npRegistrationNode: Registration node for current stack frame\npContext: CPU context (registers) at time of exception\npDispatcher: Exception dispatcher pointer\npFuncInfo: Function info structure for exception handling\nparam_6: Additional exception handling parameter (purpose varies)\npTargetFrame: Target registration node for stack unwinding\ndispatcherContext: Dispatcher context byte indicating handling mode\n\nReturns:\nint: Exception disposition code (ExceptionContinueExecution=0, ExceptionContinueSearch=1, or ExceptionNestedException=2)\n\nSpecial Cases:\nNo local variables or complex logic - all work delegated to called handler.\nFrame setup is minimal (2 instructions) before forward jump.\nThis thunk pattern is typical for C++ exception dispatching in Win32.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e2a98ca0d22e18e77c8a0aec4b4a0855",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e2a98ca0d22e18e77c8a0aec4b4a0855",
        "CFG": null,
        "PRO": "176ae5e4b2a38a4f3d01f21abf373103"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "PD2_EXT_MNE_519b6a2eaec2": {
      "addresses": {
        "LoD/PD2": "0x7B333C70"
      },
      "rvas": {
        "LoD/PD2": "0x3C70"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "bad_exception_constructor",
      "signature": "exception * bad_exception_constructor(void * this, exception * pSourceException)",
      "calling_convention": "__thiscall",
      "comment": "Constructor for std::bad_exception class. Initializes exception base class and sets up virtual function table for bad_exception type identification.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:519b6a2eaec2ae048072e1f9ec31a1f8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "519b6a2eaec2ae048072e1f9ec31a1f8",
        "CFG": null,
        "PRO": "c40c8cddf5b844fe197665df0e7c7b77"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_STR_ce4de8b58a4f": {
      "addresses": {
        "LoD/PD2": "0x7B333C8B"
      },
      "rvas": {
        "LoD/PD2": "0x3C8B"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "BadExceptionConstructor",
      "signature": "undefined4 * BadExceptionConstructor(undefined4 * pException)",
      "calling_convention": "__fastcall",
      "comment": "Initializes a std::bad_exception C++ exception object.\n\nAlgorithm:\n1. Clear field at offset +0x4 (exception message pointer)\n2. Clear field at offset +0x8 (reserved/state field)\n3. Set field at offset +0x4 to string pointer (s_bad_exception_7b33ec68)\n4. Set field at offset +0x0 to virtual function table pointer (0x7b33ec60)\n5. Return the initialized exception object pointer in EAX\n\nParameters:\npException (ECX): Pointer to the std::bad_exception object to initialize (12 bytes)\n\nReturns:\nEAX: Pointer to the initialized exception object\n\nSpecial Cases:\n- Standard C++ exception initialization pattern for bad_exception type\n- Uses __fastcall convention with implicit 'this' pointer in ECX\n- Virtual function table setup enables polymorphic exception handling\n- Field at offset +0x4 holds message string pointer after initialization\n- Field at offset +0x8 appears to be reserved/unused after clear\n\nStructure Layout:\nOffset | Size | Field Name     | Type      | Description\n0x0    | 4    | vftable        | void*     | Virtual function table pointer\n0x4    | 4    | pMessage       | char*     | Exception message string pointer\n0x8    | 4    | reserved       | uint      | Reserved/unused field",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:ce4de8b58a4f29f41d711943c49e8f1d",
      "indexes": {
        "EXP": null,
        "STR": "ce4de8b58a4f29f41d711943c49e8f1d",
        "API": null,
        "MNE": "fba3d29b6bd90bb8c4b7736f36339b2a",
        "CFG": null,
        "PRO": "c52aa4c4127c70921ba51efb79f4e843"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_ef453d2076ed": {
      "addresses": {
        "LoD/PD2": "0x7B333CA3"
      },
      "rvas": {
        "LoD/PD2": "0x3CA3"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "exception",
      "signature": "undefined exception(exception * this, exception * param_1)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: __thiscall std::exception::exception(class std::exception const &)\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ef453d2076eda05461445a10e3476c6d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ef453d2076eda05461445a10e3476c6d",
        "CFG": null,
        "PRO": "7f9bf5e2aaf2d0c89035139476cc1b80"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_b3382a09b4c0": {
      "addresses": {
        "LoD/PD2": "0x7B333CE0"
      },
      "rvas": {
        "LoD/PD2": "0x3CE0"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "operator==",
      "signature": "bool operator==(type_info * this, type_info * param_1)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: bool __thiscall type_info::operator==(class type_info const &)const \n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b3382a09b4c08311210138700a7a39f0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b3382a09b4c08311210138700a7a39f0",
        "CFG": null,
        "PRO": "07ff4746bc38e88a50e5e622f6937ed2"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_8bf44fd2e3e2": {
      "addresses": {
        "LoD/PD2": "0x7B333CFF"
      },
      "rvas": {
        "LoD/PD2": "0x3CFF"
      },
      "sizes": {
        "LoD/PD2": 45
      },
      "name": "ExceptionDestructor",
      "signature": "void * ExceptionDestructor(void * this, void * pThis, byte shouldDeallocate)",
      "calling_convention": "__thiscall",
      "comment": "Exception destructor that cleans up exception object state and optionally deallocates memory.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8bf44fd2e3e212e4a0c7c1e5e6aa6bd7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8bf44fd2e3e212e4a0c7c1e5e6aa6bd7",
        "CFG": "13ac807217091f4044d66f8ff2174dac",
        "PRO": "b44e2a92b1eb94222e2ad23dba614952"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_45f53597b31f": {
      "addresses": {
        "LoD/PD2": "0x7B333D2C"
      },
      "rvas": {
        "LoD/PD2": "0x3D2C"
      },
      "sizes": {
        "LoD/PD2": 177
      },
      "name": "SetupSEHFrame",
      "signature": "undefined4 SetupSEHFrame(int pExceptionFrame, int pDispatcher, undefined4 returnAddress, undefined4 exceptionPointer, undefined4 exceptionInfo, int threadData, int exceptionHandler)",
      "calling_convention": "__cdecl",
      "comment": "Setup Structured Exception Handling (SEH) frame for exception dispatcher\n\nAlgorithm:\n1. Call SEH prologue to initialize exception handling infrastructure\n2. Extract dispatcher RVA from param_2 offset -4 (contains function reference)\n3. Create frame info structure with exception frame details\n4. Query Thread Environment Block (TEB) for current exception context state\n5. Save current TEB exception pointers (offsets 0x10 and 0x14) for restoration\n6. Install new exception frame and exception info into TEB for active handling\n7. Set exception state flag (0xFFFFFFFF) and handler counter (1) to activate frame\n8. Call CallSettingFrameWithSEH to invoke dispatcher with frame parameters\n9. Process exception frame array if dispatcher returns frame data:\n   - Iterate through frame array entries with stride 0x14\n   - Validate frame bounds using comparison checks at offsets +0x4 and +0x8\n   - Lookup frame data from main array using validated index\n10. Setup exception handler through helper function if bounds valid\n11. Clear exception state flags and restore original TEB exception context\n12. Cleanup and return dispatcher result to caller\n\nParameters:\npExceptionFrame (int): Address of SEH exception frame structure (EBP+8)\npDispatcher (int): Address of dispatcher function with RVA at offset -4 (EBP+12)\nreturnAddress (undefined4): Return address to resume execution on exception (EBP+16)\nexceptionPointer (undefined4): Pointer to exception information structure (EBP+20)\nexceptionInfo (undefined4): Exception context data for handler (EBP+24)\nthreadData (int): Thread-specific exception state pointer (EBP+28)\nexceptionHandler (int): Exception handler function pointer (EBP+32)\n\nReturns:\nundefined4: Return value from dispatcher or exception handler result\n\nSpecial Cases:\n- Frame array processing only occurs if dispatcher returns non-zero result\n- Stride of 0x14 (20 bytes) indicates 20-byte frame entry size\n- TEB offsets 0x10 and 0x14 are standard exception context pointers\n- Exception state flag 0xFFFFFFFF enables active exception handling\n- Offsets +0x4 and +0x8 are frame boundary validation points",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:45f53597b31fcd0826ea1ca29b423361",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "45f53597b31fcd0826ea1ca29b423361",
        "CFG": "26a395e1d1b622a1afd71bf788c7ba1b",
        "PRO": "183d15b9dd18df9271ed731b8ae836f9"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "PD2_EXT_MNE_d9adb33fef74": {
      "addresses": {
        "LoD/PD2": "0x7B333E7F"
      },
      "rvas": {
        "LoD/PD2": "0x3E7F"
      },
      "sizes": {
        "LoD/PD2": 124
      },
      "name": "DestructCxxException",
      "signature": "void DestructCxxException(void)",
      "calling_convention": "__stdcall",
      "comment": "C++ Exception Object Destruction Handler\n\nCleans up and destroys C++ exception objects during structured exception handling.\nThis is called as part of SEH frame unwinding when an exception is being processed.\nValidates exception object signature and type before calling destructor.\n\nAlgorithm:\n1. Restore exception context to stack frame from EBP offsets\n2. Unlink the current exception frame via __FindAndUnlinkFrame\n3. Retrieve per-thread data with ___vcrt_getptd()\n4. Restore per-thread exception info fields (offset +0x10, +0x14)\n5. Validate exception object signature (0xe06d7363 = \"Exc\")\n6. Check exception type field at ESI+0x10 equals 0x3\n7. Check exception code type at ESI+0x14 (0x19930520, 0x19930521, or 0x19930522)\n8. If validation passes AND EBP-0x40 is zero AND EBX is non-zero:\n   a. Call __IsExceptionObjectToBeDestroyed on ESI+0x18\n   b. If destruction needed, call ___DestructExceptionObject with exception object\n\nImplicit Parameters (from caller context):\n- EBX: Caller's EBX register (must be non-zero for destruction)\n- EBP: Stack frame pointer with exception context offsets\n- ESI: Pointer to exception object structure\n\nReturns:\n- void (exception state modified in-place)\n\nSpecial Cases:\n- Magic number 0xe06d7363 is the C++ exception signature (\"Exc\" in little-endian)\n- Exception codes 0x19930520-0x19930522 are MSVC exception type indicators\n- Offset -0x40 at EBP likely gates destruction based on exception state\n- Multiple validation checks prevent destruction of unrecognized exceptions\n- Per-thread exception state stored in TLS via ___vcrt_getptd() at offsets +0x10, +0x14",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d9adb33fef74f9de50f23a25f7903d40",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d9adb33fef74f9de50f23a25f7903d40",
        "CFG": "ba3b662644e2fe1669ad554a7693e4ef",
        "PRO": "75699cf97c1a603b2559e4ca7f652855"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_5fac91b074ba": {
      "addresses": {
        "LoD/PD2": "0x7B333EFB"
      },
      "rvas": {
        "LoD/PD2": "0x3EFB"
      },
      "sizes": {
        "LoD/PD2": 32
      },
      "name": "CxxContinuationHandler",
      "signature": "void CxxContinuationHandler(int pContinuationContext)",
      "calling_convention": "__stdcall",
      "comment": "C++ Exception Continuation Handler - processes exception continuation after handler execution\n\nAlgorithm:\n1. Get per-thread vcrt data pointer for exception context access\n2. Check if exception continuation context exists (non-zero check)\n3. If continuation context found, clear the EH flag in EBP stack frame\n4. Call unexpected() to handle continuation semantics\n5. After unexpected() returns, retrieve per-thread data again\n6. Store the continuation context parameter into thread-local exception field\n7. Throw exception to propagate to outer handler\n8. If continuation context is zero (no handler), call abort() to terminate\n\nParameters:\n  pContinuationContext: int - Continuation context value from FUN_7b334141, passed by caller\n                              to determine exception flow control\n\nReturns:\n  void - This function never returns normally. It either:\n         - Throws exception (via __CxxThrowException) to continue exception propagation\n         - Calls abort() to terminate process for invalid continuation state\n\nSpecial Cases:\n  - Magic number 0x1c in EAX offset accesses vcrt per-thread exception state structure\n  - EBP offset -0x4 holds EH (exception handling) flag that must be cleared before continuing\n  - Continuation context of zero indicates no valid handler exists, forcing abort()\n  - unexpected() call implements C++ exception continuation semantics per standard\n  - __CxxThrowException_8 with NULL arguments propagates existing exception object\n\nStructure Layout:\n  VCRT Per-Thread Data @ offset 0:\n    Offset  Size  Field                Type        Description\n    0x10    4     pCurrentException    void*       Pointer to current exception record\n    0x14    4     pExceptionContext    void*       Pointer to exception context (_CONTEXT)\n    0x1c    4     continuationField    dword       Stores continuation context for handler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5fac91b074baa210a78337125484b2ff",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5fac91b074baa210a78337125484b2ff",
        "CFG": "e40dbfc826024b8cfad402a6d4b21b18",
        "PRO": "07a1e928bc2c384a45a02b07e3963de5"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_236fe8119f34": {
      "addresses": {
        "LoD/PD2": "0x7B333F1B"
      },
      "rvas": {
        "LoD/PD2": "0x3F1B"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "Catch_All@7b333f1b",
      "signature": "undefined Catch_All@7b333f1b(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:236fe8119f341f0ffb8dd45cc4672051",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "236fe8119f341f0ffb8dd45cc4672051",
        "CFG": "d0147af625798484c4e263f6efa3c3c1",
        "PRO": "d674f6dd865782819570d5e5e68de0a3"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_6fdd416dc96a": {
      "addresses": {
        "LoD/PD2": "0x7B333F3A"
      },
      "rvas": {
        "LoD/PD2": "0x3F3A"
      },
      "sizes": {
        "LoD/PD2": 74
      },
      "name": "ExFilterRethrow",
      "signature": "int ExFilterRethrow(_EXCEPTION_POINTERS * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl ExFilterRethrow(struct _EXCEPTION_POINTERS *)\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6fdd416dc96a83af6086d9a4900bdb9b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6fdd416dc96a83af6086d9a4900bdb9b",
        "CFG": "f040d7dd33a9d1964320dab4b163395e",
        "PRO": "024776cedaffd2de9c4d398577bb7574"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_aaeff191bc43": {
      "addresses": {
        "LoD/PD2": "0x7B333F84"
      },
      "rvas": {
        "LoD/PD2": "0x3F84"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "FrameUnwindToEmptyState",
      "signature": "void FrameUnwindToEmptyState(EHRegistrationNode * param_1, void * param_2, _s_FuncInfo * param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n public: static void __cdecl __FrameHandler3::FrameUnwindToEmptyState(struct EHRegistrationNode *,void *,struct _s_FuncInfo const *)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:aaeff191bc43edd324a7a541652eb7eb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "aaeff191bc43edd324a7a541652eb7eb",
        "CFG": null,
        "PRO": "78472eba13dbcc7e58d2d5f6cfb5932c"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_640f04293947": {
      "addresses": {
        "LoD/PD2": "0x7B333F9C"
      },
      "rvas": {
        "LoD/PD2": "0x3F9C"
      },
      "sizes": {
        "LoD/PD2": 195
      },
      "name": "FrameUnwindToState",
      "signature": "void FrameUnwindToState(EHRegistrationNode * param_1, void * param_2, _s_FuncInfo * param_3, int param_4)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n public: static void __cdecl __FrameHandler3::FrameUnwindToState(struct EHRegistrationNode *,void *,struct _s_FuncInfo const *,int)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:640f0429394792eab69117f8249645ba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "640f0429394792eab69117f8249645ba",
        "CFG": "fe7a1c2b92d57ec9368403fde8eec55d",
        "PRO": "c221a1d312deb0a74f47a1a18fe9a12c"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_e3813311bc5a": {
      "addresses": {
        "LoD/PD2": "0x7B33406A"
      },
      "rvas": {
        "LoD/PD2": "0x406A"
      },
      "sizes": {
        "LoD/PD2": 20
      },
      "name": "DecrementExceptionDepth",
      "signature": "void DecrementExceptionDepth(void)",
      "calling_convention": "__stdcall",
      "comment": "Decrements the exception handling depth counter in thread-local storage.\\n\\nCalled after exception frame unwinding completes to decrement the call depth counter that was incremented when entering exception handling scope. Part of the C++ exception handling mechanism (__FrameHandler3).\\n\\nAlgorithm:\\n1. Call ___vcrt_getptd() to get thread-local data pointer\\n2. Compare counter at offset +0x18 with 0\\n3. If counter > 0, call ___vcrt_getptd() again and decrement counter at +0x18\\n4. Return to caller\\n\\nReturns:\\n  void - No return value\\n\\nSpecial Cases:\\n  - Counter must be > 0 to decrement; prevents negative count\\n  - Thread-local storage is accessed via standard VCRT function\\n  - Part of structured exception handling cleanup sequence\\n  \\nStructure Layout (Thread-Local Data):\\n  Offset | Size | Field | Type | Description\\n  +0x18  | 4    | depth | int  | Exception handling depth counter",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3813311bc5a4241b81d444bd92c16c8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3813311bc5a4241b81d444bd92c16c8",
        "CFG": "0b937785f5183116206974188ae35559",
        "PRO": "d7109d0dfbeaf4212b3da3d6f4bba1c1"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_b0da31b24ce5": {
      "addresses": {
        "LoD/PD2": "0x7B334084"
      },
      "rvas": {
        "LoD/PD2": "0x4084"
      },
      "sizes": {
        "LoD/PD2": 153
      },
      "name": "ValidateExceptionInSpecification",
      "signature": "undefined4 ValidateExceptionInSpecification(int pException, int * pESTypeList)",
      "calling_convention": "__cdecl",
      "comment": "Validates whether an exception matches any allowed types in an exception specification list.\n\nAlgorithm:\n1. Validate that pESTypeList pointer is not null, abort if null\n2. Extract exception type count from ESTypeList structure at offset 0x0\n3. If type count <= 0, return 0 (no match possible)\n4. Initialize outer loop to iterate through each exception type in specification list\n5. For each type entry:\n   a. Load catchable type information from offset +0x1c in exception structure\n   b. Retrieve array of catchable types from offset +0xc in catchable structure\n   c. Get count of catchable types from array at offset 0x0\n   d. Advance to first catchable type pointer at offset +0x4\n   e. For each catchable type in array:\n      i. Call TypeMatch to test if exception type matches handler type\n      ii. If match found (TypeMatch returns non-zero), set hasMatchFound=1 and exit\n   f. Decrement remaining type count and advance to next handler type\n6. Return hasMatchFound flag in AL register (1=match found, 0=no match)\n\nParameters:\n  pException: int - EHExceptionRecord pointer containing exception information\n  pESTypeList: int* - Exception specification type list with nCount at offset 0x0\n\nReturns:\n  undefined4: Returns 1 (true) if exception matches any type in specification, 0 (false) otherwise\n\nSpecial Cases:\n  - Null ESTypeList pointer triggers abort()\n  - Empty type list (count <= 0) returns 0 (no match)\n  - Uses TypeMatch helper function to validate type compatibility\n  - Iterates through all specification types until match found or exhausted\n\nStructure Layout:\n  ESTypeList @ offset 0x0:\n    Offset  Size  Field                Type        Description\n    0x0     4     nCount               dword       Number of exception types in specification\n    0x4     4+    typeArray            dword[]     Array of catchable type pointers",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b0da31b24ce535025a64d384310b57ae",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b0da31b24ce535025a64d384310b57ae",
        "CFG": "fa15e96a8caed62de634d2cbba75fec1",
        "PRO": "c533e5b981ee4573237ffec26f7f44dd"
      },
      "basic_block_counts": {
        "LoD/PD2": 15
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_e3e3229058d3": {
      "addresses": {
        "LoD/PD2": "0x7B33411E"
      },
      "rvas": {
        "LoD/PD2": "0x411E"
      },
      "sizes": {
        "LoD/PD2": 16
      },
      "name": "_CallMemberFunction1",
      "signature": "void _CallMemberFunction1(void * param_1, void * param_2, void * param_3)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n void __stdcall _CallMemberFunction1(void * const,void * const,void * const)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e3229058d36905a1a68cfe9e9a6dce",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e3229058d36905a1a68cfe9e9a6dce",
        "CFG": null,
        "PRO": "df6fb71ee4be90edc38df8f5d9cf7858"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_2a51439d3df9": {
      "addresses": {
        "LoD/PD2": "0x7B33412E"
      },
      "rvas": {
        "LoD/PD2": "0x412E"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "_CallMemberFunction2",
      "signature": "void _CallMemberFunction2(void * param_1, void * param_2, void * param_3, int param_4)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n void __stdcall _CallMemberFunction2(void * const,void * const,void * const,int)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2a51439d3df95cdeb8e8c2f112ce2747",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2a51439d3df95cdeb8e8c2f112ce2747",
        "CFG": null,
        "PRO": "ce9ed9aab4b568dd7e92318daa716e39"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_6c78b8cdb994": {
      "addresses": {
        "LoD/PD2": "0x7B334141"
      },
      "rvas": {
        "LoD/PD2": "0x4141"
      },
      "sizes": {
        "LoD/PD2": 11
      },
      "name": "GetExceptionHandlerField",
      "signature": "undefined4 GetExceptionHandlerField(int pExceptionFrame)",
      "calling_convention": "__cdecl",
      "comment": "Extracts a field at offset 0x1c from an exception frame structure.\n\nAlgorithm:\n1. Receives exception frame pointer as parameter\n2. Dereferences pointer and reads 4-byte value at offset +0x1c\n3. Returns the extracted value in EAX\n\nParameters:\n- pExceptionFrame: Pointer to exception handling frame structure\n\nReturns:\n- EAX: 4-byte value from offset 0x1c of the exception frame\n\nSpecial Cases:\n- Called by exception handling framework during C++ exception processing\n- Offset 0x1c likely contains handler state or callback pointer\n- No parameter validation - assumes valid frame pointer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6c78b8cdb99464505b02b4fce5a90a95",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6c78b8cdb99464505b02b4fce5a90a95",
        "CFG": null,
        "PRO": "a340cfa88b7fd0a75778f359c3dd3be6"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_STR_6ce4e8a3f559": {
      "addresses": {
        "LoD/PD2": "0x7B33414C"
      },
      "rvas": {
        "LoD/PD2": "0x414C"
      },
      "sizes": {
        "LoD/PD2": 13
      },
      "name": "GetExceptionMessage",
      "signature": "char * GetExceptionMessage(void * pException)",
      "calling_convention": "__fastcall",
      "comment": "Retrieves the message/description string from an exception object.\n\nAlgorithm:\n1. Read message pointer from exception object at offset +4\n2. Test if the message pointer is null\n3. If null, return default \"Unknown_exception\" string\n4. Otherwise, return the message pointer from the exception\n\nParameters:\npException: Pointer to exception object containing message reference at offset +4\n\nReturns:\nchar*: Pointer to exception message string. Returns default \"Unknown_exception\" if the exception's message pointer is null.\n\nSpecial Cases:\n- If pException is null or invalid, accessing offset +4 will read from invalid memory\n- Default message is stored at 0x7b33ec48 in read-only data\n- The message string is not owned by this function; caller must not free it\n\nStructure Layout:\nOffset | Size | Field Name | Type | Description\n-------|------|------------|------|-------------\n+0     | 4    | vftable    | void*| Virtual function table pointer\n+4     | 4    | pMessage   | char*| Pointer to exception message string",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:6ce4e8a3f559a754022376e7624fac26",
      "indexes": {
        "EXP": null,
        "STR": "6ce4e8a3f559a754022376e7624fac26",
        "API": null,
        "MNE": "9200e0ba5b72479d735d5cb45e6d679e",
        "CFG": "7750d3e200f3a3c6416ddf41088bb841",
        "PRO": "50da7fe73b2133e88f38b670df5545c7"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_54a4c3410932": {
      "addresses": {
        "LoD/PD2": "0x7B334160"
      },
      "rvas": {
        "LoD/PD2": "0x4160"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "__CallSettingFrame@12",
      "signature": "undefined __CallSettingFrame@12(undefined4 param_1, undefined4 param_2, int param_3)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __CallSettingFrame@12\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:54a4c3410932c862e3fcae53288bc46f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "54a4c3410932c862e3fcae53288bc46f",
        "CFG": "64f001e958cb75886bced722d66d85ff",
        "PRO": "b98277cef56d8b14e8e694472ff0dddd"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_1aa16dcc47a5": {
      "addresses": {
        "LoD/PD2": "0x7B3341AC"
      },
      "rvas": {
        "LoD/PD2": "0x41AC"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "unexpected",
      "signature": "undefined unexpected(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _unexpected\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1aa16dcc47a501f5c8f75f14c67102f0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1aa16dcc47a501f5c8f75f14c67102f0",
        "CFG": "e4d929dcade813bcfed0f23f20c25712",
        "PRO": "cdc6fa5260874525d9295f7f2155002f"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_c4d7cc35846e": {
      "addresses": {
        "LoD/PD2": "0x7B3341C9"
      },
      "rvas": {
        "LoD/PD2": "0x41C9"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "GetCurrentState",
      "signature": "int GetCurrentState(EHRegistrationNode * param_1, void * param_2, _s_FuncInfo * param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n public: static int __cdecl __FrameHandler3::GetCurrentState(struct EHRegistrationNode *,void *,struct _s_FuncInfo const *)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c4d7cc35846e5594959a304e9077ef36",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c4d7cc35846e5594959a304e9077ef36",
        "CFG": "e4d929dcade813bcfed0f23f20c25712",
        "PRO": "0837d89e8e4b8612accd0762362ede27"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_a754c9ec0cf5": {
      "addresses": {
        "LoD/PD2": "0x7B3341E6"
      },
      "rvas": {
        "LoD/PD2": "0x41E6"
      },
      "sizes": {
        "LoD/PD2": 14
      },
      "name": "SetState",
      "signature": "void SetState(EHRegistrationNode * param_1, _s_FuncInfo * param_2, int param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n public: static void __cdecl __FrameHandler3::SetState(struct EHRegistrationNode *,struct _s_FuncInfo const *,int)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a754c9ec0cf5b6cbbfcbdd6a75a3dd7e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a754c9ec0cf5b6cbbfcbdd6a75a3dd7e",
        "CFG": null,
        "PRO": "1a1b3155c5789954936c221149914767"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_4fc1b92d94c9": {
      "addresses": {
        "LoD/PD2": "0x7B3341F4"
      },
      "rvas": {
        "LoD/PD2": "0x41F4"
      },
      "sizes": {
        "LoD/PD2": 99
      },
      "name": "___std_exception_copy",
      "signature": "undefined ___std_exception_copy(int * param_1, int * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___std_exception_copy\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4fc1b92d94c9c12476c4fc7a333e79b0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4fc1b92d94c9c12476c4fc7a333e79b0",
        "CFG": "910ce600523c05e66d9cc75591985feb",
        "PRO": "ebd642600af145633caa561893ae24df"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_bb91777f490f": {
      "addresses": {
        "LoD/PD2": "0x7B334257"
      },
      "rvas": {
        "LoD/PD2": "0x4257"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "___std_exception_destroy",
      "signature": "undefined ___std_exception_destroy(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___std_exception_destroy\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bb91777f490fd4dfe7fd7442b4c04f14",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bb91777f490fd4dfe7fd7442b4c04f14",
        "CFG": "ebedb8faf55908534e596ba5d47d40c7",
        "PRO": "53ac517f488e65ea357748539f5a3abc"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_234cb430475d": {
      "addresses": {
        "LoD/PD2": "0x7B334276"
      },
      "rvas": {
        "LoD/PD2": "0x4276"
      },
      "sizes": {
        "LoD/PD2": 108
      },
      "name": "__CxxThrowException@8",
      "signature": "undefined __CxxThrowException@8(int * param_1, byte * param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __CxxThrowException@8\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:234cb430475d6ce0443bd71e0382a0dc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "234cb430475d6ce0443bd71e0382a0dc",
        "CFG": "3865b5f2bb4f37e3683883ab47756ae0",
        "PRO": "097278655d3c7d1327f1428f553d83a5"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_b9c5e13a0364": {
      "addresses": {
        "LoD/PD2": "0x7B3342F0"
      },
      "rvas": {
        "LoD/PD2": "0x42F0"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "CallFunctionTableWithGuard",
      "signature": "void CallFunctionTableWithGuard(uint * pFunctionStart, uint * pFunctionEnd)",
      "calling_convention": "__cdecl",
      "comment": "Iterates through a table of function pointers and calls each one with guard verification.\n\nAlgorithm:\n1. Compare start pointer against end pointer to check if table is empty\n2. If empty (start equals end), skip execution and return\n3. If not empty, enter loop at loop_start_check_function\n4. Load function pointer from current table entry\n5. Test if function pointer is non-null at check_null_function\n6. If null, jump to loop_continue_next_entry, skip execution\n7. If non-null, call guard check function (icall guard mechanism)\n8. Call the function pointer directly\n9. Increment table pointer by 4 bytes (pointer size) at loop_continue_next_entry\n10. Compare updated pointer against end pointer at loop_boundary_check\n11. If not equal, loop back to step 4\n12. If equal, exit loop at function_end_cleanup and return\n\nParameters:\n  pFunctionStart: Pointer to first function pointer in table (array start)\n  pFunctionEnd: Pointer to one past last function pointer (array end, exclusive)\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - Empty table: If pFunctionStart equals pFunctionEnd, loop is skipped entirely\n  - Null entries: Table entries may be null; null function pointers are skipped\n  - Guard check: All non-null function pointers verified through icall guard before execution\n  - Stride: Table entries are 4 bytes apart (standard pointer size)\n\nNote: This function implements a common pattern for executing initialization/finalization routines from static arrays, commonly used in C++ runtime initialization (e.g., global constructors, atexit handlers)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b9c5e13a0364b6cb095c8a0c4ac2ab2a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b9c5e13a0364b6cb095c8a0c4ac2ab2a",
        "CFG": "af4a8e66c8e67afd2cfb0261a7557b22",
        "PRO": "bf83aafa0f2542a2b082c3e8afa70396"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_82041a8a73a8": {
      "addresses": {
        "LoD/PD2": "0x7B33431B"
      },
      "rvas": {
        "LoD/PD2": "0x431B"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "__initterm_e",
      "signature": "int __initterm_e(undefined4 * param_1, undefined4 * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __initterm_e\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:82041a8a73a8b1ac01228f41bfcec2a1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "82041a8a73a8b1ac01228f41bfcec2a1",
        "CFG": "7982cea02743e8ef27b2e318b1301c25",
        "PRO": "2c82afe0146f176622d40257a9de4d2f"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_8c4c977ffca9": {
      "addresses": {
        "LoD/PD2": "0x7B334349"
      },
      "rvas": {
        "LoD/PD2": "0x4349"
      },
      "sizes": {
        "LoD/PD2": 32
      },
      "name": "__seh_filter_dll",
      "signature": "undefined4 __seh_filter_dll(int param_1, undefined4 param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __seh_filter_dll\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8c4c977ffca90d6427f5c9eec0eb9793",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8c4c977ffca90d6427f5c9eec0eb9793",
        "CFG": "c0911ab13e8db6d703c6ff224f1b4a1f",
        "PRO": "da094c62a2dbfa36ee35a0e7d978c724"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_865344578b0e": {
      "addresses": {
        "LoD/PD2": "0x7B334369"
      },
      "rvas": {
        "LoD/PD2": "0x4369"
      },
      "sizes": {
        "LoD/PD2": 326
      },
      "name": "DispatchExceptionHandler",
      "signature": "int DispatchExceptionHandler(uint exceptionCode, __acrt_ptd * pThreadData)",
      "calling_convention": "__cdecl",
      "comment": "Dispatches an exception handler from per-thread handler table with guard protections\n\nAlgorithm:\n1. Retrieve per-thread data structure (ACRT PTD) via FUN_7b335838\n2. Return 0 if thread data is NULL\n3. Iterate through handler table searching for entry matching exceptionCode\n4. Table stored as array with 12-byte stride (offset +0xc between entries)\n5. If matching handler found, proceed to execution; else return 0\n6. Validate handler is not NULL and check type field (offset +0x8)\n7. If type is 0x5, clear handler and return 1\n8. If type is 0x1, return 0xffffffff (immediate return)\n9. For other types: Save current context from PTD+0x4, set new context parameter\n10. If handler level is 0x8: Clear handlers from offset +0x24 onwards using 12-byte stride\n11. Perform error code mapping for Windows NTSTATUS values\n12. Call guard_check_icall with error code and 0x8 parameter\n13. Execute handler function via indirect call\n14. Restore context from PTD+0x4\n15. Return 0xffffffff on success\n\nParameters:\n- exceptionCode: Windows NTSTATUS exception code (e.g., 0xc0000091 for GUARD_PAGE)\n- pThreadData: Pointer to ACRT per-thread data structure containing handler table\n\nReturns:\n- 0: Handler not found or validation failed\n- 1: Handler was in state 0x5 (cleared and executed)\n- 0xffffffff: Handler executed successfully\n\nSpecial Cases:\n- Handler type 0x5 is cleared without execution (guard page handler)\n- Handler type 0x1 returns immediately without execution\n- Error code mapping converts Windows NTSTATUS to error codes:\n  0xc0000091 -> 0x84, 0xc000008d -> 0x82, 0xc000008e -> 0x83\n  0xc000008f -> 0x86, 0xc0000090 -> 0x81, 0xc0000092 -> 0x8a\n  0xc0000093 -> 0x85, 0xc00002b4 -> 0x8e, 0xc00002b5 -> 0x8d\n- Handler level 0x8 triggers full handler table clear before execution\n- Guard check performed before all indirect handler calls for security",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:865344578b0e04d028c10d04a82cc4b8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "865344578b0e04d028c10d04a82cc4b8",
        "CFG": "20e4c484aebdcc22ab1da208d5b013a8",
        "PRO": "99776f243ca94766e443a07c8d3bc221"
      },
      "basic_block_counts": {
        "LoD/PD2": 44
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_d8e4a88a34e8": {
      "addresses": {
        "LoD/PD2": "0x7B3368BC"
      },
      "rvas": {
        "LoD/PD2": "0x68BC"
      },
      "sizes": {
        "LoD/PD2": 65
      },
      "name": "operator()<>",
      "signature": "undefined operator()<>(int * param_1, undefined4 * param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Multiple Matches With Same Base Name\n public: void __thiscall __crt_seh_guarded_call<void>::operator()<class <lambda_03b1d95aef87969028cfba75ccab2455>,class <lambda_6e4b09c48022b2350581041d5f6b0c4c> &,class <lambda_22bdf7517842c4b3e53723af5aa32b9e> >(class <lambda_03b1d95aef87969028cfba75ccab2455> &&,class <lambda_6e4b09c48022b2350581041d5f6b0c4c> &,class <lambda_22bdf7517842c4b3e53723af5aa32b9e> &&)\n public: void __thiscall __crt_seh_guarded_call<void>::operator()<class <lambda_4fdada1b837b2abbf20876fac97688ad>,class <lambda_b57350f2640456a0859d250846f69caf> &,class <lambda_eed5e4f92b5b7d55fa22c48c484aaa54> >(class <lambda_4fdada1b837b2abbf20876fac97688ad> &&,class <lambda_b57350f2640456a0859d250846f69caf> &,class <lambda_eed5e4f92b5b7d55fa22c48c484aaa54> &&)\n public: void __thiscall __crt_seh_guarded_call<void>::operator()<class <lambda_ceb1ee4838e85a9d631eb091e2fbe199>,class <lambda_ae742caa10f662c28703da3d2ea5e57e> &,class <lambda_cd08b5d6af4937fe54fc07d0c9bf6b37> >(class <lambda_ceb1ee4838e85a9d631eb091e2fbe199> &&,class <lambda_ae742caa10f662c28703da3d2ea5e57e> &,class <lambda_cd08b5d6af4937fe54fc07d0c9bf6b37> &&)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d8e4a88a34e829b0daa624dfafa2ea35",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d8e4a88a34e829b0daa624dfafa2ea35",
        "CFG": null,
        "PRO": "beaf90e9e19d1b293c3e66244af05211"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_3a54b0e12c44": {
      "addresses": {
        "LoD/PD2": "0x7B33B300"
      },
      "rvas": {
        "LoD/PD2": "0xB300"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "UnlockCriticalSection",
      "signature": "void UnlockCriticalSection(int * pMutexContainer)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper function that unlocks a critical section mutex.\n\nAlgorithm:\n1. Load the mutex container pointer from the parameter (EBP + 0x10)\n2. Dereference the pointer to get the actual mutex object\n3. Call the ACRT unlock function to release the critical section\n4. Return to caller\n\nParameters:\n- pMutexContainer: Pointer to a structure containing the mutex pointer at offset 0\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- This is a thin wrapper around __acrt_unlock used for C runtime critical section management\n- The actual mutex is nested one level deep (pointer to pointer access)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3a54b0e12c4466583f041806e6cbafb8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3a54b0e12c4466583f041806e6cbafb8",
        "CFG": null,
        "PRO": "26dcc0d98a890c2c5b3549d69179ec0b"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_118552f9636e": {
      "addresses": {
        "LoD/PD2": "0x7B3344FC"
      },
      "rvas": {
        "LoD/PD2": "0x44FC"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "DecodeCFGPointer",
      "signature": "uint DecodeCFGPointer(uint encodedPointer)",
      "calling_convention": "__cdecl",
      "comment": "Decodes a CFG (Control Flow Guard) protected function pointer\nAlgorithm:\n  1. Load encoding key from global DAT_7b345000\n  2. Extract rotation count as (key & 0x1f) bits\n  3. XOR encoded pointer with the encoding key\n  4. Rotate right the XORed value by rotation count\n  5. Return the decoded pointer value\nParameters:\n  encodedPointer: uint - Function pointer value encoded by CFG initialization\nReturns:\n  uint - Decoded function pointer ready for indirect call\nSpecial Cases:\n  Uses MSVC CFG (Control Flow Guard) encoding scheme where function pointers are XORed with a global key and rotated. The rotation count is the lower 5 bits of the key, allowing 0-31 bit rotations. Returns the original pointer value before encoding.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:118552f9636ebb54895aa82eaf47393a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "118552f9636ebb54895aa82eaf47393a",
        "CFG": null,
        "PRO": "1cd4f69f090e86bc39f625dfb8a3aec3"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_e499a7c57fcc": {
      "addresses": {
        "LoD/PD2": "0x7B334517"
      },
      "rvas": {
        "LoD/PD2": "0x4517"
      },
      "sizes": {
        "LoD/PD2": 196
      },
      "name": "ValidateControlFlowGuardIterator",
      "signature": "void ValidateControlFlowGuardIterator(void * pGuardObject)",
      "calling_convention": "__fastcall",
      "comment": "Validates and processes control flow guard iterator with callback invocation.\n\nAlgorithm:\n1. Set up SEH (Structured Exception Handling) frame for error recovery\n2. Check if guard is already initialized via global flag at 0x7b345d28\n3. If not initialized: exchange initialization counter at 0x7b345d20 with 1\n4. Retrieve iterator object through dereferenced pointer at offset +0\n5. Branch based on iterator value: null (no callback), 1 (has callback), or other (error)\n6. For null case: use default callback from 0x7b345e48, set result to 0xfffffffe\n7. For value 1 case: use error callback from 0x7b345e54, set result to 0xfffffffe\n8. Decode CFG pointer for callback validation via DecodeCFGPointer function\n9. Execute guarded callback through CallFunctionTableWithGuard with 3 null arguments\n10. Check iterator->callback_ptr (offset +0) - if null, perform final cleanup\n11. If callback_ptr non-null: iterate through two additional structure pointers (offsets +4, +8)\n12. For each pointer: invoke cleanup callbacks from pre-defined tables\n13. Mark guard as initialized in global flag at 0x7b345d28 = 1\n14. Set completion flag at iterator->completion_flag (offset +8) = 1\n15. Restore exception handling frame and return\n\nParameters:\npGuardObject [ECX]: Pointer to control flow guard iterator structure containing:\n  +0x00: void * callback_ptr - Primary callback function pointer (checked for null)\n  +0x04: void * cleanup_ptr1 - First cleanup callback pointer\n  +0x08: void * cleanup_ptr2 - Second cleanup callback pointer / completion flag\n\nReturns:\nvoid - No return value; modifies global state and executes callbacks\n\nSpecial Cases:\n- Initialization flag at 0x7b345d28 prevents re-entry\n- Default/error callbacks used from predefined table addresses\n- SEH frame handles exceptions during callback execution\n- Guard check and CFG decoding prevent invalid function pointers\n- Three-argument null parameters passed to guarded calls",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e499a7c57fcccf765915e8852ee75143",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e499a7c57fcccf765915e8852ee75143",
        "CFG": "df5c9bb335ac539ccbf1495fdc26de41",
        "PRO": "3d82c09eed6cf609350b6b86e0a83c72"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_47dc038193f5": {
      "addresses": {
        "LoD/PD2": "0x7B3345FF"
      },
      "rvas": {
        "LoD/PD2": "0x45FF"
      },
      "sizes": {
        "LoD/PD2": 146
      },
      "name": "InitializeOrCleanupException",
      "signature": "void InitializeOrCleanupException(uint exitFlag, undefined4 exceptionInfo, int cleanupMode)",
      "calling_convention": "__cdecl",
      "comment": "Initializes or cleans up C++ exception handling structures for CRT exit.\n\nAlgorithm:\n1. Set up exception handling by installing custom exception handler into FS:[0]\n2. If cleanupMode is 0 (initialization):\n   a. Call FUN_7b3346c7 to check initialization status\n   b. If successful, call FUN_7b334722 with exitFlag to register cleanup callback\n3. Store exception information pointers for scope-based exception handling\n4. Initialize exception context array with value 2 (two elements/scopes)\n5. Call operator<> to process and validate exception information structures\n6. If cleanupMode is not 0 (cleanup mode):\n   a. Restore previous exception list from FS:[0]\n   b. Return early without further processing\n7. Otherwise (initialization completed):\n   a. Call FUN_7b334696 to register final cleanup callback\n   b. Call swi(3) to invoke Windows API interrupt (possibly for final setup)\n\nParameters:\n- exitFlag: Flag/code passed to FUN_7b334722 during cleanup callback registration\n- exceptionInfo: Exception information structure pointer used for scope tracking\n- cleanupMode: Control flag - 0 means initialize, non-zero means cleanup mode\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- This function is part of C++ CRT exception handling initialization\n- Called by __exit and InitializeOrCleanupCRT during process startup/shutdown\n- Uses SEH (Structured Exception Handling) via FS:[0] register\n- Magic number 2 indicates dual-scope exception context\n- Magic address 0x7b345000 is XOR canary for stack corruption detection",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:47dc038193f5319b95be9171532acf2a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "47dc038193f5319b95be9171532acf2a",
        "CFG": "ed7a428f5334f0bccdf46bd11b3c0bb0",
        "PRO": "65bf92a91b053e53a6826cbc3a438e00"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_e8f2fbd7cc4b": {
      "addresses": {
        "LoD/PD2": "0x7B334696"
      },
      "rvas": {
        "LoD/PD2": "0x4696"
      },
      "sizes": {
        "LoD/PD2": 48
      },
      "name": "TerminateProcessWithCleanup",
      "signature": "void TerminateProcessWithCleanup(UINT exitCode)",
      "calling_convention": "__stdcall",
      "comment": "Terminates the current process with optional cleanup.\\n\\nAlgorithm:\\n1. Check if abnormal termination condition is met via FUN_7b334709()\\n2. If condition is true, get current process handle and call TerminateProcess()\\n3. Call cleanup handler FUN_7b334722() with exit code\\n4. Call ExitProcess() to terminate with the specified exit code\\n\\nParameters:\\nexitCode (UINT): The process exit code to return to the OS\\n\\nReturns:\\nThis function never returns - it always terminates the process via ExitProcess()\\n\\nSpecial Cases:\\n- If FUN_7b334709() returns false, TerminateProcess() is skipped but cleanup still occurs\\n- The cleanup function FUN_7b334722() is always called regardless of the condition\\n- ExitProcess() is the final termination call that never returns\\n\\nCalled by:\\nInitializeOrCleanupException - Exception handler for abnormal termination",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e8f2fbd7cc4bc606d67b32e3d63eee11",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e8f2fbd7cc4bc606d67b32e3d63eee11",
        "CFG": "aedec5403543a0560d8306b93234a61b",
        "PRO": "4cdbd1c15eb89b1b8c7012f818b0191c"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_9fc8a8238a68": {
      "addresses": {
        "LoD/PD2": "0x7B3346C7"
      },
      "rvas": {
        "LoD/PD2": "0x46C7"
      },
      "sizes": {
        "LoD/PD2": 66
      },
      "name": "ValidateModulePEHeaders",
      "signature": "bool ValidateModulePEHeaders(void)",
      "calling_convention": "__stdcall",
      "comment": "Validates that the current executable module has a valid PE header with expected structure.\n\nAlgorithm:\n1. Get handle to the current executable module via GetModuleHandleW(NULL)\n2. Validate module base address is non-NULL\n3. Verify MZ signature (0x5a4d) at offset +0x0 (DOS header magic)\n4. Read PE header offset from DOS header field at +0x3c\n5. Calculate PE header address (module base + offset from step 4)\n6. Verify PE signature (0x4550 \"PE\") at calculated address\n7. Verify machine type field (at offset +0x18 from PE header) equals 0x10b (i386)\n8. Verify number of data directories (at offset +0x74 from PE header) is greater than 0xe\n9. Check if Load Config Directory is present (offset +0xe8 from PE header)\n10. Return true (1) if all validations pass, false (0) otherwise\n\nReturns:\n  bool - TRUE if module has valid PE headers with Load Config directory, FALSE otherwise\n\nStructure Layout:\n  This function validates the PE format for Windows x86 executables:\n  Offset  Size  Field Name        Type     Description\n  0x0     2     Signature         WORD     MZ header signature (0x5a4d)\n  0x3c    4     e_lfanew          DWORD    File offset to PE header\n  PE Header at calculated offset:\n  0x0     4     Signature         DWORD    PE signature (0x4550 \"PE\")\n  0x18    2     Machine           WORD     Target machine (0x10b = i386)\n  0x74    4     DataDirCount      DWORD    Number of data directory entries\n  0xe8    4     LoadConfigAddr    DWORD    Load Config directory RVA",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9fc8a8238a68bf4ee6aedb45cff5a84d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9fc8a8238a68bf4ee6aedb45cff5a84d",
        "CFG": "d34aa10da8351dc30f8638a564d33bad",
        "PRO": "bbbe0a87db8b7cd57cbecd285744cd4b"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_a842f4844846": {
      "addresses": {
        "LoD/PD2": "0x7B334709"
      },
      "rvas": {
        "LoD/PD2": "0x4709"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "CheckAndGetProcessTerminationStatus",
      "signature": "char CheckAndGetProcessTerminationStatus(void)",
      "calling_convention": "__cdecl",
      "comment": "Checks process termination condition and returns termination status.\n\nAlgorithm:\n1. Call FUN_7b335a97 to check if a condition is met (returns 0 or 1)\n2. If condition result equals 1, return 0 (process should not terminate)\n3. If condition result is not 1, call FUN_7b335a72 to get status flags\n4. Negate AL (NEG AL) - converts 0 to 0, non-zero to 0x00\n5. Use SBB AL, AL to propagate sign/borrow (sets to 0xFF if borrow, 0x00 if no borrow)\n6. Increment AL (INC AL) to finalize the conversion to 0 or 1\n7. Return the computed termination status (0 = should not terminate, 1 = should terminate)\n\nParameters:\nNone\n\nReturns:\nchar - Termination status flag (0 = do not terminate, 1 = terminate process)\n\nSpecial Cases:\n- The NEG/SBB/INC sequence converts non-zero values to 1 and zero to 0\n- FUN_7b335a97 checks a critical process condition that overrides termination\n- If FUN_7b335a97 returns 1, termination is unconditionally skipped\n- FUN_7b335a72 extracts status flags from bit offset 8-31 of game state at Self+0x30+0x68",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a842f4844846eb02a043ebdc5a43e2aa",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a842f4844846eb02a043ebdc5a43e2aa",
        "CFG": "c28d843778d6313eca5e15ea77ffbb3e",
        "PRO": "73261997c9cadebdd1eabda2aaf74d05"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_STR_9fe208553bf3": {
      "addresses": {
        "LoD/PD2": "0x7B334722"
      },
      "rvas": {
        "LoD/PD2": "0x4722"
      },
      "sizes": {
        "LoD/PD2": 125
      },
      "name": "TerminateProcessViaCoreRuntime",
      "signature": "void TerminateProcessViaCoreRuntime(uint exitCode)",
      "calling_convention": "__cdecl",
      "comment": "Terminates the process via .NET runtime's CorExitProcess function.\n\nAlgorithm:\n1. Initialize exception handling frame and stack guard cookie via XOR\n2. Attempt to load mscoree.dll (CLR runtime library) with specific search flags\n3. If module loaded successfully, retrieve CorExitProcess function address\n4. If CorExitProcess found, perform guard check and invoke the function\n5. Free the module handle if it was successfully loaded\n6. Restore exception handling frame and return\n\nParameters:\nexitCode (uint): Exit code to pass to CorExitProcess function\n\nReturns:\nvoid - Function does not return normally (terminates process). If mscoree.dll cannot be loaded or CorExitProcess cannot be resolved, function returns gracefully without terminating.\n\nSpecial Cases:\n- Stack guard cookie (XOR with EBP) verifies stack integrity during execution\n- SEH frame protects against runtime errors during termination attempt\n- If mscoree.dll unavailable, function gracefully continues rather than failing",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:9fe208553bf39285e4d7233c64505337",
      "indexes": {
        "EXP": null,
        "STR": "9fe208553bf39285e4d7233c64505337",
        "API": null,
        "MNE": "70977278121cde5160e6ce8c56856d0d",
        "CFG": "6d11d394882ec5edb05b323d706064fc",
        "PRO": "529c39e328cc1289a2e8a61d1a2dcc50"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_4f35c0d25ee4": {
      "addresses": {
        "LoD/PD2": "0x7B337F19"
      },
      "rvas": {
        "LoD/PD2": "0x7F19"
      },
      "sizes": {
        "LoD/PD2": 15
      },
      "name": "StoreGlobalStateValue",
      "signature": "void StoreGlobalStateValue(uint value)",
      "calling_convention": "__cdecl",
      "comment": "Stores a value in a global state variable for later retrieval.\n\nAlgorithm:\n1. Extract the value parameter from the stack (ESP+4 after PUSH EBP)\n2. Load the value into EAX register\n3. Store EAX at the global address 0x7b345d24\n4. Return to caller\n\nParameters:\n- value (uint): The value to store in the global state variable\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- The global variable at 0x7b345d24 is accessed by ValidateControlFlowGuardIterator\n- This appears to be a simple setter function for global game state",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4f35c0d25ee4bb55f411e4f6edc16738",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4f35c0d25ee4bb55f411e4f6edc16738",
        "CFG": null,
        "PRO": "dfa4b39c76f49ba55875e6d770815b2f"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_47dfd1c23f58": {
      "addresses": {
        "LoD/PD2": "0x7B3347C2"
      },
      "rvas": {
        "LoD/PD2": "0x47C2"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "__exit",
      "signature": "void __exit(int _Code)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __exit\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:47dfd1c23f58f1be331a84c804541d54",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "47dfd1c23f58f1be331a84c804541d54",
        "CFG": null,
        "PRO": "a977aab091f96389633134c65ea4b86e"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_3a2b30f22446": {
      "addresses": {
        "LoD/PD2": "0x7B3389E8"
      },
      "rvas": {
        "LoD/PD2": "0x89E8"
      },
      "sizes": {
        "LoD/PD2": 7
      },
      "name": "GetControlFlowGuardState",
      "signature": "uint GetControlFlowGuardState(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the current control flow guard state from a global variable.\n\nAlgorithm:\n1. Load the control flow guard state value from global memory address 0x7b345d20\n2. Return the loaded value in EAX\n\nParameters:\n(none)\n\nReturns:\nEAX - Control flow guard state value (typically used for iterator validation)\n\nSpecial Cases:\n- This is a thin accessor function that simply wraps global state access\n- The global variable at 0x7b345d20 is also accessed by ValidateControlFlowGuardIterator\n- No error conditions or validation is performed\n\nStructure Layout:\nN/A - Function operates on a simple scalar value, not a structure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3a2b30f22446d682d5d541e4afa4dbe8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3a2b30f22446d682d5d541e4afa4dbe8",
        "CFG": null,
        "PRO": "ce15bdfbefe9caa173baf360bfad9829"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_STR_ef8d6b30e6f2": {
      "addresses": {
        "LoD/PD2": "0x7B3347DF"
      },
      "rvas": {
        "LoD/PD2": "0x47DF"
      },
      "sizes": {
        "LoD/PD2": 317
      },
      "name": "InitializeCommandLineArguments",
      "signature": "int InitializeCommandLineArguments(int initMode)",
      "calling_convention": "__cdecl",
      "comment": "Initializes command-line arguments by parsing the command line and setting up global argv array.\n\nAlgorithm:\n1. Validate initMode parameter (0, 1, or 2 are valid)\n2. If initMode is 1 or 2:\n   a. Initialize multibyte character support via ___acrt_initialize_multibyte()\n   b. Retrieve module path using GetModuleFileNameA() into 264-byte buffer at 0x7b345d30\n   c. Store module path to global _DAT_7b345fcc\n   d. Check global DAT_7b345fdc; if null or empty, use module path as base path\n   e. Call FUN_7b33491c to scan command line and calculate required buffer sizes\n   f. Allocate buffer via ___acrt_allocate_buffer_for_argv() for parsed arguments\n   g. If allocation fails, return 0xC (error code for allocation failure)\n   h. Call FUN_7b33491c again to parse command line into allocated buffer\n   i. If initMode == 1: store argv count (minus 1) and argv pointer to globals, return 0\n   j. If initMode == 2: call FUN_7b336713 to process arguments and return status\n3. If initMode is 0: return 0 (success)\n4. Otherwise: return 0x16 (invalid mode error) after calling FUN_7b335ce3\n\nParameters:\n  initMode (int): Initialization mode (0=no-op, 1=simple init, 2=full init with processing)\n\nReturns:\n  int: 0 for success, 0xC for allocation failure, 0x16 for invalid mode\n\nSpecial Cases:\n  - Magic value 0x104: Size of module path buffer (260 bytes + null terminator)\n  - Magic value 0xC: Allocation failure error code\n  - Magic value 0x16: Invalid mode error code\n  - DAT_7b345fdc: Optional override path; if null/empty, uses module path\n  - _DAT_7b345fcc: Global storage for module path\n  - _DAT_7b345fd0: Global storage for argc (argument count)\n  - DAT_7b345fd4: Global storage for argv pointer\n\nStructure Layout - Command Line Parsing Results:\n  Offset  Size  Field Name          Type      Description\n  0x0     0x4   argCount            uint      Number of arguments parsed\n  0x4     0x4   totalArgvSize       uint      Total bytes needed for argv array",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:ef8d6b30e6f2854d83646b8368320355",
      "indexes": {
        "EXP": null,
        "STR": "ef8d6b30e6f2854d83646b8368320355",
        "API": null,
        "MNE": "7d31c938be65b27fe6c15a18327d4634",
        "CFG": "4acacf934f451dc31717d6ff6f0726b4",
        "PRO": "cc01c53f5c09afd44738f0ef38fd06fe"
      },
      "basic_block_counts": {
        "LoD/PD2": 22
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_e58f31071319": {
      "addresses": {
        "LoD/PD2": "0x7B33491C"
      },
      "rvas": {
        "LoD/PD2": "0x491C"
      },
      "sizes": {
        "LoD/PD2": 372
      },
      "name": "ParseCommandLineArguments",
      "signature": "void ParseCommandLineArguments(byte * pInputString, byte * * ppArgvArray, byte * pOutputBuffer, int * pArgumentCount, int * pOutputLength)",
      "calling_convention": "__cdecl",
      "comment": "Parses a command-line string into individual arguments with quote and escape handling.\n\nAlgorithm:\n1. Initialize argument counter to 1 and output length to 0\n2. Store first argument pointer in argv array if provided\n3. First pass: Process initial argument from input string\n   - Toggle quote state on double-quote character (0x22)\n   - Count and copy characters to output buffer\n   - Call FUN_7b337169 to check for escape sequences\n   - Exit when null terminator or unquoted space/tab (0x20/0x09) reached\n4. Null-terminate first argument in output buffer\n5. Second pass: Process remaining arguments\n   - Skip leading whitespace (space and tab characters)\n   - Store argument pointer in argv array if provided\n   - Increment argument counter\n   - Handle backslash escape sequences with proper semantics:\n     * Count consecutive backslashes before quote\n     * Even count: all backslashes are literal\n     * Odd count: last backslash escapes the quote\n   - Toggle quote state with proper escape handling\n   - Process each character, calling FUN_7b337169 for escapes\n   - Continue until null terminator or unquoted whitespace\n6. Null-terminate current argument in output buffer\n7. Store null pointer in argv array to mark end of arguments\n8. Increment final argument count and return\n\nParameters:\n  pInputString: Pointer to input command-line string to parse\n  ppArgvArray: Pointer to pointer array for storing argument pointers (NULL allowed)\n  pOutputBuffer: Pointer to output buffer for parsed argument strings (NULL allowed)\n  pArgumentCount: Pointer to integer, initially 1, incremented for each argument\n  pOutputLength: Pointer to integer tracking total output length\n\nReturns:\n  void - Results stored via output pointers\n\nSpecial Cases:\n  - Allows dry-run with NULL pOutputBuffer and ppArgvArray\n  - Quote handling: 0x22 toggles quote state unless escaped by backslash\n  - Consecutive backslashes: count determines if quote is escaped\n  - Whitespace inside quotes does not separate arguments\n  - FUN_7b337169 determines special character escape sequences",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e58f310713195eca978b84d567d23969",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e58f310713195eca978b84d567d23969",
        "CFG": "6bef1ca8245fb69c58566b733b1309aa",
        "PRO": "17acb71da538d7ded050db51c1c23c45"
      },
      "basic_block_counts": {
        "LoD/PD2": 60
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_085c78326a5d": {
      "addresses": {
        "LoD/PD2": "0x7B334A90"
      },
      "rvas": {
        "LoD/PD2": "0x4A90"
      },
      "sizes": {
        "LoD/PD2": 79
      },
      "name": "___acrt_allocate_buffer_for_argv",
      "signature": "LPVOID ___acrt_allocate_buffer_for_argv(uint param_1, uint param_2, uint param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_allocate_buffer_for_argv\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:085c78326a5d3897bbf37b6337a72201",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "085c78326a5d3897bbf37b6337a72201",
        "CFG": "32fe905309f864f6eb5bcf0764c3f9c9",
        "PRO": "a9ce57ff4d0315f0bda7fdec43637157"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_f97d159a7b72": {
      "addresses": {
        "LoD/PD2": "0x7B338F95"
      },
      "rvas": {
        "LoD/PD2": "0x8F95"
      },
      "sizes": {
        "LoD/PD2": 11
      },
      "name": "InitializeCommandLineArgumentsWrapper",
      "signature": "void InitializeCommandLineArgumentsWrapper(int initMode)",
      "calling_convention": "__cdecl",
      "comment": "Hot-patchable wrapper for command-line argument initialization.\n\nThis function serves as a detachable entry point for the CRT's command-line\nargument initialization routine. The MOV EDI,EDI prologue at the function entry\nis a placeholder that allows the function to be patched for debugging or\ninstrumentation purposes without affecting the actual implementation.\n\nAlgorithm:\n1. Establish stack frame (PUSH EBP, MOV EBP,ESP)\n2. Jump directly to InitializeCommandLineArguments implementation\n3. All actual processing delegated to the implementation function\n\nParameters:\n- initMode (int): Initialization mode flag passed to the implementation function\n\nReturns:\n- void: No return value; initialization is performed as a side effect\n\nSpecial Cases:\n- This is a wrapper function created by the compiler for hot-patching support\n- The MOV EDI,EDI instruction at entry point is a 2-byte NOP placeholder\n- Stack frame setup and immediate teardown is part of the wrapper pattern\n- The actual implementation is at InitializeCommandLineArguments_impl",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f97d159a7b72e6f60dfaec944aff89be",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f97d159a7b72e6f60dfaec944aff89be",
        "CFG": null,
        "PRO": "dbf1585d8d4b44de5f2bbd195070d021"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_b7b9a68970bc": {
      "addresses": {
        "LoD/PD2": "0x7B334AEA"
      },
      "rvas": {
        "LoD/PD2": "0x4AEA"
      },
      "sizes": {
        "LoD/PD2": 90
      },
      "name": "InitializeApplicationEnvironment",
      "signature": "int InitializeApplicationEnvironment(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes the application environment and parses configuration.\n\nThis function sets up the application's runtime environment by initializing\nmultibyte character support, retrieving the environment path string, and\nprocessing it to create an internal configuration structure. It performs\ninitialization checks to prevent redundant setup and cleans up temporary\nresources before returning.\n\nAlgorithm:\n1. Check if already initialized (DAT_7b345e38) - return success if yes\n2. Call ___acrt_initialize_multibyte() to initialize character support\n3. Call FUN_7b33738f() to retrieve environment/path string\n4. If retrieval fails, cleanup and return -1 (failure)\n5. Call FUN_7b334b44() to parse/process the environment string\n6. If processing fails, set result to -1; otherwise result to 0\n7. Store processed structure in global variables DAT_7b345e38 and DAT_7b345e44\n8. Call FUN_7b335e34() twice to cleanup temporary allocations\n9. Return 0 on success, -1 on failure\n\nParameters:\nNone - function takes no parameters\n\nReturns:\n0 (success) if initialization completed successfully\n-1 (failure) if environment string retrieval or processing failed\n\nSpecial Cases:\n- Early return if already initialized (DAT_7b345e38 != 0)\n- Cleanup is called twice: once with NULL, once with environment string\n- Magic value -1 (0xffffffff) indicates error condition",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b7b9a68970bc2b91b78fde1fc5d99582",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b7b9a68970bc2b91b78fde1fc5d99582",
        "CFG": "f7a480f5087b3f579d153b9201ef810a",
        "PRO": "39b1eab14ac8e686b04ab4923772e174"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_9a97d9360ced": {
      "addresses": {
        "LoD/PD2": "0x7B334B44"
      },
      "rvas": {
        "LoD/PD2": "0x4B44"
      },
      "sizes": {
        "LoD/PD2": 225
      },
      "name": "ParseEnvironmentVariableBlock",
      "signature": "int ParseEnvironmentVariableBlock(char * environmentBlock)",
      "calling_convention": "__cdecl",
      "comment": "Parses environment variable block into array of pointers\n\nConverts OS environment variable block (null-terminated strings with '='\ndelimiters) into an array of pointers to individual variable strings.\nCalled during application initialization from InitializeApplicationEnvironment.\n\nAlgorithm:\n1. Count environment variables (non-'=' delimited entries)\n2. Allocate array of pointers (count + 1 for null terminator)\n3. Parse environment block and allocate individual string buffers\n4. Copy each non-'=' entry to allocated buffer and store pointer\n5. Return array pointer or null on allocation failure\n\nParameters:\n  environmentBlock: Pointer to null-terminated environment variable block\n                   Format: \"VAR1=value1\\0VAR2=value2\\0\\0\"\n\nReturns:\n  Pointer to array of char* pointers to environment strings\n  Returns NULL if memory allocation fails\n\nSpecial Cases:\n  - Handles allocation failures with error handler (FUN_7b335e34)\n  - Skips '=' delimited entries (key=value pairs)\n  - Terminates array with NULL pointer\n  - Calls __invoke_watson on string copy failures (never returns)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9a97d9360ced906724238f5a5aa04e11",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9a97d9360ced906724238f5a5aa04e11",
        "CFG": "1322b5300b775d25e65d93a737a0af9e",
        "PRO": "39ec426a54306519685eb3e23f930893"
      },
      "basic_block_counts": {
        "LoD/PD2": 24
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_c1af2f07be17": {
      "addresses": {
        "LoD/PD2": "0x7B334C26"
      },
      "rvas": {
        "LoD/PD2": "0x4C26"
      },
      "sizes": {
        "LoD/PD2": 47
      },
      "name": "free_environment<>",
      "signature": "undefined free_environment<>(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Multiple Matches With Same Base Name\n void __cdecl free_environment<char>(char * * const)\n void __cdecl free_environment<wchar_t>(wchar_t * * const)\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c1af2f07be1735e6baff61104a92ae2c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c1af2f07be1735e6baff61104a92ae2c",
        "CFG": "ee0d80f71fe25ba531bebb6d2d789b33",
        "PRO": "3716365673b07998d1fef4da67050806"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_26d45e2f7abd": {
      "addresses": {
        "LoD/PD2": "0x7B334C70"
      },
      "rvas": {
        "LoD/PD2": "0x4C70"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "uninitialize_environment_internal<>",
      "signature": "undefined uninitialize_environment_internal<>(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Multiple Matches With Same Base Name\n void __cdecl uninitialize_environment_internal<char>(char * * &)\n void __cdecl uninitialize_environment_internal<wchar_t>(wchar_t * * &)\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:26d45e2f7abdeb4dbe66acb4796522e1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "26d45e2f7abdeb4dbe66acb4796522e1",
        "CFG": "f09da8ab2298e4bafedfaee404f68269",
        "PRO": "d42972a804f22185f3b3d575d8c07931"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_d881e582ff5d": {
      "addresses": {
        "LoD/PD2": "0x7B334C8B"
      },
      "rvas": {
        "LoD/PD2": "0x4C8B"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "CleanupGameEnvironment",
      "signature": "void CleanupGameEnvironment(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleans up and releases game environment resources.\n\nAlgorithm:\n1. Initialize exception handling frame\n2. Uninitialize first environment instance (DAT_7b345e38)\n3. Uninitialize second environment instance (DAT_7b345e3c)\n4. Free first environment resources (DAT_7b345e44)\n5. Free second environment resources (DAT_7b345e40)\n6. Execute exception handling epilogue\n7. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Exception handling via __stdcall frame ensures cleanup occurs even during abnormal exits\n- Two environment instances are managed: one for primary operations, one for secondary state\n- Resources are released in reverse initialization order (LIFO)\n- This function is typically called during application shutdown or cleanup phases",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d881e582ff5d7ccdd2b1a7a549641fe2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d881e582ff5d7ccdd2b1a7a549641fe2",
        "CFG": null,
        "PRO": "a8c0aca4b4f7b010dd547b76943f610b"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_87f58a6e2960": {
      "addresses": {
        "LoD/PD2": "0x7B334CE1"
      },
      "rvas": {
        "LoD/PD2": "0x4CE1"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "operator()<class_<lambda_69a2805e680e0e292e8ba93315fe43a8>,class_<lambda_f03950bc5685219e0bcd2087efbe011e>&,class_<lambda_03fcd07e894ec930e3f35da366ca99d6>_>",
      "signature": "int operator()<class_<lambda_69a2805e680e0e292e8ba93315fe43a8>,class_<lambda_f03950bc5685219e0bcd2087efbe011e>&,class_<lambda_03fcd07e894ec930e3f35da366ca99d6>_>(__crt_seh_guarded_call<int> * this, <lambda_69a2805e680e0e292e8ba93315fe43a8> * param_1, <lambda_f03950bc5685219e0bcd2087efbe011e> * param_2, <lambda_03fcd07e894ec930e3f35da366ca99d6> * param_3)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: int __thiscall __crt_seh_guarded_call<int>::operator()<class <lambda_69a2805e680e0e292e8ba93315fe43a8>,class <lambda_f03950bc5685219e0bcd2087efbe011e> &,class <lambda_03fcd07e894ec930e3f35da366ca99d6> >(class <lambda_69a2805e680e0e292e8ba93315fe43a8> &&,class <lambda_f03950bc5685219e0bcd2087efbe011e> &,class <lambda_03fcd07e894ec930e3f35da366ca99d6> &&)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:87f58a6e2960bacc7c59439788d4ee3f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "87f58a6e2960bacc7c59439788d4ee3f",
        "CFG": null,
        "PRO": "d3e02e74f6b94da2f634f8355b3c27f8"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_4f545f8af137": {
      "addresses": {
        "LoD/PD2": "0x7B334D3C"
      },
      "rvas": {
        "LoD/PD2": "0x4D3C"
      },
      "sizes": {
        "LoD/PD2": 218
      },
      "name": "operator()",
      "signature": "int operator()(<lambda_f03950bc5685219e0bcd2087efbe011e> * this)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: int __thiscall <lambda_f03950bc5685219e0bcd2087efbe011e>::operator()(void)const \n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4f545f8af137ab50af2d57c0bcb3c126",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4f545f8af137ab50af2d57c0bcb3c126",
        "CFG": "cbc0ae4dbf8eeb860aa5fcab6be0308e",
        "PRO": "bfd72bb941d576650b300abb356bb4bf"
      },
      "basic_block_counts": {
        "LoD/PD2": 16
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_5572041f2c2f": {
      "addresses": {
        "LoD/PD2": "0x7B334E16"
      },
      "rvas": {
        "LoD/PD2": "0x4E16"
      },
      "sizes": {
        "LoD/PD2": 57
      },
      "name": "PerformUCRTCleanupWithGuard",
      "signature": "void PerformUCRTCleanupWithGuard(void)",
      "calling_convention": "__stdcall",
      "comment": "Performs UCRT-specific cleanup with control flow guard protection during CRT initialization/cleanup.\n\nAlgorithm:\n1. Set up SEH exception handling frame via __EH_prolog3 for error recovery\n2. Initialize stack frame with exception state tracking in local_8 = 0\n3. Push return address offset (0x10) onto stack for exception handler\n4. Set exception handler address via MOV EAX, 0x7b33d06c and call EH setup at 0x7b33ce78\n5. Store return address pointer in local_1c pointing to stack0x00000004\n6. Initialize cleanup flags: local_18 = 2 and local_20 = 2\n7. Clear exception state via AND [EBP-0x4], 0x0\n8. Construct three lambda callback objects in registers:\n   - Lambda 1: Initialize flag check at EBP-0x1c\n   - Lambda 2: Return address tracking at EBP-0x18\n   - Lambda 3: Cleanup operation at EBP-0x14\n9. Push three callback parameters: EBP-0x14, EBP-0x18, EBP-0x1c (all offsets are negative, measured from EBP)\n10. Invoke operator<> with three lambda arguments via CALL 0x7b334ce1\n11. Call __EH_epilog3 at 0x7b33ce64 to unwind SEH frame and restore context\n12. Return to caller via RET\n\nParameters:\nNone - void function, operates on stack locals and SEH state\n\nReturns:\nvoid - No return value; performs side effects through guarded callback invocation\n\nSpecial Cases:\n- SEH frame handles exceptions during cleanup callback execution\n- Three lambda functions coordinate cleanup sequence via callback mechanism\n- Magic numbers: 0x10 (exception frame offset), 0x2 (flag initialization values)\n- __stdcall convention - callee pops return address, no parameters\n- This function is called during both UCRT initialization and control flow guard validation paths\n- Deferred exception handling enables safe cleanup even if callbacks fail\n\nStructure Layout:\nUCRT Cleanup Frame (9 bytes):\nOffset  Size  Field Name             Type      Description\n0x00    4     ehState                dword     Exception handling state (0 = ready)\n0x04    1     guardedCallObject[9]   byte[9]   __crt_seh_guarded_call<int> structure\n0x0D    1     guardedCallObject[1]   byte      Guard call structure continuation\n0x10    4     cleanupFlag            dword     Cleanup operation flag (value 2)\n0x14    4     returnAddressPtr       pointer   Pointer to return address on stack\n0x18    4     initFlag               dword     Initialization flag (value 2)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5572041f2c2f097f78c868a32fe931c5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5572041f2c2f097f78c868a32fe931c5",
        "CFG": null,
        "PRO": "a158cc2992ab110e5dc1aaf586b50705"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_f4dc1f9fea33": {
      "addresses": {
        "LoD/PD2": "0x7B334E54"
      },
      "rvas": {
        "LoD/PD2": "0x4E54"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "__initialize_onexit_table",
      "signature": "undefined4 __initialize_onexit_table(int * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __initialize_onexit_table\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f4dc1f9fea33b3ce87b75112461b249c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f4dc1f9fea33b3ce87b75112461b249c",
        "CFG": "6f3c48c8a30820a9a8a6c4f4ad80c87c",
        "PRO": "2b6713d06753c15a83125ec403586cc2"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_bab8af5768f2": {
      "addresses": {
        "LoD/PD2": "0x7B334EE6"
      },
      "rvas": {
        "LoD/PD2": "0x4EE6"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "uninitialize_allocated_memory",
      "signature": "undefined1 uninitialize_allocated_memory(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _uninitialize_allocated_memory\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bab8af5768f2617fdbac83cd8d96cb3b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bab8af5768f2617fdbac83cd8d96cb3b",
        "CFG": null,
        "PRO": "b882005b45fa4ee6b00fb9273a6b2e3b"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_41e061a55daa": {
      "addresses": {
        "LoD/PD2": "0x7B334F4D"
      },
      "rvas": {
        "LoD/PD2": "0x4F4D"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "RotateXorTransform",
      "signature": "uint RotateXorTransform(uint inputValue)",
      "calling_convention": "__cdecl",
      "comment": "Applies rotation-based XOR cipher transformation to input value.\n\nAlgorithm:\n1. Load cipher key from global constant DAT_7b345000\n2. Extract lower 5 bits of key (& 0x1f) as key rotation offset\n3. Calculate rotate amount as (0x20 - key_offset) to determine right rotation count\n4. Perform right rotate operation on input value by calculated amount\n5. XOR rotated result with cipher key constant\n6. Return transformed value in EAX\n\nParameters:\n  inputValue (uint): 32-bit value to be transformed by the cipher\n\nReturns:\n  uint: Rotated and XOR-encrypted result\n\nImplementation Details:\n  - Uses 32-bit rotate right (ROR) instruction with CL register\n  - Cipher key stored at DAT_7b345000 provides both rotation amount and XOR mask\n  - Key format: lower 5 bits determine rotation offset (0-31 bits)\n  - Rotation direction: right rotation to mask/unmask data bits\n  - Operation is reversible: applying same transform twice restores original value\n\nSpecial Cases:\n  - If key lower bits = 0, rotate amount = 0x20 (full 32-bit rotation = identity)\n  - If key lower bits = 0x1f, rotate amount = 1 (minimal rotation)\n  - XOR with same key twice reverses the transformation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:41e061a55daafd6f7c4823f6701de408",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "41e061a55daafd6f7c4823f6701de408",
        "CFG": null,
        "PRO": "40a2e24a2ec6396af8469bfb232e6239"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_3206315f335d": {
      "addresses": {
        "LoD/PD2": "0x7B334F6C"
      },
      "rvas": {
        "LoD/PD2": "0x4F6C"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "operator()",
      "signature": "void operator()(<lambda_af42a3ee9806e9a7305d451646e05244> * this, __crt_multibyte_data * * param_1)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: void __thiscall <lambda_af42a3ee9806e9a7305d451646e05244>::operator()(struct __crt_multibyte_data * &)const \n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3206315f335ddcb42b1f140a67d90aef",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3206315f335ddcb42b1f140a67d90aef",
        "CFG": "42bdec2f11c73aa6056b6c694ab2bc19",
        "PRO": "db6b322512e82fa2dff77bf9fa7784ed"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_301bd5440f60": {
      "addresses": {
        "LoD/PD2": "0x7B334F9A"
      },
      "rvas": {
        "LoD/PD2": "0x4F9A"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "___acrt_initialize",
      "signature": "undefined ___acrt_initialize(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_initialize\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:301bd5440f60703ca7a24a8fb30f1e56",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "301bd5440f60703ca7a24a8fb30f1e56",
        "CFG": null,
        "PRO": "ff6ae24f594dff8cfc31bacfd137dca8"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_2f8fb49d6e3a": {
      "addresses": {
        "LoD/PD2": "0x7B334FBF"
      },
      "rvas": {
        "LoD/PD2": "0x4FBF"
      },
      "sizes": {
        "LoD/PD2": 48
      },
      "name": "___acrt_uninitialize",
      "signature": "undefined1 ___acrt_uninitialize(char param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_uninitialize\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2f8fb49d6e3a6e73cf5cbd24f73c1d88",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2f8fb49d6e3a6e73cf5cbd24f73c1d88",
        "CFG": "2555e203409cbc2d4a46fa3a51b3c448",
        "PRO": "c3ae7d0a3897de213add353986c557a6"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_134a136c35da": {
      "addresses": {
        "LoD/PD2": "0x7B334FEF"
      },
      "rvas": {
        "LoD/PD2": "0x4FEF"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "___acrt_uninitialize_critical",
      "signature": "undefined4 ___acrt_uninitialize_critical(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_uninitialize_critical\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:134a136c35da3c89f34fcaa3501c784e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "134a136c35da3c89f34fcaa3501c784e",
        "CFG": null,
        "PRO": "ce46c9d87722ccc13a17ae94593e6068"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_28d00bb6a01c": {
      "addresses": {
        "LoD/PD2": "0x7B335001"
      },
      "rvas": {
        "LoD/PD2": "0x5001"
      },
      "sizes": {
        "LoD/PD2": 52
      },
      "name": "terminate",
      "signature": "undefined terminate(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _terminate\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:28d00bb6a01cf52af280033a78fdd434",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "28d00bb6a01cf52af280033a78fdd434",
        "CFG": "8bbfe2737ef55f3a9a35ae1b43be54c6",
        "PRO": "07e6a14aebcd21dd55f38aa8e4e531f0"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_b7f3517230d0": {
      "addresses": {
        "LoD/PD2": "0x7B33503D"
      },
      "rvas": {
        "LoD/PD2": "0x503D"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "DeallocateHeapMemory",
      "signature": "void DeallocateHeapMemory(LPVOID memoryPointer)",
      "calling_convention": "__cdecl",
      "comment": "Deallocates heap memory block via wrapper to internal heap manager.\n\nAlgorithm:\n1. Set local reserved stack space to 0 for parameter passing\n2. Load reserved value into EAX\n3. Call internal heap deallocation routine (FUN_7b335e34)\n4. Clean up stack and return\n\nParameters:\n- memoryPointer (LPVOID): Pointer to heap memory block to deallocate. Can be NULL.\n\nReturns:\n- void: No return value. Any errors from heap deallocation are handled internally.\n\nSpecial Cases:\n- NULL pointer handling: If memoryPointer is NULL, the operation is safely skipped\n- Error handling: Failures in HeapFree call result in errno being set via __acrt_errno_from_os_error\n- Used by: VCRT exception handling and thread-local storage cleanup\n\nContext:\nThis is a VCRT internal function that serves as a deallocator for heap memory\nallocated during exception handling and thread management. The local reserved\nvariable is used to pass an implicit parameter to FUN_7b335e34.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b7f3517230d0ec4d7a74053fb7875b36",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b7f3517230d0ec4d7a74053fb7875b36",
        "CFG": null,
        "PRO": "5e559b70e3bfffce29afee20bf0cdee3"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_3e1e254ecf03": {
      "addresses": {
        "LoD/PD2": "0x7B335063"
      },
      "rvas": {
        "LoD/PD2": "0x5063"
      },
      "sizes": {
        "LoD/PD2": 90
      },
      "name": "CopyStringWithOffsetAndLength",
      "signature": "undefined4 CopyStringWithOffsetAndLength(char * pDestinationBuffer, int nBufferLength, char * pSourceString)",
      "calling_convention": "__cdecl",
      "comment": "Copies string from offset to destination buffer with bounds checking\n\nAlgorithm:\n1. Validate that pDestinationBuffer and nBufferLength are non-zero\n2. If pSourceString (offset) is zero, clear destination and return error 0x16\n3. Loop copying bytes from source to destination up to nBufferLength iterations\n4. Check for null terminator after each byte - if found, return success (0)\n5. If buffer filled without finding null terminator, add null terminator\n6. Set error code 0x22 (ENAMETOOLONG/buffer overflow) and call error handlers\n7. Call FUN_7b335dc4 to get thread local data and FUN_7b335ce3 for cleanup\n8. Return error code in EAX\n\nParameters:\n  pDestinationBuffer: Pointer to destination buffer for copied string\n  nBufferLength: Maximum number of bytes to copy (buffer capacity)\n  pSourceString: Pointer to source string to copy from\n\nReturns:\n  0 on success (null terminator found within buffer)\n  0x16 (EINVAL) if pSourceString is null or nBufferLength is zero\n  0x22 (ENAMETOOLONG) if buffer filled without finding null terminator\n\nSpecial Cases:\n  - Error codes 0x16 and 0x22 are C runtime errno values\n  - Null terminator is required in source string\n  - If pDestinationBuffer is null but nBufferLength is non-zero, crash occurs\n  - Loop accesses source[i] where offset is pSourceString (not array index)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3e1e254ecf03309396e24484f0d3e9f2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3e1e254ecf03309396e24484f0d3e9f2",
        "CFG": "6915877a0ed6cfe545ad9e144a0163e7",
        "PRO": "f2da543ab27086c22477efc07498f578"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_149a36a120ba": {
      "addresses": {
        "LoD/PD2": "0x7B3350BD"
      },
      "rvas": {
        "LoD/PD2": "0x50BD"
      },
      "sizes": {
        "LoD/PD2": 67
      },
      "name": "_abort",
      "signature": "void _abort(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _abort\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:149a36a120ba0433bb5c3b2eec7f1a8d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "149a36a120ba0433bb5c3b2eec7f1a8d",
        "CFG": "fd32fcbc1bb7eeb18567ac64ddfa5c84",
        "PRO": "215490b9ee6c7e587130a063619d0406"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_ecdcac90e329": {
      "addresses": {
        "LoD/PD2": "0x7B335110"
      },
      "rvas": {
        "LoD/PD2": "0x5110"
      },
      "sizes": {
        "LoD/PD2": 93
      },
      "name": "InitializeFileStreamState",
      "signature": "FileStreamState * InitializeFileStreamState(void * this, FileStreamState * pFileState, undefined4 * pInitData)",
      "calling_convention": "__thiscall",
      "comment": "Initializes a FileStreamState structure with either provided initialization data or default values.\n\nAlgorithm:\n1. Clear all flag bytes in the structure (offsets 0x14, 0x8, 0x1c, 0x24)\n2. Clear the primary data field (offset 0x0)\n3. Check if pInitData parameter is null\n4. If pInitData is provided: copy data from pInitData[0] to field 0xc, copy pInitData[1] to field 0x10, set flag at 0x14 to 1\n5. If pInitData is null: check global flag at 0x7b346308\n6. If global flag is zero: load default data from global pointers and apply to structure\n7. Return pointer to initialized structure\n\nParameters:\n- pFileState (FileStreamState *): Implicit this pointer in ECX, points to structure to initialize\n- pInitData (undefined4 *): Optional initialization data array (two elements: value and metadata)\n\nReturns:\n- FileStreamState *: Returns pointer to initialized structure (pFileState)\n\nSpecial Cases:\n- If pInitData is NULL, the function falls back to global default values\n- The global flag at 0x7b346308 controls whether default initialization occurs\n- Multiple flag bytes are set to indicate initialization state",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ecdcac90e329a157a1abf708578a4217",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ecdcac90e329a157a1abf708578a4217",
        "CFG": "d4dea6f97df0c4a99e65dae9c9b89fdf",
        "PRO": "6f344308602636001cf69eddedccae44"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_576dacb1a3c6": {
      "addresses": {
        "LoD/PD2": "0x7B335170"
      },
      "rvas": {
        "LoD/PD2": "0x5170"
      },
      "sizes": {
        "LoD/PD2": 60
      },
      "name": "ApplyStreamProperties",
      "signature": "void ApplyStreamProperties(void * pStreamConfig)",
      "calling_convention": "__fastcall",
      "comment": "Apply configuration properties to a stream object.\n\nThis function processes stream properties from a configuration structure and applies them to an associated stream object. It handles conditional flag checking and selective property application based on control bytes.\n\nAlgorithm:\n1. Check control flag at config+0x14 for value 0x02\n2. If match, clear bit 1 in configuration flags at [config+0x0]+0x350\n3. Check first property enable flag at config+0x1c\n4. If enabled, read value from config+0x18 and apply to stream object+0x10\n5. Check second property enable flag at config+0x24\n6. If enabled, read value from config+0x20 and apply to stream object+0x14\n7. Return\n\nParameters:\n- pStreamConfig: Pointer to stream configuration structure containing control flags and property values at specific offsets\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- Mode flag bit 1 is cleared only when control flag equals 0x02\n- Properties are conditionally applied based on enable flags at offsets 0x1c and 0x24\n- Uses __fastcall convention: parameter passed in ECX register",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:576dacb1a3c65987f59c7822dad4d341",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "576dacb1a3c65987f59c7822dad4d341",
        "CFG": "32e15db7c5b22f7bb7a58182cedf6021",
        "PRO": "dc1ce46d34a9b413d8aec9c253abd3f8"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_b36978890275": {
      "addresses": {
        "LoD/PD2": "0x7B3351B0"
      },
      "rvas": {
        "LoD/PD2": "0x51B0"
      },
      "sizes": {
        "LoD/PD2": 77
      },
      "name": "InitializeThreadLocalData",
      "signature": "void * InitializeThreadLocalData(void * * ppThreadData)",
      "calling_convention": "__fastcall",
      "comment": "Initializes thread-local data structure for CRT operations.\n\nAlgorithm:\n1. Save the current Windows error state via GetLastError()\n2. Check if the thread data is already initialized (byte flag at offset +2)\n3. If first initialization: zero the value at offset +1 and set the flag to 1\n4. If already initialized: use the existing value at offset +1\n5. Call FUN_7b3358e9() helper with saved error state and init flag\n6. Store returned thread data pointer at offset 0 of the input structure\n7. Restore the Windows error state via SetLastError()\n8. Return the initialized thread data pointer\n\nParameters:\n- ppThreadData: Pointer to __acrt_ptd pointer structure (passed in ECX via __fastcall)\n  Contains: [0] pointer to thread data, [1] initialization value, [2] initialized flag\n\nReturns:\n- void *: Pointer to the initialized thread-local data structure, or NULL on failure\n\nSpecial Cases:\n- Preserves Windows error state across initialization\n- Supports deferred initialization (multiple calls reuse existing data)\n- Structure offsets: +0 = data pointer, +1 = init value, +2 = init flag",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b369788902753172319dc36d2bb5b99e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b369788902753172319dc36d2bb5b99e",
        "CFG": "f3972dcdfa4d57713101074a08462fae",
        "PRO": "a56767cb34208fb0974c9b587f3b085d"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_a764d17f20af": {
      "addresses": {
        "LoD/PD2": "0x7B335200"
      },
      "rvas": {
        "LoD/PD2": "0x5200"
      },
      "sizes": {
        "LoD/PD2": 91
      },
      "name": "GetThreadContextData",
      "signature": "int * GetThreadContextData(int * * pContextRef)",
      "calling_convention": "__fastcall",
      "comment": "Retrieves or initializes per-thread ACRT context data structure.\\n\\nThis function ensures a thread context is available by either returning an existing context\\nor allocating and initializing a new one. It manages error states and maintains context\\npointers through thread-local storage.\\n\\nAlgorithm:\\n1. Check if context already initialized at *pContextRef (offset +0x0)\\n2. If initialized, return existing context pointer\\n3. Otherwise, save current thread error state via GetLastError()\\n4. Check initialization flag at pContextRef[2] (offset +0x8)\\n5. If not initialized (byte == 0), initialize default values at pContextRef[1] and set flag to 1\\n6. If already initialized, use existing value from pContextRef[1]\\n7. Call FUN_7b3358e9 to allocate/retrieve thread-local per-thread data structure\\n8. Store returned thread data pointer at *pContextRef (offset +0x0)\\n9. Restore thread error state via SetLastError()\\n10. If allocation failed (returned NULL), call abort() to terminate\\n11. Return the thread context data pointer\\n\\nParameters:\\n- pContextRef: Pointer to thread context reference structure with fields at:\\n  Offset +0x0: Current context pointer (__acrt_ptd*)\\n  Offset +0x4: Initialization value (int)\\n  Offset +0x8: Initialization flag (byte, 0 = not init, 1 = initialized)\\n\\nReturns:\\n- int *: Pointer to the thread's ACRT per-thread data structure containing\\n  locale data at offset +0x4c and multibyte data at offset +0x48\\n\\nSpecial Cases:\\n- If context allocation fails, program terminates via abort()\\n- Thread error state (via GetLastError) is preserved during context operations\\n- Initialization flag prevents re-initialization once set\\n- Default initialization value is 0 when flag is not set",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a764d17f20af7e503dc1ad3285470708",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a764d17f20af7e503dc1ad3285470708",
        "CFG": "d8db9e15aaed1543314905874c94395f",
        "PRO": "ede6117d4be15346aaa26973a18d165c"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_c29e481f5f12": {
      "addresses": {
        "LoD/PD2": "0x7B335260"
      },
      "rvas": {
        "LoD/PD2": "0x5260"
      },
      "sizes": {
        "LoD/PD2": 91
      },
      "name": "InitializeEncodingState",
      "signature": "void InitializeEncodingState(int * pEncodingState)",
      "calling_convention": "__fastcall",
      "comment": "Initializes encoding state structure with thread context and locale data.\n\nAlgorithm:\n1. Retrieve thread context data pointer from parameter array\n2. Copy locale information from thread context offset 0x13 to pEncodingState[3]\n3. Copy multibyte data pointer from thread context offset 0x12 to pEncodingState[4]\n4. Call UpdateThreadLocaleData to initialize locale settings with pEncodingState+3 and code page\n5. Call update_locale_multibyte_data to initialize multibyte encoding with pEncodingState+4\n6. Check initialization flag at thread context offset 0xd4 (bit 1: 0x2)\n7. If flag not set, set flag in thread context and mark pEncodingState[5] as initialized (0x2)\n8. Return to caller\n\nParameters:\n- pEncodingState: Pointer to encoding state structure with layout:\n    [0] = Reserved/unused\n    [1] = Code page identifier for encoding\n    [3] = Locale info pointer (filled from context[0x13])\n    [4] = Multibyte data pointer (filled from context[0x12])\n    [5] = Initialization flag (set to 0x2 on completion)\n\nReturns: void\n\nSpecial Cases:\n- Thread context offset 0xd4 contains flags, bit 1 (0x2) indicates initialization state\n- Function safely checks flag before setting to avoid re-initialization\n- Initialization is idempotent: flag check prevents duplicate processing\n- pEncodingState must be valid pointer to writable structure with minimum 6 integer fields",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c29e481f5f126f2c87a4f965ee41afb6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c29e481f5f126f2c87a4f965ee41afb6",
        "CFG": "3d8ce31b4468dcfe3dac3889efcf7817",
        "PRO": "bf681854d334009ccbaca38ba67a885e"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_60eae47e900b": {
      "addresses": {
        "LoD/PD2": "0x7B3352C0"
      },
      "rvas": {
        "LoD/PD2": "0x52C0"
      },
      "sizes": {
        "LoD/PD2": 107
      },
      "name": "CompareMemoryOptimized",
      "signature": "int CompareMemoryOptimized(int baseOffset, uint * pBuffer2, uint maxBytes)",
      "calling_convention": "__cdecl",
      "comment": "Optimized memory comparison with aligned dword fast path.\\n\\nCompares two buffers with length limit, using byte-by-byte comparison for unaligned portions and optimized dword comparison for aligned sections. Uses null-terminator detection trick to improve performance.\\n\\nAlgorithm:\\n1. Validate input length (maxBytes > 0)\\n2. Calculate offset between buffers: baseOffset = buffer1 - buffer2\\n3. Check alignment of buffer2 pointer (& 3)\\n4. If unaligned, perform byte-by-byte comparison until aligned or mismatch\\n5. For aligned portions, use dword comparison with null-detection optimization\\n6. Resume byte-by-byte if dword comparison detects null terminator or mismatch\\n7. Return 0 if buffers are equal, nonzero if different\\n\\nParameters:\\n  baseOffset (int): Difference value between buffer1 and buffer2 addresses\\n  pBuffer2 (uint *): Pointer to second buffer (typically the reference/pattern)\\n  maxBytes (uint): Maximum number of bytes to compare (length limit)\\n\\nReturns:\\n  0: Buffers are equal within maxBytes limit\\n  non-zero: Buffers differ (negative if pBuffer2 byte is greater, positive otherwise)\\n\\nSpecial Cases:\\n  - If maxBytes is 0, returns 0 immediately without comparison\\n  - Uses null-terminator detection: (0xfefefeff XOR pattern) detects 0x00 bytes\\n  - Page boundary check: If aligned pointer + offset crosses 0xffc boundary, falls back to byte comparison\\n  - Supports comparison of unaligned memory regions",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:60eae47e900bd5cccfca9527af704a4d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "60eae47e900bd5cccfca9527af704a4d",
        "CFG": "64da69ef3217f47828e6e59b6b548a38",
        "PRO": "c53d1abcc8089d5fc2c8b3e9e4d2fd4e"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_363a4980e85d": {
      "addresses": {
        "LoD/PD2": "0x7B335330"
      },
      "rvas": {
        "LoD/PD2": "0x5330"
      },
      "sizes": {
        "LoD/PD2": 8
      },
      "name": "GetCarryFlagStatus",
      "signature": "uint GetCarryFlagStatus(void)",
      "calling_convention": "__stdcall",
      "comment": "Evaluates the carry flag and returns a status code.\n\nAlgorithm:\n1. Execute SBB EAX, EAX to set EAX based on the carry flag\n   - If CF=1: EAX becomes 0xFFFFFFFF (borrow occurred)\n   - If CF=0: EAX becomes 0x00000000 (no borrow)\n2. Perform bitwise OR with 0x1 to ensure result is always odd\n   - If CF=1: Result = 0xFFFFFFFF | 0x1 = 0xFFFFFFFF\n   - If CF=0: Result = 0x00000000 | 0x1 = 0x00000001\n3. Pop saved registers ESI and EBX from stack\n4. Return with callee cleanup\n\nReturns:\nuint - Status value based on carry flag state. Returns 0xFFFFFFFF if carry flag\nwas set, or 0x00000001 if carry flag was clear. This is a minimal utility\nfunction typically used for conditional return values or status checking\nbased on CPU arithmetic flags set by a preceding operation.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:363a4980e85db23a06cc2f6499b0be9a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "363a4980e85db23a06cc2f6499b0be9a",
        "CFG": null,
        "PRO": "03174e169631020a4401034eca31b3cc"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_8dd65e2de8e1": {
      "addresses": {
        "LoD/PD2": "0x7B335343"
      },
      "rvas": {
        "LoD/PD2": "0x5343"
      },
      "sizes": {
        "LoD/PD2": 58
      },
      "name": "_wcsncmp",
      "signature": "int _wcsncmp(wchar_t * _Str1, wchar_t * _Str2, size_t _MaxCount)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _wcsncmp\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8dd65e2de8e15bfddea67861f02c0369",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8dd65e2de8e15bfddea67861f02c0369",
        "CFG": "981689129fcdb6123df344857609aa1c",
        "PRO": "2dd6a66206e14e50a58e220088eaef18"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_90d00f9a9be3": {
      "addresses": {
        "LoD/PD2": "0x7B33537D"
      },
      "rvas": {
        "LoD/PD2": "0x537D"
      },
      "sizes": {
        "LoD/PD2": 70
      },
      "name": "operator()<class_<lambda_15ade71b0218206bbe3333a0c9b79046>,class_<lambda_da44e0f8b0f19ba52fefafb335991732>&,class_<lambda_207f2d024fc103971653565357d6cd41>_>",
      "signature": "void operator()<class_<lambda_15ade71b0218206bbe3333a0c9b79046>,class_<lambda_da44e0f8b0f19ba52fefafb335991732>&,class_<lambda_207f2d024fc103971653565357d6cd41>_>(__crt_seh_guarded_call<void> * this, <lambda_15ade71b0218206bbe3333a0c9b79046> * param_1, <lambda_da44e0f8b0f19ba52fefafb335991732> * param_2, <lambda_207f2d024fc103971653565357d6cd41> * param_3)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: void __thiscall __crt_seh_guarded_call<void>::operator()<class <lambda_15ade71b0218206bbe3333a0c9b79046>,class <lambda_da44e0f8b0f19ba52fefafb335991732> &,class <lambda_207f2d024fc103971653565357d6cd41> >(class <lambda_15ade71b0218206bbe3333a0c9b79046> &&,class <lambda_da44e0f8b0f19ba52fefafb335991732> &,class <lambda_207f2d024fc103971653565357d6cd41> &&)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:90d00f9a9be307cf02192609b64b05fb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "90d00f9a9be307cf02192609b64b05fb",
        "CFG": null,
        "PRO": "abfb8b9bf9495533a26506aaee1d3911"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_e1c55cb55aa8": {
      "addresses": {
        "LoD/PD2": "0x7B3353CF"
      },
      "rvas": {
        "LoD/PD2": "0x53CF"
      },
      "sizes": {
        "LoD/PD2": 95
      },
      "name": "operator()<class_<lambda_38edbb1296d33220d7e4dd0ed76b244a>,class_<lambda_5ce1d447e08cb34b2473517608e21441>&,class_<lambda_fb385d3da700c9147fc39e65dd577a8c>_>",
      "signature": "void operator()<class_<lambda_38edbb1296d33220d7e4dd0ed76b244a>,class_<lambda_5ce1d447e08cb34b2473517608e21441>&,class_<lambda_fb385d3da700c9147fc39e65dd577a8c>_>(__crt_seh_guarded_call<void> * this, <lambda_38edbb1296d33220d7e4dd0ed76b244a> * param_1, <lambda_5ce1d447e08cb34b2473517608e21441> * param_2, <lambda_fb385d3da700c9147fc39e65dd577a8c> * param_3)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: void __thiscall __crt_seh_guarded_call<void>::operator()<class <lambda_38edbb1296d33220d7e4dd0ed76b244a>,class <lambda_5ce1d447e08cb34b2473517608e21441> &,class <lambda_fb385d3da700c9147fc39e65dd577a8c> >(class <lambda_38edbb1296d33220d7e4dd0ed76b244a> &&,class <lambda_5ce1d447e08cb34b2473517608e21441> &,class <lambda_fb385d3da700c9147fc39e65dd577a8c> &&)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e1c55cb55aa8db0333c697605412e2da",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e1c55cb55aa8db0333c697605412e2da",
        "CFG": "0186fb67df5760129d902b254084ed17",
        "PRO": "49080df2751a0bbae1ee6aaa4ce55a97"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_018929dfed03": {
      "addresses": {
        "LoD/PD2": "0x7B33543A"
      },
      "rvas": {
        "LoD/PD2": "0x543A"
      },
      "sizes": {
        "LoD/PD2": 73
      },
      "name": "operator()<class_<lambda_6affb1475c98b40b75cdec977db92e3c>,class_<lambda_b8d4b9c228a6ecc3f80208dbb4b4a104>&,class_<lambda_608742c3c92a14382c1684fc64f96c88>_>",
      "signature": "void operator()<class_<lambda_6affb1475c98b40b75cdec977db92e3c>,class_<lambda_b8d4b9c228a6ecc3f80208dbb4b4a104>&,class_<lambda_608742c3c92a14382c1684fc64f96c88>_>(__crt_seh_guarded_call<void> * this, <lambda_6affb1475c98b40b75cdec977db92e3c> * param_1, <lambda_b8d4b9c228a6ecc3f80208dbb4b4a104> * param_2, <lambda_608742c3c92a14382c1684fc64f96c88> * param_3)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: void __thiscall __crt_seh_guarded_call<void>::operator()<class <lambda_6affb1475c98b40b75cdec977db92e3c>,class <lambda_b8d4b9c228a6ecc3f80208dbb4b4a104> &,class <lambda_608742c3c92a14382c1684fc64f96c88> >(class <lambda_6affb1475c98b40b75cdec977db92e3c> &&,class <lambda_b8d4b9c228a6ecc3f80208dbb4b4a104> &,class <lambda_608742c3c92a14382c1684fc64f96c88> &&)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:018929dfed036d141182e3999b8af35e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "018929dfed036d141182e3999b8af35e",
        "CFG": null,
        "PRO": "b9b7eb95233f327f6b0938a989653201"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_f1aacf68262f": {
      "addresses": {
        "LoD/PD2": "0x7B33548F"
      },
      "rvas": {
        "LoD/PD2": "0x548F"
      },
      "sizes": {
        "LoD/PD2": 78
      },
      "name": "operator()<class_<lambda_a7e850c220f1c8d1e6efeecdedd162c6>,class_<lambda_46720907175c18b6c9d2717bc0d2d362>&,class_<lambda_9048902d66e8d99359bc9897bbb930a8>_>",
      "signature": "void operator()<class_<lambda_a7e850c220f1c8d1e6efeecdedd162c6>,class_<lambda_46720907175c18b6c9d2717bc0d2d362>&,class_<lambda_9048902d66e8d99359bc9897bbb930a8>_>(__crt_seh_guarded_call<void> * this, <lambda_a7e850c220f1c8d1e6efeecdedd162c6> * param_1, <lambda_46720907175c18b6c9d2717bc0d2d362> * param_2, <lambda_9048902d66e8d99359bc9897bbb930a8> * param_3)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: void __thiscall __crt_seh_guarded_call<void>::operator()<class <lambda_a7e850c220f1c8d1e6efeecdedd162c6>,class <lambda_46720907175c18b6c9d2717bc0d2d362> &,class <lambda_9048902d66e8d99359bc9897bbb930a8> >(class <lambda_a7e850c220f1c8d1e6efeecdedd162c6> &&,class <lambda_46720907175c18b6c9d2717bc0d2d362> &,class <lambda_9048902d66e8d99359bc9897bbb930a8> &&)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f1aacf68262fc1f946b8a051c3854e39",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f1aacf68262fc1f946b8a051c3854e39",
        "CFG": null,
        "PRO": "884caae5190509afce3c79bd9330bde2"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_562784e2aa25": {
      "addresses": {
        "LoD/PD2": "0x7B3354E9"
      },
      "rvas": {
        "LoD/PD2": "0x54E9"
      },
      "sizes": {
        "LoD/PD2": 153
      },
      "name": "construct_ptd",
      "signature": "void construct_ptd(__acrt_ptd * param_1, __crt_locale_data * * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl construct_ptd(struct __acrt_ptd * const,struct __crt_locale_data * * const)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:562784e2aa25b159cff8ea785681ccea",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "562784e2aa25b159cff8ea785681ccea",
        "CFG": null,
        "PRO": "0172703fd4aed2588677c56666bcf022"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_0461e4ddc4a8": {
      "addresses": {
        "LoD/PD2": "0x7B335582"
      },
      "rvas": {
        "LoD/PD2": "0x5582"
      },
      "sizes": {
        "LoD/PD2": 33
      },
      "name": "destroy_fls",
      "signature": "void destroy_fls(void * param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n void __stdcall destroy_fls(void *)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0461e4ddc4a81a1faaeadac79911ab99",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0461e4ddc4a81a1faaeadac79911ab99",
        "CFG": "933c8d35515351e80b24e6fc18dff69c",
        "PRO": "4c564f0c90abea0c5f19c8ee66fca94d"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_96b8fe1446ce": {
      "addresses": {
        "LoD/PD2": "0x7B3355A3"
      },
      "rvas": {
        "LoD/PD2": "0x55A3"
      },
      "sizes": {
        "LoD/PD2": 205
      },
      "name": "destroy_ptd",
      "signature": "void destroy_ptd(__acrt_ptd * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl destroy_ptd(struct __acrt_ptd * const)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:96b8fe1446ce53329ed3372543aeb919",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "96b8fe1446ce53329ed3372543aeb919",
        "CFG": "ac02799931187a24621263cce6da4d79",
        "PRO": "79b21cdbe380271ef40f083eaa6ad132"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_43a145a45a08": {
      "addresses": {
        "LoD/PD2": "0x7B335670"
      },
      "rvas": {
        "LoD/PD2": "0x5670"
      },
      "sizes": {
        "LoD/PD2": 75
      },
      "name": "replace_current_thread_locale_nolock",
      "signature": "void replace_current_thread_locale_nolock(__acrt_ptd * param_1, __crt_locale_data * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl replace_current_thread_locale_nolock(struct __acrt_ptd * const,struct __crt_locale_data * const)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:43a145a45a08af0e15f2b8158b52f01e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "43a145a45a08af0e15f2b8158b52f01e",
        "CFG": "fbea47b737f9cded99d3ac1117fd0429",
        "PRO": "321914051a811ffee5a9662a2940c323"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_0bd6fdb5bbf6": {
      "addresses": {
        "LoD/PD2": "0x7B3356BB"
      },
      "rvas": {
        "LoD/PD2": "0x56BB"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "___acrt_freeptd",
      "signature": "undefined ___acrt_freeptd(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_freeptd\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0bd6fdb5bbf6a0dc064c573db9a07995",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0bd6fdb5bbf6a0dc064c573db9a07995",
        "CFG": "2bea3eb19dd06b49df098eed6ded289c",
        "PRO": "e9b4ceb4b14177e8aa2f8d02baa5a083"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_18b8c05cf28b": {
      "addresses": {
        "LoD/PD2": "0x7B3356E7"
      },
      "rvas": {
        "LoD/PD2": "0x56E7"
      },
      "sizes": {
        "LoD/PD2": 186
      },
      "name": "GetOrCreateThreadData",
      "signature": "__acrt_ptd * GetOrCreateThreadData(void)",
      "calling_convention": "__stdcall",
      "comment": "Gets or creates per-thread data structure for current thread. Manages thread-local storage initialization with proper error handling and cleanup.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:18b8c05cf28b1cda135708a22a318443",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "18b8c05cf28b1cda135708a22a318443",
        "CFG": "de3b2abd2d26c8e930d32a58f5915ffe",
        "PRO": "98dfb9cbc1028fb05fd5e9f284f5ad29"
      },
      "basic_block_counts": {
        "LoD/PD2": 19
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_6b10fdd13f5f": {
      "addresses": {
        "LoD/PD2": "0x7B3357A2"
      },
      "rvas": {
        "LoD/PD2": "0x57A2"
      },
      "sizes": {
        "LoD/PD2": 149
      },
      "name": "GetOrAllocateThreadData",
      "signature": "__acrt_ptd * GetOrAllocateThreadData(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves or allocates the per-thread CRT data (PTD) structure from FLS.\n\nAlgorithm:\n1. Read FLS index from global DAT_7b345090, check if initialized (== -1 / 0xffffffff)\n2. If FLS index is valid, call ___acrt_FlsGetValue_4 to retrieve existing PTD pointer\n3. If retrieved PTD exists and is not null, return it immediately (fast path)\n4. If PTD is null or FLS uninitialized, attempt allocation by setting FLS marker to -1\n5. On FLS set success, allocate 0x364 bytes (868 bytes) for __acrt_ptd via __calloc_base\n6. If allocation fails, reset FLS to null, cleanup via FUN_7b335e34, and abort process\n7. If allocation succeeds, store new PTD pointer to FLS via ___acrt_FlsSetValue_8\n8. If FLS store fails, reset FLS to null, cleanup via FUN_7b335e34(pThreadData), abort\n9. On successful FLS store, call construct_ptd to initialize PTD structure with locale\n10. Call FUN_7b335e34 with null parameter (cleanup/completion callback)\n11. Return allocated and initialized PTD pointer to caller\n\nParameters:\nNone (uses implicit thread context via FLS global index)\n\nReturns:\n__acrt_ptd * - Pointer to initialized per-thread CRT data structure; never null\n  (function aborts on any failure rather than returning error code)\n\nSpecial Cases:\n- Sentinel value -1 (0xffffffff) prevents concurrent re-entry during initialization\n- Any FLS operation failure triggers immediate abort via _abort() call\n- Structure size 0x364 (868 bytes) includes all per-thread CRT state\n- Locale data initialized from DAT_7b3462ec (__crt_locale_data pointer table)\n- FUN_7b335e34 appears to be cleanup/notification callback for allocation events\n- Called only from ___acrt_initialize_multibyte during CRT startup\n- Part of Microsoft Visual C++ CRT (ucrtbase.dll or msvcrXXX.dll implementation)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6b10fdd13f5f7ee0973b90d8d8b2b1a0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6b10fdd13f5f7ee0973b90d8d8b2b1a0",
        "CFG": "99acbd9ba054b4b87602cdd9a1dd0e2a",
        "PRO": "25896cddb6ff42aa36c897ca3be143a1"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_6202de4645be": {
      "addresses": {
        "LoD/PD2": "0x7B335838"
      },
      "rvas": {
        "LoD/PD2": "0x5838"
      },
      "sizes": {
        "LoD/PD2": 177
      },
      "name": "GetOrCreatePerThreadData",
      "signature": "__acrt_ptd * GetOrCreatePerThreadData(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieve or create per-thread C runtime data for current thread.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6202de4645be18693665b1972a057c15",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6202de4645be18693665b1972a057c15",
        "CFG": "7f72cddf6a4ca37cae276ff8e4e5b285",
        "PRO": "b8c20d535c83efc66707c550e4c2df25"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_3973079e5826": {
      "addresses": {
        "LoD/PD2": "0x7B3358E9"
      },
      "rvas": {
        "LoD/PD2": "0x58E9"
      },
      "sizes": {
        "LoD/PD2": 163
      },
      "name": "GetOrAllocateThreadContextData",
      "signature": "__acrt_ptd * GetOrAllocateThreadContextData(undefined4 reserved, int contextIndex)",
      "calling_convention": "__cdecl",
      "comment": "GetOrAllocateThreadContextData - Manages allocation and retrieval of per-thread data (PTD) structures\n\nAlgorithm:\n1. Check if FLS (Fiber Local Storage) key DAT_7b345090 has been initialized\n2. If not initialized (equals -1) or no data stored, set FLS to -1 and allocate new 868-byte PTD structure\n3. If allocation succeeds, store PTD pointer in FLS and initialize it with construct_ptd\n4. If allocation fails, clear FLS and return NULL\n5. If stored value equals -1 (sentinel), return NULL to indicate initialization failure\n6. If already allocated, multiply context index by PTD size (0x364) and add to base PTD pointer\n7. Return resulting PTD pointer or NULL on error\n\nParameters:\n- reserved (undefined4): Reserved parameter, not used\n- contextIndex (int): Context index for multi-context support; multiplied by 0x364 (868 bytes per context)\n\nReturns:\n- __acrt_ptd *: Pointer to context-specific PTD structure, or NULL if allocation/initialization failed\n\nSpecial Cases:\n- Magic value 0xFFFFFFFF (-1) used as sentinel to indicate initialization in progress\n- Size constant 0x364 (868 decimal) is the size of __acrt_ptd structure\n- If FLS key is uninitialized (equals -1), triggers allocation sequence\n- Failed allocations are marked with sentinel value -1 in FLS to prevent repeated attempts\n- construct_ptd called to initialize newly allocated PTD structures",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3973079e58265304ff2d57d22a229905",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3973079e58265304ff2d57d22a229905",
        "CFG": "a6afe2d10ce96567817331ec22986868",
        "PRO": "f004dd56f2e17f2e5f57222e67f0f15a"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_e0e104542d51": {
      "addresses": {
        "LoD/PD2": "0x7B3359B8"
      },
      "rvas": {
        "LoD/PD2": "0x59B8"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "___acrt_uninitialize_ptd",
      "signature": "undefined4 ___acrt_uninitialize_ptd(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_uninitialize_ptd\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e0e104542d511ea3331eb7fed1ab9e5a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e0e104542d511ea3331eb7fed1ab9e5a",
        "CFG": "8f793f81eebf6b1a28e081f351d196b1",
        "PRO": "2b2bb31208431f1e6d8c4a47aff7a366"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_c0a4ab78c7bb": {
      "addresses": {
        "LoD/PD2": "0x7B335A5B"
      },
      "rvas": {
        "LoD/PD2": "0x5A5B"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "___acrt_lock",
      "signature": "undefined ___acrt_lock(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_lock\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c0a4ab78c7bbdc5939a3219df84ac650",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c0a4ab78c7bbdc5939a3219df84ac650",
        "CFG": null,
        "PRO": "cfd35da87f07fe4aa636fe8a82b5867e"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_7a3970d89129": {
      "addresses": {
        "LoD/PD2": "0x7B335A2A"
      },
      "rvas": {
        "LoD/PD2": "0x5A2A"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "CleanupCriticalSections",
      "signature": "BOOL CleanupCriticalSections(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleans up all allocated critical section objects.\n\nALGORITHM:\n1. Load global critical section counter (0x7b345fb0)\n2. If counter is zero, skip cleanup and return success\n3. Calculate total size needed for all critical sections (count * 0x18 bytes each)\n4. Set EDI to point to end of critical section array (0x7b345e48 + calculated offset)\n5. Loop through each critical section from end to start:\n   a. Call DeleteCriticalSection() on current critical section pointer\n   b. Decrement global counter (0x7b345fb0)\n   c. Move to previous critical section (subtract 0x18)\n   d. Continue loop until all processed\n6. Return TRUE (0x01 in AL) to indicate success\n\nPARAMETERS:\n(none) - Function operates on global critical section array\n\nRETURNS:\nAL = 0x01 (TRUE) - Always returns success after cleanup\n\nSPECIAL CASES:\n- Handles empty array gracefully (counter = 0) by skipping loop\n- Critical sections stored in fixed global array at 0x7b345e48\n- Each critical section is 0x18 bytes in size\n- Uses decrementing loop for efficient backwards iteration\n\nSTRUCTURE LAYOUT:\nThe function manages an array of critical sections stored at address 0x7b345e48.\nEach critical section entry is 0x18 (24) bytes in size. The global counter at\n0x7b345fb0 tracks the number of active critical sections that need cleanup.\nThe function iterates backwards through this array, deleting each one.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7a3970d89129d50ca1d42c01fc54f6d0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7a3970d89129d50ca1d42c01fc54f6d0",
        "CFG": "b299961a4ff9924d9c5832fc43b80e26",
        "PRO": "12ae3557c99dcfc144f196e3b3aa262e"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_e601501afe68": {
      "addresses": {
        "LoD/PD2": "0x7B335A72"
      },
      "rvas": {
        "LoD/PD2": "0x5A72"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "GetProcessTerminationFlag",
      "signature": "uint GetProcessTerminationFlag(void)",
      "calling_convention": "__stdcall",
      "comment": "Extracts the process termination flag from the Process Environment Block (PEB).\n\nAlgorithm:\n1. Load Thread Information Block pointer from FS:[0x18]\n2. Read PEB pointer from TIB offset 0x30\n3. Read termination flags from PEB offset 0x68\n4. Extract bit at offset 8 using SHR EAX, 0x8\n5. Mask to single bit using AND AL, 0x1\n6. Return the extracted termination flag (0 = do not terminate, 1 = terminate)\n\nParameters:\nNone - This is a naked function with no explicit parameters. Uses Windows FS segment\nto access thread context implicitly.\n\nReturns:\nuint - The process termination flag (bit 8 of PEB + 0x68). Returns 0 when\ntermination is not requested, 1 when termination should proceed.\n\nStructure Layout:\nPEB (Process Environment Block) accessed via TIB:\nOffset    Size    Field Name              Type    Description\n0x30      4       PEB Pointer             ptr     From TIB base address\n0x68      4       ProcessFlags            dword   Contains termination flag at bit 8\n\nWindows TIB (Thread Information Block):\nOffset    Size    Field Name              Type    Description\n0x18      4       TIB Pointer             ptr     Accessed via FS segment register\n0x30      4       PEB Address             ptr     Process Environment Block address\n\nSpecial Cases:\n- Uses Windows TIB segment FS:[0x18] to access per-thread data\n- Works with Windows Process Environment Block (PEB) structure\n- Only extracts single bit 8 from the flags field\n- Called from CheckAndGetProcessTerminationStatus to determine process exit status",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e601501afe682ac9c11131099d892567",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e601501afe682ac9c11131099d892567",
        "CFG": null,
        "PRO": "a0521d663205d8ec916aeb3fda3b9196"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_d7fe3dde48da": {
      "addresses": {
        "LoD/PD2": "0x7B335A84"
      },
      "rvas": {
        "LoD/PD2": "0x5A84"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "GetSignBitFromSelfPointer",
      "signature": "uint GetSignBitFromSelfPointer(void)",
      "calling_convention": "__stdcall",
      "comment": "Extracts sign bit from Self pointer chain.\n\nAlgorithm:\n1. Load TEB (Thread Environment Block) pointer from FS:[0x18]\n2. Read Self pointer from TEB offset +0x30\n3. Dereference Self at offset +0x10 to get intermediate pointer\n4. Dereference intermediate at offset +0x8 to get target value\n5. Extract bit 31 (sign bit) via arithmetic right shift by 0x1f\n6. Return result as uint (0 if bit clear, 1 if bit set)\n\nReturns:\n  uint - The sign bit (bit 31) of the value at Self->+0x10->+0x8\n\nSpecial Cases:\n  Uses TEB-based Self pointer for thread-local context access\n  Sign bit extraction via SHR by 0x1f converts sign bit to 0 or 1\n  No validation of pointer chain; crashes if any pointer is NULL\n\nStructure Layout:\n  TEB[0x30] = Self pointer (context structure)\n  Self[0x10] = Pointer to state container\n  State[0x8] = Flag field with sign bit significance",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d7fe3dde48dafb03e042111f1b10ecb0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d7fe3dde48dafb03e042111f1b10ecb0",
        "CFG": null,
        "PRO": "6642bdd6e708b98b09f7380f42659016"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_32411d9bd442": {
      "addresses": {
        "LoD/PD2": "0x7B335A97"
      },
      "rvas": {
        "LoD/PD2": "0x5A97"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "IsProcessStateValid",
      "signature": "bool IsProcessStateValid(void)",
      "calling_convention": "__stdcall",
      "comment": "Validates process state by checking sign bit condition and invoking state handler if needed.\n\nAlgorithm:\n1. Initialize status value to 0\n2. Retrieve sign bit from self pointer via GetSignBitFromSelfPointer()\n3. Test if sign bit is set (check if result equals 0)\n4. If sign bit is NOT set (JNZ skips to step 6), invoke FUN_7b33763a() with status value as output parameter\n5. Set return value to 0 and compare status value against 1\n6. Return true if status value is NOT equal to 1, false otherwise\n\nReturns:\n- bool: true if status value is not equal to 1 (indicating valid/inactive state), false if status value equals 1 (indicating set/active state)\n\nSpecial Cases:\n- Magic number 1 indicates an active/set state\n- The function conditionally executes FUN_7b33763a() based on sign bit condition\n- Status value is passed by reference as output parameter",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:32411d9bd442619bc1c91b66286639bc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "32411d9bd442619bc1c91b66286639bc",
        "CFG": "3faa1a24a3d4c996032f03064ca761f6",
        "PRO": "b702565b1dbef1eb561507b0fc19b1e1"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_e8dbf0276f45": {
      "addresses": {
        "LoD/PD2": "0x7B335ABE"
      },
      "rvas": {
        "LoD/PD2": "0x5ABE"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "GetCachedLastError",
      "signature": "undefined4 GetCachedLastError(int * pErrorCtx)",
      "calling_convention": "__fastcall",
      "comment": "Retrieves and caches the last error code from Windows with lazy initialization.\n\nAlgorithm:\n1. Check if error context is already initialized (initialized flag at offset +0x8)\n2. If not initialized: call GetLastError() to retrieve current error, zero out errorCode field, set initialized flag to 1, call SetLastError() to restore original error, return 0\n3. If already initialized: return cached errorCode from offset +0x4\n\nParameters:\n  pErrorCtx (ECX): Pointer to ErrorContext structure containing cached error state\n    - Offset +0x4: DWORD errorCode - cached error code value\n    - Offset +0x8: byte initialized - flag indicating if error has been cached (0=not cached, 1=cached)\n\nReturns:\n  EAX: DWORD error code (0 on first call, cached error code on subsequent calls)\n\nSpecial Cases:\n  - On initialization, the function preserves the original Windows error state\n  - The initialized flag prevents overwriting cached errors on subsequent calls\n  - Returns 0 on first call to indicate no error was cached yet\n\nStructure Layout:\n  Offset  Size  Field       Type    Description\n  +0x00   4     reserved0   dword   Reserved/unused field\n  +0x04   4     errorCode   dword   Cached Windows error code\n  +0x08   1     initialized byte    Flag: 0=not cached, 1=cached\n  +0x09   3     reserved1   byte[3] Padding for alignment\n  Total: 12 bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e8dbf0276f45b580cfb11edfd59fa97b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e8dbf0276f45b580cfb11edfd59fa97b",
        "CFG": "e6f5aaef1039a61daa103ba7f60faedc",
        "PRO": "6855209e1f68cd47fe126a6cc0b2d0c4"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_fe4b300c8aac": {
      "addresses": {
        "LoD/PD2": "0x7B335AE7"
      },
      "rvas": {
        "LoD/PD2": "0x5AE7"
      },
      "sizes": {
        "LoD/PD2": 313
      },
      "name": "___acrt_call_reportfault",
      "signature": "undefined ___acrt_call_reportfault(int param_1, DWORD param_2, DWORD param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_call_reportfault\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fe4b300c8aac3ca15e5af72954831681",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fe4b300c8aac3ca15e5af72954831681",
        "CFG": "61fa1b89b7ac2fb25538ca8bf5f0c526",
        "PRO": "19a049074892458dc9cb15ecb4bbfcf3"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_4dab91cc3a43": {
      "addresses": {
        "LoD/PD2": "0x7B335C2F"
      },
      "rvas": {
        "LoD/PD2": "0x5C2F"
      },
      "sizes": {
        "LoD/PD2": 55
      },
      "name": "InitializeAndConfigureFileStream",
      "signature": "void InitializeAndConfigureFileStream(wchar_t * filePath, wchar_t * outputPath, wchar_t * configName, uint flags, uintptr_t options)",
      "calling_convention": "__cdecl",
      "comment": "Initializes and configures a file stream with specified parameters.\n\nAlgorithm:\n1. Allocates 0x28 byte stack buffer for FileStreamState structure\n2. Calls InitializeFileStreamState to initialize the state with NULL pointer\n3. Calls FUN_7b335c66 to configure stream with provided file paths and options\n4. Calls ApplyStreamProperties to finalize and apply stream configuration\n\nParameters:\n  filePath: Path to input file (wchar_t*)\n  outputPath: Destination path for output (wchar_t*)\n  configName: Configuration name or identifier (wchar_t*)\n  flags: Control flags for stream behavior (uint)\n  options: Optional settings and flags (uintptr_t)\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  All input parameters can be NULL pointers\n  FileStreamState buffer is 40 bytes and includes stream metadata\n  Function uses __cdecl calling convention with 5 parameters\n\nStructure Layout:\n  FileStreamState @ Stack[-0x28] (40 bytes)\n    Offset  Size  Field          Type     Description\n    +0x00   0x04  Header1        uint     State header/magic\n    +0x04   0x04  Header2        uint     State header/version\n    +0x08   0x04  StreamPtr      void*    Stream object pointer\n    +0x0C   0x04  StateFlags     uint     State control flags\n    +0x10   0x04  Property1      uint     Configuration property 1\n    ...additional fields...\n    0x28 bytes total",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4dab91cc3a43376255a32bfefb498f9a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4dab91cc3a43376255a32bfefb498f9a",
        "CFG": null,
        "PRO": "baa53b741f77b7e29b73a7d2a3776071"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_5b7f275cb0bc": {
      "addresses": {
        "LoD/PD2": "0x7B335C66"
      },
      "rvas": {
        "LoD/PD2": "0x5C66"
      },
      "sizes": {
        "LoD/PD2": 124
      },
      "name": "InvokeThreadLocalFunction",
      "signature": "void InvokeThreadLocalFunction(wchar_t * pFormat, wchar_t * pArg1, wchar_t * pArg2, uint nFlags, uintptr_t pContext, int * pThreadLocal)",
      "calling_convention": "__cdecl",
      "comment": "Retrieves and invokes an indirect function pointer from thread-local data with validation.\\n\\nThis function implements a thread-local function dispatch mechanism with safety checks. It maintains a thread-local context storing function pointers at offset 0x35c. The function initializes thread-local data on first call, retrieves the function handler, performs pre-call validation through guard_check_icall, and then invokes the handler. On initialization failure, it calls the error handler __invoke_watson with the original parameters.\\n\\nAlgorithm:\\n1. Load thread-local data pointer from pThreadLocal\\n2. If null, initialize thread-local storage via InitializeThreadLocalData\\n3. If initialization fails, retrieve error handler via GetCachedLastError\\n4. Extract function pointer from thread-local data at offset +0x35c\\n5. If function pointer is null, invoke error handler __invoke_watson\\n6. Perform pre-call validation with guard_check_icall\\n7. Invoke the retrieved function handler\\n8. Return to caller\\n\\nParameters:\\n- pFormat: Error format string for watson callback\\n- pArg1: Error argument 1 for watson callback\\n- pArg2: Error argument 2 for watson callback\\n- nFlags: Flags passed to error handler\\n- pContext: Context data passed to error handler\\n- pThreadLocal: Pointer to thread-local storage pointer (in/out)\\n\\nReturns:\\n- void: No return value\\n\\nSpecial Cases:\\n- Thread-local initialization failure triggers __invoke_watson which never returns\\n- Function handler is obfuscated via XOR with DAT_7b345000 and ROR by 5 bits\\n- Guard check failure also triggers __invoke_watson",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5b7f275cb0bc93933303fa9e9fa92678",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5b7f275cb0bc93933303fa9e9fa92678",
        "CFG": "4a4b1579ec6eca124aec7de297c71716",
        "PRO": "1a9b1f7d00870dba9b70a76759ea7ba7"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "PD2_EXT_MNE_6d7257d3f6d6": {
      "addresses": {
        "LoD/PD2": "0x7B335CE3"
      },
      "rvas": {
        "LoD/PD2": "0x5CE3"
      },
      "sizes": {
        "LoD/PD2": 16
      },
      "name": "InitializeDefaultFileStream",
      "signature": "void InitializeDefaultFileStream(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize file stream with default null parameters\n\nThis is a thin wrapper function that initializes a file stream by calling\nInitializeAndConfigureFileStream with all null/zero parameters. It serves\nas a default initialization entry point when no specific configuration is needed.\n\nAlgorithm:\n1. Clear EAX register (set to 0)\n2. Push 5 zero values on stack as parameters\n3. Call InitializeAndConfigureFileStream with null parameters\n4. Clean up stack and return\n\nParameters:\n  None - all parameters to InitializeAndConfigureFileStream are null/zero\n\nReturns:\n  void - no return value\n\nSpecial Cases:\n  All 5 parameters passed to InitializeAndConfigureFileStream are null (0x0),\n  indicating default/uninitialized state for all configuration options.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6d7257d3f6d65324a2aaddba53de9ad0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6d7257d3f6d65324a2aaddba53de9ad0",
        "CFG": null,
        "PRO": "6bb201ec76d18640cb75d1a71f0b1e27"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_b586167a1ef2": {
      "addresses": {
        "LoD/PD2": "0x7B335CF3"
      },
      "rvas": {
        "LoD/PD2": "0x5CF3"
      },
      "sizes": {
        "LoD/PD2": 52
      },
      "name": "__invoke_watson",
      "signature": "void __invoke_watson(wchar_t * param_1, wchar_t * param_2, wchar_t * param_3, uint param_4, uintptr_t param_5)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __invoke_watson\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b586167a1ef2c659ec3fba77eabe3e07",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b586167a1ef2c659ec3fba77eabe3e07",
        "CFG": "667714027c789a8b486a563a19e4b634",
        "PRO": "4b62159d02001ebc89f69d9d9f8f6933"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_0eb9c57737c9": {
      "addresses": {
        "LoD/PD2": "0x7B335D27"
      },
      "rvas": {
        "LoD/PD2": "0x5D27"
      },
      "sizes": {
        "LoD/PD2": 67
      },
      "name": "FID_conflict:___acrt_errno_from_os_error",
      "signature": "int FID_conflict:___acrt_errno_from_os_error(ulong param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Multiple Matches With Different Base Names\n ___acrt_errno_from_os_error\n __get_errno_from_oserr\n\nLibraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0eb9c57737c9945526588481caeeb787",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0eb9c57737c9945526588481caeeb787",
        "CFG": "fd32fcbc1bb7eeb18567ac64ddfa5c84",
        "PRO": "0176da6b0dc1599352f33a9407593854"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_c9e474235f8a": {
      "addresses": {
        "LoD/PD2": "0x7B335D6A"
      },
      "rvas": {
        "LoD/PD2": "0x5D6A"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "___acrt_errno_map_os_error",
      "signature": "undefined ___acrt_errno_map_os_error(ulong param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_errno_map_os_error\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c9e474235f8ab0b2b23a632af418b776",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c9e474235f8ab0b2b23a632af418b776",
        "CFG": null,
        "PRO": "0df243cde0809b16507f170521759f7e"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_1d0bb52082b9": {
      "addresses": {
        "LoD/PD2": "0x7B335D8D"
      },
      "rvas": {
        "LoD/PD2": "0x5D8D"
      },
      "sizes": {
        "LoD/PD2": 36
      },
      "name": "CaptureWindowsErrorCode",
      "signature": "void CaptureWindowsErrorCode(DWORD lastError, int errorContext)",
      "calling_convention": "__cdecl",
      "comment": "Captures a Windows system error code and stores error information in a context structure.\n\nAlgorithm:\n1. Store error flag 0x1 at context offset 0x24 (error occurred)\n2. Store the Windows error code at context offset 0x20\n3. Call ___acrt_errno_from_os_error(lastError) to convert Windows error to C runtime error code\n4. Store conversion flag 0x1 at context offset 0x1c (error code converted)\n5. Store the C runtime error code at context offset 0x18\n\nParameters:\n- lastError (DWORD): Windows system error code (typically from GetLastError() API)\n- errorContext (int): Pointer to error context structure where error information is stored\n\nReturns:\n- void: No return value; all results stored in errorContext structure\n\nSpecial Cases:\n- Error code 0 (ERROR_SUCCESS) is still captured if passed to this function\n- Context structure must be at least 37 bytes (offset 0x24+1)\n- This function is called from file I/O operations to propagate errors to higher-level handlers\n- The conversion from Windows error codes to C runtime errors enables proper errno-based error handling\n\nStructure Layout - Error Context:\nOffset | Size | Field Name | Type | Description\n0x18   | 4    | crtError   | int  | C runtime error code from errno conversion\n0x1c   | 1    | convFlag   | byte | Conversion flag (0x1 = error converted)\n0x20   | 4    | winError   | int  | Windows system error code (from GetLastError)\n0x24   | 1    | errFlag    | byte | Error occurred flag (0x1 = error occurred)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1d0bb52082b9f6efd6d5ae65e96cba3b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1d0bb52082b9f6efd6d5ae65e96cba3b",
        "CFG": null,
        "PRO": "f1c341c8227b4f521094a3957fc9377f"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_644c94180542": {
      "addresses": {
        "LoD/PD2": "0x7B335DC4"
      },
      "rvas": {
        "LoD/PD2": "0x5DC4"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "GetPerThreadErrnoData",
      "signature": "__acrt_ptd * GetPerThreadErrnoData(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves or creates per-thread errno data structure.\n\nAlgorithm:\n1. Call GetOrCreatePerThreadData() to obtain thread-local storage\n2. Test if returned pointer is NULL\n3. If NULL, return fallback static errno data at 0x7b345098\n4. If valid, return pointer offset by 0x14 bytes into thread data\n\nReturns:\nPointer to __acrt_ptd errno data structure. Returns either:\n- Static fallback errno data if thread initialization failed\n- Offset thread-local errno data at +0x14 from thread storage\n\nSpecial Cases:\n- GetOrCreatePerThreadData() may fail and return NULL during thread startup\n- Fallback static data at 0x7b345098 used as emergency errno storage\n- Offset of 0x14 (20 bytes) points to errno field within thread structure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:644c941805424b14885c3ec129aaf89f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "644c941805424b14885c3ec129aaf89f",
        "CFG": "8d598d6ff87f51df69fb6e8ad46943ae",
        "PRO": "718bea72506b1dca2b998a61c63f56e8"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_66f9491d9af8": {
      "addresses": {
        "LoD/PD2": "0x7B335DD7"
      },
      "rvas": {
        "LoD/PD2": "0x5DD7"
      },
      "sizes": {
        "LoD/PD2": 93
      },
      "name": "__calloc_base",
      "signature": "LPVOID __calloc_base(uint param_1, uint param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __calloc_base\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:66f9491d9af8fd3d55a819090c569edf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "66f9491d9af8fd3d55a819090c569edf",
        "CFG": "1746c214e0525153db871cfe57f9d146",
        "PRO": "f05a869ef6461fa6aff7afd9541d5ca5"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_e5315069105e": {
      "addresses": {
        "LoD/PD2": "0x7B335E34"
      },
      "rvas": {
        "LoD/PD2": "0x5E34"
      },
      "sizes": {
        "LoD/PD2": 58
      },
      "name": "FreeHeapMemory",
      "signature": "void FreeHeapMemory(LPVOID pMemoryBlock)",
      "calling_convention": "__cdecl",
      "comment": "Deallocates heap memory with error handling and errno propagation.\n\nAlgorithm:\n1. Check if pMemoryBlock pointer is non-NULL (test against 0x0)\n2. If non-NULL, call HeapFree() with handle DAT_7b3460cc, flags 0, and memory pointer\n3. Test if HeapFree() succeeded (EAX != 0 means success)\n4. If HeapFree() failed (EAX == 0), retrieve OS error code via GetLastError()\n5. Convert OS error code to POSIX errno via FID_conflict____acrt_errno_from_os_error()\n6. Call GetOrCreateThreadDataRef() to obtain thread-local storage structure\n7. Store converted errno value at offset +0 of thread data structure\n8. Return to caller\n\nParameters:\n- pMemoryBlock (LPVOID): Pointer to heap memory block to deallocate. Can be NULL (safely skipped).\n\nReturns:\n- void: No return value. Errors are stored in thread-local errno field.\n\nSpecial Cases:\n- NULL pointer: Function checks for NULL and skips deallocation entirely\n- HeapFree failure: Stores OS error code as POSIX errno in thread data for caller retrieval\n- Thread data management: Always accesses thread-local storage for errno propagation\n- Used by VCRT exception handling and memory cleanup routines\n\nStructure Layout (Thread Data Access):\nOffset  Size  Field Name        Type        Description\n0       4     errno_field       int         POSIX error number (set on HeapFree failure)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e5315069105ea6aba50d064eb91813a2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e5315069105ea6aba50d064eb91813a2",
        "CFG": "0ffa8e79f94ada14a14186aa3a749bfc",
        "PRO": "8ccfbf4526b25bdef0981a4695dcd7b6"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_4c3e5943e224": {
      "addresses": {
        "LoD/PD2": "0x7B335E6E"
      },
      "rvas": {
        "LoD/PD2": "0x5E6E"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "CompareValues",
      "signature": "int CompareValues(int firstValue, int secondValue)",
      "calling_convention": "__cdecl",
      "comment": "Performs a three-way signed comparison between two integer values.\n\nAlgorithm:\n1. Load secondValue from stack [EBP + 0xc] into EAX\n2. Compare EAX with firstValue at [EBP + 0x8]\n3. If secondValue >= firstValue, jump to check_greater_than (0x7b335e80)\n4. Otherwise (secondValue < firstValue), set EAX to 0xffffffff (-1) and return\n5. At check_greater_than: Use SBB EAX, EAX to set EAX based on carry flag\n6. Negate EAX to convert borrow result to 0 or 1\n\nParameters:\n- firstValue: int, first value for comparison (loaded from [EBP + 0x8])\n- secondValue: int, second value for comparison (loaded from [EBP + 0xc])\n\nReturns:\n- int: -1 (0xffffffff) if secondValue < firstValue\n       0 if secondValue == firstValue\n       1 if secondValue > firstValue\n\nSpecial Cases:\n- Function implements the semantics of qsort-style comparison callbacks\n- Return value can be directly used to sort in ascending order by difference\n- No null pointer checks or parameter validation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4c3e5943e2240c0e96abb1f751479a77",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4c3e5943e2240c0e96abb1f751479a77",
        "CFG": "35cb04bc19b2020a12670858f7d7ed27",
        "PRO": "d4c428d686eef7cbadbe32cd12577e12"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_4ec4cb66c626": {
      "addresses": {
        "LoD/PD2": "0x7B335E86"
      },
      "rvas": {
        "LoD/PD2": "0x5E86"
      },
      "sizes": {
        "LoD/PD2": 178
      },
      "name": "__acrt_convert_wcs_mbs_cp<char,wchar_t,class_<lambda_62f6974d9771e494a5ea317cc32e971c>,struct___crt_win32_buffer_internal_dynamic_resizing>",
      "signature": "int __acrt_convert_wcs_mbs_cp<char,wchar_t,class_<lambda_62f6974d9771e494a5ea317cc32e971c>,struct___crt_win32_buffer_internal_dynamic_resizing>(char * param_1, __crt_win32_buffer<wchar_t,struct___crt_win32_buffer_internal_dynamic_resizing> * param_2, <lambda_62f6974d9771e494a5ea317cc32e971c> * param_3, uint param_4)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl __acrt_convert_wcs_mbs_cp<char,wchar_t,class <lambda_62f6974d9771e494a5ea317cc32e971c>,struct __crt_win32_buffer_internal_dynamic_resizing>(char const * const,class __crt_win32_buffer<wchar_t,struct __crt_win32_buffer_internal_dynamic_resizing> &,class <lambda_62f6974d9771e494a5ea317cc32e971c> const &,unsigned int)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4ec4cb66c626783f3bd931a61a044c86",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4ec4cb66c626783f3bd931a61a044c86",
        "CFG": "dcf6e83f6e4873a0e42c4eef04e33e42",
        "PRO": "fc9244c7eda016ca16244e039f58297d"
      },
      "basic_block_counts": {
        "LoD/PD2": 15
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_7820bcb35356": {
      "addresses": {
        "LoD/PD2": "0x7B335F38"
      },
      "rvas": {
        "LoD/PD2": "0x5F38"
      },
      "sizes": {
        "LoD/PD2": 198
      },
      "name": "ConvertWideStringToBuffer",
      "signature": "int ConvertWideStringToBuffer(LPCWSTR lpSourceString, void * pOutputBuffer, int nMaxLength, UINT codePage)",
      "calling_convention": "__cdecl",
      "comment": "Converts a wide character (UTF-16) string to a multibyte string and stores the result in a managed buffer structure.\n\nAlgorithm:\n1. Check if source string pointer is NULL; if so, deallocate buffer and clear all fields\n2. If source string is not NULL, check if it points to empty string (null terminator)\n3. If string is empty, allocate buffer with capacity 1 byte and write null terminator\n4. If string is not empty, call ConvertWideCharToMultiByte to calculate required length in target encoding\n5. If conversion query fails, retrieve Windows error code, map to errno, get thread error storage, return error\n6. Check if current buffer capacity is less than required length\n7. If reallocation needed, call allocate() to resize buffer; return error if allocation fails\n8. Call FUN_7b336575 to perform actual wide-to-multibyte conversion with specified code page\n9. If conversion fails, retrieve Windows error code, map to errno, return error\n10. On success, store actual converted length (minus null terminator) and return 0\n\nParameters:\nlpSourceString: Source wide character string (LPCWSTR), may be NULL\npOutputBuffer: Pointer to __crt_win32_buffer structure containing managed byte buffer\nnMaxLength: Maximum capacity of output buffer in bytes\ncodePage: Windows code page for character conversion (e.g., CP_UTF8)\n\nReturns:\n0 on success\nNonzero error code from thread error storage on failure\n\nStructure Layout (pOutputBuffer):\nOffset  Size  Field Name        Type      Description\n0x0     4     buffer_ptr        void*     Pointer to allocated buffer\n0x4     4     current_size      int       Currently used bytes\n0x8     4     capacity          int       Allocated capacity in bytes\n0xc     4     (reserved)        int       Reserved field\nTotal: 16 bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7820bcb3535676126683410b40ecffda",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7820bcb3535676126683410b40ecffda",
        "CFG": "f7106213b601a67591285814324a7d56",
        "PRO": "d43b208e265dd50b797734e855ebb721"
      },
      "basic_block_counts": {
        "LoD/PD2": 16
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_19bef61e780c": {
      "addresses": {
        "LoD/PD2": "0x7B335FFE"
      },
      "rvas": {
        "LoD/PD2": "0x5FFE"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "__acrt_mbs_to_wcs_cp<struct___crt_win32_buffer_internal_dynamic_resizing>",
      "signature": "int __acrt_mbs_to_wcs_cp<struct___crt_win32_buffer_internal_dynamic_resizing>(char * param_1, __crt_win32_buffer<wchar_t,struct___crt_win32_buffer_internal_dynamic_resizing> * param_2, uint param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl __acrt_mbs_to_wcs_cp<struct __crt_win32_buffer_internal_dynamic_resizing>(char const * const,class __crt_win32_buffer<wchar_t,struct __crt_win32_buffer_internal_dynamic_resizing> &,unsigned int)\n\nLibraries: Visual Studio 2019 Debug, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:19bef61e780c74e5dff166aab3ca2cb4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "19bef61e780c74e5dff166aab3ca2cb4",
        "CFG": null,
        "PRO": "9d4e6efeadbc5b314f2bb0bfa7bc4374"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_ad7c5bf304ca": {
      "addresses": {
        "LoD/PD2": "0x7B33601B"
      },
      "rvas": {
        "LoD/PD2": "0x601B"
      },
      "sizes": {
        "LoD/PD2": 380
      },
      "name": "BuildArgumentBuffer",
      "signature": "int BuildArgumentBuffer(char * * ppArguments, void * * ppBuffer)",
      "calling_convention": "__cdecl",
      "comment": "Parses and consolidates command-line arguments into a contiguous memory buffer.\\n\\nAlgorithm:\\n1. If ppBuffer is NULL, mark error code 0x16 and initialize default file stream\\n2. Initialize local buffer list structure and iterate through argument array\\n3. For each argument string, use strpbrk to check for delimiter characters (' ', '*', '#')\\n4. If no delimiter found, add entire argument to buffer list; otherwise call delimiter handler\\n5. Calculate total buffer size needed: count arguments, measure all strings with null terminators\\n6. Allocate contiguous memory buffer for argument pointers and string data\\n7. Copy each argument string from temporary list into new buffer at calculated offsets\\n8. Set output ppBuffer to point to allocated buffer containing compacted argument array\\n9. Free temporary argument list structure and return success code 0\\n\\nParameters:\\nppArguments : char** - Array of null-terminated argument strings to consolidate\\nppBuffer    : void** - Output pointer that receives allocated argument buffer address\\n\\nReturns:\\n0   - Success: ppBuffer contains valid argument buffer\\n0x16 - Error: ppBuffer is NULL (thread data initialization error)\\n-1  - Error: Failed to allocate memory for buffer\\nnon-zero - Error: String copy validation failed (invokes watson error handler)\\n\\nSpecial Cases:\\n- Empty or NULL argument arrays handled gracefully\\n- Delimiter characters ' ', '*', '#' trigger special string parsing via FUN_7b336249\\n- String length calculation includes null terminators for each string plus array padding\\n- Failed memory allocation immediately frees temporary structures and exits\\n- String copy errors invoke __invoke_watson() which terminates process\\n\\nStructure Layout:\\nThe function manipulates an internal argument_list<> structure with:\\n  Offset  Size  Field Name         Type   Description\\n  0x00    4     pointerArray       void*  Array of string pointers\\n  0x04    4     endPointer         void*  Points past last valid entry\\nTotal Structure Size: 8 bytes (managed internally)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ad7c5bf304cac1ec0470974f13d366d4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ad7c5bf304cac1ec0470974f13d366d4",
        "CFG": "da8a91c57591a238999cfe055c4a889f",
        "PRO": "a71b133d306b9e66edbd630da50a50b2"
      },
      "basic_block_counts": {
        "LoD/PD2": 29
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_1743000d07d0": {
      "addresses": {
        "LoD/PD2": "0x7B336198"
      },
      "rvas": {
        "LoD/PD2": "0x6198"
      },
      "sizes": {
        "LoD/PD2": 176
      },
      "name": "copy_and_add_argument_to_buffer<char>",
      "signature": "int copy_and_add_argument_to_buffer<char>(char * param_1, char * param_2, uint param_3, argument_list<char> * param_4)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl copy_and_add_argument_to_buffer<char>(char const * const,char const * const,unsigned int,class `anonymous namespace'::argument_list<char> &)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1743000d07d02d097ed61851905367b5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1743000d07d02d097ed61851905367b5",
        "CFG": "acd9c34a5e33b58a92e7ed133adc66ed",
        "PRO": "df485c995045e9e6e6f8a2ddb1a33ac8"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_87bb04582ef1": {
      "addresses": {
        "LoD/PD2": "0x7B336249"
      },
      "rvas": {
        "LoD/PD2": "0x6249"
      },
      "sizes": {
        "LoD/PD2": 645
      },
      "name": "ExpandWildcardPathAndAddToBuffer",
      "signature": "int ExpandWildcardPathAndAddToBuffer(uchar * pBasePath, uchar * pWildcardPos, argument_list<char> * pArgumentBuffer)",
      "calling_convention": "__cdecl",
      "comment": "Expands wildcard patterns in file paths and adds matched files to argument buffer.\n\nAlgorithm:\n1. Validates input path and locates the wildcard position by scanning backward from the pattern start\n2. Extracts the base path and determines the separator character (drive letter colon, path slash, or backslash)\n3. Converts the base path pattern to wide characters for Windows API compatibility using __acrt_mbs_to_wcs_cp\n4. Uses FindFirstFileExW with the wide pattern and FindExSearchNameMatch flag for efficient file enumeration\n5. Loops through all matching files using FindNextFileW to retrieve each match\n6. Filters out . and .. directory entries to prevent recursive directory traversal\n7. Converts matched wide character filenames back to the target multibyte encoding\n8. Adds each valid match to the output argument buffer via copy_and_add_argument_to_buffer\n9. Accumulates matched entries in the buffer and records initial/final element counts\n10. Sorts all newly added matches using qsort with custom comparator function CompareValues\n11. Cleans up allocated wide character buffers and releases the find handle\n12. Returns status code (0=success, non-zero=error)\n\nParameters:\n  pBasePath (uchar *): Pointer to the start of the base path string\n  pWildcardPos (uchar *): Position in the path where the pattern wildcards start (may point to a relative path component)\n  pArgumentBuffer (argument_list<char> *): Output buffer structure to accumulate matched filenames\n\nReturns:\n  0 on success (all matching files found and added to buffer)\n  non-zero on error (file pattern not found, or failed to add matches to buffer)\n\nSpecial Cases:\n  - Handles drive letters (C:), UNC paths (\\\\\\\\server\\\\share), and relative paths with identical logic\n  - Filters out . (current directory) and .. (parent directory) entries to prevent infinite recursion\n  - Detects and reports errors when FindFirstFileExW returns INVALID_HANDLE_VALUE (pattern matches no files)\n  - Properly tracks and cleans up two levels of wide character buffers: the base path buffer and per-match filename buffers\n  - Uses ACP (ANSI Code Page) compatibility codepage for correct multibyte/wide character conversion\n  - Sorts results by using qsort with custom comparator to maintain consistent file ordering across different systems",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:87bb04582ef12a152cd0685b406c72f9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "87bb04582ef12a152cd0685b406c72f9",
        "CFG": "c6504bccb637991ad683f482c1de0244",
        "PRO": "0d9e51a75facd9e13bfbb86d68348b7d"
      },
      "basic_block_counts": {
        "LoD/PD2": 46
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_825ffe21bc5f": {
      "addresses": {
        "LoD/PD2": "0x7B3364CE"
      },
      "rvas": {
        "LoD/PD2": "0x64CE"
      },
      "sizes": {
        "LoD/PD2": 130
      },
      "name": "InitLocaleContext",
      "signature": "void * InitLocaleContext(void * this, int * pLocaleData)",
      "calling_convention": "__thiscall",
      "comment": "Initializes a locale context object with locale data from thread or parameter.\n\nAlgorithm:\n1. Clear the initialization flag at offset 0xc\n2. Calculate pointer to locale data field at offset 0x4\n3. Check if pLocaleData parameter is NULL\n4. If NULL and locale system is initialized:\n   - Call GetOrCreateThreadData() to obtain thread-local data\n   - Copy locale data pointer from thread data offset 0x4c\n   - Copy locale value from thread data offset 0x48\n   - Call ___acrt_update_locale_info() to update with thread data\n   - Call UpdateLocaleIfNeeded() to finalize locale\n   - Load flags from context offset 0x350\n   - Check if flag bit 0x2 is already set\n   - If not set, set flag 0x2 and set initialization flag\n5. If pLocaleData is not NULL:\n   - Use provided locale data directly (offset 0x0 = data ptr, offset 0x4 = value)\n6. Store locale values in context and return this pointer\n\nParameters:\n  this (ECX): Pointer to locale context object to initialize\n  pLocaleData: Optional pointer to initial locale data (NULL = use thread data)\n\nReturns:\n  Pointer to initialized context object (this)\n\nSpecial Cases:\n  - If pLocaleData is NULL and locale system not initialized, returns with default values\n  - Flag bit 0x2 at offset 0x350 indicates locale has been initialized\n  - Initialization flag at offset 0xc is set only when thread data is used\n  - Offsets 0x4 and 0x8 store primary locale data within context\n\nStructure Layout:\n  Offset  Size  Field             Type    Description\n  0x0     4     thread_data       ptr     Pointer to __acrt_ptd thread data\n  0x4     4     locale_data       ptr     Pointer to locale data\n  0x8     4     locale_value      int     Locale value or code\n  0xc     1     init_flag         byte    Initialization flag (1 if from thread)\n  0x350   4     flags             uint    Status flags (bit 0x2 = initialized)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:825ffe21bc5fffcf9ff3e8ab8118c486",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "825ffe21bc5fffcf9ff3e8ab8118c486",
        "CFG": "4c039a36e9199ae2f847ed8b459b14c6",
        "PRO": "2448d0bf37c9a2de64343f5a6474ec39"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_2c69468e4701": {
      "addresses": {
        "LoD/PD2": "0x7B336550"
      },
      "rvas": {
        "LoD/PD2": "0x6550"
      },
      "sizes": {
        "LoD/PD2": 37
      },
      "name": "~argument_list<>",
      "signature": "undefined ~argument_list<>(undefined4 * param_1)",
      "calling_convention": "__fastcall",
      "comment": "Library Function - Multiple Matches With Same Base Name\n public: __thiscall `anonymous namespace'::argument_list<char>::~argument_list<char>(void)\n public: __thiscall `anonymous namespace'::argument_list<char>::~argument_list<char>(void)\n public: __thiscall `anonymous namespace'::argument_list<wchar_t>::~argument_list<wchar_t>(void)\n public: __thiscall `anonymous namespace'::argument_list<wchar_t>::~argument_list<wchar_t>(void)\n\nLibrary: Visual Studio 2015 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2c69468e4701011b3392b622e57d3678",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2c69468e4701011b3392b622e57d3678",
        "CFG": "a9c729cc86b83c7c1ad73572a77516e6",
        "PRO": "3b27eb7ba5bff45de8ba59807ffb0f4c"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_db3e013359b6": {
      "addresses": {
        "LoD/PD2": "0x7B336575"
      },
      "rvas": {
        "LoD/PD2": "0x6575"
      },
      "sizes": {
        "LoD/PD2": 36
      },
      "name": "ConvertWideStringToMultiByte",
      "signature": "void ConvertWideStringToMultiByte(uint codePage, LPCWSTR pWideString, LPSTR pMultiByteBuffer, int bufferSize)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper function to convert wide-character string to multi-byte string representation.\n\nAlgorithm:\n1. Call Windows API ConvertWideCharToMultiByte with provided parameters\n2. Convert wide character string using specified code page\n3. Write result to output buffer with specified size limit\n4. Return from function\n\nParameters:\n  codePage - Code page identifier for character conversion (e.g., CP_ACP=0, CP_UTF8=65001)\n  pWideString - Pointer to null-terminated wide-character input string\n  pMultiByteBuffer - Pointer to output buffer for multi-byte string result\n  bufferSize - Maximum size of output buffer in bytes\n\nReturns:\n  void - Function returns no value; result stored in pMultiByteBuffer\n\nSpecial Cases:\n  - Input string must be null-terminated\n  - Output buffer size must be sufficient for converted string\n  - Conversion flags set to 0 (no special processing)\n  - Default character and success output parameters not used",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:db3e013359b6f457e10ef6d6f14d9807",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "db3e013359b6f457e10ef6d6f14d9807",
        "CFG": null,
        "PRO": "9fd83346965ae1ccc8207a6b9028b9ab"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_bc198c9debcb": {
      "addresses": {
        "LoD/PD2": "0x7B336599"
      },
      "rvas": {
        "LoD/PD2": "0x6599"
      },
      "sizes": {
        "LoD/PD2": 63
      },
      "name": "__acrt_get_utf8_acp_compatibility_codepage",
      "signature": "uint __acrt_get_utf8_acp_compatibility_codepage(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n unsigned int __cdecl __acrt_get_utf8_acp_compatibility_codepage(void)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bc198c9debcbf615c5bc60988ed4c1f4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bc198c9debcbf615c5bc60988ed4c1f4",
        "CFG": "02273156f0e4b98efa76244054230009",
        "PRO": "143a7ecb0085bcfcc3660f6fc074132b"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_622cccd70890": {
      "addresses": {
        "LoD/PD2": "0x7B3365D8"
      },
      "rvas": {
        "LoD/PD2": "0x65D8"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "_deallocate",
      "signature": "void _deallocate(__crt_win32_buffer<wchar_t,struct___crt_win32_buffer_internal_dynamic_resizing> * this)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n private: void __thiscall __crt_win32_buffer<wchar_t,struct __crt_win32_buffer_internal_dynamic_resizing>::_deallocate(void)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:622cccd70890db97f418764d812b095e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "622cccd70890db97f418764d812b095e",
        "CFG": "8f793f81eebf6b1a28e081f351d196b1",
        "PRO": "23ed600a51dd7ad1f69c8b57042f336e"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_beee665df4a2": {
      "addresses": {
        "LoD/PD2": "0x7B3365F2"
      },
      "rvas": {
        "LoD/PD2": "0x65F2"
      },
      "sizes": {
        "LoD/PD2": 60
      },
      "name": "allocate",
      "signature": "int allocate(void * this, uint param_1)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Multiple Matches With Same Base Name\n public: int __thiscall __crt_win32_buffer<char,struct __crt_win32_buffer_internal_dynamic_resizing>::allocate(unsigned int)\n public: int __thiscall __crt_win32_buffer<char,struct __crt_win32_buffer_public_dynamic_resizing>::allocate(unsigned int)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:beee665df4a2db0920647dd4d54df36d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "beee665df4a2db0920647dd4d54df36d",
        "CFG": "19c71a436cd9b62cd94468fdd6017761",
        "PRO": "d27761f7d36ff0091fe293d1495d2a7a"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_91336d4559b3": {
      "addresses": {
        "LoD/PD2": "0x7B33662E"
      },
      "rvas": {
        "LoD/PD2": "0x662E"
      },
      "sizes": {
        "LoD/PD2": 63
      },
      "name": "allocate",
      "signature": "int allocate(__crt_win32_buffer<wchar_t,struct___crt_win32_buffer_internal_dynamic_resizing> * this, uint param_1)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: int __thiscall __crt_win32_buffer<wchar_t,struct __crt_win32_buffer_internal_dynamic_resizing>::allocate(unsigned int)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:91336d4559b379f6802f6fc02bee9a0e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "91336d4559b379f6802f6fc02bee9a0e",
        "CFG": "85e807ad41b8340ac7aa6e764f7d6a4d",
        "PRO": "0471034e38325a1c37181de5af43688d"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_1cef1ae5210e": {
      "addresses": {
        "LoD/PD2": "0x7B33666D"
      },
      "rvas": {
        "LoD/PD2": "0x666D"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "allocate",
      "signature": "int allocate(void * * param_1, uint param_2, __crt_win32_buffer_empty_debug_info * param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n public: static int __cdecl __crt_win32_buffer_internal_dynamic_resizing::allocate(void * * const,unsigned int,class __crt_win32_buffer_empty_debug_info const &)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1cef1ae5210ea6ba89c2f903625a2a75",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1cef1ae5210ea6ba89c2f903625a2a75",
        "CFG": null,
        "PRO": "b83f505d1123dce1c32f09fc779e3a68"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_84894fb111f0": {
      "addresses": {
        "LoD/PD2": "0x7B33668C"
      },
      "rvas": {
        "LoD/PD2": "0x668C"
      },
      "sizes": {
        "LoD/PD2": 135
      },
      "name": "expand_if_necessary",
      "signature": "int expand_if_necessary(argument_list<char> * this)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n private: int __thiscall `anonymous namespace'::argument_list<char>::expand_if_necessary(void)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:84894fb111f0bc699d5ac8b77ae4117b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "84894fb111f0bc699d5ac8b77ae4117b",
        "CFG": "fd9972b93bc30d9b5de608b2276eeb40",
        "PRO": "bac12cd41714af9bdb5e22db26aaf1b9"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_d79dae3c7e5a": {
      "addresses": {
        "LoD/PD2": "0x7B33671E"
      },
      "rvas": {
        "LoD/PD2": "0x671E"
      },
      "sizes": {
        "LoD/PD2": 194
      },
      "name": "ConvertWideStringToBuffer",
      "signature": "int ConvertWideStringToBuffer(LPCWSTR pWideString, int pBufferStruct, undefined4 param_3, uint codePage)",
      "calling_convention": "__cdecl",
      "comment": "Converts a wide character string to multi-byte format and stores result in managed buffer.\n\nAlgorithm:\n1. Validate input wide string pointer (NULL check)\n2. If NULL, call error handler FUN_7b336807 and return 0\n3. Check if string is empty (first character is L'\\0')\n4. For empty string: allocate buffer if needed, clear output, return 0\n5. For non-empty string: calculate required buffer size via first conversion pass\n6. Check if conversion succeeded and retrieve required size from EAX\n7. On error: get OS error code, map to errno, retrieve thread data errno value, return error\n8. Verify required size fits in allocated buffer capacity (offset +0xc)\n9. If size insufficient: reallocate buffer via allocate() function\n10. If reallocation fails: clear output buffer at offset +8, return 0\n11. Perform actual conversion via ConvertWideStringToMultiByte()\n12. On conversion success: store character count minus 1 at offset +0x10, return 0\n13. On conversion failure: get OS error, map to errno, return thread errno value\n\nParameters:\n  pWideString: Input wide character string (LPCWSTR), may be NULL\n  pBufferStruct: Pointer to buffer management structure:\n                 +0x8: pointer to output multi-byte buffer\n                 +0xc: capacity of allocated buffer in bytes\n                 +0x10: length of converted string (chars - 1)\n  param_3: Unused parameter (undefined4 type)\n  codePage: Code page identifier for character conversion (uint)\n\nReturns:\n  0 on success (conversion completed or empty string)\n  Non-zero error code on failure (OS error mapped to errno)\n\nSpecial Cases:\n  NULL input pointer triggers FUN_7b336807 callback\n  Empty string initializes buffer and returns 0\n  Buffer reallocation failure clears output and returns 0\n  Two-pass conversion: first determines size, second performs conversion\n  String length stored as count-1 (excluding null terminator)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d79dae3c7e5ad2007e4eaa87540f688c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d79dae3c7e5ad2007e4eaa87540f688c",
        "CFG": "f146e2952b94af5309ccf74dfad329ea",
        "PRO": "7e99ea503b67c0c5e16d75aa8bf65f3f"
      },
      "basic_block_counts": {
        "LoD/PD2": 26
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_eff9bc0895af": {
      "addresses": {
        "LoD/PD2": "0x7B3367E0"
      },
      "rvas": {
        "LoD/PD2": "0x67E0"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "allocate",
      "signature": "undefined4 allocate(int param_1)",
      "calling_convention": "__fastcall",
      "comment": "Library Function - Multiple Matches With Same Base Name\n public: int __thiscall __crt_win32_buffer<char,struct __crt_win32_buffer_no_resizing>::allocate(unsigned int)\n public: int __thiscall __crt_win32_buffer<wchar_t,struct __crt_win32_buffer_no_resizing>::allocate(unsigned int)\n\nLibraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:eff9bc0895af26d0e13a0e5f97593b47",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "eff9bc0895af26d0e13a0e5f97593b47",
        "CFG": "90c4f17418cec0d76ed106d2d34ca67f",
        "PRO": "178a3e5ae0bc65735aee7aa43a347a28"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_240d5cb2d2b3": {
      "addresses": {
        "LoD/PD2": "0x7B336807"
      },
      "rvas": {
        "LoD/PD2": "0x6807"
      },
      "sizes": {
        "LoD/PD2": 20
      },
      "name": "ClearBufferFields",
      "signature": "void ClearBufferFields(void * pBuffer)",
      "calling_convention": "__fastcall",
      "comment": "Clears all buffer structure fields and resets the deallocation flag.\n\nAlgorithm:\n1. Check if deallocation flag at offset +0x14 is set (non-zero)\n2. If flag is set, clear it by writing zero to offset +0x14\n3. Clear the buffer pointer/size field at offset +0x8 to zero\n4. Clear the capacity field at offset +0xc to zero\n5. Clear the size/length field at offset +0x10 to zero\n6. Return\n\nParameters:\npBuffer: Pointer to __crt_win32_buffer structure passed in ECX register\n\nReturns:\nvoid\n\nSpecial Cases:\nThe deallocation flag at offset +0x14 is only cleared if already set, indicating\nthe buffer contents have been deallocated. The other fields (offset +0x8, +0xc, +0x10)\nare always cleared to zero regardless of previous state.\n\nStructure Layout (__crt_win32_buffer):\nOffset  Size  Field Name     Type      Description\n0x0     4     buffer_ptr     void*     Pointer to allocated buffer\n0x4     4     current_size   int       Currently used bytes\n0x8     4     field_8        int       Size or status field\n0xc     4     capacity       int       Allocated capacity\n0x10    4     length         int       String length without null term\n0x14    1     dealloc_flag   byte      Deallocation flag (cleared when deallocated)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:240d5cb2d2b375c575a495ac0089b042",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "240d5cb2d2b375c575a495ac0089b042",
        "CFG": "b370095729a55966f830f9e42a501d33",
        "PRO": "0c0e816f8c64846a372207830df801e5"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_0a1f072e8055": {
      "addresses": {
        "LoD/PD2": "0x7B33681B"
      },
      "rvas": {
        "LoD/PD2": "0x681B"
      },
      "sizes": {
        "LoD/PD2": 161
      },
      "name": "___acrt_GetModuleFileNameA",
      "signature": "undefined ___acrt_GetModuleFileNameA(HMODULE param_1, undefined4 param_2, undefined4 param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_GetModuleFileNameA\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0a1f072e805577cbd86c2197975d37b7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0a1f072e805577cbd86c2197975d37b7",
        "CFG": "3907a61015bea53abae30d1d00c37cc2",
        "PRO": "8bc662292686f111bd319f85ba50fcc7"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_b4c322a1f5cc": {
      "addresses": {
        "LoD/PD2": "0x7B336909"
      },
      "rvas": {
        "LoD/PD2": "0x6909"
      },
      "sizes": {
        "LoD/PD2": 131
      },
      "name": "operator()",
      "signature": "void operator()(<lambda_ae742caa10f662c28703da3d2ea5e57e> * this)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: void __thiscall <lambda_ae742caa10f662c28703da3d2ea5e57e>::operator()(void)const \n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b4c322a1f5ccf1db0109c706b1f587f9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b4c322a1f5ccf1db0109c706b1f587f9",
        "CFG": "7b115c7406f655d5b90d1a91fd7d880f",
        "PRO": "ffc9fcda6e1a640987d4220f05279c75"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_STR_88a45bf881e9": {
      "addresses": {
        "LoD/PD2": "0x7B33698C"
      },
      "rvas": {
        "LoD/PD2": "0x698C"
      },
      "sizes": {
        "LoD/PD2": 62
      },
      "name": "CPtoLocaleName",
      "signature": "wchar_t * CPtoLocaleName(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n wchar_t const * __cdecl CPtoLocaleName(int)\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:88a45bf881e99a329ace0f4ea9d019a8",
      "indexes": {
        "EXP": null,
        "STR": "88a45bf881e99a329ace0f4ea9d019a8",
        "API": null,
        "MNE": "3929bd79ce29f38cda0437f1eae9dc40",
        "CFG": "9e769e092d33a5207cb8844b2ed2ef06",
        "PRO": "12a97fe170cd849b65c45ed689979d60"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_55e6daeb0b3a": {
      "addresses": {
        "LoD/PD2": "0x7B3369CA"
      },
      "rvas": {
        "LoD/PD2": "0x69CA"
      },
      "sizes": {
        "LoD/PD2": 113
      },
      "name": "getSystemCP",
      "signature": "int getSystemCP(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl getSystemCP(int)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:55e6daeb0b3a2f6cfed9f312027ebf3a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "55e6daeb0b3a2f6cfed9f312027ebf3a",
        "CFG": "2eac58840615cf8c3efb808b75a8ecaf",
        "PRO": "55e641fc0586378379e9e0fe90762d1d"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_c0c6df9df199": {
      "addresses": {
        "LoD/PD2": "0x7B336A3B"
      },
      "rvas": {
        "LoD/PD2": "0x6A3B"
      },
      "sizes": {
        "LoD/PD2": 99
      },
      "name": "InitializeDefaultCodePageTables",
      "signature": "void InitializeDefaultCodePageTables(void * pCodePageInfo)",
      "calling_convention": "__cdecl",
      "comment": "Initializes a code page info structure with default character mapping tables.\n\nAlgorithm:\n1. Clear the character type table (257 bytes) using memset\n2. Initialize structure header fields (offsets +0x4, +0x8, +0x21c) to zero\n3. Initialize locale name field and reserved fields to zero (offsets +0xc to +0x14)\n4. Copy 257-byte forward code page mapping from global table DAT_7b3450b8\n5. Copy 256-byte reverse mapping table from global table DAT_7b3451b9\n\nParameters:\n- pCodePageInfo: Pointer to code page info structure to initialize\n\nReturns:\n- void\n\nSpecial Cases:\n- This is a fallback initialization used when normal code page lookup fails\n- The function initializes both forward and reverse character mappings\n- Magic numbers: 0x101 (257 bytes for forward table), 0x100 (256 bytes for reverse)\n- Offsets: +0x18 (forward table), +0x119 (reverse table, calculated as 0x18+0x101)\n\nStructure Layout:\nOffset | Size | Field Name         | Type       | Description\n-------|------|-------------------|------------|--------------------\n0x0    | 4    | reserved0         | dword      | Reserved field\n0x4    | 4    | codePageId        | dword      | Code page identifier\n0x8    | 4    | flags             | dword      | Locale/encoding flags\n0xc    | 8    | localeData        | dword[2]   | Locale-specific data (6 words total)\n0x18   | 257  | charTypeTable     | byte[257]  | Character type mapping (0-256)\n0x119  | 256  | reverseMapping    | byte[256]  | Reverse character mapping\n0x21c  | 4    | localeName        | wchar_t*   | Pointer to locale name string",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c0c6df9df1992eca33150f0384391f99",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c0c6df9df1992eca33150f0384391f99",
        "CFG": "cb55111c99dcd27c33594c903599235c",
        "PRO": "e0f59548f29e2f31edb7dc08a2a9caf6"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_9081b130a587": {
      "addresses": {
        "LoD/PD2": "0x7B336A9E"
      },
      "rvas": {
        "LoD/PD2": "0x6A9E"
      },
      "sizes": {
        "LoD/PD2": 421
      },
      "name": "InitializeCharacterTypeTables",
      "signature": "void InitializeCharacterTypeTables(void * pCodePageInfo)",
      "calling_convention": "__cdecl",
      "comment": "Initializes character type tables and case mapping tables for a specific code page.\n\nAlgorithm:\n1. Verify stack cookie for security validation\n2. Check if code page is 0xFDE9 (invalid marker); if so, use fallback initialization\n3. If invalid code page, fill character type table with simple defaults (0x10 for A-Z, 0x20 for a-z)\n4. If valid code page, call GetCPInfo to retrieve code page information including lead byte ranges\n5. Initialize base character map [0..0xFF] with identity mapping and space at index 0\n6. Mark all lead bytes in base map as spaces (0x20) to exclude from processing\n7. Call ConvertAndCheckStringCharacterTypes to classify characters (alpha, digit, etc.)\n8. Call LCMapStringA twice to generate uppercase and lowercase case mappings\n9. For each byte 0..0xFF:\n   - Check character type flags from classification table\n   - If character is uppercase (flag 0x1), set 0x10 flag and store uppercase mapping\n   - If character is lowercase (flag 0x2), set 0x20 flag and store lowercase mapping\n   - If neither, store 0x00 (unmapped)\n10. Store final mapped character in table[byte + 0x100] for reverse lookups\n11. Verify stack cookie before returning\n\nParameters:\n  pCodePageInfo: void* - Pointer to code page information structure containing:\n    +0x4: UINT code page identifier\n    +0x19: BYTE[256] - Character type flags table (output)\n    +0x21C: WCHAR* - Reserved/flags for LCMapStringA operations\n\nReturns:\n  void - Modifies character tables in-place via pCodePageInfo pointer\n\nSpecial Cases:\n  - Code page 0xFDE9 triggers fallback simple initialization\n  - Lead bytes in multi-byte code pages are marked as spaces to prevent mapping\n  - Character type flags: 0x10 = uppercase, 0x20 = lowercase, 0x00 = unmapped\n  - Reverse lookup table at [base + 0x100] stores mapped character values for quick lookup\n  - Stack cookie validation provides buffer overflow detection",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9081b130a587a4d185bf061a84c1269f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9081b130a587a4d185bf061a84c1269f",
        "CFG": "af90d421740e5e6c68665eec611a98f7",
        "PRO": "a334a3dc4bb1291f61b82e3b98e381f3"
      },
      "basic_block_counts": {
        "LoD/PD2": 50
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_f54e4b4076bd": {
      "addresses": {
        "LoD/PD2": "0x7B336C43"
      },
      "rvas": {
        "LoD/PD2": "0x6C43"
      },
      "sizes": {
        "LoD/PD2": 341
      },
      "name": "InitializeThreadCodePage",
      "signature": "int InitializeThreadCodePage(int codePage, char requiresInitialization, __acrt_ptd * threadData, __crt_multibyte_data * * pMultibyteData)",
      "calling_convention": "__cdecl",
      "comment": "Initializes multibyte character code page data for the current thread.\n\nAlgorithm:\n1. Update thread's multibyte data pointers via update_thread_multibyte_data_internal\n2. Retrieve system code page identifier using getSystemCP\n3. Check if system code page matches current thread code page at offset +0x48/+0x4\n4. If already correct, return success (0)\n5. If different:\n   a. Allocate 0x220 byte buffer for new code page info structure\n   b. Return -1 (ERROR) if allocation fails\n   c. Copy current code page data (0x88 dwords) to local stack buffer\n   d. Copy local buffer to newly allocated structure\n   e. Clear first dword (offset +0x0) of new structure\n   f. Initialize new code page info with InitializeCodePageInfo\n   g. If initialization fails, free allocated memory and return -1\n6. If initialization succeeds:\n   a. If requiresInitialization flag set, call AtomicTestAndSetInitFlag\n   b. Perform atomic decrement of reference count at *[threadData+0x48]\n   c. If reference count reaches 0 and not default code page, free old structure\n   d. Set first dword of new structure to 1 (initialized flag)\n   e. Update thread data pointer to new structure at threadData+0x48\n7. If condition flag [threadData+0x350] & DAT_7b345730 == 0:\n   a. Call SEH-guarded code block with parameter references\n   b. If initializeGlobals flag set, store multibyte data to global DAT_7b34567c\n8. Free temporary allocation (if applicable) and return status code\n\nParameters:\n  codePage: Code page identifier to initialize\n  requiresInitialization: Flag indicating if global initialization required (0=no, 1=yes)\n  threadData: Pointer to thread control block (__acrt_ptd structure)\n  pMultibyteData: Pointer to multibyte data structure pointer\n\nReturns:\n  0: Success, code page already initialized\n  1: Success, new code page initialized\n  -1: Failure, either allocation failed or initialization error\n\nSpecial Cases:\n  - Magic value 0x220 (544 bytes): Size of code page info structure allocation\n  - Magic value 0x88 (136 dwords): Copy size for code page data (544 bytes / 4)\n  - Default code page address: 0x7b3450a0 (compared against to avoid freeing default)\n  - Code page location: Always at threadData[0x48], sub-offset +4 for actual code page ID\n  - Atomic operations: Uses LOCK prefix for thread-safe reference count decrement",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f54e4b4076bdafe44f8e53fd946f14ed",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f54e4b4076bdafe44f8e53fd946f14ed",
        "CFG": "c9242ff4098950bb196a356b0a7cd8c7",
        "PRO": "de8afe59bf1d3d0b5440cb44ff00c50b"
      },
      "basic_block_counts": {
        "LoD/PD2": 17
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_9bc05fe94e2b": {
      "addresses": {
        "LoD/PD2": "0x7B336D98"
      },
      "rvas": {
        "LoD/PD2": "0x6D98"
      },
      "sizes": {
        "LoD/PD2": 129
      },
      "name": "update_thread_multibyte_data_internal",
      "signature": "__crt_multibyte_data * update_thread_multibyte_data_internal(__acrt_ptd * param_1, __crt_multibyte_data * * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n struct __crt_multibyte_data * __cdecl update_thread_multibyte_data_internal(struct __acrt_ptd * const,struct __crt_multibyte_data * * const)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9bc05fe94e2b9303b8e97be2aa0fb172",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9bc05fe94e2b9303b8e97be2aa0fb172",
        "CFG": "36932fe0346a00c6ccf28110d4a63fcd",
        "PRO": "3741a117f669e5ee49566c4067f5b917"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_f23ef2b3a6cf": {
      "addresses": {
        "LoD/PD2": "0x7B33A423"
      },
      "rvas": {
        "LoD/PD2": "0xA423"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "UnlockMultithreadDataLock",
      "signature": "void UnlockMultithreadDataLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases lock for multi-threaded C runtime data access.\n\nAlgorithm:\n1. Call ___acrt_unlock with lock ID 5 to release the multi-threaded data lock\n2. Return to caller\n\nParameters:\nNone - wrapper function that unlocks a fixed-ID resource\n\nReturns:\nvoid\n\nSpecial Cases:\nLock ID 5 is reserved for multi-threaded string conversion state in Visual C runtime\nCalled as part of thread-local data initialization/cleanup sequence\nPaired with lock acquisition in update_thread_multibyte_data_internal",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "211c041d2750fdb055d3452229e7c914"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_a3be8b06a2b4": {
      "addresses": {
        "LoD/PD2": "0x7B338980"
      },
      "rvas": {
        "LoD/PD2": "0x8980"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "RestoreExceptionHandler",
      "signature": "void RestoreExceptionHandler(void)",
      "calling_convention": "__stdcall",
      "comment": "Restores the exception handler pointer from the saved stack location.\n\nThis function restores the thread's exception handler pointer (stored in FS:[0])\nfrom a previously saved value on the stack. This is typically called during\nstructured exception handling (SEH) cleanup, restoring the previous exception\nhandler chain when exiting a protected block.\n\nAlgorithm:\n1. Load the saved exception handler pointer from [EBP - 0x10] into ECX\n2. Store the exception handler pointer into FS:[0] to restore the handler chain\n3. Restore saved register state (ECX, EDI, ESI, EBX) from the stack\n4. Execute LEAVE to restore EBP and SP\n5. Return to caller\n\nReturns:\n  void - No return value; function modifies the exception handler state\n\nSpecial Cases:\n  - FS:[0] is the exception handler pointer used by Windows SEH mechanism\n  - Stack frame is preserved via LEAVE instruction before return\n  - Register restoration order: ECX, EDI, ESI, EBX (reverse of save order)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a3be8b06a2b40480e0229ac7ae834885",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a3be8b06a2b40480e0229ac7ae834885",
        "CFG": null,
        "PRO": "3ada8c8978f649fc965bd35cb94fda43"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_d91349f5defa": {
      "addresses": {
        "LoD/PD2": "0x7B336E38"
      },
      "rvas": {
        "LoD/PD2": "0x6E38"
      },
      "sizes": {
        "LoD/PD2": 72
      },
      "name": "___acrt_initialize_multibyte",
      "signature": "undefined4 ___acrt_initialize_multibyte(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_initialize_multibyte\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d91349f5defa655773f15756410cc404",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d91349f5defa655773f15756410cc404",
        "CFG": "e8304c2afda95740a391a275b6b161fd",
        "PRO": "ee1decd11d05f37188aa24a3f1d2d12d"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_05763b103f9f": {
      "addresses": {
        "LoD/PD2": "0x7B336E80"
      },
      "rvas": {
        "LoD/PD2": "0x6E80"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "InitializeThreadMultibyteData",
      "signature": "void InitializeThreadMultibyteData(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize thread-specific multibyte character data for locale support.\n\nThis function ensures that each thread has properly initialized multibyte character\ndata structures for the current locale. It retrieves or creates thread-local data\nand updates the multibyte character encoding information used by locale-dependent\nstring operations.\n\nAlgorithm:\n1. Call GetOrCreateThreadData() to obtain/create thread context structure\n2. Pass thread context and global multibyte data pointer to update_thread_multibyte_data_internal()\n3. Return to caller after initialization complete\n\nParameters:\nNone: Function takes no parameters; operates on thread-local data structures\n\nReturns:\nvoid: No return value; initializes thread state as side effect\n\nSpecial Cases:\nDAT_7b345fc0: Global multibyte data pointer passed to update function; points to\nlocale-specific multibyte character encoding tables and state structures\nGlobal state: Function modifies thread-local data; safe for concurrent calls from\ndifferent threads as each operates on separate thread context",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:05763b103f9f2ac70627795795ca4ee1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "05763b103f9f2ac70627795795ca4ee1",
        "CFG": null,
        "PRO": "d8d593375e4b196a5be132cf998621f6"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_79af0bc23b87": {
      "addresses": {
        "LoD/PD2": "0x7B336E93"
      },
      "rvas": {
        "LoD/PD2": "0x6E93"
      },
      "sizes": {
        "LoD/PD2": 517
      },
      "name": "InitializeCodePageInfo",
      "signature": "void InitializeCodePageInfo(uint codePageId, void * pCodePageInfo)",
      "calling_convention": "__cdecl",
      "comment": "Initializes code page information structure with character type tables and locale data.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:79af0bc23b876e2e49bc9fca4ac6ba51",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "79af0bc23b876e2e49bc9fca4ac6ba51",
        "CFG": "3f3ca72292dc36e5d2f161287468afe0",
        "PRO": "21636fed5a524f0f6b5cbaa34d77c029"
      },
      "basic_block_counts": {
        "LoD/PD2": 38
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_dba49a9c71c9": {
      "addresses": {
        "LoD/PD2": "0x7B337098"
      },
      "rvas": {
        "LoD/PD2": "0x7098"
      },
      "sizes": {
        "LoD/PD2": 129
      },
      "name": "_memcpy_s",
      "signature": "errno_t _memcpy_s(void * _Dst, rsize_t _DstSize, void * _Src, rsize_t _MaxCount)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memcpy_s\n\nLibraries: Visual Studio 2012, Visual Studio 2015, Visual Studio 2017, Visual Studio 2019",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:dba49a9c71c970d66b5110c04eefbf85",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "dba49a9c71c970d66b5110c04eefbf85",
        "CFG": "8f8c300876570b5d8e434f76a3ca5407",
        "PRO": "cdf88f293ebb89243786763a3f153b4e"
      },
      "basic_block_counts": {
        "LoD/PD2": 15
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_e42ca910bd4d": {
      "addresses": {
        "LoD/PD2": "0x7B337119"
      },
      "rvas": {
        "LoD/PD2": "0x7119"
      },
      "sizes": {
        "LoD/PD2": 80
      },
      "name": "ValidateCharacterAttribute",
      "signature": "uint ValidateCharacterAttribute(void * pCharLookupTable, byte characterIndex, uint attributeMask, byte flagMask)",
      "calling_convention": "__cdecl",
      "comment": "Validates whether a character has a specific attribute flag set in lookup tables.\n\nAlgorithm:\n1. Call GetOrCreateThreadData to retrieve thread-local character lookup tables\n2. Get character properties byte from table at offset [charPropertiesTable + 0x19 + characterIndex]\n3. Check if flagMask bits are set in the properties byte\n4. If any flag bits set, jump to match_found - return 1\n5. If no flags set, check if attributeMask is non-zero (skip attribute check if zero)\n6. If attributeMask is zero, return 0 (no match)\n7. If attributeMask is non-zero, load attribute word from [attributeTablePtr[0] + characterIndex*2]\n8. Test if (attributeMask AND loaded_attribute_word) is non-zero\n9. If bits match, return 1; if no bits match, return 0\n10. If needsCleanup flag is set, clear bit 0x2 from [threadData + 0x350]\n\nParameters:\n  pCharLookupTable: Pointer to thread-local character property lookup table (may be NULL)\n  characterIndex: Index of character to validate (0-255)\n  attributeMask: Bitmask for attribute validation; 0 means skip attribute check\n  flagMask: Bitmask for direct property flag check\n\nReturns:\n  uint: 1 if character has the specified attribute/flag, 0 if not\n\nSpecial Cases:\n  - Returns 0 if pCharLookupTable is NULL (no lookup data available)\n  - attributeMask of 0 causes function to skip attribute table check\n  - Character properties stored as byte at fixed offset +0x19 in table\n  - Attributes stored as words (2 bytes) indexed by characterIndex*2\n  - Thread cleanup flag at offset 0x350 in thread data\n  - Cleanup bit 0x2 is cleared if needsCleanup is set",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e42ca910bd4d3da6dbcd9fea211b0276",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e42ca910bd4d3da6dbcd9fea211b0276",
        "CFG": "d977068f91f71cd3a21101f3f0e9a64a",
        "PRO": "7bd03aeb95f988a3d64325565d8789ed"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_a0233b04111e": {
      "addresses": {
        "LoD/PD2": "0x7B337169"
      },
      "rvas": {
        "LoD/PD2": "0x7169"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "IsEscapeCharacter",
      "signature": "undefined4 IsEscapeCharacter(byte character)",
      "calling_convention": "__cdecl",
      "comment": "Determines if a character requires special escape sequence handling during command-line parsing.\n\nAlgorithm:\n1. Call FUN_7b337119 with character as second parameter\n2. Pass additional flags: third param=0, fourth param=4 (escape attribute flag)\n3. FUN_7b337119 checks character properties against internal lookup tables\n4. Return non-zero if character has escape flag (0x4) set, 0 if no escape needed\n\nParameters:\n  character: Single byte character to check for escape sequence requirements\n\nReturns:\n  undefined4: Non-zero (1) if character requires escaping, 0 if no escape needed\n\nContext:\n  Called by ParseCommandLineArguments during command-line string parsing.\n  Used to identify characters that need escape handling with backslash.\n  Wrapper function delegating to FUN_7b337119 character property checker.\n\nSpecial Cases:\n  - Return value is treated as boolean (non-zero = true, zero = false)\n  - Flag 0x4 indicates character needs escape handling in command strings\n  - Escape characters allow literal inclusion of special chars in arguments",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a0233b04111edb7a8a617e9b940ca401",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a0233b04111edb7a8a617e9b940ca401",
        "CFG": null,
        "PRO": "258e305e32fecd402f33ed337f79f36c"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_f5adec5b89fa": {
      "addresses": {
        "LoD/PD2": "0x7B33719A"
      },
      "rvas": {
        "LoD/PD2": "0x719A"
      },
      "sizes": {
        "LoD/PD2": 152
      },
      "name": "ClassifyWideCharacter",
      "signature": "uint ClassifyWideCharacter(uint charCode, uint flags)",
      "calling_convention": "__cdecl",
      "comment": "Classifies wide character codes and determines character properties.\n\nAlgorithm:\n1. Load character code from first parameter into EAX\n2. Compare against multiple Unicode code point groups:\n   - First group: codes < 0xdead (includes 0x2a, 0xc42c-0xc42e, 0xc431-0xc435)\n   - Second group: codes >= 0xdead but <= 0xdeb1 (includes 0xdead-0xdeae, 0xdeac)\n   - Third group: codes > 0xdeb1 (includes 0xdeb1-0xdeb3, 0xfde9, 0xf9e8)\n3. For recognized character codes, return 0\n4. For code 0xfde9 or others in third group, apply flags mask (flags & 8)\n5. For unrecognized codes, return flags parameter unchanged\n\nParameters:\ncharCode: uint - Unicode code point to classify (checked against magic numbers)\nflags: uint - Character property flags (returned on match)\n\nReturns:\nuint - 0 for classified codes, (flags & 8) for special codes, flags for unrecognized\n\nSpecial Cases:\n- Code 0xfde9 is special: returns only bit 3 of flags (mask 0x8)\n- Code 0xd698 also triggers special return (flags & 8)\n- Multiple code groups handled with sequential subtraction checks\n- Unrecognized codes return flags unchanged for passthrough behavior",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f5adec5b89fa18d060bee6305a312fb6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f5adec5b89fa18d060bee6305a312fb6",
        "CFG": "ef503b57559f1d264a6c58a545f5a99a",
        "PRO": "3000ce8aea0c63e466ab12d459ff9f2d"
      },
      "basic_block_counts": {
        "LoD/PD2": 27
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_d13e3a9dfbfc": {
      "addresses": {
        "LoD/PD2": "0x7B337232"
      },
      "rvas": {
        "LoD/PD2": "0x7232"
      },
      "sizes": {
        "LoD/PD2": 42
      },
      "name": "ConvertMultiByteToWideChar",
      "signature": "void ConvertMultiByteToWideChar(uint codePage, uint flags, LPCSTR sourceString, int sourceLength, LPWSTR destBuffer, int destLength)",
      "calling_convention": "__cdecl",
      "comment": "Converts a multi-byte character string to a wide-character string using Windows API.\n\nAlgorithm:\n1. Query character conversion flags for the specified code page by calling FUN_7b33719a\n2. Call Windows MultiByteToWideChar API with the code page, flags, source string, and destination buffer\n3. Return to caller\n\nParameters:\n- codePage: Code page identifier (e.g., CP_ACP for ANSI, CP_UTF8 for UTF-8)\n- flags: Conversion flags (used by MultiByteToWideChar, typically 0 or MB_PRECOMPOSED)\n- sourceString: Pointer to null-terminated multi-byte source string\n- sourceLength: Length of source string in bytes (-1 for null-terminated)\n- destBuffer: Pointer to wide-character destination buffer\n- destLength: Size of destination buffer in wide characters\n\nReturns:\n- void (result not returned; caller checks buffer contents)\n\nSpecial Cases:\n- If sourceLength is -1, the function treats sourceString as null-terminated\n- destLength should be at least ceil(sourceLength * 4) for safety\n- Conversion flags obtained from FUN_7b33719a determine character handling (e.g., composite characters)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d13e3a9dfbfc1a6057ef6afb0e3c13bf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d13e3a9dfbfc1a6057ef6afb0e3c13bf",
        "CFG": null,
        "PRO": "5ccf98067ecadb528cbec98c2208cc79"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "PD2_EXT_MNE_2f554e15a48b": {
      "addresses": {
        "LoD/PD2": "0x7B33725C"
      },
      "rvas": {
        "LoD/PD2": "0x725C"
      },
      "sizes": {
        "LoD/PD2": 144
      },
      "name": "FilterCharacterByCodePoint",
      "signature": "uint FilterCharacterByCodePoint(uint unicodeCodePoint, uint charAttributes)",
      "calling_convention": "__cdecl",
      "comment": "Filters Unicode characters by checking against a predefined list of code points.\\n\\nAlgorithm:\\n1. Compare unicodeCodePoint against three ranges: [0x0, 0xc433], [0xc434, 0xdead), [0xdead, infinity)\\n2. Within each range, check for specific character code points (0x2a, 0xc42c-0xc42e, 0xc431, 0xc433, 0xc435, 0xd698, 0xdead-0xdeb3, 0xfde8)\\n3. If code point matches a forbidden value, return 0 (filtered/blocked)\\n4. If code point does not match any forbidden values, return charAttributes with bit 0x80 cleared (unfiltered)\\n\\nParameters:\\n  unicodeCodePoint - Unicode code point value to filter\\n  charAttributes - Character attributes containing flags (bit 0x80 is filtering flag)\\n\\nReturns:\\n  0 if code point is forbidden/filtered\\n  charAttributes & 0xffffff7f if code point is allowed (bit 0x80 cleared)\\n\\nSpecial Cases:\\n  Multiple character ranges checked: Korean Hangul (0xc42c-0xc435), Thai (0xd698), Arabic (0xdead-0xdeb3), unassigned (0xfde8)\\n  Magic constant 0xfde8 represents unassigned Unicode point\\n  Bit mask 0xffffff7f clears the high bit (0x80) from character attributes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2f554e15a48ba5e5331f929500321d63",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2f554e15a48ba5e5331f929500321d63",
        "CFG": "922a42e28bc123f0d5d8837a2850ede6",
        "PRO": "0f6f513bdcb3f7763480a929f947dc1a"
      },
      "basic_block_counts": {
        "LoD/PD2": 25
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_6f90fe512523": {
      "addresses": {
        "LoD/PD2": "0x7B3372EC"
      },
      "rvas": {
        "LoD/PD2": "0x72EC"
      },
      "sizes": {
        "LoD/PD2": 108
      },
      "name": "ConvertWideCharToMultiByte",
      "signature": "void ConvertWideCharToMultiByte(uint dwCodePage, uint dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, uint dwCompFlags, LPBOOL lpUsedDefaultChar)",
      "calling_convention": "__cdecl",
      "comment": "Converts wide character string to multibyte (ANSI) string with proper codepage handling.\\n\\nAlgorithm:\\n1. Check if codepage is UTF-7 (65000) or special variant (0xfde9)\\n2. Get conversion flags from FUN_7b33725c\\n3. For UTF-7/variant: clear the output flag parameter if provided\\n4. Call WideCharToMultiByte with conditional parameters based on codepage\\n5. Return from function\\n\\nParameters:\\n- dwCodePage: Target codepage (65000=UTF-7, 0xfde9=UTF-8 variant, others standard)\\n- dwFlags: Input flags for conversion behavior\\n- lpWideCharStr: Source wide character string (LPCWSTR)\\n- cchWideChar: Character count of wide string\\n- lpMultiByteStr: Destination buffer for multibyte string (LPSTR)\\n- cbMultiByte: Size of destination buffer in bytes\\n- dwCompFlags: Additional flags (conditionally used based on codepage)\\n- lpUsedDefaultChar: Optional output flag (conditionally used based on codepage)\\n\\nReturns:\\n- void\\n\\nSpecial Cases:\\n- UTF-7 (65000) and 0xfde9: Handle flag initialization and conditional parameter passing\\n- Conditional parameter masking: dwCompFlags and lpUsedDefaultChar only used for non-UTF codepages\\n- Flag initialization: lpUsedDefaultChar is zeroed for UTF codepages to prevent undefined behavior\\n\\nStructure Layout:\\nNone (wrapper function for Windows API)\\n\\nNotes:\\nThe function implements conditional parameter passing to WideCharToMultiByte based on codepage type.\\nThis is a thin wrapper that handles UTF-specific behavior before delegating to the system API.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6f90fe512523992448a711651a71fc2c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6f90fe512523992448a711651a71fc2c",
        "CFG": "3a585170bc4bf7b3485c5d93cab06b1b",
        "PRO": "61bf5d940571fd5d67c3d14a54619b53"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "PD2_EXT_MNE_a95646d8d22c": {
      "addresses": {
        "LoD/PD2": "0x7B337358"
      },
      "rvas": {
        "LoD/PD2": "0x7358"
      },
      "sizes": {
        "LoD/PD2": 55
      },
      "name": "find_end_of_double_null_terminated_sequence",
      "signature": "wchar_t * find_end_of_double_null_terminated_sequence(wchar_t * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n wchar_t const * __cdecl find_end_of_double_null_terminated_sequence(wchar_t const * const)\n\nLibraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a95646d8d22ce011ed8cfdab99140425",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a95646d8d22ce011ed8cfdab99140425",
        "CFG": "fe43afd9f3cfefc6a888c38c288cd751",
        "PRO": "b3663a0d95934c4929855bc560f9917e"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_9986705100b1": {
      "addresses": {
        "LoD/PD2": "0x7B33738F"
      },
      "rvas": {
        "LoD/PD2": "0x738F"
      },
      "sizes": {
        "LoD/PD2": 160
      },
      "name": "CopyEnvironmentStringsW",
      "signature": "LPWCH CopyEnvironmentStringsW(void)",
      "calling_convention": "__stdcall",
      "comment": "Allocates and copies the environment variable block to a new buffer.\n\nThis function retrieves the system environment variables string block via GetEnvironmentStringsW, calculates its total size by finding the double-null terminator, allocates new memory, and copies the environment block into that memory. The original system environment block is freed after copying.\n\nAlgorithm:\n1. Call GetEnvironmentStringsW to get the system environment block pointer\n2. Call find_end_of_double_null_terminated_sequence to locate the end of the environment block\n3. Calculate the environment block size in characters (bytes / 2)\n4. Call FUN_7b3372ec with size=0 to query the memory needed for conversion\n5. If size calculation fails, free original block and return NULL\n6. Allocate memory for the environment block using __malloc_base\n7. If allocation fails, call error handler FUN_7b335e34 and return NULL\n8. Call FUN_7b3372ec again with destination buffer to perform actual copy\n9. If copy succeeds, call FUN_7b335e34(NULL) for cleanup\n10. If copy fails, call FUN_7b335e34 with allocated buffer and return NULL\n11. Always free the original system environment block with FreeEnvironmentStringsW\n12. Return allocated buffer with copied data or NULL on any failure\n\nParameters: (none)\n\nReturns:\n  LPWCH - Pointer to newly allocated buffer containing copied environment strings, or NULL if operation failed\n\nSpecial Cases:\n  - GetEnvironmentStringsW returns NULL if no environment block exists\n  - Double-null terminator (0x0000) marks end of environment string array\n  - Size calculation and actual copy are separate operations via FUN_7b3372ec\n  - All error paths clean up by freeing both original and allocated buffers\n  - FUN_7b335e34 appears to be an error handler that may handle memory cleanup or logging",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9986705100b11eaf7f4aa4131d6686b4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9986705100b11eaf7f4aa4131d6686b4",
        "CFG": "0d3e35d28ed73875cc5ddd828625347a",
        "PRO": "ea9f1ed1b06cb4db9f1b58e75e925e57"
      },
      "basic_block_counts": {
        "LoD/PD2": 17
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_211c0e57bcbe": {
      "addresses": {
        "LoD/PD2": "0x7B33742F"
      },
      "rvas": {
        "LoD/PD2": "0x742F"
      },
      "sizes": {
        "LoD/PD2": 109
      },
      "name": "__recalloc_base",
      "signature": "LPVOID __recalloc_base(void * param_1, uint param_2, uint param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __recalloc_base\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:211c0e57bcbeb6b4390a0f712029b92f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "211c0e57bcbeb6b4390a0f712029b92f",
        "CFG": "bf31b103239c8413537200f3861c6900",
        "PRO": "78624cf0a10d2bb1c3da84b7766b2136"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_STR_f9eab449ecae": {
      "addresses": {
        "LoD/PD2": "0x7B33749C"
      },
      "rvas": {
        "LoD/PD2": "0x749C"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "try_get_AreFileApisANSI",
      "signature": "_func_int * try_get_AreFileApisANSI(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int (__stdcall*__cdecl try_get_AreFileApisANSI(void))(void)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:f9eab449ecae69bd01b6f6abdcbc80b5",
      "indexes": {
        "EXP": null,
        "STR": "f9eab449ecae69bd01b6f6abdcbc80b5",
        "API": null,
        "MNE": "06ecc2bf829f9069ac3c1b4dda34cbe5",
        "CFG": null,
        "PRO": "f7994cfefd4ca57312e4b422a34f20d2"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_STR_fa1f9177d46a": {
      "addresses": {
        "LoD/PD2": "0x7B3374B6"
      },
      "rvas": {
        "LoD/PD2": "0x74B6"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "FID_conflict:try_get_LCMapStringEx",
      "signature": "undefined FID_conflict:try_get_LCMapStringEx(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Multiple Matches With Different Base Names\n int (__stdcall*__cdecl try_get_CompareStringEx(void))(wchar_t const *,unsigned long,wchar_t const *,int,wchar_t const *,int,struct _nlsversioninfo *,void *,long)\n int (__stdcall*__cdecl try_get_LCMapStringEx(void))(wchar_t const *,unsigned long,wchar_t const *,int,wchar_t *,int,struct _nlsversioninfo *,void *,long)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:fa1f9177d46a932add310f1e87b46c6a",
      "indexes": {
        "EXP": null,
        "STR": "fa1f9177d46a932add310f1e87b46c6a",
        "API": null,
        "MNE": "06ecc2bf829f9069ac3c1b4dda34cbe5",
        "CFG": null,
        "PRO": "b352334a700edcedc59c9482b91bd2ec"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_STR_392392fd6e6f": {
      "addresses": {
        "LoD/PD2": "0x7B3374D0"
      },
      "rvas": {
        "LoD/PD2": "0x74D0"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "try_get_LocaleNameToLCID",
      "signature": "_func_ulong_wchar_t_ptr_ulong * try_get_LocaleNameToLCID(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n unsigned long (__stdcall*__cdecl try_get_LocaleNameToLCID(void))(wchar_t const *,unsigned long)\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:392392fd6e6f7526e88e42b12b254196",
      "indexes": {
        "EXP": null,
        "STR": "392392fd6e6f7526e88e42b12b254196",
        "API": null,
        "MNE": "06ecc2bf829f9069ac3c1b4dda34cbe5",
        "CFG": null,
        "PRO": "015628509232b0332d76c1e238605d4b"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_STR_a4eedc969147": {
      "addresses": {
        "LoD/PD2": "0x7B3374EA"
      },
      "rvas": {
        "LoD/PD2": "0x74EA"
      },
      "sizes": {
        "LoD/PD2": 203
      },
      "name": "LoadIndexedDllModule",
      "signature": "void * LoadIndexedDllModule(int * pIndices, int * pIndicesEnd)",
      "calling_convention": "__cdecl",
      "comment": "Loads indexed DLL modules with cached handles and thread-safe synchronization.\\n\\nIterates through an array of DLL indices, loads each DLL via LoadLibraryExW with\\nLOAD_LIBRARY_SEARCH_SYSTEM32 flag (0x800), caches results in a shared array, and\\nreturns the first successfully loaded module handle. Uses LOCK/UNLOCK for atomic\\ncache operations to prevent race conditions in multi-threaded environments.\\n\\nAlgorithm:\\n1. Loop through array of indices from pIndices to pIndicesEnd\\n2. Load current index value and check cache at offset (index * 4) in cache array\\n3. If cached handle exists:\\n   - Return immediately if valid module handle (not 0 or 0xFFFFFFFF)\\n   - Continue to next index if cache marked as failed (0xFFFFFFFF)\\n4. If cache empty (0x0):\\n   - Load library path from indexed pointer array (0x7b33ef68 base)\\n   - Call LoadLibraryExW with LOAD_LIBRARY_SEARCH_SYSTEM32 flag\\n   - If load fails with ERROR_INVALID_PARAMETER (0x57):\\n     - Check if library name starts with \\\"api_ms_\\\" or \\\"ext_ms_\\\"\\n     - If neither pattern matches, retry LoadLibraryExW without flags\\n5. On success or cached valid handle:\\n   - Atomically store handle in cache (XCHG)\\n   - If old cache entry was non-zero, free it with FreeLibrary\\n   - Return loaded module handle\\n6. On failure:\\n   - Atomically mark cache as failed with 0xFFFFFFFF\\n   - Continue to next index\\n7. Return NULL (0x0) if all indices exhausted\\n\\nParameters:\\n  pIndices: int * - Pointer to array of DLL index values (start of iteration)\\n  pIndicesEnd: int * - Pointer to end of array (loop termination check)\\n\\nReturns:\\n  void * - HMODULE handle of first successfully loaded DLL, or NULL if all fail\\n\\nSpecial Cases:\\n  - API*MS* libraries (Windows 8+) use LOAD_LIBRARY_SEARCH_SYSTEM32 (0x800)\\n  - ERROR_INVALID_PARAMETER (0x57) triggers retry without flags\\n  - Cache entries use 0xFFFFFFFF as failure sentinel to prevent retry loops\\n  - Atomic XCHG operations ensure thread-safe cache updates\\n  - Old module handles freed after atomic store to clean up previous attempts\\n\\nCache Structure (0x7b345fe8 base, index * 4 offset):\\n  0x0: Empty (not yet loaded)\\n  0xFFFFFFFF: Failed (load already attempted, do not retry)\\n  Other: Valid HMODULE handle",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:a4eedc969147b655e23b105580b53461",
      "indexes": {
        "EXP": null,
        "STR": "a4eedc969147b655e23b105580b53461",
        "API": null,
        "MNE": "c1269defc9bad22b62a1916688e57cb8",
        "CFG": "21ac527cba523aaf3454972442b74108",
        "PRO": "fc2c87edb2ce4aecb91a514f07971519"
      },
      "basic_block_counts": {
        "LoD/PD2": 35
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_39c6ea94cc75": {
      "addresses": {
        "LoD/PD2": "0x7B3375B5"
      },
      "rvas": {
        "LoD/PD2": "0x75B5"
      },
      "sizes": {
        "LoD/PD2": 133
      },
      "name": "ResolveObfuscatedApiAddress",
      "signature": "FARPROC ResolveObfuscatedApiAddress(int apiIndex, LPCSTR functionName, int * pModuleHandles, int * pFunctionPointers)",
      "calling_convention": "__cdecl",
      "comment": "Resolves an obfuscated API function address from a cache or by loading and looking up.\n\nAlgorithm:\n1. Load the cached API address from table at [0x7b346040 + apiIndex*4]\n2. Apply XOR rotation deobfuscation using rotation amount from [0x7b345000]\n3. If deobfuscated value equals -1 (0xFFFFFFFF), proceed to load phase\n4. If deobfuscated value is non-zero, return it as the cached result\n5. If deobfuscated value is zero, proceed to load phase\n6. Call FUN_7b3374ea to load the required module and get module handle\n7. If module load fails, store error sentinel (-1) and return 0\n8. Call GetProcAddress [0x7b33e080] with module handle and function name\n9. If GetProcAddress fails, store error sentinel and return 0\n10. Call RotateXorTransform at 0x7b334f4d to obfuscate the function pointer\n11. Store obfuscated result back to cache at [0x7b346040 + apiIndex*4]\n12. Return the unobfuscated function pointer (EDI contains result)\n\nParameters:\n- apiIndex: Index into the API table (multiplied by 4 for array offset)\n- functionName: Name of the function to resolve (passed to GetProcAddress)\n- pModuleHandles: Pointer to module handle array/storage\n- pFunctionPointers: Pointer to function pointer array/storage\n\nReturns:\nEAX: Unobfuscated function pointer if successful, 0 if load/resolution failed",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:39c6ea94cc75a52bde6d6d6adb2af45b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "39c6ea94cc75a52bde6d6d6adb2af45b",
        "CFG": "ff721dbf63c8dc1f6e2dd3786cee79e8",
        "PRO": "e12e2c08c50397ced245ea1964ac1cfe"
      },
      "basic_block_counts": {
        "LoD/PD2": 17
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_STR_4c61a9c71696": {
      "addresses": {
        "LoD/PD2": "0x7B33763A"
      },
      "rvas": {
        "LoD/PD2": "0x763A"
      },
      "sizes": {
        "LoD/PD2": 64
      },
      "name": "GetProcessTerminationMethod",
      "signature": "int GetProcessTerminationMethod(void)",
      "calling_convention": "__stdcall",
      "comment": "Dynamically loads and invokes the AppPolicyGetProcessTerminationMethod Windows API function.\nThis function uses delayed binding to retrieve the termination method handler from kernel32.dll\nby ordinal, applies CFG (Control Flow Guard) validation, and executes the retrieved function.\nReturns either the termination method value or error code 0xc0000225 if the function is unavailable.\n\nAlgorithm:\n1. Call FUN_7b3375b5 with ordinal 0x19 to retrieve function pointer for\n   AppPolicyGetProcessTerminationMethod from kernel32.dll\n2. Test if function pointer is NULL\n3. If NULL, jump to ordinal_not_found to return error code\n4. If valid, push CFG validation value (0xfffffffa) and call guard_check_icall\n5. Call the retrieved function pointer\n6. Return result in EAX\n\nParameters:\n(none - function takes no parameters)\n\nReturns:\nint: Termination method value from AppPolicyGetProcessTerminationMethod,\n     or error code 0xc0000225 (STATUS_DLL_NOT_FOUND) if function unavailable\n\nSpecial Cases:\n- Magic number 0x19: Ordinal identifier for AppPolicyGetProcessTerminationMethod in kernel32.dll\n- Magic number 0xfffffffa: CFG check value passed to guard_check_icall validation\n- Magic number 0xc0000225: NTSTATUS error code indicating DLL function not found\n- Function uses __stdcall calling convention with callee cleanup (RET 0x4)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:4c61a9c716962c1e7eed8e34874ec39f",
      "indexes": {
        "EXP": null,
        "STR": "4c61a9c716962c1e7eed8e34874ec39f",
        "API": null,
        "MNE": "5649c9d1a738299fb1cdec24db371b01",
        "CFG": "b724ed9bc22393fb1bfd3fcd83003d6f",
        "PRO": "7b35dc4338c0447c94d92976b2f8f439"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_6c9ec7b99b0d": {
      "addresses": {
        "LoD/PD2": "0x7B33767A"
      },
      "rvas": {
        "LoD/PD2": "0x767A"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "___acrt_AreFileApisANSI@0",
      "signature": "int ___acrt_AreFileApisANSI@0(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_AreFileApisANSI@0\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6c9ec7b99b0db251912cc83a9da1745a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6c9ec7b99b0db251912cc83a9da1745a",
        "CFG": "ebedb8faf55908534e596ba5d47d40c7",
        "PRO": "c2ec7cbe6780d1943a07d0dca833746e"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_ecc255d93f2d": {
      "addresses": {
        "LoD/PD2": "0x7B337699"
      },
      "rvas": {
        "LoD/PD2": "0x7699"
      },
      "sizes": {
        "LoD/PD2": 63
      },
      "name": "___acrt_FlsAlloc@4",
      "signature": "undefined ___acrt_FlsAlloc@4(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_FlsAlloc@4\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ecc255d93f2de7bd40d203689b269209",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ecc255d93f2de7bd40d203689b269209",
        "CFG": "85e807ad41b8340ac7aa6e764f7d6a4d",
        "PRO": "d9642e25c09a78984799f232dac81bb8"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_23cf53ccba93": {
      "addresses": {
        "LoD/PD2": "0x7B337717"
      },
      "rvas": {
        "LoD/PD2": "0x7717"
      },
      "sizes": {
        "LoD/PD2": 63
      },
      "name": "___acrt_FlsFree@4",
      "signature": "undefined ___acrt_FlsFree@4(DWORD param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_FlsFree@4\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:23cf53ccba938ee171a7985d0643662b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "23cf53ccba938ee171a7985d0643662b",
        "CFG": "ae5a7295f41b2cc6d381601031fd744e",
        "PRO": "2ff469b73c286f3db22a9c22dd5b4126"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_a6b920955629": {
      "addresses": {
        "LoD/PD2": "0x7B337756"
      },
      "rvas": {
        "LoD/PD2": "0x7756"
      },
      "sizes": {
        "LoD/PD2": 66
      },
      "name": "___acrt_FlsSetValue@8",
      "signature": "undefined ___acrt_FlsSetValue@8(DWORD param_1, LPVOID param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_FlsSetValue@8\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a6b920955629fe293acf22149f429a20",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a6b920955629fe293acf22149f429a20",
        "CFG": "b41b669e2a92a6b4b08274310bd54407",
        "PRO": "0f3e15b8f7082ab8081d4c054f1577ed"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_6f93d754e044": {
      "addresses": {
        "LoD/PD2": "0x7B337798"
      },
      "rvas": {
        "LoD/PD2": "0x7798"
      },
      "sizes": {
        "LoD/PD2": 75
      },
      "name": "___acrt_InitializeCriticalSectionEx@12",
      "signature": "undefined ___acrt_InitializeCriticalSectionEx@12(LPCRITICAL_SECTION param_1, DWORD param_2, undefined4 param_3)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_InitializeCriticalSectionEx@12\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6f93d754e044efa070526b303204bf07",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6f93d754e044efa070526b303204bf07",
        "CFG": "b0b6c8a5de38261b0976fdc3569fd12f",
        "PRO": "42eba447fef782713ed0f64a0a4c86c1"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_0f096e2572c6": {
      "addresses": {
        "LoD/PD2": "0x7B3377E3"
      },
      "rvas": {
        "LoD/PD2": "0x77E3"
      },
      "sizes": {
        "LoD/PD2": 93
      },
      "name": "FID_conflict:___acrt_CompareStringEx@36",
      "signature": "undefined FID_conflict:___acrt_CompareStringEx@36(wchar_t * param_1, DWORD param_2, LPCWSTR param_3, int param_4, LPWSTR param_5, int param_6, undefined4 param_7, undefined4 param_8, undefined4 param_9)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Multiple Matches With Different Base Names\n ___acrt_CompareStringEx@36\n ___acrt_LCMapStringEx@36\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0f096e2572c6a1c02c79779c4dda7c78",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0f096e2572c6a1c02c79779c4dda7c78",
        "CFG": "d69bc82e329d76c21526cdfbd9e8cc3d",
        "PRO": "3f2cddfae12cd701d8e538eadbeb702a"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 9
      }
    },
    "PD2_EXT_MNE_de454e6d0988": {
      "addresses": {
        "LoD/PD2": "0x7B337840"
      },
      "rvas": {
        "LoD/PD2": "0x7840"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "___acrt_LocaleNameToLCID@8",
      "signature": "undefined ___acrt_LocaleNameToLCID@8(wchar_t * param_1, ulong param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_LocaleNameToLCID@8\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:de454e6d09883e71084bfc6752b21a8c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "de454e6d09883e71084bfc6752b21a8c",
        "CFG": "6c3b0aa07951c5e00ecf5c0f67c56cb3",
        "PRO": "aa80c99e869e1dc41cc243703ff4d118"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_10dc882307c4": {
      "addresses": {
        "LoD/PD2": "0x7B337885"
      },
      "rvas": {
        "LoD/PD2": "0x7885"
      },
      "sizes": {
        "LoD/PD2": 54
      },
      "name": "___acrt_uninitialize_winapi_thunks",
      "signature": "undefined1 ___acrt_uninitialize_winapi_thunks(char param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_uninitialize_winapi_thunks\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:10dc882307c46086e1e49866197b18da",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "10dc882307c46086e1e49866197b18da",
        "CFG": "3c82f776bc14fd149747b0369faec340",
        "PRO": "e6531ca509cc44dfb04d4c4209be523c"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_2dcb77563266": {
      "addresses": {
        "LoD/PD2": "0x7B3378D6"
      },
      "rvas": {
        "LoD/PD2": "0x78D6"
      },
      "sizes": {
        "LoD/PD2": 182
      },
      "name": "initialize_inherited_file_handles_nolock",
      "signature": "void initialize_inherited_file_handles_nolock(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl initialize_inherited_file_handles_nolock(void)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2dcb775632664051b0ebbd14e3616bba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2dcb775632664051b0ebbd14e3616bba",
        "CFG": "76ee64efd521ccdda93299f40f5aa2f2",
        "PRO": "45f86cbaf3950584cd384c577adc4335"
      },
      "basic_block_counts": {
        "LoD/PD2": 19
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_aec8926cff9c": {
      "addresses": {
        "LoD/PD2": "0x7B33798C"
      },
      "rvas": {
        "LoD/PD2": "0x798C"
      },
      "sizes": {
        "LoD/PD2": 176
      },
      "name": "InitializeStdioHandles",
      "signature": "void InitializeStdioHandles(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes standard I/O file handles for stdin, stdout, and stderr.\n\nAlgorithm:\n1. Loop through 3 standard file descriptor indices (0=stdin, 1=stdout, 2=stderr)\n2. Calculate file descriptor structure pointer using strided lookup table\n3. Check if descriptor already initialized (handle != -1 and != -2)\n4. If uninitialized, retrieve appropriate standard handle via GetStdHandle()\n5. Validate handle is not invalid (not -1, not NULL)\n6. Determine handle type using GetFileType() API\n7. Store handle in descriptor structure and set type flags:\n   - FILE_TYPE_PIPE (2): Set flag 0x40 (pipe flag)\n   - FILE_TYPE_CHAR (3): Set flag 0x08 (character device flag)\n8. If validation fails at any step, mark as invalid (0xfffffffe) and set error flag\n9. For stdio redirects, also update referenced pointer array if available\n\nParameters:\nNone - uses static file descriptor table at 0x7b3460d0\n\nReturns:\nNone (void function)\n\nSpecial Cases:\n- GetStdHandle() constants: 0xfffffff6=stdin, 0xfffffff5=stdout, 0xfffffff4=stderr\n- Invalid handle value: 0xfffffffe indicates initialization failure\n- Descriptor structure: 0x38 bytes, handle field at +0x18, flags field at +0x28\n- Optional redirect table at 0x7b3462f4 contains pointers to alternate descriptor blocks\n\nStructure Layout:\nOffset  Size  Field Name          Type      Description\n0x00    0x18  Reserved            unknown   Unanalyzed prefix data\n0x18    0x04  handle              HANDLE    Windows file handle for I/O\n0x28    0x01  flags               byte      Type/status flags (0x81=init, 0x40=pipe, 0x08=char)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:aec8926cff9c96a2b57b5f95d180efe9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "aec8926cff9c96a2b57b5f95d180efe9",
        "CFG": "9ea393fd83fdfd9c93235cc3cdfd8fc4",
        "PRO": "757710600ba131c8d7ea7de642bd9a04"
      },
      "basic_block_counts": {
        "LoD/PD2": 20
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_7e6060d94cc1": {
      "addresses": {
        "LoD/PD2": "0x7B337AC8"
      },
      "rvas": {
        "LoD/PD2": "0x7AC8"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "___acrt_execute_initializers",
      "signature": "undefined4 ___acrt_execute_initializers(undefined4 * param_1, undefined4 * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_execute_initializers\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7e6060d94cc1865fed2b781757f3faea",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7e6060d94cc1865fed2b781757f3faea",
        "CFG": "f8e3ba3746e9ae51df413c84a6a6840c",
        "PRO": "0c37a23b658b1275e85eed4b47fb0986"
      },
      "basic_block_counts": {
        "LoD/PD2": 15
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_5e5f475b09cf": {
      "addresses": {
        "LoD/PD2": "0x7B337B30"
      },
      "rvas": {
        "LoD/PD2": "0x7B30"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "___acrt_execute_uninitializers",
      "signature": "undefined1 ___acrt_execute_uninitializers(int param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_execute_uninitializers\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5e5f475b09cf01829b02de9f878c2671",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5e5f475b09cf01829b02de9f878c2671",
        "CFG": "87293770fff7dd02aae145b197058be3",
        "PRO": "1713d889f91ad517da683793ec045891"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_f330b0bce0c7": {
      "addresses": {
        "LoD/PD2": "0x7B337B70"
      },
      "rvas": {
        "LoD/PD2": "0x7B70"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "CheckDecodedCFGPointer",
      "signature": "bool CheckDecodedCFGPointer(uint codeAddress)",
      "calling_convention": "__cdecl",
      "comment": "Validates and executes a decoded control flow guard (CFG) pointer with security checks.\n\nAlgorithm:\n1. Call GetDecodedCFGPointer() to retrieve the encoded CFG pointer from program metadata\n2. Check if the returned pointer is NULL - if NULL, return false (validation failed)\n3. If pointer is valid, push the codeAddress parameter onto stack\n4. Load the pointer value into ECX register\n5. Call guard_check_icall to validate the code address against CFG policy\n6. Call the retrieved code pointer function to execute the guard check\n7. Convert non-zero return value to boolean (true/false) using NEG and SBB instructions\n8. Return boolean result to caller\n\nParameters:\n- codeAddress (uint): The code address to validate against the control flow guard policy\n\nReturns:\n- bool: true if the code address passes CFG validation, false if CFG pointer is invalid or check fails\n\nSpecial Cases:\n- NULL CFG pointer: Returns false immediately without calling guard functions\n- CFG check failure: guard_check_icall may raise exception on policy violation\n- Return value conversion: Uses NEG/SBB pattern to convert integer 0/non-zero to boolean false/true",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f330b0bce0c78b61732e03164daf7704",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f330b0bce0c78b61732e03164daf7704",
        "CFG": "2bea3eb19dd06b49df098eed6ded289c",
        "PRO": "559e8fc71afbc3111a1f2151af05c307"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_fe9dac67a004": {
      "addresses": {
        "LoD/PD2": "0x7B337B9C"
      },
      "rvas": {
        "LoD/PD2": "0x7B9C"
      },
      "sizes": {
        "LoD/PD2": 75
      },
      "name": "GetDecodedCFGPointer",
      "signature": "int GetDecodedCFGPointer(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves and decodes a Control Flow Guard protected function pointer in thread-safe manner.\n\nAlgorithm:\n1. Call __SEH_prolog4 to set up structured exception handling\n2. Acquire critical section lock via ___acrt_lock(0)\n3. Load global CFG-protected pointer from DAT_7b3462d4\n4. Call DecodeCFGPointer to decode the protected pointer\n5. Release critical section lock via UnlockCriticalSection\n6. Store decoded pointer in exceptionState for exception handler restoration\n7. Return decoded function pointer value in EAX\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nReturns decoded function pointer (int) in EAX that has been validated by CFG mechanism.\nPointer is safe to call through guard check or NULL if decoding fails.\n\nSpecial Cases:\n- Uses __SEH_prolog4 for structured exception handling with proper cleanup\n- DAT_7b3462d4 is global CFG-protected function pointer storage\n- Critical section prevents race conditions during pointer decoding\n- Exception state restored at exit (local_14) for proper error handling",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fe9dac67a004cbab62879dff3a8d806e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fe9dac67a004cbab62879dff3a8d806e",
        "CFG": null,
        "PRO": "c55e7e48b878c959a4aa64912380aa2d"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_727fd3fa2b90": {
      "addresses": {
        "LoD/PD2": "0x7B337BF3"
      },
      "rvas": {
        "LoD/PD2": "0x7BF3"
      },
      "sizes": {
        "LoD/PD2": 89
      },
      "name": "GetRotatedXorValue",
      "signature": "uint GetRotatedXorValue(int * pLockValue)",
      "calling_convention": "__stdcall",
      "comment": "Returns the result of XORing and rotating two global CRT data values with thread-safe locking.\n\nAlgorithm:\n1. Acquire CRT lock using the provided lock value pointer\n2. Load lower 5 bits of global DAT_7b345000 as rotation count\n3. XOR DAT_7b3462e0 with DAT_7b345000\n4. Rotate the XOR result right by the rotation count (via ROR instruction)\n5. Release CRT lock\n6. Return the rotated XOR result\n\nParameters:\n- pLockValue: Pointer to CRT lock integer value used for thread synchronization\n\nReturns:\n- uint: The result of (DAT_7b3462e0 ^ DAT_7b345000) rotated right by (DAT_7b345000 & 0x1f) bits\n\nSpecial Cases:\n- Rotation amount is limited to 5 bits (0-31), masking with 0x1f\n- Uses SEH (Structured Exception Handling) prologue for Windows exception safety\n- Uses __stdcall convention with 3-byte parameter cleanup (RET 0xc)\n- Accesses CRT global data protected by lock mechanism",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:727fd3fa2b90fa98bd1b4af4ab0b7793",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "727fd3fa2b90fa98bd1b4af4ab0b7793",
        "CFG": null,
        "PRO": "3066451f39292d3f91255ffec5a3cb74"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_41600ae30682": {
      "addresses": {
        "LoD/PD2": "0x7B337C5B"
      },
      "rvas": {
        "LoD/PD2": "0x7C5B"
      },
      "sizes": {
        "LoD/PD2": 66
      },
      "name": "get_global_action_nolock",
      "signature": "_func_void_int * * get_global_action_nolock(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void (__cdecl** __cdecl get_global_action_nolock(int))(int)\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:41600ae306827ebc303914ec10618e02",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "41600ae306827ebc303914ec10618e02",
        "CFG": "d0ad0d5fe9cf52186bcd9f260a9eebde",
        "PRO": "db705cacc0ade8e647ef6cb3d3a024ae"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_b2491f66c9f7": {
      "addresses": {
        "LoD/PD2": "0x7B337C9D"
      },
      "rvas": {
        "LoD/PD2": "0x7C9D"
      },
      "sizes": {
        "LoD/PD2": 40
      },
      "name": "siglookup",
      "signature": "__crt_signal_action_t * siglookup(int param_1, __crt_signal_action_t * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n struct __crt_signal_action_t * __cdecl siglookup(int,struct __crt_signal_action_t * const)\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b2491f66c9f7fa25e9bd70135d2ddcaf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b2491f66c9f7fa25e9bd70135d2ddcaf",
        "CFG": "9f0e6dcc6217912767c0e6d0aa226117",
        "PRO": "ac3f33e019a85cb680792286194a9fdb"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_cb0244e24146": {
      "addresses": {
        "LoD/PD2": "0x7B338627"
      },
      "rvas": {
        "LoD/PD2": "0x8627"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "___acrt_get_sigabrt_handler",
      "signature": "undefined ___acrt_get_sigabrt_handler(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_get_sigabrt_handler\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cb0244e2414688808ad59380d274f95c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cb0244e2414688808ad59380d274f95c",
        "CFG": null,
        "PRO": "5c457dc77c464246e4a4bb54c9ef870c"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_9ab6007fcb52": {
      "addresses": {
        "LoD/PD2": "0x7B337CEC"
      },
      "rvas": {
        "LoD/PD2": "0x7CEC"
      },
      "sizes": {
        "LoD/PD2": 30
      },
      "name": "InitializeGlobalState",
      "signature": "void InitializeGlobalState(uint initValue)",
      "calling_convention": "__cdecl",
      "comment": "Initializes four consecutive global state variables with the same value.\n\nAlgorithm:\n1. Load initialization value from stack parameter (EBP + 0x8)\n2. Write value to global at 0x7b3462d8\n3. Write value to global at 0x7b3462dc\n4. Write value to global at 0x7b3462e0\n5. Write value to global at 0x7b3462e4\n6. Return to caller\n\nParameters:\n  initValue (uint): Initialization value written to all four globals\n\nReturns:\n  void: No return value\n\nSpecial Cases:\n  - All four globals receive the identical value\n  - Globals are 16 bytes apart, suggesting they may be related state fields\n  - Function performs no validation or conditional logic\n  - Simple linear setup operation with no error handling",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9ab6007fcb5231b0e844fe1836ec991a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9ab6007fcb5231b0e844fe1836ec991a",
        "CFG": null,
        "PRO": "86e7344bc9014e3a3d99ccee6d7caf6b"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_6f8cbf4b3682": {
      "addresses": {
        "LoD/PD2": "0x7B337D0A"
      },
      "rvas": {
        "LoD/PD2": "0x7D0A"
      },
      "sizes": {
        "LoD/PD2": 463
      },
      "name": "InvokeSignalHandler",
      "signature": "undefined4 InvokeSignalHandler(int signalNumber)",
      "calling_convention": "__cdecl",
      "comment": "Invokes the registered signal handler for a given signal number.\n\nAlgorithm:\n1. Validate signal number is in valid range (0-26)\n2. For signals 2, 4, 6, 8, 11: get process-local thread data\n3. For signals 15, 21, 22: get global signal action handler\n4. If needed, acquire mutex lock (3) for thread-safe access\n5. Load handler function pointer from signal action structure\n6. If mutex held, decode CFG-protected pointer\n7. Check if handler is SIG_DFL (0x1) or SIG_IGN (0x0)\n8. For signals 4, 8, 11: save and reset process context state\n9. For signal 8: save and set thread context to 0x8c, then loop clearing context fields\n10. Call handler function through CFG guard check\n11. Restore saved process/thread context after handler returns\n12. Release mutex if acquired\n13. Return 0 on success, -1 on error\n\nParameters:\n  signalNumber - Signal number to invoke handler for (0-26)\n\nReturns:\n  0 on successful handler invocation\n  -1 if signal number invalid or handler lookup fails\n\nSpecial Cases:\n  - Signal 8 requires thread context management via GetOrCreateThreadData\n  - Signals 4, 8, 11 use per-process context saved in signal action offset +4\n  - Mutex 3 acquired only for process-local signals to prevent concurrent access\n  - CFG pointer decoding applied only when mutex held\n  - Loop at offset 7b337e3a clears context entries (12 bytes each) for signal 8",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6f8cbf4b368252733b601f9c8584317f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6f8cbf4b368252733b601f9c8584317f",
        "CFG": "9003fe44325d89af3b4644c928ee3f1e",
        "PRO": "62b6e0c5841185cda0420c2a697e7c0b"
      },
      "basic_block_counts": {
        "LoD/PD2": 51
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_0e4dc8777cb1": {
      "addresses": {
        "LoD/PD2": "0x7B337E94"
      },
      "rvas": {
        "LoD/PD2": "0x7E94"
      },
      "sizes": {
        "LoD/PD2": 16
      },
      "name": "UnlockMutexIfFlagSet",
      "signature": "void UnlockMutexIfFlagSet(void)",
      "calling_convention": "__stdcall",
      "comment": "Conditionally unlock the CRT mutex based on a flag value.\n\nAlgorithm:\n1. Test the BL register (shouldUnlock) to determine if unlock is needed\n2. If flag is clear (zero), skip to return (check_flag -> unlock_skip)\n3. If flag is set, push mutex ID 3 onto stack\n4. Call ___acrt_unlock(3) to release the critical section\n5. Pop ECX to maintain stack balance and restore caller context\n6. Return to caller\n\nParameters:\nIMPLICIT shouldUnlock (BL): Flag indicating whether to unlock the mutex\n  - Non-zero: Perform mutex unlock operation\n  - Zero: Skip unlock and return immediately\n\nReturns:\nvoid - No return value. Function performs side-effect of unlocking if flag set.\n\nSpecial Cases:\n- BL is an implicit parameter passed in the BL register from caller\n- Stack frame at [EBP + -0x20] contains caller-saved context\n- Mutex ID 3 is hardcoded (CRT-specific resource identifier)\n- Calling convention: __stdcall with implicit register parameter\n\nStructure Layout:\nN/A - No structure data accessed. Only uses BL register flag.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0e4dc8777cb1c5b4c0810d7e56f371bc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0e4dc8777cb1c5b4c0810d7e56f371bc",
        "CFG": "31a1b9bb32221aaf75bc1a6e9cedc57f",
        "PRO": "7b74e7807e741e695d23a795321ef45e"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_6adb83dee884": {
      "addresses": {
        "LoD/PD2": "0x7B337EFC"
      },
      "rvas": {
        "LoD/PD2": "0x7EFC"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "ValidateRotatedBitPattern",
      "signature": "bool ValidateRotatedBitPattern(void)",
      "calling_convention": "__stdcall",
      "comment": "Validates a rotated bit pattern by comparing XORed global values.\n\nAlgorithm:\n1. Load rotation amount from global data (lower 5 bits of DAT_7b345000)\n2. XOR g_GlobalValue with DAT_7b345000 to compute comparison value\n3. Rotate right (ROR) the XOR result by the rotation amount\n4. Test if rotated value is non-zero\n5. Return true if rotated value != 0, false otherwise\n\nReturns:\n- true if the rotated XOR result contains non-zero bits\n- false if the rotated XOR result equals zero\n\nSpecial Cases:\n- Rotation amount is masked to 5 bits (0-31), supporting 32-bit rotation\n- Used for floating-point exception handling validation\n- Operates on global data values, not parameters\n\nPurpose:\nThis function appears to validate a rotating bit pattern check in floating-point exception handling. It may be used to detect specific exception conditions or validate exception state.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6adb83dee884c52831dea2322f82176e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6adb83dee884c52831dea2322f82176e",
        "CFG": null,
        "PRO": "a96ffb9e36e754a2e6bc26016824038a"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_f75d59011e64": {
      "addresses": {
        "LoD/PD2": "0x7B337F28"
      },
      "rvas": {
        "LoD/PD2": "0x7F28"
      },
      "sizes": {
        "LoD/PD2": 54
      },
      "name": "DecryptAndCallProtectedFunction",
      "signature": "undefined4 DecryptAndCallProtectedFunction(undefined4 callParam)",
      "calling_convention": "__cdecl",
      "comment": "Decrypts and calls an obfuscated function pointer with guard verification.\n\nAlgorithm:\n1. Load rotation amount from DAT_7b345000 (mask to 5 bits for ROR operand)\n2. Load encrypted function pointer from DAT_7b3462e8\n3. XOR the encrypted pointer with the key value from DAT_7b345000\n4. Right-rotate the XOR result by the rotation amount\n5. Check if decrypted pointer is NULL\n6. If NULL, return 0\n7. If non-NULL, invoke guard_check_icall with the call parameter\n8. Call the decrypted function pointer with no parameters\n9. Return the function result\n\nParameters:\n- callParam (undefined4): Parameter passed to guard_check_icall before function invocation\n\nReturns:\n- undefined4: Return value from the decrypted function, or 0 if pointer is NULL\n\nSpecial Cases:\n- This function implements obfuscated indirect control flow using XOR encryption and bitwise rotation\n- Guard verification via guard_check_icall prevents unauthorized function calls\n- Return value is 0 if the decrypted function pointer evaluates to NULL",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f75d59011e64aefb4849e5842be6f552",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f75d59011e64aefb4849e5842be6f552",
        "CFG": "cd20c04c14c0a652449ef1b40a9b39c3",
        "PRO": "fc5797220e8dec6c9717c65b4c99834c"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_9bb8b5cc6d87": {
      "addresses": {
        "LoD/PD2": "0x7B337F5E"
      },
      "rvas": {
        "LoD/PD2": "0x7F5E"
      },
      "sizes": {
        "LoD/PD2": 128
      },
      "name": "operator()<class_<lambda_2866be3712abc81a800a822484c830d8>,class_<lambda_39ca0ed439415581b5b15c265174cece>&,class_<lambda_2b24c74d71094a6cd0cb82e44167d71b>_>",
      "signature": "void operator()<class_<lambda_2866be3712abc81a800a822484c830d8>,class_<lambda_39ca0ed439415581b5b15c265174cece>&,class_<lambda_2b24c74d71094a6cd0cb82e44167d71b>_>(__crt_seh_guarded_call<void> * this, <lambda_2866be3712abc81a800a822484c830d8> * param_1, <lambda_39ca0ed439415581b5b15c265174cece> * param_2, <lambda_2b24c74d71094a6cd0cb82e44167d71b> * param_3)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: void __thiscall __crt_seh_guarded_call<void>::operator()<class <lambda_2866be3712abc81a800a822484c830d8>,class <lambda_39ca0ed439415581b5b15c265174cece> &,class <lambda_2b24c74d71094a6cd0cb82e44167d71b> >(class <lambda_2866be3712abc81a800a822484c830d8> &&,class <lambda_39ca0ed439415581b5b15c265174cece> &,class <lambda_2b24c74d71094a6cd0cb82e44167d71b> &&)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9bb8b5cc6d8707ea1c0835cf6c7deec2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9bb8b5cc6d8707ea1c0835cf6c7deec2",
        "CFG": "833dd2b2958695689b3c401989f44f23",
        "PRO": "f3d346b9944f8af18760612d3d8e5917"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_eca078c0e6a7": {
      "addresses": {
        "LoD/PD2": "0x7B337FEA"
      },
      "rvas": {
        "LoD/PD2": "0x7FEA"
      },
      "sizes": {
        "LoD/PD2": 160
      },
      "name": "operator()<class_<lambda_2cc53f568c5a2bb6f192f930a45d44ea>,class_<lambda_ab61a845afdef5b7c387490eaf3616ee>&,class_<lambda_c2ffc0b7726aa6be21d5f0026187e748>_>",
      "signature": "void operator()<class_<lambda_2cc53f568c5a2bb6f192f930a45d44ea>,class_<lambda_ab61a845afdef5b7c387490eaf3616ee>&,class_<lambda_c2ffc0b7726aa6be21d5f0026187e748>_>(__crt_seh_guarded_call<void> * this, <lambda_2cc53f568c5a2bb6f192f930a45d44ea> * param_1, <lambda_ab61a845afdef5b7c387490eaf3616ee> * param_2, <lambda_c2ffc0b7726aa6be21d5f0026187e748> * param_3)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: void __thiscall __crt_seh_guarded_call<void>::operator()<class <lambda_2cc53f568c5a2bb6f192f930a45d44ea>,class <lambda_ab61a845afdef5b7c387490eaf3616ee> &,class <lambda_c2ffc0b7726aa6be21d5f0026187e748> >(class <lambda_2cc53f568c5a2bb6f192f930a45d44ea> &&,class <lambda_ab61a845afdef5b7c387490eaf3616ee> &,class <lambda_c2ffc0b7726aa6be21d5f0026187e748> &&)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:eca078c0e6a72a986acdc9537de0692a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "eca078c0e6a72a986acdc9537de0692a",
        "CFG": "3b8167c3b593e05f63f64d35e9f1d6f2",
        "PRO": "bd5544af69d1b6b439c18aa8694ae42b"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_a1c5a63dfb48": {
      "addresses": {
        "LoD/PD2": "0x7B338096"
      },
      "rvas": {
        "LoD/PD2": "0x8096"
      },
      "sizes": {
        "LoD/PD2": 77
      },
      "name": "common_flush_all",
      "signature": "int common_flush_all(bool param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl common_flush_all(bool)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a1c5a63dfb48e91ed1fd252c2e990055",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a1c5a63dfb48e91ed1fd252c2e990055",
        "CFG": "9f028b99b33abba3895bcfdb69b70d33",
        "PRO": "4d339f02dfe602ad1e566341c635d59f"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_cb8396fe8ff3": {
      "addresses": {
        "LoD/PD2": "0x7B3380E3"
      },
      "rvas": {
        "LoD/PD2": "0x80E3"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "CheckConditionAndCountMatch",
      "signature": "int CheckConditionAndCountMatch(int pConditionObject, int * pMatchCount)",
      "calling_convention": "__cdecl",
      "comment": "Conditional matcher that tests object state and processes matching results.\n\nAlgorithm:\n1. Validate object pointer is non-null; return 0 if null\n2. Load flags field from object at offset +0xc\n3. Test bit 13 of the flags field\n4. If bit 13 not set, return 0 (not a match)\n5. If bit 13 set, call ExtractBitFlags on the flags field\n6. If extraction succeeds (return value != 0), return 1 (match found)\n7. If extraction fails (return value == 0), increment match counter and return 0\n\nParameters:\n  pConditionObject (int): Pointer to object with flags at offset +0xc\n  pMatchCount (int*): Pointer to counter incremented on failed extractions\n\nReturns:\n  int: 1 if condition matched and extraction succeeded, 0 otherwise\n\nSpecial Cases:\n  - Bit 13 must be set in flags field for condition to evaluate\n  - ExtractBitFlags return value determines success/failure (non-zero=success)\n  - Counter is only incremented when extraction fails",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cb8396fe8ff3de5d634fa060e04a2215",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cb8396fe8ff3de5d634fa060e04a2215",
        "CFG": "2dd4ce25af21102b5e50a4036c05572b",
        "PRO": "81069c540bf2ac05f49af96ea5e7892a"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_a23cedad3f20": {
      "addresses": {
        "LoD/PD2": "0x7B338114"
      },
      "rvas": {
        "LoD/PD2": "0x8114"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "ExtractBitFlags",
      "signature": "uint ExtractBitFlags(uint encodedValue)",
      "calling_convention": "__cdecl",
      "comment": "Extracts and validates bit flags from an encoded parameter value.\n\nAlgorithm:\n1. Load parameter from stack into ECX (bits 0-31 of encoded value)\n2. Mask lower 2 bits of ECX into AL (check pattern in bits 0-1)\n3. Compare AL with 0x2 to check if bits [1:0] == 0b10\n4. If pattern doesn't match, jump to extract_high_bits (0x7b33812d)\n5. If pattern matches, test CL with 0xc0 (check if bits 7 or 6 are set)\n6. If bits 7 and 6 are both zero, jump to extract_high_bits\n7. If bits 7 or 6 are set, decrement AL (0x2 becomes 0x1) and return\n8. At extract_high_bits: shift ECX right by 11 bits and mask result with 0x1\n9. Return the masked bit value\n\nParameters:\n  encodedValue (uint) - Bit-packed parameter with:\n    Bits [1:0]   - Pattern field (checked for 0b10)\n    Bits [7:6]   - Flag bits (checked if non-zero)\n    Bits [31:11] - Upper bits (shifted right by 11)\n\nReturns:\n  uint - Extracted flag value:\n    Returns 0x01 if pattern bits match 0b10 and flag bits non-zero\n    Otherwise returns bit 11 of encoded value (shifted right 11, masked with 0x1)\n\nSpecial Cases:\n  - If bits [1:0] != 0x2, the function extracts bit [11] only\n  - If bits [1:0] == 0x2 but bits [7:6] are zero, extracts bit [11]\n  - Only when both bit pattern and flag bits are set does it return 0x1",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a23cedad3f20e966e19a0555066ea7ce",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a23cedad3f20e966e19a0555066ea7ce",
        "CFG": "754bfc5d47177c4cbdd43b336248c7ba",
        "PRO": "7907afc5f1792147a7315f8e9572b972"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_ddd74fa79e28": {
      "addresses": {
        "LoD/PD2": "0x7B338137"
      },
      "rvas": {
        "LoD/PD2": "0x8137"
      },
      "sizes": {
        "LoD/PD2": 105
      },
      "name": "FlushFileBuffer",
      "signature": "int FlushFileBuffer(FILE * pFile, int * pErrorStatus)",
      "calling_convention": "__cdecl",
      "comment": "Flushes buffered file data to disk and updates FILE structure status flags.\n\nAlgorithm:\n1. Retrieve FILE structure flags pointer (offset +0xC in FILE)\n2. Check if file is in write mode (flags & 0x3 == 0x2) and buffering enabled (flags & 0xC0 != 0)\n3. Extract buffered data pointer from FILE._cnt and FILE._ptr fields\n4. Calculate buffer size as difference between _ptr and _cnt pointers\n5. Reset _ptr to _cnt and clear _base pointer\n6. If buffer has data (size > 0), get file descriptor via __fileno()\n7. Call ValidateAndWriteFileData() to write buffer to disk\n8. If write fails (bytes written != expected), set error flag (0x10) with atomic OR.LOCK\n9. If write succeeds and bit 2 of flags is set, clear bit 1 (0x2) with atomic AND.LOCK\n10. Return 0 on success, 0xFFFFFFFF (-1) on write error\n\nParameters:\npFile - FILE * : Pointer to FILE structure with buffered data\npErrorStatus - int * : Pointer to error status variable (updated on write failure)\n\nReturns:\nint : 0 on success, -1 (0xFFFFFFFF) on write failure or if file not in write mode\n\nSpecial Cases:\n- File must be in write mode with buffering enabled to flush\n- If buffer size <= 0, function returns immediately without writing\n- Atomic lock operations (LOCK prefix) ensure thread-safe flag updates\n- Bit operations: flags & 0x3 checks write mode, flags >> 2 & 1 checks linebuffer bit\n\nStructure Layout:\nFILE struct offsets accessed:\n  Offset 0x0 - _ptr : char* : Current write position in buffer\n  Offset 0x4 - _cnt : char* : Start of buffer data\n  Offset 0x8 - _base : char* : Base address (cleared on flush)\n  Offset 0xC - _flag : int* : Status flags (write mode, buffering, error flags)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ddd74fa79e2850965c61334573e992a2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ddd74fa79e2850965c61334573e992a2",
        "CFG": "7d4114318ba7986221a23514c4eadd98",
        "PRO": "aa5e6dde5f03a1f420dde8864da4c1fd"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_e292cc027763": {
      "addresses": {
        "LoD/PD2": "0x7B3381A0"
      },
      "rvas": {
        "LoD/PD2": "0x81A0"
      },
      "sizes": {
        "LoD/PD2": 101
      },
      "name": "FlushFileStream",
      "signature": "int FlushFileStream(FILE * pFile)",
      "calling_convention": "__cdecl",
      "comment": "Flushes buffered data in a file stream to disk.\n\nAlgorithm:\n1. Initialize a local stream state structure for temporary data tracking\n2. If pFile is NULL, flush all open streams via common_flush_all()\n3. If pFile is provided:\n   a. Call FUN_7b338137 to process the file buffer contents\n   b. If successful, check if write mode is enabled (bit 11 of _flag at offset 0xc)\n   c. If write flag set, obtain file descriptor via __fileno()\n   d. Call __commit() to synchronize file descriptor to disk\n   e. If __commit() succeeds, skip error handling\n4. If any operation fails, set return value to -1\n5. Clean up stream state via ApplyStreamProperties()\n6. Return status: 0 for success, -1 for failure\n\nParameters:\n- pFile (FILE *): Pointer to file stream to flush, or NULL to flush all streams\n\nReturns:\n- int: 0 on success or if no action needed, -1 if flush operation failed\n\nSpecial Cases:\n- When pFile is NULL, flushes all open streams system-wide\n- Checks write permission flag before attempting disk sync\n- Returns 0 if write flag not set (no sync needed for read-only streams)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e292cc027763aa464deac76707c77b1f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e292cc027763aa464deac76707c77b1f",
        "CFG": "d449b8a93132d675d922372d839a516a",
        "PRO": "bf47dec8ea54a09a2b9ca3ddc801b3ce"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_908f1f8c30b4": {
      "addresses": {
        "LoD/PD2": "0x7B338336"
      },
      "rvas": {
        "LoD/PD2": "0x8336"
      },
      "sizes": {
        "LoD/PD2": 20
      },
      "name": "__lock_file",
      "signature": "void __lock_file(FILE * _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __lock_file\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:908f1f8c30b4f00a21e46093676dbdd5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "908f1f8c30b4f00a21e46093676dbdd5",
        "CFG": null,
        "PRO": "d0d28182912a979caae088ab67d6b0c4"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_7801dc6c9001": {
      "addresses": {
        "LoD/PD2": "0x7B33834A"
      },
      "rvas": {
        "LoD/PD2": "0x834A"
      },
      "sizes": {
        "LoD/PD2": 78
      },
      "name": "__malloc_base",
      "signature": "LPVOID __malloc_base(SIZE_T param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __malloc_base\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7801dc6c9001232ed9ef537819640b6d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7801dc6c9001232ed9ef537819640b6d",
        "CFG": "f5b3808224712f53ffb598587c395b6c",
        "PRO": "2471b09939d1d138672cd8b3f92f6d64"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_ffdd82626896": {
      "addresses": {
        "LoD/PD2": "0x7B3383F6"
      },
      "rvas": {
        "LoD/PD2": "0x83F6"
      },
      "sizes": {
        "LoD/PD2": 45
      },
      "name": "___acrt_update_locale_info",
      "signature": "undefined ___acrt_update_locale_info(int param_1, int * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_update_locale_info\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ffdd82626896f5ba90f554ad3e2b4996",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ffdd82626896f5ba90f554ad3e2b4996",
        "CFG": "13ac807217091f4044d66f8ff2174dac",
        "PRO": "40f58c937d26b9dd9cdbd04f25812088"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_6dcf03ea4ff7": {
      "addresses": {
        "LoD/PD2": "0x7B338423"
      },
      "rvas": {
        "LoD/PD2": "0x8423"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "UpdateThreadLocaleData",
      "signature": "void UpdateThreadLocaleData(int pThreadContext, int * pThreadLocaleData, int localeIndex)",
      "calling_convention": "__cdecl",
      "comment": "Updates thread locale data if conditions are met.\n\nAlgorithm:\n1. Load the current locale value from *pThreadLocaleData\n2. Compare against expected value from table at index localeIndex\n3. If values match, skip update and return\n4. Load the thread context (pThreadContext)\n5. Check if flag at offset 0x350 in thread context is clear\n6. If flag is set, skip update and return\n7. Call ___acrt_update_thread_locale_data() to get new locale value\n8. Store result back to *pThreadLocaleData\n9. Return\n\nParameters:\n- pThreadContext: Pointer to thread context structure\n- pThreadLocaleData: Pointer to thread locale data field to update\n- localeIndex: Index into locale table for validation\n\nReturns:\n- void (no return value; updates *pThreadLocaleData as side effect)\n\nSpecial Cases:\n- Skips update if current value matches expected value in table\n- Skips update if flag at thread context offset 0x350 is already set\n- Only called during thread initialization or locale changes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6dcf03ea4ff7c06b9832c5b1ee6df008",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6dcf03ea4ff7c06b9832c5b1ee6df008",
        "CFG": "6c3b0aa07951c5e00ecf5c0f67c56cb3",
        "PRO": "555b5a433007e980c29450781bec03c2"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_ee4a05548ebe": {
      "addresses": {
        "LoD/PD2": "0x7B338454"
      },
      "rvas": {
        "LoD/PD2": "0x8454"
      },
      "sizes": {
        "LoD/PD2": 307
      },
      "name": "DecodeCharacterWithEncodingState",
      "signature": "uint DecodeCharacterWithEncodingState(LPWSTR pOutputChar, byte * pInputBuffer, uint bufferLength, int * pEncodingState)",
      "calling_convention": "__cdecl",
      "comment": "Decodes a single character from input buffer with encoding state awareness.\n\nAlgorithm:\n1. Validate input parameters (pInputBuffer and pEncodingState must be non-null)\n2. Check if encoding state is initialized (byte at offset +0x14 == 0)\n   - If not initialized, call FUN_7b335260 to initialize state\n3. Fetch encoding state magic value from pEncodingState[0xc] (offset +0xc = 8 bytes * 3/2)\n4. Handle UTF-8 decoding (state magic == 0xfde9):\n   - Call DecodeUTF8Character via FUN_7b33a4fb with pInputBuffer, bufferLength, and pEncodingState\n   - Return result status if successful (>= 0)\n   - Return -1 if decode fails\n5. For standard encoding (non-UTF-8):\n   a. Check if encoding table (pEncodingState[0] + 0xa8) is empty/null\n      - If yes and pOutputChar is valid, write single byte as wide char and return 1\n   b. Check if character at pInputBuffer[0] maps to negative value in table\n      - If yes, multi-byte sequence: call FUN_7b337232 with length from pEncodingState[0xc+0x4]\n      - If length valid and conversion succeeds, return converted length\n      - Otherwise set error flags and return -1\n   c. If single-byte mapping exists:\n      - Call FUN_7b337232 with length 1\n      - If successful, return 1\n      - Otherwise set error flags and return -1\n6. Set error flags on failure (pEncodingState[0x1c] = 1, pEncodingState[0x18] = 0x2a)\n7. Return 1 on success or -1 on error\n\nParameters:\npOutputChar (LPWSTR): Output buffer for decoded character (wide char), or null to skip storage\npInputBuffer (byte*): Input byte buffer containing character(s) to decode\nbufferLength (uint): Length in bytes of input buffer starting at pInputBuffer\npEncodingState (int*): Encoding state structure with fields:\n  [0xc]=magic value (0xfde9 for UTF-8, else standard encoding table)\n  [0] = encoding table base pointer\n  [0x4] = byte length for multi-byte sequences\n  [0x14] = initialization flag (0 = not init, non-zero = initialized)\n  [0x1c] = error flag (written on failure)\n  [0x18] = error code holder (0x2a = sentinel value)\n\nReturns:\nuint: Status code\n  1 = Success (single byte decoded)\n  Value >= 1 = Success (bytes consumed)\n  0 = No output written\n  -1 (0xffffffff) = Decoding error or invalid state\n\nSpecial Cases:\n- Magic value 0xfde9 at offset +0xc indicates UTF-8 encoding state\n- Null pOutputChar parameter: decode still occurs but result not stored\n- Uninitialized state: automatically initialized via FUN_7b335260 call\n- Empty encoding table at offset 0xa8: treats as single-byte passthrough\n- Multi-byte sequences: uses byte length at offset +0x4 from state\n- Error conditions set sentinel 0x2a in offset +0x18",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ee4a05548ebe6e554150ed4f0180f2f9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ee4a05548ebe6e554150ed4f0180f2f9",
        "CFG": "4162e55f3fabcfabaf019088b3d5e690",
        "PRO": "51dd88d541a03186ed77cd2f8edbca77"
      },
      "basic_block_counts": {
        "LoD/PD2": 26
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_c680ced5c53f": {
      "addresses": {
        "LoD/PD2": "0x7B338587"
      },
      "rvas": {
        "LoD/PD2": "0x8587"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "__fileno",
      "signature": "int __fileno(FILE * _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __fileno\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c680ced5c53f9df2eb79ca251719af08",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c680ced5c53f9df2eb79ca251719af08",
        "CFG": "90c4f17418cec0d76ed106d2d34ca67f",
        "PRO": "b3c817296f428fd11908a53af1198d27"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_4179e8ffeb5b": {
      "addresses": {
        "LoD/PD2": "0x7B3385AE"
      },
      "rvas": {
        "LoD/PD2": "0x85AE"
      },
      "sizes": {
        "LoD/PD2": 98
      },
      "name": "operator()<class_<lambda_e5124f882df8998aaf41531e079ba474>,class_<lambda_3e16ef9562a7dcce91392c22ab16ea36>&,class_<lambda_e25ca0880e6ef98be67edffd8c599615>_>",
      "signature": "void operator()<class_<lambda_e5124f882df8998aaf41531e079ba474>,class_<lambda_3e16ef9562a7dcce91392c22ab16ea36>&,class_<lambda_e25ca0880e6ef98be67edffd8c599615>_>(__crt_seh_guarded_call<void> * this, <lambda_e5124f882df8998aaf41531e079ba474> * param_1, <lambda_3e16ef9562a7dcce91392c22ab16ea36> * param_2, <lambda_e25ca0880e6ef98be67edffd8c599615> * param_3)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: void __thiscall __crt_seh_guarded_call<void>::operator()<class <lambda_e5124f882df8998aaf41531e079ba474>,class <lambda_3e16ef9562a7dcce91392c22ab16ea36> &,class <lambda_e25ca0880e6ef98be67edffd8c599615> >(class <lambda_e5124f882df8998aaf41531e079ba474> &&,class <lambda_3e16ef9562a7dcce91392c22ab16ea36> &,class <lambda_e25ca0880e6ef98be67edffd8c599615> &&)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4179e8ffeb5b9222b592fbc9ea164c44",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4179e8ffeb5b9222b592fbc9ea164c44",
        "CFG": "473d086ee94878b8f6ec467e2de64aec",
        "PRO": "88544d08e1d768d05b76a3f9c6b77ba9"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_4a14b880453c": {
      "addresses": {
        "LoD/PD2": "0x7B33861C"
      },
      "rvas": {
        "LoD/PD2": "0x861C"
      },
      "sizes": {
        "LoD/PD2": 11
      },
      "name": "AtomicTestAndSetInitFlag",
      "signature": "int AtomicTestAndSetInitFlag(void)",
      "calling_convention": "__stdcall",
      "comment": "Performs atomic test-and-set operation on global initialization flag.\\n\\nAlgorithm:\\n1. Clear EAX register and set target value to 1\\n2. Load address of global initialization flag (0x7b346308) into ECX\\n3. Atomically exchange current flag value with 1 using XCHG instruction\\n4. Return previous flag value in EAX\\n\\nReturns:\\n  0 if flag was not previously set (first caller wins the initialization)\\n  1 if flag was already set (subsequent callers see it was already done)\\n\\nSpecial Cases:\\n  XCHG to memory provides implicit atomic semantics without LOCK prefix\\n  Used during C runtime initialization for one-time initialization of multibyte character support\\n  Global flag at 0x7b346308 acts as synchronization point for multiple threads\\n  Called from FUN_7b336c43 during locale setup with conditional logic based on return value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4a14b880453c1b7e037c61c3c0341b07",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4a14b880453c1b7e037c61c3c0341b07",
        "CFG": null,
        "PRO": "64553968d2f848cf79f2d8a81f5897e9"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_6b7eabbe24cf": {
      "addresses": {
        "LoD/PD2": "0x7B33864E"
      },
      "rvas": {
        "LoD/PD2": "0x864E"
      },
      "sizes": {
        "LoD/PD2": 125
      },
      "name": "___acrt_add_locale_ref",
      "signature": "undefined ___acrt_add_locale_ref(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_add_locale_ref\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6b7eabbe24cfa72b3fe335d59e14ee79",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6b7eabbe24cfa72b3fe335d59e14ee79",
        "CFG": "64bc209334ca106024506b670c5aaf9d",
        "PRO": "74afe2a88853d226c379f5577bd6f138"
      },
      "basic_block_counts": {
        "LoD/PD2": 17
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_e4d177e5ae59": {
      "addresses": {
        "LoD/PD2": "0x7B3386CB"
      },
      "rvas": {
        "LoD/PD2": "0x86CB"
      },
      "sizes": {
        "LoD/PD2": 328
      },
      "name": "___acrt_free_locale",
      "signature": "undefined ___acrt_free_locale(LPVOID param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_free_locale\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e4d177e5ae596869aa69c1d70df6f43a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e4d177e5ae596869aa69c1d70df6f43a",
        "CFG": "36349bcdbabbe0436404e326c55bc937",
        "PRO": "9542c5fa2e4d3fb47cb21effdf018dea"
      },
      "basic_block_counts": {
        "LoD/PD2": 27
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_87f44fc8e938": {
      "addresses": {
        "LoD/PD2": "0x7B338813"
      },
      "rvas": {
        "LoD/PD2": "0x8813"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "___acrt_locale_add_lc_time_reference",
      "signature": "undefined * ___acrt_locale_add_lc_time_reference(undefined * * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_locale_add_lc_time_reference\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:87f44fc8e938eab6507761382adce7aa",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "87f44fc8e938eab6507761382adce7aa",
        "CFG": "e6f5aaef1039a61daa103ba7f60faedc",
        "PRO": "979d8d2514585f637d4defc620406c5d"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_b8190ec680c1": {
      "addresses": {
        "LoD/PD2": "0x7B33883C"
      },
      "rvas": {
        "LoD/PD2": "0x883C"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "___acrt_locale_free_lc_time_if_unreferenced",
      "signature": "undefined ___acrt_locale_free_lc_time_if_unreferenced(undefined * * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_locale_free_lc_time_if_unreferenced\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b8190ec680c120458d53398875622c7d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b8190ec680c120458d53398875622c7d",
        "CFG": "b299961a4ff9924d9c5832fc43b80e26",
        "PRO": "a321254b721a4430611b95f87ab6414b"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_1621b59440b5": {
      "addresses": {
        "LoD/PD2": "0x7B33886D"
      },
      "rvas": {
        "LoD/PD2": "0x886D"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "___acrt_locale_release_lc_time_reference",
      "signature": "undefined * ___acrt_locale_release_lc_time_reference(undefined * * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_locale_release_lc_time_reference\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1621b59440b528d3aecaa7c5ed932877",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1621b59440b528d3aecaa7c5ed932877",
        "CFG": "e6f5aaef1039a61daa103ba7f60faedc",
        "PRO": "979d8d2514585f637d4defc620406c5d"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_a8fcae630212": {
      "addresses": {
        "LoD/PD2": "0x7B338896"
      },
      "rvas": {
        "LoD/PD2": "0x8896"
      },
      "sizes": {
        "LoD/PD2": 129
      },
      "name": "___acrt_release_locale_ref",
      "signature": "undefined ___acrt_release_locale_ref(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_release_locale_ref\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a8fcae6302121688ab84f97b546a9ba8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a8fcae6302121688ab84f97b546a9ba8",
        "CFG": "368a49afee490612d01c74a4d00d7e24",
        "PRO": "2920fd3dc683e93c0deb2d7fd3714684"
      },
      "basic_block_counts": {
        "LoD/PD2": 19
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_a76022919c98": {
      "addresses": {
        "LoD/PD2": "0x7B338917"
      },
      "rvas": {
        "LoD/PD2": "0x8917"
      },
      "sizes": {
        "LoD/PD2": 98
      },
      "name": "___acrt_update_thread_locale_data",
      "signature": "int ___acrt_update_thread_locale_data(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_update_thread_locale_data\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a76022919c989d345443bfc07d791316",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a76022919c989d345443bfc07d791316",
        "CFG": "6fb487bc229d0bcd2f870f6ee59e6d22",
        "PRO": "6421c56eb28b62154fae8724bb546ef4"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_a8a04c013e86": {
      "addresses": {
        "LoD/PD2": "0x7B338998"
      },
      "rvas": {
        "LoD/PD2": "0x8998"
      },
      "sizes": {
        "LoD/PD2": 80
      },
      "name": "__updatetlocinfoEx_nolock",
      "signature": "undefined * * __updatetlocinfoEx_nolock(undefined4 * param_1, undefined * * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __updatetlocinfoEx_nolock\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a8a04c013e86edd9bf47c2c7caff9097",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a8a04c013e86edd9bf47c2c7caff9097",
        "CFG": "eb3b6093f922424734a78d0a744b94e3",
        "PRO": "21d68c7808343dc7255dd6bd688a9ec6"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_ed0422b71e9e": {
      "addresses": {
        "LoD/PD2": "0x7B3389F0"
      },
      "rvas": {
        "LoD/PD2": "0x89F0"
      },
      "sizes": {
        "LoD/PD2": 1229
      },
      "name": "_qsort",
      "signature": "void _qsort(void * _Base, size_t _NumOfElements, size_t _SizeOfElements, _PtFuncCompare * _PtFuncCompare)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _qsort\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ed0422b71e9e434a26516a831611a9bd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ed0422b71e9e434a26516a831611a9bd",
        "CFG": "e83c45bd92d1e38f0b92a568fd3649ca",
        "PRO": "fae0985d45287b89f294da3231b13492"
      },
      "basic_block_counts": {
        "LoD/PD2": 81
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_076ec72b28fb": {
      "addresses": {
        "LoD/PD2": "0x7B338EDE"
      },
      "rvas": {
        "LoD/PD2": "0x8EDE"
      },
      "sizes": {
        "LoD/PD2": 183
      },
      "name": "CopyBytesWithLimits",
      "signature": "uint CopyBytesWithLimits(char * pDestBuffer, int bufferSize, int sourceOffset, int maxBytesToCopy)",
      "calling_convention": "__cdecl",
      "comment": "Copies bytes from source to destination buffer with size and count constraints.\\n\\nAlgorithm:\\n1. Validate parameters (destination, buffer size, byte limit)\\n2. If byte limit is 0, null-terminate and return success\\n3. If destination is null or source offset is invalid, set error and return\\n4. Calculate source offset relative to destination pointer\\n5. Enter copy loop based on byte limit type:\\n   - If limit is -1: copy unlimited bytes or until null terminator, up to buffer size\\n   - If limit > 0: copy with both size and byte count limits\\n6. For each byte: load from source, store to destination, check for null terminator\\n7. After copy: null-terminate destination buffer\\n8. Return status: 0 (success), 0x50 (truncated with -1 limit), 0x16 (invalid param), 0x22 (buffer overflow)\\n\\nParameters:\\n- pDestBuffer: Target buffer where bytes are copied\\n- bufferSize: Maximum size of destination buffer\\n- sourceOffset: Source position to copy from\\n- maxBytesToCopy: Maximum bytes to copy (-1 for unlimited)\\n\\nReturns:\\n- 0: Success with no truncation\\n- 0x50 (80): Success but copy was limited by buffer size (unlimited mode)\\n- 0x16 (22): Invalid parameters (null dest, invalid source, missing size)\\n- 0x22 (34): Buffer overflow or truncation occurred\\n\\nSpecial Cases:\\n- maxBytesToCopy = -1: Unlimited mode, copy until null or buffer full\\n- maxBytesToCopy = 0: Just null-terminate destination\\n- sourceOffset = 0: Treated as invalid source\\n- bufferSize = 0: Invalid, returns error code\\n\\nStructure Layout:\\nThis function works with raw byte buffers accessed via pointer arithmetic.\\nThe sourceOffset parameter is typically the difference from destination base.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:076ec72b28fbb37622dad97be1d01ea4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "076ec72b28fbb37622dad97be1d01ea4",
        "CFG": "cf4a8f374fb3eadf37d67fc1a15101d8",
        "PRO": "49164ecbad59e902ba1c24b60f1c5dbc"
      },
      "basic_block_counts": {
        "LoD/PD2": 28
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_262b55d4b1f2": {
      "addresses": {
        "LoD/PD2": "0x7B338FA0"
      },
      "rvas": {
        "LoD/PD2": "0x8FA0"
      },
      "sizes": {
        "LoD/PD2": 64
      },
      "name": "_strpbrk",
      "signature": "char * _strpbrk(char * _Str, char * _Control)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strpbrk\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:262b55d4b1f21fd166621d0ca2135ed8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "262b55d4b1f21fd166621d0ca2135ed8",
        "CFG": "fd48d6310d325d495db3e5b0dc4529ca",
        "PRO": "de907609c9ddaaea9fc64ebc489a583b"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_34260d5eec81": {
      "addresses": {
        "LoD/PD2": "0x7B338FE0"
      },
      "rvas": {
        "LoD/PD2": "0x8FE0"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "__mbsdec",
      "signature": "uchar * __mbsdec(uchar * _Start, uchar * _Pos)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mbsdec\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:34260d5eec8139d14f8eaa440ecdab22",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "34260d5eec8139d14f8eaa440ecdab22",
        "CFG": null,
        "PRO": "c3142cea20aab0f47fbf5ade03bfd374"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_eaa05e5abea2": {
      "addresses": {
        "LoD/PD2": "0x7B338FF7"
      },
      "rvas": {
        "LoD/PD2": "0x8FF7"
      },
      "sizes": {
        "LoD/PD2": 141
      },
      "name": "__mbsdec_l",
      "signature": "uchar * __mbsdec_l(uchar * _Start, uchar * _Pos, _locale_t _Locale)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mbsdec_l\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:eaa05e5abea2c5ef0b83c962333d2ba7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "eaa05e5abea2c5ef0b83c962333d2ba7",
        "CFG": "b45158575cd2e0bfd79f64510e74643f",
        "PRO": "15650f5e63ff76e2f3a44f86a6dd7a7f"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_6c5190e4e0b3": {
      "addresses": {
        "LoD/PD2": "0x7B339084"
      },
      "rvas": {
        "LoD/PD2": "0x9084"
      },
      "sizes": {
        "LoD/PD2": 257
      },
      "name": "ConvertAndCheckStringCharacterTypes",
      "signature": "int ConvertAndCheckStringCharacterTypes(int * pContext, DWORD localeId, LPCSTR inputString, int conversionType, LPWORD charTypeArray, uint bufferSize, int flags)",
      "calling_convention": "__cdecl",
      "comment": "Converts a string and retrieves character type information using Windows locale settings.\n\nThis function converts an ANSI/multibyte string to Unicode and determines the character type classifications (uppercase, lowercase, digit, whitespace, etc.) for each character. It handles both stack-allocated and heap-allocated conversion buffers based on the required size.\n\nAlgorithm:\n1. Initialize context structure via FUN_7b3364ce from first parameter\n2. Use bufferSize parameter if provided, otherwise load default from context offset +0x8\n3. Call FUN_7b337232 to get string conversion length with specified flags\n4. Return early if conversion fails (returns 0)\n5. Calculate required buffer size: length*2+8 bytes for Unicode conversion with alignment margin\n6. If buffer \u2264 0x400 (1024) bytes, allocate on stack; otherwise allocate from heap\n7. Clear allocated buffer memory with _memset to zeros\n8. Perform actual string conversion via FUN_7b337232 into the allocated buffer\n9. If conversion succeeds, call GetStringTypeW to classify each character by type\n10. Clean up allocated buffer via CleanupAllocatedBuffer\n11. If cleanup flag is set, clear bit 1 in context offset +0x350 (AND with 0xfffffffd)\n12. Validate stack cookie and return result\n\nParameters:\n- pContext: Pointer to context structure (modified by FUN_7b3364ce), accessed at offset +0x350 for flags and offset +0x8 for default buffer size\n- localeId: Windows locale identifier passed to GetStringTypeW for character classification\n- inputString: Input ANSI/multibyte string to convert\n- conversionType: String conversion flags combined with flags parameter\n- charTypeArray: Output array of WORDs receiving character type bits from GetStringTypeW\n- bufferSize: Unicode conversion buffer size in WCHARs (0=use default from context+0x8)\n- flags: Conversion flags (0=normal, 1=wide output)\n\nReturns:\n- int: Result from GetStringTypeW (0=failure, non-zero=success), or 0 if string conversion fails\n\nSpecial Cases:\n- Conversion buffer allocation uses dynamic sizing: if converted length*2+8 \u2264 1024 bytes, stack allocation is faster; otherwise heap allocation necessary\n- Magic value 0xdddd written to heap-allocated buffer start as sentinel value\n- Magic value 0xcccc written for stack-allocated path as sentinel value\n- Context cleanup flag (bit 1 at offset +0x350) may be modified on function exit if local cleanup flag set during initialization\n- Stack cookie validation performed via ValidateStackCookie for security verification before return",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6c5190e4e0b3dbd861f91d05ba97d242",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6c5190e4e0b3dbd861f91d05ba97d242",
        "CFG": "5d1cb893526c5dca2039877396d57c92",
        "PRO": "054b16d0716d6607fc3c4b2f51d21dde"
      },
      "basic_block_counts": {
        "LoD/PD2": 34
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "PD2_EXT_MNE_f28d5c05cf0f": {
      "addresses": {
        "LoD/PD2": "0x7B339185"
      },
      "rvas": {
        "LoD/PD2": "0x9185"
      },
      "sizes": {
        "LoD/PD2": 32
      },
      "name": "CleanupAllocatedBuffer",
      "signature": "void CleanupAllocatedBuffer(int * pBufferPtr)",
      "calling_convention": "__cdecl",
      "comment": "Validates and cleans up an allocated buffer with a magic number header.\n\nChecks if the provided buffer pointer is valid and has the required sentinel\nmagic number (0xdddd) at offset -8 bytes before the pointer. If both conditions\nare met, delegates cleanup to FUN_7b335e34.\n\nAlgorithm:\n1. Check if pBufferPtr is non-null\n2. Subtract 8 bytes from pBufferPtr to access the header\n3. Verify magic number at header equals 0xdddd\n4. If valid, call FUN_7b335e34 with header pointer for cleanup\n5. Return to caller\n\nParameters:\n  pBufferPtr: Pointer to allocated buffer data (actual buffer starts 8 bytes after header)\n\nReturns:\n  void\n\nSpecial Cases:\n  - NULL pointer: No cleanup performed, function returns immediately\n  - Invalid magic number: No cleanup performed, indicates corrupted or uninitialized buffer\n  - Magic number 0xdddd: Standard sentinel indicating valid managed allocation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f28d5c05cf0f479daa327cbc72809da8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f28d5c05cf0f479daa327cbc72809da8",
        "CFG": "8f07861f6cd1d62ebc3afdfd7666728c",
        "PRO": "a7d6e345aaf753191784d9a17e0ec5dc"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_d683610fe37d": {
      "addresses": {
        "LoD/PD2": "0x7B3391A5"
      },
      "rvas": {
        "LoD/PD2": "0x91A5"
      },
      "sizes": {
        "LoD/PD2": 495
      },
      "name": "MapWideCharacterString",
      "signature": "int MapWideCharacterString(int * pLCTable, wchar_t * pSourceString, uint dwMapFlags, char * pSourceBytes, int cbSourceBytes, LPWSTR pDestString, int cbDestString, uint dwCodePage, int bUnicodeWidth)",
      "calling_convention": "__cdecl",
      "comment": "Maps wide character string using locale code page and mapping flags.\n\nAlgorithm:\n1. Get stack cookie for security verification and store XOR with return address\n2. Validate source byte length: call ___strncnt to count actual bytes if length specified\n3. Get locale code page: use param_8 if specified, else load from pLCTable->CodePage (offset +8)\n4. Call FUN_7b337232 to get required output buffer size based on mapping flags\n5. If size is 0, return 0 (no mapping needed)\n6. Allocate output buffer (use stack if size < 0x401, else use __malloc_base)\n7. If stack/heap allocation succeeds, pad buffer with 0xcccc/0xdddd pattern\n8. Call FUN_7b337232 again with allocated buffer to perform actual mapping\n9. If second mapping succeeds:\n   - Call FID_conflict____acrt_CompareStringEx_36 to compare mapped result with source\n   - If 0x400 flag (NORM_IGNORECASE or similar) is set:\n     * Allocate second buffer for comparison result\n     * Call FID_conflict____acrt_CompareStringEx_36 again if pDestString provided and size permits\n     * If param_7 > 0, use dest string directly without second mapping\n   - Call FUN_7b3372ec to process mapping result\n10. Free allocated buffers via FUN_7b339185\n11. Verify stack cookie and return\n\nParameters:\npLCTable (int*): Pointer to locale table containing code page info at offset +8\npSourceString (wchar_t*): Wide character source string for comparison\ndwMapFlags (uint): Mapping flags (0x400 indicates special comparison handling)\npSourceBytes (char*): Source byte string to map\ncbSourceBytes (int): Length of source bytes (-1 means null-terminated)\npDestString (LPWSTR): Destination buffer for mapped string output\ncbDestString (int): Size of destination buffer in wide characters\ndwCodePage (uint): Code page to use (0 means read from pLCTable)\nbUnicodeWidth (int): Unicode width indicator (affects output format)\n\nReturns:\nint: Non-zero if mapping succeeds and result processed, 0 if allocation fails or mapping returns 0\n\nSpecial Cases:\n- Stack allocation (0xcccc pattern) used if buffer < 0x401 bytes\n- Heap allocation (0xdddd pattern) used if buffer >= 0x401 bytes\n- If param_7 == 0, pDestString is set to NULL and comparison skipped\n- Magic number 0x400 controls whether secondary comparison/transformation occurs\n- Stack cookie checked via ValidateStackCookie before return for buffer overflow detection",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d683610fe37d4dbbe5012d024cbd8a01",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d683610fe37d4dbbe5012d024cbd8a01",
        "CFG": "d62e3b62cca807962786641373723e9a",
        "PRO": "60d5f8af96063912a733e64d9a891a6e"
      },
      "basic_block_counts": {
        "LoD/PD2": 42
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 9
      }
    },
    "PD2_EXT_MNE_1a4cdc7cc16e": {
      "addresses": {
        "LoD/PD2": "0x7B339394"
      },
      "rvas": {
        "LoD/PD2": "0x9394"
      },
      "sizes": {
        "LoD/PD2": 73
      },
      "name": "___acrt_LCMapStringA",
      "signature": "undefined ___acrt_LCMapStringA(int * param_1, wchar_t * param_2, uint param_3, char * param_4, int param_5, LPWSTR param_6, int param_7, uint param_8, int param_9)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_LCMapStringA\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1a4cdc7cc16e44f870ec14fe34a7f129",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1a4cdc7cc16e44f870ec14fe34a7f129",
        "CFG": "66b388b5bf2646eebda1fbdb1d0c48c4",
        "PRO": "3319a57c23c6e09bbde82160b0d44f47"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 9
      }
    },
    "PD2_EXT_MNE_821454df2335": {
      "addresses": {
        "LoD/PD2": "0x7B3393EC"
      },
      "rvas": {
        "LoD/PD2": "0x93EC"
      },
      "sizes": {
        "LoD/PD2": 51
      },
      "name": "FID_conflict:__msize_base",
      "signature": "size_t FID_conflict:__msize_base(void * _Memory)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Multiple Matches With Different Base Names\n __msize\n __msize_base\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:821454df23359278f97d5ca0cd1ae75b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "821454df23359278f97d5ca0cd1ae75b",
        "CFG": "a6bf393c372acd04e8e2250d24df4a4c",
        "PRO": "e1d7aa91b5786301a2078faef33ae0ed"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_fa7c994c7841": {
      "addresses": {
        "LoD/PD2": "0x7B33941F"
      },
      "rvas": {
        "LoD/PD2": "0x941F"
      },
      "sizes": {
        "LoD/PD2": 105
      },
      "name": "__realloc_base",
      "signature": "LPVOID __realloc_base(LPVOID param_1, uint param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __realloc_base\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fa7c994c784156ccfeaf3d874d33c0f8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fa7c994c784156ccfeaf3d874d33c0f8",
        "CFG": "cbe9ac554b36f626c7a102af34a3afe6",
        "PRO": "2a11998d866825c8108c4280503b57ab"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_STR_26b7b4c301dc": {
      "addresses": {
        "LoD/PD2": "0x7B339488"
      },
      "rvas": {
        "LoD/PD2": "0x9488"
      },
      "sizes": {
        "LoD/PD2": 80
      },
      "name": "FID_conflict:GetTableIndexFromLocaleName",
      "signature": "undefined4 FID_conflict:GetTableIndexFromLocaleName(ushort * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Multiple Matches With Different Base Names\n int __cdecl GetTableIndexFromLocaleName(wchar_t const *)\n int __cdecl ATL::_AtlGetTableIndexFromLocaleName(wchar_t const *)\n _GetTableIndexFromLocaleName\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:26b7b4c301dce06ee4ee12c760af217f",
      "indexes": {
        "EXP": null,
        "STR": "26b7b4c301dce06ee4ee12c760af217f",
        "API": null,
        "MNE": "7e2b485dc7304f3b39b5e52f47d21fe1",
        "CFG": "b1a6965cb130b946575a112e50949cce",
        "PRO": "eefcdf0845e6a0ca9afbda70f196f160"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_f9cb8bbabfde": {
      "addresses": {
        "LoD/PD2": "0x7B3394D8"
      },
      "rvas": {
        "LoD/PD2": "0x94D8"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "___acrt_DownlevelLocaleNameToLCID",
      "signature": "undefined4 ___acrt_DownlevelLocaleNameToLCID(ushort * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_DownlevelLocaleNameToLCID\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f9cb8bbabfde9f0d802b895666dd6def",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f9cb8bbabfde9f0d802b895666dd6def",
        "CFG": "2bea3eb19dd06b49df098eed6ded289c",
        "PRO": "6cb037196f20475bc9b4a51d3c907db4"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_9e6717354394": {
      "addresses": {
        "LoD/PD2": "0x7B339504"
      },
      "rvas": {
        "LoD/PD2": "0x9504"
      },
      "sizes": {
        "LoD/PD2": 123
      },
      "name": "___acrt_lowio_create_handle_array",
      "signature": "undefined4 * ___acrt_lowio_create_handle_array(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_lowio_create_handle_array\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9e6717354394017443de5a44cb09f0b6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9e6717354394017443de5a44cb09f0b6",
        "CFG": "9deb949d4a97738d074d21851bff7e3a",
        "PRO": "7fabee32f89a9727b9219ac2533f94c0"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_077522c6148b": {
      "addresses": {
        "LoD/PD2": "0x7B33957F"
      },
      "rvas": {
        "LoD/PD2": "0x957F"
      },
      "sizes": {
        "LoD/PD2": 53
      },
      "name": "___acrt_lowio_destroy_handle_array",
      "signature": "undefined ___acrt_lowio_destroy_handle_array(LPCRITICAL_SECTION param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_lowio_destroy_handle_array\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:077522c6148b6219a33ff503efe78b61",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "077522c6148b6219a33ff503efe78b61",
        "CFG": "cbafa6d7274a163cbd4737f3f5446571",
        "PRO": "0815f411a7b4f31f8743e5e3d0dc5ab9"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_c4b813a7b219": {
      "addresses": {
        "LoD/PD2": "0x7B3395B4"
      },
      "rvas": {
        "LoD/PD2": "0x95B4"
      },
      "sizes": {
        "LoD/PD2": 146
      },
      "name": "___acrt_lowio_ensure_fh_exists",
      "signature": "undefined4 ___acrt_lowio_ensure_fh_exists(uint param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_lowio_ensure_fh_exists\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c4b813a7b21903a4ba0e3c408035d058",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c4b813a7b21903a4ba0e3c408035d058",
        "CFG": "6818c90695212ca5c4ebb043f243585c",
        "PRO": "d48f84dc641d9bef59c561ff7392a224"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_f0eea9e7b937": {
      "addresses": {
        "LoD/PD2": "0x7B339675"
      },
      "rvas": {
        "LoD/PD2": "0x9675"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "AcquireResourceLock",
      "signature": "void AcquireResourceLock(uint resourceId)",
      "calling_convention": "__cdecl",
      "comment": "Acquires a critical section lock for a pooled resource identified by a composite resource ID.\n\nAlgorithm:\n1. Extract lower 6 bits of resourceId as slot index within the bank\n2. Extract upper bits of resourceId as bank index (right-shifted by 6)\n3. Calculate offset = (slot_index) * 0x38 (56 bytes per resource entry)\n4. Look up the bank array at DAT_7b3460d0 using bank_index * 4\n5. Add offset to base pointer from bank array to locate critical section\n6. Call EnterCriticalSection to acquire the lock\n\nParameters:\n- resourceId (uint): Composite resource identifier encoding both bank index (bits 6+) and slot index (bits 0-5). The lower 6 bits select one of 64 slots within a bank, and the upper bits select which bank's resource pool to access.\n\nReturns:\n- void (no return value; function performs synchronous lock acquisition)\n\nSpecial Cases:\n- The resource ID uses a 6-bit slot encoding (0-63) with remaining bits for bank selection\n- Each resource entry is 0x38 (56) bytes in size\n- Critical sections are stored in a multi-level indexing scheme to support large resource pools\n- The function blocks until the lock is successfully acquired",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f0eea9e7b937909bb6d7a1715646f825",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f0eea9e7b937909bb6d7a1715646f825",
        "CFG": null,
        "PRO": "3db69c51af0643e138395283f40bbca9"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_f23488124f61": {
      "addresses": {
        "LoD/PD2": "0x7B339698"
      },
      "rvas": {
        "LoD/PD2": "0x9698"
      },
      "sizes": {
        "LoD/PD2": 145
      },
      "name": "CloseResourceHandleState",
      "signature": "void CloseResourceHandleState(uint resourceIndex)",
      "calling_convention": "__cdecl",
      "comment": "Clears resource-specific handle state and optionally closes standard handles.\n\nAlgorithm:\n1. Validate resourceIndex is within valid range (0 to DAT_7b3462d0)\n2. Calculate state array offset using (resourceIndex & 0x3f) * 0x38\n3. Look up state array base pointer from table using (resourceIndex >> 6)\n4. Check if resource is marked active (flag byte at offset+0x28 & 1)\n5. Verify handle is valid (not -1) at state offset+0x18\n6. Call GetGlobalFlag() to check if in console mode\n7. If in console mode (flag=1), dispatch by resourceIndex:\n   - Index 0: Call SetStdHandle(STD_INPUT_HANDLE=0xFFFFFFF6, NULL)\n   - Index 1: Call SetStdHandle(STD_OUTPUT_HANDLE=0xFFFFFFF5, NULL)\n   - Index 2: Call SetStdHandle(STD_ERROR_HANDLE=0xFFFFFFF4, NULL)\n8. Write -1 to handle state at offset+0x18 to mark cleared\n9. Return 0 for success\n10. If validation fails, call FUN_7b335dc4 and FUN_7b335db1 for error reporting\n11. Return 0xFFFFFFFF for invalid index\n\nParameters:\n- resourceIndex (uint): Index into global resource handle table, range 0-255+\n\nReturns:\n- 0: Resource handle state cleared successfully\n- 0xFFFFFFFF: Invalid resource index or handle not valid\n\nSpecial Cases:\n- Handles indices 0, 1, 2 as standard I/O handle indices (stdin/stdout/stderr)\n- Only modifies standard handles when in console mode (GetGlobalFlag=1)\n- Uses 2-level indirect array addressing: DAT_7b3460d0[resourceIndex>>6][offset]\n- State array has stride 0x38 (56 bytes) per entry, indexed by lower 6 bits\n- Magic numbers: 0x3f=63 (6-bit mask), 0x38=56 (stride), 0x28=active flag offset, 0x18=handle offset\n\nStructure Layout - Resource State Entry:\nOffset | Size | Field Name | Type | Description\n0x00   | 56   | entry[56]  | byte | State entry, 56 bytes total per resource\n0x18   | 4    | handle     | int  | Handle value (-1 if invalid/closed)\n0x28   | 1    | flags      | byte | Active flag (bit 0 = open/valid)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23488124f6199f67aa05d7c007a3b69",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23488124f6199f67aa05d7c007a3b69",
        "CFG": "2675712b39dde43e72311ab29c4f8a0a",
        "PRO": "75e9293711e84b8bf84a1ee4e045b895"
      },
      "basic_block_counts": {
        "LoD/PD2": 24
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_62faa96bf3c7": {
      "addresses": {
        "LoD/PD2": "0x7B339729"
      },
      "rvas": {
        "LoD/PD2": "0x9729"
      },
      "sizes": {
        "LoD/PD2": 106
      },
      "name": "GetFileHandleFromIndex",
      "signature": "HANDLE GetFileHandleFromIndex(uint handleIndex)",
      "calling_convention": "__cdecl",
      "comment": "Retrieves a Windows file HANDLE from the descriptor table based on an index.\n\nAlgorithm:\n1. Check if handleIndex equals 0xFFFFFFFE (-2), which triggers initialization/reset\n2. If initialization requested, call FUN_7b335db1 and clear error state (write 0)\n3. Call FUN_7b335dc4 and set error code to 9\n4. Jump to return error code path\n5. For normal lookups, validate handleIndex is non-negative (not signed)\n6. Check if handleIndex is within valid range (< DAT_7b3462d0, the descriptor table size)\n7. If out of range, jump to error handler\n8. Calculate descriptor entry offset: lower 6 bits (& 0x3F) * 0x38 = entry offset in block\n9. Calculate descriptor table index: shift handleIndex right by 6 bits for table selection\n10. Load descriptor table pointer from DAT_7b3460d0 using table index\n11. Load descriptor block at pointer location\n12. Test bit 0 at offset +0x28 + entry_offset to check if handle is open/allocated\n13. If bit is not set (handle not allocated), jump to error handler\n14. If bit is set, load HANDLE value from offset +0x18 + entry_offset\n15. Pop saved registers and return the retrieved HANDLE value\n16. Error path: call FUN_7b335db1 to clear state, call FUN_7b335dc4 to set error 9\n17. Call FUN_7b335ce3 for additional error processing\n18. Load 0xFFFFFFFF into EAX as error return code\n19. Restore stack frame and return with error code\n\nParameters:\n- handleIndex: uint - Index into the descriptor table. Special value 0xFFFFFFFE (-2) triggers reset/initialization. Valid range is 0 to (DAT_7b3462d0 - 1).\n\nReturns:\n- HANDLE: On success, returns the Windows file HANDLE stored at descriptor table entry\n- 0xFFFFFFFF (-1): On error, invalid index, or handle not allocated\n\nSpecial Cases:\n- Magic Value 0xFFFFFFFE: Reserved for initialization/reset operation; clears error state and sets error code 9\n- Descriptor Table Layout: 2D table where outer array uses DAT_7b3460d0, each entry is 0x4 bytes (pointer)\n- Descriptor Entry Layout: Each entry is 0x38 bytes; bit 0 at offset +0x28 indicates allocation status\n- Allocated Handle Storage: Windows HANDLE stored at offset +0x18 within descriptor entry\n- Stride Calculation: Entry offset = (handleIndex & 0x3F) * 0x38; allows up to 64 handles per block\n- Table Index: handleIndex >> 6 selects which descriptor block to use; supports multiple blocks for scalability",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:62faa96bf3c78f5ed0ea2c4515e6dcde",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "62faa96bf3c78f5ed0ea2c4515e6dcde",
        "CFG": "eb75f0b009e5d824741621967c5406cd",
        "PRO": "fdf5754b81e278d1bea27fe5429ff1bf"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_c14b7d9f7c2f": {
      "addresses": {
        "LoD/PD2": "0x7B339793"
      },
      "rvas": {
        "LoD/PD2": "0x9793"
      },
      "sizes": {
        "LoD/PD2": 147
      },
      "name": "FlushFileAndUnlock",
      "signature": "undefined4 FlushFileAndUnlock(uint * pStreamContext, undefined4 * pFileHandleIndex)",
      "calling_convention": "__stdcall",
      "comment": "Flushes file buffers to disk and unlocks the file handle.\n\nAlgorithm:\n1. Initialize return status to 0 (success)\n2. Call stream preparation function FUN_7b339652 with stream context\n3. Extract file handle index from param_2\n4. Calculate file descriptor table offset: index/64 as table index, (index%64)*0x38 as entry offset\n5. Test bit 0 of the descriptor entry to check if file handle is open\n6. If file is closed, skip to error handling\n7. If file is open, call FUN_7b339729 to retrieve the HANDLE object from the index\n8. Call Windows API FlushFileBuffers(hFile) to flush all buffered data to disk\n9. Test result of FlushFileBuffers call\n10. If successful (non-zero), jump to cleanup phase\n11. If failed (zero), call GetLastError to retrieve Windows error code\n12. Call FUN_7b335db1 to store the Windows error in thread context\n13. Call FUN_7b335dc4 to access error state and set error code 0x9 (file flush error)\n14. Set return value in ESI to 0xFFFFFFFF (failure code -1)\n15. Call UnlockFileHandleWrapper to release file handle lock and cleanup resources\n16. Return status value in EAX\n\nParameters:\n- pStreamContext: Pointer to stream/file context structure containing file management state\n- pFileHandleIndex: Pointer to unsigned integer containing the file handle index in the descriptor table\n\nReturns:\n- 0x00000000 (0) if file flush succeeds or file handle was not open\n- 0xFFFFFFFF (-1) if FlushFileBuffers fails or error occurs during processing\n\nSpecial Cases:\n- Error Code 0x9: File buffer flush operation failed; actual Windows error stored via FUN_7b335db1\n- Unopened Files: If bit 0 of file descriptor is not set, flush is skipped and function returns success\n- Windows Error Preservation: GetLastError result is captured and stored for diagnostic purposes\n- Exception Handling: SEH frame managed by __SEH_prolog4 for structured exception handling",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c14b7d9f7c2f0554fc35d4474ea0fe9d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c14b7d9f7c2f0554fc35d4474ea0fe9d",
        "CFG": "5f865b07fbd149fe0d57e8cc3d9d2f83",
        "PRO": "1861963b397e238f6af9fce1e2915da8"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_3dfb0e9c9ab5": {
      "addresses": {
        "LoD/PD2": "0x7B339835"
      },
      "rvas": {
        "LoD/PD2": "0x9835"
      },
      "sizes": {
        "LoD/PD2": 125
      },
      "name": "__commit",
      "signature": "int __commit(int _FileHandle)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __commit\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3dfb0e9c9ab554df7dd5052a12a4b91c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3dfb0e9c9ab554df7dd5052a12a4b91c",
        "CFG": "6d11d394882ec5edb05b323d706064fc",
        "PRO": "6e311390662ab97da9c849a83d25d904"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_e2092ca8f567": {
      "addresses": {
        "LoD/PD2": "0x7B3398B2"
      },
      "rvas": {
        "LoD/PD2": "0x98B2"
      },
      "sizes": {
        "LoD/PD2": 962
      },
      "name": "ProcessAndWriteEncodedText",
      "signature": "void ProcessAndWriteEncodedText(DWORD * pOutputInfo, uint encodeType, uint * pReadBuffer, int outputCP, int * pEncodeState)",
      "calling_convention": "__cdecl",
      "comment": "Encodes text from UTF-8 buffer to console-compatible format and writes to file.\n\nThis function processes character-by-character encoding conversion from UTF-8 source\nto target encoding (typically UTF-16 for console output), with special handling for\nDiablo II legacy text encoding at state 0xfde9. Handles newline normalization by\ninserting carriage returns before LF characters on Windows.\n\nAlgorithm:\n1. Initialize output structures and console code page\n2. Validate encoding state and fetch state magic value (0xfde9 for D2 text)\n3. Loop through each character in source buffer:\n   a. Extract character and check encoding state (D2 vs standard)\n   b. For D2 text (0xfde9): Handle dual-byte sequences or single-byte conversion\n   c. For standard text: Convert UTF-8 to UTF-16 using system encoder\n   d. Write encoded bytes to file handle\n   e. If character is LF (0x0A), also write CR (0x0D) for Windows line endings\n4. Update output counters with bytes written\n5. Continue until end of source buffer or error\n6. Return with error code in output structure if write fails\n\nParameters:\n- pOutputInfo: Output structure, offsets [0]=error, [4]=bytesWritten, [8]=totalSize\n- encodeType: Encoding type identifier encoding slot/index\n- pReadBuffer: Source UTF-8 text buffer to encode\n- outputCP: Output code page for encoding (Windows CP identifier)\n- pEncodeState: Encoding state structure (contains magic value at offset 0xc)\n\nReturns: void (errors stored in pOutputInfo[0])\n\nSpecial Cases:\n- Magic value 0xfde9 at pEncodeState[3] indicates Diablo II text encoding\n- Handles flag 0x04 for dual-byte character prefixes\n- Validates buffer boundaries before writing\n- Inserts CR+LF for newline normalization (0x0A becomes 0x0D 0x0A)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e2092ca8f567bc0e5dc92e91f4f5e581",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e2092ca8f567bc0e5dc92e91f4f5e581",
        "CFG": "f9f3129f80f9cc63b27c67d1cab45fc2",
        "PRO": "fd28d7ab86f6811f018bbdd967dffa8b"
      },
      "basic_block_counts": {
        "LoD/PD2": 56
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_0458f672ddb7": {
      "addresses": {
        "LoD/PD2": "0x7B339C79"
      },
      "rvas": {
        "LoD/PD2": "0x9C79"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "write_double_translated_unicode_nolock",
      "signature": "write_result write_double_translated_unicode_nolock(char * param_1, uint param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n struct `anonymous namespace'::write_result __cdecl write_double_translated_unicode_nolock(char const * const,unsigned int)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0458f672ddb743a082eba2e96af8397d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0458f672ddb743a082eba2e96af8397d",
        "CFG": "555d704848b8e783f7d263b7ca7bd009",
        "PRO": "a3295eea0a2ab011addfecbce2107696"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_0d05214adc30": {
      "addresses": {
        "LoD/PD2": "0x7B339CE1"
      },
      "rvas": {
        "LoD/PD2": "0x9CE1"
      },
      "sizes": {
        "LoD/PD2": 125
      },
      "name": "GetConsoleHandleMode",
      "signature": "bool GetConsoleHandleMode(uint consoleIndex, void * pConsoleInfo, DWORD * pMode)",
      "calling_convention": "__cdecl",
      "comment": "Retrieves console mode from a console handle at specified index\\nAlgorithm:\\n1. Validate console index using CheckIndexBitFlag\\n2. Calculate array offset: arrayIndex = consoleIndex >> 6, slotOffset = (consoleIndex & 0x3f) * 0x38\\n3. Load base address from DAT_7b3460d0[arrayIndex]\\n4. Check if console at offset +0x28 has negative flag (console type indicator)\\n5. If flag is negative, check if console is initialized (byte at +0x14)\\n6. Call initialization if needed via FUN_7b335260\\n7. Validate console write state at offset +0xa8 or check flag at +0x29\\n8. If conditions met, retrieve console handle at offset +0x18\\n9. Call GetConsoleMode to retrieve console mode into pMode\\n10. Return true if successful, false otherwise\\n\\nParameters:\\n- consoleIndex: Index into console array (validated via bit flag check)\\n- pConsoleInfo: Pointer to console info structure (offset 0xc has pointer, 0x14 has flag)\\n- pMode: Output parameter to store console mode\\n\\nReturns:\\n- true if console mode retrieved successfully\\n- false if index invalid, console not initialized, or GetConsoleMode fails\\n\\nStructure Layout:\\nConsole descriptor at DAT_7b3460d0[arrayIndex]:\\n  +0x18: HANDLE - Console handle\\n  +0x28: byte - Console flags (negative = valid console)\\n  +0x29: byte - Special flag indicator",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0d05214adc30281db24720a89248d709",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0d05214adc30281db24720a89248d709",
        "CFG": "33da3718f9d8f76fa5ccda61a30ccbf4",
        "PRO": "b8a70642579488eb4e88d0e49b86eae3"
      },
      "basic_block_counts": {
        "LoD/PD2": 15
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_7364e85ef83d": {
      "addresses": {
        "LoD/PD2": "0x7B339D5E"
      },
      "rvas": {
        "LoD/PD2": "0x9D5E"
      },
      "sizes": {
        "LoD/PD2": 219
      },
      "name": "write_text_ansi_nolock",
      "signature": "write_result write_text_ansi_nolock(int param_1, char * param_2, uint param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n struct `anonymous namespace'::write_result __cdecl write_text_ansi_nolock(int,char const * const,unsigned int)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7364e85ef83d311208352b086ab149d9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7364e85ef83d311208352b086ab149d9",
        "CFG": "b26838ba2a6f3f877a1ecec3c2fcd486",
        "PRO": "09ef13875dfc1023cf35bb0454005c84"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_5b4da472478d": {
      "addresses": {
        "LoD/PD2": "0x7B339E39"
      },
      "rvas": {
        "LoD/PD2": "0x9E39"
      },
      "sizes": {
        "LoD/PD2": 233
      },
      "name": "write_text_utf16le_nolock",
      "signature": "write_result write_text_utf16le_nolock(int param_1, char * param_2, uint param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n struct `anonymous namespace'::write_result __cdecl write_text_utf16le_nolock(int,char const * const,unsigned int)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5b4da472478d9d34756d0d10b38c9571",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5b4da472478d9d34756d0d10b38c9571",
        "CFG": "4bb4d8fef12feef6fa1c849c52a1f060",
        "PRO": "e7cedba94fecd8716b2f05ef5e7d52db"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_cd0aff424184": {
      "addresses": {
        "LoD/PD2": "0x7B339F22"
      },
      "rvas": {
        "LoD/PD2": "0x9F22"
      },
      "sizes": {
        "LoD/PD2": 306
      },
      "name": "write_text_utf8_nolock",
      "signature": "write_result write_text_utf8_nolock(int param_1, char * param_2, uint param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n struct `anonymous namespace'::write_result __cdecl write_text_utf8_nolock(int,char const * const,unsigned int)\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cd0aff424184376b639a11c5a2e7ee81",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd0aff424184376b639a11c5a2e7ee81",
        "CFG": "43bfa7755b199d59be8d58047587b019",
        "PRO": "8c6de1899bffff68116638f2f872da62"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_b22f314a67ff": {
      "addresses": {
        "LoD/PD2": "0x7B33A054"
      },
      "rvas": {
        "LoD/PD2": "0xA054"
      },
      "sizes": {
        "LoD/PD2": 259
      },
      "name": "ValidateAndWriteFileData",
      "signature": "int ValidateAndWriteFileData(char * fileDescriptor, uint * dataBuffer, uint bytesToWrite, int * statusInfo)",
      "calling_convention": "__cdecl",
      "comment": "ValidateAndWriteFileData - Validates file descriptor and entity state before writing buffered data\n\nAlgorithm:\n1. Check if fileDescriptor is sentinel value 0xFFFFFFFE (error handling case)\n2. If sentinel, set error flags in statusInfo structure and return -1\n3. Otherwise, validate fileDescriptor range:\n   - Check if fileDescriptor is non-negative\n   - Compare against global limit DAT_7b3462d0\n4. If validation fails, set error flags in statusInfo and return -1\n5. If valid, calculate array indices using bitwise operations:\n   - arrayIndexShifted = fileDescriptor >> 6 (divide by 64)\n   - elementOffset = (fileDescriptor & 0x3F) * 0x38 (multiply by 56)\n6. Check bit flag at data array location DAT_7b3460d0[arrayIndexShifted] + elementOffset + 0x28\n7. If bit flag not set, set error flags and return -1\n8. If bit flag set:\n   - Call FUN_7b339652 to acquire lock on entity\n   - Recheck bit flag to ensure still valid\n   - If still valid, call WriteDataToFile with parameters\n   - Call UnlockFileHandle to release lock\n   - Return result from WriteDataToFile\n9. If flag cleared after lock, set error flags and call FUN_7b335c66 error handler\n\nParameters:\nfileDescriptor (char*): File descriptor or entity index, validated against range limits\ndataBuffer (uint*): Pointer to data buffer to write\nbytesToWrite (uint): Number of bytes to write from buffer\nstatusInfo (int*): Pointer to status structure (offsets: 0x18=code, 0x1C=flag1, 0x20=flag2, 0x24=flag3)\n\nReturns:\nint: Number of bytes written on success, or -1 on validation failure\nStatus flags updated in statusInfo structure at offsets 0x18, 0x1C, 0x20, 0x24\n\nSpecial Cases:\n- Sentinel value 0xFFFFFFFE triggers immediate error handling\n- Double-checks bit flag after acquiring lock to detect race conditions\n- Uses 56-byte (0x38) element stride in data array\n- Bit position 0 in flag byte indicates valid entity\n- Error code 9 written to statusInfo[0x18] on validation failures\n",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b22f314a67ff2c7a74006f79f81bfcad",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b22f314a67ff2c7a74006f79f81bfcad",
        "CFG": "d5923c4652142fa570aa0914fbd8a2bf",
        "PRO": "21eb19d58b125699b867d7addc3cb2fc"
      },
      "basic_block_counts": {
        "LoD/PD2": 16
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_d4c2d26a88b1": {
      "addresses": {
        "LoD/PD2": "0x7B33AA89"
      },
      "rvas": {
        "LoD/PD2": "0xAA89"
      },
      "sizes": {
        "LoD/PD2": 8
      },
      "name": "UnlockFileHandle",
      "signature": "void UnlockFileHandle(void)",
      "calling_convention": "__stdcall",
      "comment": "Unlocks a file handle by calling the C runtime unlock function.\n\nAlgorithm:\n1. Push EDI register (implicit file handle parameter) to stack\n2. Call ___acrt_lowio_unlock_fh to unlock the file handle\n3. Pop ECX to discard the return address\n4. Return to caller\n\nParameters:\nIMPLICIT: EDI - File descriptor/handle to unlock (passed in EDI register)\n\nReturns:\nvoid - This function has no return value\n\nNotes:\nThis is a thin wrapper around the C runtime library's file unlock function.\nCalled as part of error handling and cleanup during file I/O operations.\nEDI contains the file handle that needs to be unlocked.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d4c2d26a88b113bd75739659d4ef7dd5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d4c2d26a88b113bd75739659d4ef7dd5",
        "CFG": null,
        "PRO": "af3e5e91e2eb128326058022bc390896"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_f047f0bb5673": {
      "addresses": {
        "LoD/PD2": "0x7B33A165"
      },
      "rvas": {
        "LoD/PD2": "0xA165"
      },
      "sizes": {
        "LoD/PD2": 540
      },
      "name": "WriteDataToFile",
      "signature": "int WriteDataToFile(char * pFileHandle, uint * pData, uint dataSize, int * pErrorStruct)",
      "calling_convention": "__cdecl",
      "comment": "WriteDataToFile: Write data to a file with format-specific encoding.\n\nAlgorithm:\n1. Validate input parameters (non-zero dataSize, valid pData pointer)\n2. Extract file handle components using bit operations: handle_index = pFileHandle >> 6, slot_offset = (pFileHandle & 0x3f) * 0x38\n3. Retrieve encoding type from file metadata at [handle_table + slot_offset + 0x29]\n4. Validate encoding type compatibility with data size (reject UTF-16 encodings with odd-sized data)\n5. Check file flags at [handle_table + slot_offset + 0x28] for write mode requirements\n6. If handle has seek flag (0x20), seek to end of file before writing\n7. Call encoding validator for file format compatibility via FUN_7b339ce1\n8. Select appropriate encoding function based on file format and encoding type:\n   - Format 0 (raw): FUN_7b3398b2 or direct WriteFile\n   - Format 1 (UTF-16 double-encoded): write_double_translated_unicode_nolock\n   - Format 2/3 (text): encoding-specific text writers (UTF-8, UTF-16LE, ANSI)\n9. Execute chosen encoding function to convert and write data\n10. Store result codes in resultArray: [error_code, bytes_attempted, bytes_written, reserved]\n11. Check for write errors: if bytes_attempted != bytes_written, return difference\n12. If error code is 0 and EOF marker check enabled (0x40), verify first byte is 0x1a for EOF\n13. On error code 5 (Access Denied), set error codes 9 and 5 in pErrorStruct\n14. On other errors, call error handler FUN_7b335d8d to format error message\n15. Return -1 on all errors, 0 on success with proper EOF detection\n\nParameters:\n- pFileHandle: char* - File handle reference encoded as (index << 6) | slot, unpacks to file metadata location\n- pData: uint* - Pointer to data buffer to write\n- dataSize: uint - Size in bytes of data to write, must be non-zero and valid for encoding type\n- pErrorStruct: int* - Pointer to error structure (40+ bytes) where offset +0x18=error code, +0x1c=error bit, +0x20=error value, +0x24=error flag\n\nReturns:\n- 0: Write succeeded and data was properly encoded/written\n- -1: Critical error occurred (missing parameters, encoding error, file write failure, EOF detection failed)\n- positive: Mismatch between bytes requested and bytes written (error indicator)\n\nSpecial Cases:\n- If dataSize is 0, returns immediately with 0\n- If pData is null, sets error structure to indicate invalid parameters and returns -1\n- UTF-16 encodings (type 1, 2) require even-sized data; odd-sized data triggers error return\n- Error code 5 maps to Access Denied exception in error structure\n- File handle must exist in global handle table DAT_7b3460d0; invalid handles may crash\n- EOF check only applies if file flags have 0x40 set; disabled for binary write modes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f047f0bb5673f1eede133e21a6263a31",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f047f0bb5673f1eede133e21a6263a31",
        "CFG": "09bda741bd942a51b0c077e66e966a02",
        "PRO": "66c257c1d088fafc10604375e081a8e2"
      },
      "basic_block_counts": {
        "LoD/PD2": 41
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_1490225f6e61": {
      "addresses": {
        "LoD/PD2": "0x7B33A381"
      },
      "rvas": {
        "LoD/PD2": "0xA381"
      },
      "sizes": {
        "LoD/PD2": 162
      },
      "name": "ProcessAndCleanupStreams",
      "signature": "int ProcessAndCleanupStreams(void)",
      "calling_convention": "__stdcall",
      "comment": "Iterates through all stream objects in the global stream table, processes any streams with the processed flag set (bit 13 at offset +0xc), counts successful operations, and cleans up resources including critical sections and allocated memory.\n\nAlgorithm:\n1. Initialize success counter to 0\n2. Acquire critical section lock via ___acrt_lock(8)\n3. Loop from stream index 3 to DAT_7b3462f0 (total stream count):\n   a. Load stream handle from DAT_7b3462f4[index]\n   b. If stream pointer is null, skip to next index\n   c. Check bit 13 of the flag field at stream offset +0xc\n   d. If bit 13 is set, call ProcessFileStream() on the stream\n   e. If ProcessFileStream returns -1, skip count increment\n   f. If ProcessFileStream succeeds (return != -1), increment success counter\n   g. Delete critical section stored at stream offset +0x20\n   h. Call FUN_7b335e34 to deallocate stream memory\n   i. Clear the stream pointer in the table\n4. Release critical section lock via UnlockCriticalSection()\n5. Return total count of successfully processed streams\n\nParameters:\nNone\n\nReturns:\nint - Count of streams successfully processed by ProcessFileStream. Value is zero if no streams match the processed flag criteria or all calls fail.\n\nSpecial Cases:\nMagic value -1: ProcessFileStream returns -1 on error; any return other than -1 is considered success\nBit 13 test: Flag at offset +0xc indicates whether stream has been processed and is ready for file I/O\nOffset values: Critical section at +0x20, flags at +0xc are offsets from stream structure base address\nIndex start: Loop begins at index 3, not 0; indices 0-2 are reserved or handled elsewhere",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1490225f6e61e23460b0ad7b0812ef57",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1490225f6e61e23460b0ad7b0812ef57",
        "CFG": "e69b5b2d2ce6c635a72554fac4fc9756",
        "PRO": "fe22072246588c6f297e624a6c709720"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_baa4962c289a": {
      "addresses": {
        "LoD/PD2": "0x7B33A42C"
      },
      "rvas": {
        "LoD/PD2": "0xA42C"
      },
      "sizes": {
        "LoD/PD2": 64
      },
      "name": "___acrt_stdio_free_buffer_nolock",
      "signature": "undefined ___acrt_stdio_free_buffer_nolock(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_stdio_free_buffer_nolock\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:baa4962c289ab932127049f807079e1f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "baa4962c289ab932127049f807079e1f",
        "CFG": "b724ed9bc22393fb1bfd3fcd83003d6f",
        "PRO": "3f49546fada9ba9407efe3b4e8ef46a9"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_733b5221be18": {
      "addresses": {
        "LoD/PD2": "0x7B33A46C"
      },
      "rvas": {
        "LoD/PD2": "0xA46C"
      },
      "sizes": {
        "LoD/PD2": 86
      },
      "name": "CheckIndexBitFlag",
      "signature": "byte CheckIndexBitFlag(uint nIndex)",
      "calling_convention": "__cdecl",
      "comment": "Checks if a specific bit flag is set for an indexed element in a sparse bit-vector array.\n\nAlgorithm:\n1. Check if nIndex equals 0xfffffffe (special error marker)\n2. If special marker: log error code 9 to TLS error context, return 0\n3. Validate nIndex is non-negative and less than DAT_7b3462d0 (max valid index)\n4. If out of bounds: log error code 9, call exception handler, return 0\n5. Extract bit field: upper 6 bits (nIndex >> 6) index into DAT_7b3460d0 array of pointers\n6. Calculate element offset: (nIndex & 0x3f) * 0x38 bytes per element\n7. Load byte at (pointer + 0x28 + element_offset) which contains the flag byte\n8. Extract bit 0x40 (bit 6) and return as status byte (0 if clear, 0x40 if set)\n\nParameters:\nnIndex - Element index to check; special value 0xfffffffe triggers error logging\n\nReturns:\nbyte - Contains bit 0x40 if flag is set (non-zero when true), 0 if flag is clear or error\n\nSpecial Cases:\nMagic number 0xfffffffe: Special marker for TLS error initialization\nMagic number 0x3f: Bitmask to extract lower 6 bits (modulo 64)\nMagic number 0x38: Element stride in bytes (56 bytes per indexed element)\nMagic number 0x28: Byte offset within element to flag field\nMagic number 0x40: Bit mask for specific flag (bit 6 of status byte)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:733b5221be189bbc3ce5891090507b61",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "733b5221be189bbc3ce5891090507b61",
        "CFG": "1d91ef73be473d07b0518e7381470fa8",
        "PRO": "3eab0234f553e924d98befe92a8c6699"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_bbecb901a0b3": {
      "addresses": {
        "LoD/PD2": "0x7B33A4C2"
      },
      "rvas": {
        "LoD/PD2": "0xA4C2"
      },
      "sizes": {
        "LoD/PD2": 13
      },
      "name": "fegetround",
      "signature": "undefined fegetround(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _fegetround\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bbecb901a0b363c16291d4ef44c843bd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bbecb901a0b363c16291d4ef44c843bd",
        "CFG": null,
        "PRO": "bbe0f29261f07bd5b74df2e266486998"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_586845a95c67": {
      "addresses": {
        "LoD/PD2": "0x7B33A4CF"
      },
      "rvas": {
        "LoD/PD2": "0xA4CF"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "GetUTF8StringLengthCategory",
      "signature": "char GetUTF8StringLengthCategory(char * pString)",
      "calling_convention": "__stdcall",
      "comment": "Determines the length category of a UTF-8 encoded string.\n\nThis function is used during UTF-8 to UTF-16 conversion to classify strings\nby their effective length. It checks the first three bytes of the string to\ndetermine how many characters or bytes need to be processed.\n\nAlgorithm:\n1. Load the input string pointer from the stack parameter\n2. Check if the first byte is null (offset +0)\n3. If null, return 1 (empty string)\n4. Check if the second byte is null (offset +1)\n5. If null, return 2 (single character string)\n6. Check if the third byte is null (offset +2)\n7. Return 3 if third byte is null, or 4 if third byte contains data\n8. Clean up stack frame and return to caller\n\nParameters:\n- pString: Pointer to null-terminated UTF-8 encoded string to classify\n\nReturns:\n- 1: String is empty (only contains null terminator at offset 0)\n- 2: String has exactly one character before null terminator (null at offset 1)\n- 3: String has exactly two characters before null terminator (null at offset 2)\n- 4: String has three or more characters (non-null byte at offset 2)\n\nSpecial Cases:\n- Input must be a valid pointer to readable memory\n- Function assumes input is null-terminated UTF-8 data\n- No validation of UTF-8 encoding correctness, only byte length",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:586845a95c67a6dc9239748fcb06a007",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "586845a95c67a6dc9239748fcb06a007",
        "CFG": "55d660ebbef99c0baa319e016760b8fc",
        "PRO": "0c4b0fe30a3f0f80bc2f61834056d4ce"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_9a26155e544e": {
      "addresses": {
        "LoD/PD2": "0x7B33A4FB"
      },
      "rvas": {
        "LoD/PD2": "0xA4FB"
      },
      "sizes": {
        "LoD/PD2": 67
      },
      "name": "DecodeUTF8WithValidation",
      "signature": "uint DecodeUTF8WithValidation(ushort * pOutputChar, byte * pUTF8Buffer, uint bufferSize, uint * pByteOffset, int errorState)",
      "calling_convention": "__cdecl",
      "comment": "Decodes a UTF-8 character from a byte buffer and validates the codepoint value.\n\nAlgorithm:\n1. Call DecodeUTF8Character to decode the next UTF-8 sequence from the buffer\n2. Check if decode result < 5 (success states 0-4 mean valid, >= 5 means error)\n3. If successful, check if decoded codepoint exceeds 0xFFFF (valid Unicode BMP range)\n4. If exceeds max range, replace with replacement character 0xFFFD\n5. If pOutputChar is not null, store the validated codepoint as a 16-bit word\n6. Return the decode result status to caller\n\nParameters:\npOutputChar (ushort*): Output pointer for decoded character, or null to skip storage\npUTF8Buffer (byte*): Input buffer containing UTF-8 encoded bytes\nbufferSize (uint): Size/length of the input buffer in bytes\npByteOffset (uint*): Offset pointer tracking position in buffer (modified by decode)\nerrorState (int): Error state code passed to decoder for context\n\nReturns:\nuint: Decode status code from DecodeUTF8Character\n  0-4: Success (valid UTF-8 sequence decoded)\n  >=5: Error (invalid UTF-8 or other decode error)\n\nSpecial Cases:\n- Codepoint replacement: Invalid codepoints > 0xFFFF are replaced with U+FFFD\n- Null pointer handling: If pOutputChar is null, decoding still occurs but result not stored\n- Buffer size limits: Respects bufferSize to prevent overruns\n- UTF-8 validation: Only stores results for valid multi-byte UTF-8 sequences",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9a26155e544e15b60c49b8c9af675241",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9a26155e544e15b60c49b8c9af675241",
        "CFG": "dfed70108de23c8b59558196fdc2451c",
        "PRO": "ebfbd5af60cc27dd9e89f91978a0c470"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_4eca1d0a9f0f": {
      "addresses": {
        "LoD/PD2": "0x7B33A53E"
      },
      "rvas": {
        "LoD/PD2": "0xA53E"
      },
      "sizes": {
        "LoD/PD2": 264
      },
      "name": "ConvertUTF8ToUTF16",
      "signature": "int ConvertUTF8ToUTF16(void * this, ushort * pDestBuffer, byte * * ppSourceBuffer, uint destCapacity, uint * pErrorState, int errorCodePtr)",
      "calling_convention": "__thiscall",
      "comment": "Converts UTF-8 encoded text to UTF-16 format (UCS-2 with surrogate pairs for extended chars).\n\nAlgorithm:\n1. Check if destination buffer pointer is NULL to determine conversion mode\n2. If NULL destination (counting mode): iterate through UTF-8 source and count resulting UTF-16 code units without writing output\n3. If valid destination (conversion mode):\n   a. Get source length using FUN_7b33a4cf (returns length of next UTF-8 character)\n   b. Decode UTF-8 character using DecodeUTF8Character which returns bytes consumed or error code\n   c. Handle decoded character: if > 0xFFFF, encode as UTF-16 surrogate pair (high surrogate 0xD800-0xDBFF, low 0xDC00-0xDFFF)\n   d. Write single UTF-16 code unit for characters <= 0xFFFF\n   e. Repeat until destination buffer full (destCapacity exhausted) or source exhausted\n4. Return count of UTF-16 code units written to destination, or -1 on error\n5. On error, set error state at errorCodePtr+0x1c to 1 and error code at errorCodePtr+0x18 to 0x2A\n\nParameters:\n- this: implicit this pointer (ECX register) - object instance\n- pDestBuffer: pointer to destination UTF-16 buffer (ushort array), NULL for length-only calculation\n- ppSourceBuffer: pointer to source byte pointer (allows advancing source position)\n- destCapacity: maximum number of UTF-16 code units to write (counts each surrogate pair unit)\n- pErrorState: pointer to error status object (updated on decode errors)\n- errorCodePtr: pointer to error context structure (offsets +0x18 for code, +0x1c for flag)\n\nReturns:\n- Positive integer: number of UTF-16 code units written/counted\n- -1: error during UTF-8 decode (invalid sequence or incomplete character)\n\nSpecial Cases:\n- Magic value 0xFFFF: boundary between single UTF-16 unit and surrogate pair encoding\n- Characters 0x10000-0x10FFFF: require surrogate pair encoding using formula (char-0x10000)\n- High surrogate: ((char >> 10) | 0xD800)\n- Low surrogate: ((char & 0x3FF) | 0xDC00)\n- Error code 0x2A: UTF-8 decode error or invalid character sequence\n- NULL source pointer: treated as end of input, returns 0",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4eca1d0a9f0f4fe18f12de6be0694a12",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4eca1d0a9f0f4fe18f12de6be0694a12",
        "CFG": "ff9f2f7d6f9bf1f2aa49feb750e2ec89",
        "PRO": "925a32b3c4a5b66511c6a5e9d39a78cf"
      },
      "basic_block_counts": {
        "LoD/PD2": 21
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "PD2_EXT_MNE_31d289fb5779": {
      "addresses": {
        "LoD/PD2": "0x7B33A646"
      },
      "rvas": {
        "LoD/PD2": "0xA646"
      },
      "sizes": {
        "LoD/PD2": 254
      },
      "name": "___acrt_locale_free_monetary",
      "signature": "undefined ___acrt_locale_free_monetary(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_locale_free_monetary\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:31d289fb57796ea89416395a3bf93a68",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "31d289fb57796ea89416395a3bf93a68",
        "CFG": "888577915c4dc51aaea3302f4efccbc2",
        "PRO": "55ede1086407de99360b3c12d1dbb321"
      },
      "basic_block_counts": {
        "LoD/PD2": 28
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_222a3af06689": {
      "addresses": {
        "LoD/PD2": "0x7B33A744"
      },
      "rvas": {
        "LoD/PD2": "0xA744"
      },
      "sizes": {
        "LoD/PD2": 105
      },
      "name": "___acrt_locale_free_numeric",
      "signature": "undefined ___acrt_locale_free_numeric(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_locale_free_numeric\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:222a3af066895a477ac4476ed1017961",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "222a3af066895a477ac4476ed1017961",
        "CFG": "dbcfe5b3a1e464acc6b646fb5b28c75c",
        "PRO": "1b0cb2f63204ea3d31b873a87a091195"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_4efc62c9beb3": {
      "addresses": {
        "LoD/PD2": "0x7B33A7AD"
      },
      "rvas": {
        "LoD/PD2": "0xA7AD"
      },
      "sizes": {
        "LoD/PD2": 37
      },
      "name": "FreePointerArray",
      "signature": "void FreePointerArray(void * * pPointerArray, int count)",
      "calling_convention": "__cdecl",
      "comment": "Frees an array of heap-allocated pointers\\n\\nAlgorithm:\\n1. Calculate end pointer as base + (count * 4 bytes)\\n2. Loop through each pointer in the array\\n3. Call FUN_7b335e34 to free each pointer via HeapFree\\n4. Increment pointer by 4 bytes (one DWORD) and repeat\\n5. Return when all pointers have been freed\\n\\nParameters:\\npPointerArray (void**): Base pointer to array of void pointers to free\\ncount (int): Number of pointers in the array\\n\\nReturns:\\nvoid: No return value. Heap free errors are logged internally by FUN_7b335e34\\n\\nSpecial Cases:\\n- Null pointers are handled gracefully by FUN_7b335e34\\n- Array elements are expected to be 4-byte pointers (32-bit)\\n- Called multiple times from ___acrt_locale_free_time for resource cleanup",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4efc62c9beb3599abeb4022d5797549f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4efc62c9beb3599abeb4022d5797549f",
        "CFG": "a9c729cc86b83c7c1ad73572a77516e6",
        "PRO": "020018724dd2b5c12eaf011e6cd5ba7f"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_dbf581d5fd50": {
      "addresses": {
        "LoD/PD2": "0x7B33A7D2"
      },
      "rvas": {
        "LoD/PD2": "0xA7D2"
      },
      "sizes": {
        "LoD/PD2": 228
      },
      "name": "___acrt_locale_free_time",
      "signature": "undefined ___acrt_locale_free_time(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_locale_free_time\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:dbf581d5fd5090508da74747dbf8e9fd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "dbf581d5fd5090508da74747dbf8e9fd",
        "CFG": "d03648ef17280c97be1611d9fd0a9b94",
        "PRO": "5f4b91e6f93447553a1b2c14d8040bd5"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_4757db11b7b2": {
      "addresses": {
        "LoD/PD2": "0x7B33A8B6"
      },
      "rvas": {
        "LoD/PD2": "0xA8B6"
      },
      "sizes": {
        "LoD/PD2": 28
      },
      "name": "___strncnt",
      "signature": "undefined ___strncnt(char * param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___strncnt\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4757db11b7b2343f9aedab64cb45c899",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4757db11b7b2343f9aedab64cb45c899",
        "CFG": "aed4449cad9c680425c75a8429257195",
        "PRO": "f42e94f181cff3d3f5c47b1600037184"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_bdb526ee05fd": {
      "addresses": {
        "LoD/PD2": "0x7B33A8D2"
      },
      "rvas": {
        "LoD/PD2": "0xA8D2"
      },
      "sizes": {
        "LoD/PD2": 79
      },
      "name": "CompareWideStringsNoCaseLength",
      "signature": "int CompareWideStringsNoCaseLength(ushort * pFirstString, ushort * pSecondString, int comparisonLength)",
      "calling_convention": "__cdecl",
      "comment": "Compares two wide-character (UTF-16) strings case-insensitively up to a specified length.\n\nAlgorithm:\n1. Check if comparisonLength is zero - return 0 if true (empty comparison)\n2. Enter loop for each character pair:\n   a. Load character from first string and advance pointer by 2 bytes\n   b. Convert uppercase ASCII (0x41-0x5A) to lowercase by adding 0x20\n   c. Load character from second string and advance pointer by 2 bytes\n   d. Convert uppercase ASCII (0x41-0x5A) to lowercase by adding 0x20\n   e. Calculate difference: firstCharValue - secondCharValue\n   f. Continue loop only if characters match AND neither is null AND counter not exhausted\n3. Return difference value (0 if all characters match, non-zero for first difference)\n\nParameters:\n- pFirstString: Pointer to first wide-character string (UTF-16, not null-terminated)\n- pSecondString: Pointer to second wide-character string (UTF-16, not null-terminated)\n- comparisonLength: Number of characters to compare (positive integer)\n\nReturns:\n- 0 if all comparisonLength characters match case-insensitively\n- Positive if first differing character in pFirstString > pSecondString (after case conversion)\n- Negative if first differing character in pFirstString < pSecondString (after case conversion)\n- Returns immediately when encountering a null character (0x0000) even if comparisonLength not reached\n\nSpecial Cases:\n- Magic number 0x41: ASCII 'A' (uppercase range start 65)\n- Magic number 0x5A: ASCII 'Z' (uppercase range end 90), so 0x1A = 26 letters\n- Magic number 0x20: Case conversion offset (32 decimal, difference between upper and lower ASCII)\n- Uppercase check: (char - 0x41) < 0x1A detects A-Z range efficiently\n- Null terminator handling: Function stops at first null character for both strings",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bdb526ee05fd688d935b4c5ad10b5ed1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bdb526ee05fd688d935b4c5ad10b5ed1",
        "CFG": "9cbb600873eef61c86824aadedc3c874",
        "PRO": "82bb402c3523e58c3146c826a2d9775e"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_41cf85657f6a": {
      "addresses": {
        "LoD/PD2": "0x7B33A927"
      },
      "rvas": {
        "LoD/PD2": "0xA927"
      },
      "sizes": {
        "LoD/PD2": 131
      },
      "name": "SeekFilePointerInternal",
      "signature": "LARGE_INTEGER SeekFilePointerInternal(uint handleId, undefined4 reserved1, undefined4 reserved2, PLARGE_INTEGER pFilePosition, int pErrorContext)",
      "calling_convention": "__cdecl",
      "comment": "Seeks a file pointer to a new position and handles any seek errors.\n\nAlgorithm:\n1. Retrieve file handle from handle manager using handleId\n2. If handle is invalid (0xffffffff), set error flags in context and return\n3. Set up LARGE_INTEGER with desired position (reserved2 as low part, &positionLow as high part)\n4. Call SetFilePointerEx to perform the actual seek operation with moveMethod\n5. If SetFilePointerEx fails, retrieve error code and invoke error handler\n6. If SetFilePointerEx succeeds, check if position components are valid (not -1)\n7. If position is invalid, clear slot busy flag and return error\n8. Return combined LARGE_INTEGER result (high and low parts)\n\nParameters:\n- handleId (uint): Identifier for file handle in handle manager\n- reserved1 (undefined4): Reserved parameter, unused\n- reserved2 (undefined4): Low 32 bits of desired file position\n- pFilePosition (PLARGE_INTEGER): Pointer to LARGE_INTEGER for new file position\n- pErrorContext (int): Pointer to error context structure for error reporting\n\nReturns:\n- LARGE_INTEGER: Combined result (EDX:EAX) containing position or error indicator (0xffffffff:0xffffffff)\n\nSpecial Cases:\n- Invalid handle (0xffffffff): Sets error code 9 in context\n- Seek failure: Calls error handler with Windows error code\n- Position validation: Returns error if high or low position bits are invalid",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:41cf85657f6ad5ff45b17d91010f2d46",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "41cf85657f6ad5ff45b17d91010f2d46",
        "CFG": "ef353e1a6ec60e54c1a32cd883661c5e",
        "PRO": "bc56a2332f1a1788793ab117aa94b8c0"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_b543930f8802": {
      "addresses": {
        "LoD/PD2": "0x7B33A9AA"
      },
      "rvas": {
        "LoD/PD2": "0xA9AA"
      },
      "sizes": {
        "LoD/PD2": 30
      },
      "name": "SeekFilePointerForHandle",
      "signature": "undefined8 SeekFilePointerForHandle(uint handleId, undefined4 reserved1, undefined4 reserved2, PLARGE_INTEGER pFilePosition, int pErrorContext)",
      "calling_convention": "__cdecl",
      "comment": "Wrapper function for file pointer seeking\nThis function is a simple pass-through wrapper that delegates all parameters directly to the internal file seeking implementation (FUN_7b33a927). It serves as an intermediary layer for file position operations.\n\nAlgorithm:\n1. Accept file handle identifier and position parameters\n2. Forward all parameters unchanged to SeekFilePointerInternal\n3. Return the result as a LARGE_INTEGER (high/low parts)\n\nParameters:\n- handleId (uint): File handle identifier or index\n- reserved1 (undefined4): Reserved parameter (typically 0)\n- reserved2 (undefined4): Reserved parameter (typically 0)\n- pFilePosition (PLARGE_INTEGER): Pointer to LARGE_INTEGER structure for new file position\n- pErrorContext (int): Pointer to error context structure\n\nReturns:\n- undefined8: LARGE_INTEGER result (union of high and low 32-bit parts) containing the operation result or error code\n\nSpecial Cases:\n- Reserved parameters are unused in current implementation\n- Error context is passed through for error reporting in SeekFilePointerInternal",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b543930f88020295eb72bcda2c5f9e6c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b543930f88020295eb72bcda2c5f9e6c",
        "CFG": null,
        "PRO": "8f156be76a0cfa5c819cccc23fd13a4c"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_f6db893b09d1": {
      "addresses": {
        "LoD/PD2": "0x7B33A9C8"
      },
      "rvas": {
        "LoD/PD2": "0xA9C8"
      },
      "sizes": {
        "LoD/PD2": 50
      },
      "name": "__putwch_nolock",
      "signature": "wint_t __putwch_nolock(wchar_t _WCh)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __putwch_nolock\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f6db893b09d1f61a0654fae64be2e22d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f6db893b09d1f61a0654fae64be2e22d",
        "CFG": "37df6770e2b24dae8705aa111e96e769",
        "PRO": "37f81d2fdb0ada64f8e090483157c76b"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_1168db019ea9": {
      "addresses": {
        "LoD/PD2": "0x7B33A9FA"
      },
      "rvas": {
        "LoD/PD2": "0xA9FA"
      },
      "sizes": {
        "LoD/PD2": 137
      },
      "name": "CloseFileWithValidation",
      "signature": "int CloseFileWithValidation(FILE * pFile, int * pErrorState)",
      "calling_convention": "__cdecl",
      "comment": "Closes a file handle with validation and proper error handling.\n\nAlgorithm:\n1. Check if FILE pointer is NULL\n   - If NULL: Set error flags (offset +0x1c = 0x1, offset +0x18 = 0x16) and call error handler\n   - Return 0xffffffff\n2. If FILE is not NULL: Extract flags from FILE._flag at offset +0xc\n3. Test bit 12 (0x1000) of the flags via right shift by 0xc\n4. If bit 12 is SET: Call file unlock sequence and return -1\n5. If bit 12 is CLEAR:\n   - Lock the file using __lock_file\n   - Call CloseFileAndCleanup to release resources\n   - Unlock file using UnlockFileStream\n   - Return cleanup result in EAX\n6. Execute exception handling cleanup (restore ExceptionList)\n7. Return status code\n\nParameters:\n  pFile (FILE *) - Pointer to FILE structure; checked at offset +0xc for flag validation\n  pErrorState (int *) - Pointer to error state structure; error codes written at offsets +0x18 and +0x1c\n\nReturns:\n  int - Status code: 0xffffffff (-1) on error, or result from CloseFileAndCleanup on success\n\nSpecial Cases:\n  - NULL FILE pointer treated as error condition\n  - Bit 12 of FILE._flag indicates valid/invalid state\n  - Error code 0x16 written to offset +0x18 for NULL pointer case\n  - Function uses SEH (Structured Exception Handling) for cleanup guarantee",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1168db019ea996650d019e8d60e2fdc8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1168db019ea996650d019e8d60e2fdc8",
        "CFG": "46cb4e36e66ba115acf50aa1bbde514c",
        "PRO": "386f69e9947dc885fb04145428566c41"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_69a9b2297933": {
      "addresses": {
        "LoD/PD2": "0x7B33AA91"
      },
      "rvas": {
        "LoD/PD2": "0xAA91"
      },
      "sizes": {
        "LoD/PD2": 142
      },
      "name": "CloseFileAndCleanup",
      "signature": "void CloseFileAndCleanup(FILE * pFile, int * pErrorStatus)",
      "calling_convention": "__cdecl",
      "comment": "Closes a file stream and performs cleanup of buffers and temporary files.\n\nALGORITHM:\n1. Validate that file pointer is not null; if null, set error status 0x16 and exit\n2. Check if file has been modified (flag bit 13 set)\n3. If modified, call FUN_7b338137 to perform file operations\n4. Free the file buffer using ___acrt_stdio_free_buffer_nolock\n5. Get file descriptor using __fileno\n6. Validate and setup file descriptor using ValidateAndSetupFileDescriptor\n7. If validation succeeds and temporary file exists, delete it using FUN_7b335e34\n8. Free the file stream resource using __acrt_stdio_free_stream\n9. Return void\n\nPARAMETERS:\n- pFile: FILE pointer to the stream being closed\n- pErrorStatus: Pointer to error status integer for error reporting\n\nRETURNS:\n- void\n\nSPECIAL CASES:\n- Null file pointer: Sets error code 0x16 (Invalid Argument)\n- Modified files: Performs flush and buffer cleanup before closing\n- Temporary files: Automatically deletes associated temp files if validation succeeds",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:69a9b229793357f2d47b7422434d40ed",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "69a9b229793357f2d47b7422434d40ed",
        "CFG": "89eea4ac70333d826a07750e8a7558be",
        "PRO": "add27b46c972357ecc2eab69fbe4c813"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_467b6ea4a537": {
      "addresses": {
        "LoD/PD2": "0x7B33AB1F"
      },
      "rvas": {
        "LoD/PD2": "0xAB1F"
      },
      "sizes": {
        "LoD/PD2": 48
      },
      "name": "ProcessFileStream",
      "signature": "int ProcessFileStream(FILE * pFileStream)",
      "calling_convention": "__cdecl",
      "comment": "Processes a file stream by initializing state, reading/processing the stream, and cleaning up.\n\nAlgorithm:\n1. Initialize file state structure with default values (FUN_7b335110)\n2. Process the file stream using the initialized state structure (FUN_7b33a9fa)\n3. Clean up and finalize state structure, writing back pending values (FUN_7b335170)\n4. Return the processing result\n\nParameters:\n- pFileStream (FILE *): Input file stream to process, may be NULL\n\nReturns:\n- int: Status code from stream processing (0xffffffff on error, 0+ on success)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:467b6ea4a5375e2d9f73e8fcca653f19",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "467b6ea4a5375e2d9f73e8fcca653f19",
        "CFG": null,
        "PRO": "a7e887550905e3c132af559bdf387546"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_e89f139b7ebc": {
      "addresses": {
        "LoD/PD2": "0x7B33ABA8"
      },
      "rvas": {
        "LoD/PD2": "0xABA8"
      },
      "sizes": {
        "LoD/PD2": 197
      },
      "name": "ComputeLogarithmBase10WithExceptionHandling",
      "signature": "uint ComputeLogarithmBase10WithExceptionHandling(int highBits, uint lowBits)",
      "calling_convention": "__cdecl",
      "comment": "Computes base-10 logarithm (log10) of a double-precision floating point value with FPU exception handling.\n\nAlgorithm:\n1. Save current FPU control word via FSTCW [ESP]\n2. Test zero condition flag (ZF from FPU) to determine input type\n3. If ZF=1: Input is denormalized/subnormal - process mantissa directly\n4. If ZF=0: Input is normal IEEE double - extract exponent and mantissa from param_2\n5. Check for zero input: Both exponent and mantissa zero -> return status 2\n6. Execute FYL2X instruction to compute Y * log2(X) scaled logarithm\n7. Test exception flag at [0x7b346324]:\n   - If set: Return result in EAX (exceptions suppressed)\n   - If clear: Call error handler for proper exception processing\n8. Return status code: 0=normal, 1=special value, 2=zero input\n\nParameters:\n  highBits (int param_1): Sign and exponent bits of IEEE 754 double\n  lowBits (uint param_2): Mantissa bits of IEEE 754 double\n\nReturns:\n  uint: Status code (0=normal result, 1=special value, 2=zero)\n  FPU ST0: Result value (log10 or special value)\n\nSpecial Cases:\n  Zero input: Loads -infinity value to FPU\n  Negative input: Handled via error handler\n  Denormalized numbers: Special mantissa checking\n  NaN/Infinity: FPU exception mechanism",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e89f139b7ebc271ec35e77bf5175b40a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e89f139b7ebc271ec35e77bf5175b40a",
        "CFG": "d94ba0b9810e28a747c6a467ecdc38f3",
        "PRO": "7ce7da908aaf3da0781772ca7943b91e"
      },
      "basic_block_counts": {
        "LoD/PD2": 23
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_064573f93882": {
      "addresses": {
        "LoD/PD2": "0x7B33AD7D"
      },
      "rvas": {
        "LoD/PD2": "0xAD7D"
      },
      "sizes": {
        "LoD/PD2": 176
      },
      "name": "TransformFpuControlWord",
      "signature": "uint TransformFpuControlWord(uint fpuControlWord)",
      "calling_convention": "__cdecl",
      "comment": "Transforms FPU control word by remapping precision and rounding mode bits.\n\nAlgorithm:\n1. Extract bits 15 and 6 (0x8040 mask) to determine precision mode and map to output bits\n   - If bits_15_6 == 0x8000 (bit 15 set): precision bits = 0xc00\n   - Else if bits_15_6 == 0x40 (bit 6 set): precision bits = 0x800\n   - Else if bits_15_6 == 0x8040 (both bits set): precision bits = 0x400\n   - Else: precision bits = 0 (no precision mode)\n2. Extract bits 14-13 (0x6000 mask) to determine rounding mode and map to output bits\n   - If bits_14_13 == 0x2000: rounding bits = 0x100\n   - Else if bits_14_13 == 0x4000: rounding bits = 0x200\n   - Else if bits_14_13 == 0x6000: rounding bits = 0x300\n   - Else: rounding bits = 0 (no rounding mode)\n3. Extract bits 12-11 (0x1800) and bits 9-8 (0x300), apply bit shifting and ORing to consolidate low-order bits\n4. Combine all bit groups: transformed_value | precision_bits | rounding_bits\n\nParameters:\n  fpuControlWord (uint): 32-bit FPU control word containing precision and rounding mode bits\n\nReturns:\n  uint: Transformed control word with remapped precision and rounding mode bits\n\nSpecial Cases:\n  - If neither bit 15 nor bit 6 is set, precision output is 0 (no valid precision mode)\n  - Bits are extracted as 16-bit short for precision check, but manipulated as 32-bit values\n  - Bit shifting operations preserve lower-order bits while consolidating high-order control bits",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:064573f93882ecc3f39943c44d3f0342",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "064573f93882ecc3f39943c44d3f0342",
        "CFG": "3705aef8abbc0be4dcfeccd2db20b36c",
        "PRO": "a00537081ca5d1335738e3c32b12e950"
      },
      "basic_block_counts": {
        "LoD/PD2": 15
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_444f103d5b14": {
      "addresses": {
        "LoD/PD2": "0x7B33AE2D"
      },
      "rvas": {
        "LoD/PD2": "0xAE2D"
      },
      "sizes": {
        "LoD/PD2": 173
      },
      "name": "RemapFpuControlBits",
      "signature": "uint RemapFpuControlBits(uint fpuControlWord)",
      "calling_convention": "__cdecl",
      "comment": "Remaps FPU control word bits from one format to another.\n\nConverts a floating-point control word by reorganizing its bit fields. This function handles the transformation of precision control bits (bits 8-9) and rounding mode bits (bits 10-11) into a different bit layout, along with other control bits.\n\nAlgorithm:\n1. Initialize precision control variable to 0x1000\n2. Extract and check precision bits (bits 8-9) from input:\n   - If bits are 0 (no precision bits set): set precision to 0x2000\n   - If bits are 0x200: keep precision as 0x1000\n   - Otherwise: set precision to 0\n3. Extract rounding mode bits (bits 10-11) and map to output values:\n   - 0x400 maps to 0x100\n   - 0x800 maps to 0x200\n   - 0xc00 maps to 0x300\n   - 0 maps to 0\n4. Perform complex bit field reorganization:\n   - Bit 0: shifted left 4 positions\n   - Bit 1: shifted left 3 positions, combined with bit 4\n   - Bit 2: preserved and doubled\n   - Bit 3: extracted and combined with bit 4 result\n   - Bit 12: shifted left 2 positions\n5. Combine all remapped fields using OR operations\n\nParameters:\n  fpuControlWord - The FPU control word to remap (typically 16-bit value)\n\nReturns:\n  uint - The remapped control word with reorganized bit fields\n\nSpecial Cases:\n  - Precision bits (8-9) are critical; different values select different behaviors\n  - Rounding mode bits (10-11) must be carefully mapped\n  - Multiple bit shifts and masks are applied to ensure proper field alignment",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:444f103d5b146a92092cf2739042d05b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "444f103d5b146a92092cf2739042d05b",
        "CFG": "0fee459a58cbbbd282d434809b423815",
        "PRO": "f6ab970d1f9e82e4be4744d172d400fe"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_8a2ad80a4d28": {
      "addresses": {
        "LoD/PD2": "0x7B33AEDA"
      },
      "rvas": {
        "LoD/PD2": "0xAEDA"
      },
      "sizes": {
        "LoD/PD2": 34
      },
      "name": "___acrt_fenv_get_common_round_control",
      "signature": "uint ___acrt_fenv_get_common_round_control(uint param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___acrt_fenv_get_common_round_control\n\nLibraries: Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8a2ad80a4d28ebf029e0ace415f49bf9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8a2ad80a4d28ebf029e0ace415f49bf9",
        "CFG": "28d68ef41469e49f60578a0ac553bdfd",
        "PRO": "fd86561558d5a24a6d3a0659bfde0e12"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_66ef614f2705": {
      "addresses": {
        "LoD/PD2": "0x7B33AEFC"
      },
      "rvas": {
        "LoD/PD2": "0xAEFC"
      },
      "sizes": {
        "LoD/PD2": 128
      },
      "name": "___acrt_fenv_get_control",
      "signature": "uint ___acrt_fenv_get_control(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___acrt_fenv_get_control\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:66ef614f2705cf804fa2950e8597c1e4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "66ef614f2705cf804fa2950e8597c1e4",
        "CFG": "60034b6e3b6f6a6854152e28e68604b8",
        "PRO": "0694a44bb111098cc6f44e25949f6c99"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_980a0f88dd0c": {
      "addresses": {
        "LoD/PD2": "0x7B33AF7C"
      },
      "rvas": {
        "LoD/PD2": "0xAF7C"
      },
      "sizes": {
        "LoD/PD2": 20
      },
      "name": "ClearOutputBufferAndReturnValue",
      "signature": "uint ClearOutputBufferAndReturnValue(uint inputValue, uint * pOutputBuffer)",
      "calling_convention": "__cdecl",
      "comment": "Clears an 8-byte output buffer while returning an input value unchanged.\n\nAlgorithm:\n1. Receive input value parameter and output buffer pointer parameter\n2. Zero out first dword at output buffer address (AND with 0x0)\n3. Zero out second dword at output buffer address + 4 (AND with 0x0)\n4. Return the original input value in EAX\n5. Exit function with caller stack cleanup\n\nParameters:\ninputValue (uint): Value to be returned unchanged by the function\npOutputBuffer (uint*): Pointer to 8-byte output buffer (2 dwords) to be cleared\n\nReturns:\nuint: Returns the inputValue parameter unchanged; used for pass-through operations\n\nSpecial Cases:\n- Function zeros exactly 8 bytes (two 4-byte dwords) at output buffer\n- Uses AND with 0x0 (equivalent to MOV 0) to zero bytes\n- Input parameter is preserved and returned; output buffer clearing is side effect\n- Typical usage: Initialize output structure while maintaining a return value\n- Called by UTF-8 decoding operations to clear state/output buffers\n\nStructure Layout (pOutputBuffer):\nOffset  Size  Field Name      Type   Description\n0x0     4     field_0         uint   First dword (zeroed by function)\n0x4     4     field_4         uint   Second dword (zeroed by function)\nTotal: 8 bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:980a0f88dd0cd4580fbd17a07b71b77c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "980a0f88dd0cd4580fbd17a07b71b77c",
        "CFG": null,
        "PRO": "4b70a51b80e24e592c7ca2ce41b033bb"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_36781661040e": {
      "addresses": {
        "LoD/PD2": "0x7B33AF90"
      },
      "rvas": {
        "LoD/PD2": "0xAF90"
      },
      "sizes": {
        "LoD/PD2": 34
      },
      "name": "InitializeUTF8State",
      "signature": "undefined4 InitializeUTF8State(undefined4 * pOutputBuffer, int pStateContext)",
      "calling_convention": "__cdecl",
      "comment": "Initialize UTF-8 decoder state and output buffer\n\nAlgorithm:\n1. Clear the output buffer (first two DWORDs set to 0)\n2. Initialize decoder state with error flag (byte at offset +0x1c = 1)\n3. Set state size/capacity field to 0x2a (42 bytes)\n4. Return error code 0xffffffff\n\nParameters:\n- pOutputBuffer: Pointer to output buffer (two DWORDs, 8 bytes total)\n- pStateContext: Pointer to decoder state context structure\n\nReturns:\n- 0xffffffff: Initialization error code or state marker\n\nSpecial Cases:\n- Magic number 0x2a (42): Appears to be maximum buffer size or state capacity\n- Initial state sets error flag (0x1c byte = 1), indicating starting state\n- Unconditional return of 0xffffffff suggests this initializes error handling state\n\nNote: Called by DecodeUTF8Character to prepare decoder state before processing input",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:36781661040e383f18f94912bb7ad0f9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "36781661040e383f18f94912bb7ad0f9",
        "CFG": null,
        "PRO": "aca61c2a7df503782d138bc744b89053"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_9061698c2f2d": {
      "addresses": {
        "LoD/PD2": "0x7B33AFB2"
      },
      "rvas": {
        "LoD/PD2": "0xAFB2"
      },
      "sizes": {
        "LoD/PD2": 433
      },
      "name": "DecodeUTF8Character",
      "signature": "int DecodeUTF8Character(uint * pCodePoint, byte * pSource, uint sourceLength, uint * pDecodeState, int errorCallback)",
      "calling_convention": "__cdecl",
      "comment": "Decodes a single UTF-8 character from a byte sequence into a Unicode code point.\n\nAlgorithm:\n1. Initialize stack cookie for buffer overflow protection\n2. Handle null or empty input: default to ASCII mode with empty source pointer\n3. Check decode state: if state is empty (fresh decode), proceed to decode first byte\n4. Read first UTF-8 byte and determine sequence length:\n   - If high bit clear (0x00-0x7F): single-byte ASCII character\n   - If pattern 110xxxxx (0xC0-0xDF): two-byte sequence, extract length 2\n   - If pattern 1110xxxx (0xE0-0xEF): three-byte sequence, extract length 3\n   - If pattern 11110xxx (0xF0-0xF7): four-byte sequence, extract length 4\n   - Otherwise: invalid UTF-8 start byte, call error handler\n5. Extract initial code point bits from first byte using bit mask (0xFF >> byte_count)\n6. Read continuation bytes (each starting with 10xxxxxx pattern):\n   - Process up to byte_count continuation bytes\n   - Validate each byte matches 10xxxxxx continuation pattern (AND 0xC0 == 0x80)\n   - Accumulate code point: shift left 6 bits, OR with 6 bits from continuation byte\n   - If any continuation byte is invalid, call error handler\n7. Validate decoded code point:\n   - Check if length matches available bytes in source\n   - If incomplete, save state for resumption and return\n   - Check for surrogate pair range (0xD800-0xDFFF): invalid in UTF-8, call error handler\n   - Check for out-of-range code point (>= 0x110000): invalid, call error handler\n   - Check for non-minimal encoding (check against boundaries: 0x80 for 2-byte, 0x800 for 3-byte, 0x10000 for 4-byte)\n8. If all validation passes: store code point to pCodePoint, call success handler\n9. Return: 1 for single-byte ASCII, 0 for error, negative if incomplete sequence waiting for more bytes\n\nParameters:\npCodePoint (ECX): Pointer to uint to receive decoded code point value\npSource (EAX): Pointer to UTF-8 byte buffer, or NULL for empty input\nsourceLength (EBP+0x10): Number of bytes available in source buffer\npDecodeState (ESI): Pointer to decode state structure with fields:\n  +0x0: uint codePoint - accumulated code point value during multi-byte decoding\n  +0x4: byte byteCount - number of bytes in sequence (2-4 for multi-byte)\n  +0x6: byte bytesRemaining - bytes still needed for current sequence\n  May be NULL pointer, in which case default state used\nerrorCallback (EBP+0x18): Callback address for error handling (negative param for error type)\n\nReturns:\n1: Successfully decoded single-byte ASCII character\n0: Error in UTF-8 encoding (invalid byte sequence, surrogate pair, overlong encoding, out-of-range)\n-1: Sequence incomplete, waiting for continuation bytes (saved in pDecodeState)\nStatus code in EAX indicates result of decoding operation\n\nSpecial Cases:\n- NULL pSource: Treats as empty input, returns minimal valid state\n- NULL pCodePoint: Skips storing result but still validates sequence\n- Surrogate pairs (0xD800-0xDFFF): Always invalid in UTF-8, triggers error handler\n- Overlong encodings: Detected by checking decoded value against minimum encoding boundaries\n- Resumption: pDecodeState preserves state between calls for incomplete sequences",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9061698c2f2d7d643f020eebe10937a2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9061698c2f2d7d643f020eebe10937a2",
        "CFG": "7a7795225bd0a578ca0a42264a39c8cd",
        "PRO": "7c8c586677979b2b5a2af54c166238f1"
      },
      "basic_block_counts": {
        "LoD/PD2": 47
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_ecf4fe5a7e47": {
      "addresses": {
        "LoD/PD2": "0x7B33B170"
      },
      "rvas": {
        "LoD/PD2": "0xB170"
      },
      "sizes": {
        "LoD/PD2": 97
      },
      "name": "___ascii_strnicmp",
      "signature": "int ___ascii_strnicmp(char * _Str1, char * _Str2, size_t _MaxCount)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___ascii_strnicmp\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ecf4fe5a7e473ceb70f30e35ac316045",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ecf4fe5a7e473ceb70f30e35ac316045",
        "CFG": "9d6ee55adf71a7a6ea890de91748a26f",
        "PRO": "416c862cdb184741475b23605c2c2d89"
      },
      "basic_block_counts": {
        "LoD/PD2": 16
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_STR_777b7e8fcf87": {
      "addresses": {
        "LoD/PD2": "0x7B33B1D1"
      },
      "rvas": {
        "LoD/PD2": "0xB1D1"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "__dcrt_lowio_initialize_console_output",
      "signature": "void __dcrt_lowio_initialize_console_output(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl __dcrt_lowio_initialize_console_output(void)\n\nLibraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:777b7e8fcf8755cf556144c52bff0cf1",
      "indexes": {
        "EXP": null,
        "STR": "777b7e8fcf8755cf556144c52bff0cf1",
        "API": null,
        "MNE": "d111cac37e95e6477bce95a18c0a4d2e",
        "CFG": null,
        "PRO": "c8ebdd6e1aaa15ad5ec76e15cc2d8115"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_fc814c436a02": {
      "addresses": {
        "LoD/PD2": "0x7B33B1F0"
      },
      "rvas": {
        "LoD/PD2": "0xB1F0"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "___dcrt_lowio_ensure_console_output_initialized",
      "signature": "bool ___dcrt_lowio_ensure_console_output_initialized(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___dcrt_lowio_ensure_console_output_initialized\n\nLibraries: Visual Studio 2019 Debug, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fc814c436a025d40b299a1745b8891d7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fc814c436a025d40b299a1745b8891d7",
        "CFG": "ebedb8faf55908534e596ba5d47d40c7",
        "PRO": "c7af47baa72fbc11cb12d41a7d57bd1f"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_58f0efeda523": {
      "addresses": {
        "LoD/PD2": "0x7B33B20F"
      },
      "rvas": {
        "LoD/PD2": "0xB20F"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "FID_conflict:___dcrt_terminate_console_output",
      "signature": "undefined FID_conflict:___dcrt_terminate_console_output(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Multiple Matches With Different Base Names\n ___dcrt_terminate_console_input\n ___dcrt_terminate_console_output\n\nLibraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:58f0efeda5232bc3e0a46b677755366d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "58f0efeda5232bc3e0a46b677755366d",
        "CFG": "07cb2342909a04dfb4401d2e279eca04",
        "PRO": "fd3e17c01e554b790565934599afd4c1"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_6299b2977dd3": {
      "addresses": {
        "LoD/PD2": "0x7B33B226"
      },
      "rvas": {
        "LoD/PD2": "0xB226"
      },
      "sizes": {
        "LoD/PD2": 85
      },
      "name": "___dcrt_write_console",
      "signature": "BOOL ___dcrt_write_console(void * param_1, DWORD param_2, LPDWORD param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___dcrt_write_console\n\nLibraries: Visual Studio 2019 Debug, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6299b2977dd3d57cb3bf14d315461e0e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6299b2977dd3d57cb3bf14d315461e0e",
        "CFG": "410ab348637d7ec98eb50c4e351a2bae",
        "PRO": "f59c1dbca61f1e1f2cf65be3624c1e4b"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_307e17e4fa60": {
      "addresses": {
        "LoD/PD2": "0x7B33B27B"
      },
      "rvas": {
        "LoD/PD2": "0xB27B"
      },
      "sizes": {
        "LoD/PD2": 130
      },
      "name": "CloseValidatedResourceHandle",
      "signature": "undefined4 CloseValidatedResourceHandle(uint resourceIndex, int * pErrorContext)",
      "calling_convention": "__stdcall",
      "comment": "Closes a validated resource handle with error checking and state cleanup.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:307e17e4fa60da57125ace2774e91d6d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "307e17e4fa60da57125ace2774e91d6d",
        "CFG": "b5eb684e653ac2568d66b145edb2f76b",
        "PRO": "dfa704ac4d5cbc6dff5cf27555b36e76"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_c29539044f2d": {
      "addresses": {
        "LoD/PD2": "0x7B33B30C"
      },
      "rvas": {
        "LoD/PD2": "0xB30C"
      },
      "sizes": {
        "LoD/PD2": 163
      },
      "name": "ValidateAndSetupFileDescriptor",
      "signature": "int ValidateAndSetupFileDescriptor(uint fileDescriptor, int * pErrorStruct)",
      "calling_convention": "__cdecl",
      "comment": "Validates file descriptor and initializes error structure fields.\\n\\nAlgorithm:\\n1. Check if fileDescriptor is -2 (FFFF FFFE) for special handling\\n   - If -2, initialize error structure with default values (error code 9)\\n   - Set flags at +0x1c, +0x24 to indicate error initialization\\n2. Check if fileDescriptor is non-negative\\n3. Check if fileDescriptor is less than maximum descriptor count\\n4. Check validity bit in descriptor validation bitmap:\\n   - Bitmap base at DAT_7b3460d0\\n   - Calculate entry: (descriptor >> 6) selects 4-byte array element\\n   - Calculate bit: (descriptor & 0x3f) selects bit within entry (0-63)\\n   - Stride between entries: 0x38 bytes\\n5. If descriptor is valid, call FUN_7b33b27b to process descriptor\\n6. If descriptor invalid or out of range:\\n   - Call FUN_7b335c66 with NULL parameters to report error\\n   - Initialize error structure with error code 9\\n\\nParameters:\\n- fileDescriptor (uint): File descriptor to validate (0 to max-1, or -2 for special case)\\n- pErrorStruct (int*): Pointer to error structure with fields:\\n  +0x18: Error code (0=success, 9=initialization error)\\n  +0x1c: Error flag byte (1=error occurred)\\n  +0x20: Extended error/status field\\n  +0x24: Error notification flag\\n\\nReturns:\\n- int: -1 (0xFFFFFFFF) on error, or return value from FUN_7b33b27b on success\\n\\nSpecial Cases:\\n- fileDescriptor == -2 (0xFFFFFFFE): Special initialization case, sets error code 9\\n- Negative fileDescriptor: Treated as invalid, jumps to error handler\\n- fileDescriptor >= limit: Treated as out of range, jumps to error handler\\n- Invalid bit in bitmap: Treated as non-existent descriptor, jumps to error handler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c29539044f2d1ea1dd8d64637953ac47",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c29539044f2d1ea1dd8d64637953ac47",
        "CFG": "91cd16fac685cfc7f4b2c6d937a3e779",
        "PRO": "2b81d82b430a50dd02eb044beac10048"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_d3da1a6e99fa": {
      "addresses": {
        "LoD/PD2": "0x7B33B3AF"
      },
      "rvas": {
        "LoD/PD2": "0xB3AF"
      },
      "sizes": {
        "LoD/PD2": 160
      },
      "name": "CloseResourceHandle",
      "signature": "undefined4 CloseResourceHandle(uint resourceIndex, int errorContext)",
      "calling_convention": "__cdecl",
      "comment": "Closes a game resource handle and clears its state entry.\n\nAlgorithm:\n1. Call FUN_7b339729(resourceIndex) to retrieve handle value for the resource\n2. If handle is invalid (-1), exit with zero error code (success case for already-closed)\n3. Check if both resource 1 and resource 2 are open by testing flags at DAT_7b3460d0+0x98 and +0x60\n4. If both resources are open, retrieve both handle values and compare them\n5. If handles match (same underlying file), skip CloseHandle and proceed to cleanup\n6. Otherwise, call Windows CloseHandle API on the resource handle\n7. If CloseHandle fails (EAX=0), call GetLastError to capture the system error code\n8. Call FUN_7b339698(resourceIndex) for resource-specific cleanup operations\n9. Clear the active state byte at (resourceIndex&amp;0x3f)*0x38 + 0x28 in the state array\n10. If error occurred, call FUN_7b335d8d(lastError, errorContext) and return 0xFFFFFFFF\n11. If no error, return 0 for success\n\nParameters:\n- resourceIndex (uint): Index into resource handle table (range 0-255+)\n- errorContext (int): Context passed to error reporting function\n\nReturns:\n- 0: Handle closed successfully\n- 0xFFFFFFFF: CloseHandle failed, lastError returned by Windows API\n\nStructure Layout - Resource State Array:\nOffset | Size | Field Name | Type | Description\n0x00   | 56   | state[64]  | struct[64x56] | Array indexed by (resourceIndex&amp;0x3f) with stride 0x38\n0x28   | 1    | flags      | byte | Active flag (bit 0 = open), cleared to 0 on close\n0x60   | 1    | resource2  | byte | Flag bit for resource 2 open status\n0x98   | 1    | resource1  | byte | Flag bit for resource 1 open status",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d3da1a6e99fa9cfad40b1bb1f6d7e6ac",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d3da1a6e99fa9cfad40b1bb1f6d7e6ac",
        "CFG": "2092f58a2ad22ceba56927537aaf71da",
        "PRO": "1be05984c8b2686a7c9e793978b7da7e"
      },
      "basic_block_counts": {
        "LoD/PD2": 20
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_0176a5b704fb": {
      "addresses": {
        "LoD/PD2": "0x7B33B44F"
      },
      "rvas": {
        "LoD/PD2": "0xB44F"
      },
      "sizes": {
        "LoD/PD2": 59
      },
      "name": "__acrt_stdio_free_stream",
      "signature": "void __acrt_stdio_free_stream(__crt_stdio_stream param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl __acrt_stdio_free_stream(class __crt_stdio_stream)\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0176a5b704fb61d959b1442def5bb0bd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0176a5b704fb61d959b1442def5bb0bd",
        "CFG": null,
        "PRO": "95a95b870f796f506f3f4fb478947245"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_a1c22e91e56d": {
      "addresses": {
        "LoD/PD2": "0x7B33B4A0"
      },
      "rvas": {
        "LoD/PD2": "0xB4A0"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "ConvertX87ToDoubleForComputeExtendedMath",
      "signature": "void ConvertX87ToDoubleForComputeExtendedMath(void)",
      "calling_convention": "__stdcall",
      "comment": "Converts x87 extended precision floating-point to double and calls ComputeExtendedMathFunction.\n\nAlgorithm:\n1. Set up standard stack frame with 8 bytes local space\n2. Align ESP to 16-byte boundary for SSE requirement\n3. Store x87 FP80 value from ST0 as double to stack\n4. Load double from stack into XMM0 register\n5. Call ComputeExtendedMathFunction with double in XMM0\n6. Clean up stack and return\n\nParameters:\nNone. Input value is implicitly in x87 FP80 register ST0.\n\nReturns:\nvoid. Result from ComputeExtendedMathFunction is discarded.\n\nSpecial Cases:\n- Stack alignment: ESP is explicitly aligned to 16-byte boundary before SSE operations\n- FP conversion: x87 extended precision (80-bit) is converted to IEEE double (64-bit)\n- Calling convention bridge: Converts x87 calling convention to SSE/XMM convention\n\nStructure Layout:\nNo structures accessed. This is a pure floating-point conversion wrapper.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a1c22e91e56d6050e83a99db31e20ef5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a1c22e91e56d6050e83a99db31e20ef5",
        "CFG": null,
        "PRO": "1d78a642f23dfa61af853cd956d4101e"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_236b351f4f55": {
      "addresses": {
        "LoD/PD2": "0x7B33B4BE"
      },
      "rvas": {
        "LoD/PD2": "0xB4BE"
      },
      "sizes": {
        "LoD/PD2": 614
      },
      "name": "ComputeExtendedMathFunction",
      "signature": "float10 ComputeExtendedMathFunction(float10 * __return_storage_ptr__, double inputValue)",
      "calling_convention": "__cdecl",
      "comment": "Computes extended-precision transcendental math function (sin/cos/tan variant)\\n\\nPerforms high-precision computation using SSE instructions with table-driven polynomial approximation. Handles special cases including NaN, infinity, subnormal numbers, and overflow/underflow conditions. Returns float10 (80-bit extended precision) result with error codes through ___libm_error_support.\\n\\nAlgorithm:\\n1. Extract exponent and sign from input double (bits [62:52])\\n2. Load SSE register with input value and prepare for range reduction\\n3. Use exponent bits to select polynomial approximation table\\n4. Compute polynomial coefficients using SIMD operations\\n5. Check for out-of-range exponent values (special case threshold)\\n6. For normal range: apply table-based approximation with corrections\\n7. For special cases (NaN/infinity): handle via error path with ___libm_error_support\\n8. Return result as float10 (80-bit extended precision) in ST(0)\\n\\nParameters:\\n  inputValue (double): Input floating-point value for transcendental computation\\n\\nReturns:\\n  float10: Extended-precision computation result in ST(0)\\n\\nSpecial Cases:\\n  - NaN input: Returns special NaN value (0x7b342168)\\n  - Positive infinity (ECX=0x7fe): Returns \\u03c0/2 (0x7b342160)\\n  - Negative infinity (ECX=-1): Multiplies by -1 and retries (0x7b342150)\\n  - Exponent 0x7ff (infinity/NaN): Delegates to ___libm_error_support\\n  - Subnormal numbers: Normalizes via exponent correction loop\\n  \\nError Codes:\\n  0x8: Division by zero error\\n  0x9: Overflow/underflow condition\\n  0x3e9: Domain error (invalid input)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:236b351f4f558ddf9d59e832c106b7dc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "236b351f4f558ddf9d59e832c106b7dc",
        "CFG": "d1f099d3e1288b30c1cc4fa5b2b40b0a",
        "PRO": "6c4c6647cd4b53dd1b396e9262fcbad4"
      },
      "basic_block_counts": {
        "LoD/PD2": 22
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_457863e0e5e0": {
      "addresses": {
        "LoD/PD2": "0x7B33B730"
      },
      "rvas": {
        "LoD/PD2": "0xB730"
      },
      "sizes": {
        "LoD/PD2": 86
      },
      "name": "ComputeLogExponentialTransform",
      "signature": "float10 ComputeLogExponentialTransform(float10 * __return_storage_ptr__, undefined4 inputValue, undefined1 controlByte)",
      "calling_convention": "__fastcall",
      "comment": "Computes logarithmic and exponential transformations on floating-point values with control flags for reciprocals, scaling, and negation.\n\nAlgorithm:\n1. Save control byte 0xfe to stack for flag preservation\n2. Check validation flag in high byte (CH) of inputValue\n3. If validation needed: call ValidateFloatIntegrity() and retrieve control flags\n4. If validation passed (code 0): call GetInitializedFloatConstant() and return early\n5. For normal path: call ComputeExponentialMinus1() to compute exponential\n6. Add 1.0 to exponential result (implements 2^x + 1 computation)\n7. Test reciprocal flag at [EBP-0x9f] bit 0\n8. If reciprocal flag set: compute 1 / result (reciprocal transformation)\n9. Test scale flag in DL register bit 0x40\n10. If scale flag clear: apply FSCALE to scale result by exponent factor\n11. Test negate flag in CH register\n12. If negate flag set: negate the final result using FCHS\n13. Call StubFPStackCleanup() to manage FPU stack state\n14. Return computed float10 value in ST0\n15. On validation failure: call GetInitializedFloatConstant() for recovery\n16. For error code 2: keep sign flag normal, else invert sign\n17. Take absolute value of input and retry logarithm computation\n\nParameters:\n  inputValue [EDX:ECX] - 32-bit input value with control flags in high byte (CH)\n  controlByte [DL] - Control byte with scaling and conditional flags\n\nReturns:\n  float10 - Transformed floating-point result in ST0 (x87 FPU register ST0)\n\nSpecial Cases:\n  - Validation failure handling: error code 2 processes differently than other codes\n  - Reciprocal mode: inverts the final result 1/x\n  - Scaling mode: applies FPU FSCALE instruction using exponent in ST1\n  - Negation mode: inverts sign of final result\n  - Control flags use bit patterns: 0xFE base, CH for validation/negate, [EBP-0x9f] for reciprocal\n  - Magic number 0xFE: control flag initialization value\n  - Retry path: automatically handles invalid inputs by taking absolute value\n\nStack Usage:\n  [EBP-0x90] = Control byte 0xfe (saved)\n  [EBP-0x9f] = Reciprocal flag storage (bit 0 tested)\n  in_stack_00000004 = Stack parameter (floating-point reference)\n\nFPU Operations:\n  - FYL2X: Computes y*log2(x) for logarithm base conversion\n  - FLDL2E: Loads log2(e) constant for exponential scaling\n  - FMULP: Multiplication with FPU stack pop\n  - FADDP: Addition with FPU stack pop\n  - FSCALE: Scale by power of 2 (exponent in ST1)\n  - FDIVRP: Division with reverse operands and pop\n  - FCHS: Change sign (negate)\n  - FABS: Take absolute value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:457863e0e5e0aaaca0dbb328e53091e9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "457863e0e5e0aaaca0dbb328e53091e9",
        "CFG": "113c47e200358f32fc9592a5a725da85",
        "PRO": "fa5a38cb52345a2769ecb91a7497e22a"
      },
      "basic_block_counts": {
        "LoD/PD2": 20
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_d5f0d2733adf": {
      "addresses": {
        "LoD/PD2": "0x7B33B88D"
      },
      "rvas": {
        "LoD/PD2": "0xB88D"
      },
      "sizes": {
        "LoD/PD2": 114
      },
      "name": "ComputeExponentialMinus1",
      "signature": "void ComputeExponentialMinus1(double value, byte controlFlags)",
      "calling_convention": "__fastcall",
      "comment": "Computes 2^x - 1 (exponential minus one) using x87 FPU instructions.\n\nAlgorithm:\n1. Load input value from ST0 and compute its absolute value\n2. Compare absolute value with threshold constant at 0x7b3421de\n3. If value exceeds threshold, jump to error handling path\n4. Otherwise, round the input value to nearest integer\n5. Compare rounded value with zero\n6. Compute fractional part as (input - rounded_input)\n7. Test fractional part for zero (NaN check)\n8. Apply absolute value to fractional part\n9. Use F2XM1 instruction to compute 2^frac - 1, returning result in ST0\n\nParameters:\n  value: Extended precision floating-point input (in ST0 FPU register)\n  controlFlags: Control and status flags from FPU\n\nReturns:\n  Extended precision floating-point result (2^x - 1) in ST0\n\nSpecial Cases:\n  - Handles values exceeding threshold constant\n  - Manages floating-point exceptions via status word\n  - Fractional part computation prevents overflow in F2XM1\n  - Uses FABS to handle negative fractional parts correctly",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d5f0d2733adf4d1dce64e7fb83efd1d4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d5f0d2733adf4d1dce64e7fb83efd1d4",
        "CFG": "d6344fc8e579e5907ad157bcb99d8080",
        "PRO": "510f3268b381a774770b98be40124f81"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_df587a37c863": {
      "addresses": {
        "LoD/PD2": "0x7B33B8D0"
      },
      "rvas": {
        "LoD/PD2": "0xB8D0"
      },
      "sizes": {
        "LoD/PD2": 52
      },
      "name": "ValidateFloatIntegrity",
      "signature": "undefined4 ValidateFloatIntegrity(void)",
      "calling_convention": "__stdcall",
      "comment": "Validates floating-point number integrity for precision calculations.\n\nChecks whether a floating-point value in the x87 FPU stack (ST0) represents\nan exact integer and whether its scaled value also represents an exact integer.\nUsed to verify numeric precision in floating-point operations.\n\nAlgorithm:\n1. Load and round the input value (ST0) to nearest integer\n2. Compare rounded value with original to detect non-integer values\n3. If integer: load ST0, multiply by scaling constant at 0x7b3421f2\n4. Round the scaled value and compare with original scaled result\n5. Return status code based on validation results\n\nParameters:\n- ST0 (x87 stack): Floating-point value to validate (80-bit extended precision)\n\nReturns:\n- 0 (EAX): Value is not an integer\n- 1 (EAX): Value is an integer but scaled result is not\n- 2 (EAX): Both value and scaled result are integers\n\nSpecial Cases:\n- Uses x87 FPU comparison flags (FSTSW/SAHF) for conditional checks\n- Scaling constant at 0x7b3421f2 is applied to test precision limits\n- Called from FUN_7b33b730 for floating-point data validation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:df587a37c8639f83cd433c3a3fbdafc4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "df587a37c8639f83cd433c3a3fbdafc4",
        "CFG": "06d66ec7bcb1f57e7b149a0880226930",
        "PRO": "b5ba49bd58125ef109dd1a838e946bc1"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_970e9ff091d3": {
      "addresses": {
        "LoD/PD2": "0x7B33B940"
      },
      "rvas": {
        "LoD/PD2": "0xB940"
      },
      "sizes": {
        "LoD/PD2": 117
      },
      "name": "DispatchFPUExceptionHandler",
      "signature": "void DispatchFPUExceptionHandler(void * pExceptionContext, void * pHandlerTable)",
      "calling_convention": "__fastcall",
      "comment": "Dispatch FPU exception handler through virtual method table lookup.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:970e9ff091d33e0cb05e30f2142e63fe",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "970e9ff091d33e0cb05e30f2142e63fe",
        "CFG": "a7475d7992491ef55650f6bf8ddca095",
        "PRO": "960e361d1a9d84d906a5da45c701f690"
      },
      "basic_block_counts": {
        "LoD/PD2": 19
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_99ac315fad0e": {
      "addresses": {
        "LoD/PD2": "0x7B33BA54"
      },
      "rvas": {
        "LoD/PD2": "0xBA54"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "StubFPStackCleanup",
      "signature": "void StubFPStackCleanup(void)",
      "calling_convention": "__stdcall",
      "comment": "Stub function containing only floating-point stack cleanup and no-op padding\n\nThis appears to be dead code or a placeholder function with no meaningful logic.\nContains only FPU stack manipulation (FXCH, FSTP) and padding instructions (LEA self-references).\nCalled once from FUN_7b33b730 but performs no actual work.\n\nAlgorithm:\n1. Exchange FPU stack top with ST1\n2. Execute no-op padding instructions (LEA ESP, [ESP])\n3. Pop and discard FPU stack top value\n4. Return to caller\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Function contains only stub/padding code with no actual implementation\n- All instructions after FXCH are either FPU stack cleanup or no-op padding\n- Possible candidates for removal or inlining by compiler optimizer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:99ac315fad0e50673c730cf7cada2459",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "99ac315fad0e50673c730cf7cada2459",
        "CFG": "f692539e5e4b2c6051f22edb98cfce4a",
        "PRO": "a58a3aab0e55916d5f79cc0fcc6cd90f"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_038f21ccadf0": {
      "addresses": {
        "LoD/PD2": "0x7B33BA7A"
      },
      "rvas": {
        "LoD/PD2": "0xBA7A"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "ReturnFloatZero",
      "signature": "float10 ReturnFloatZero(float10 * __return_storage_ptr__)",
      "calling_convention": "__stdcall",
      "comment": "Returns a floating-point zero value.\n\nAlgorithm:\n1. Pop the top of the FPU stack (discard incoming value)\n2. Load zero onto the FPU stack\n3. Return the zero value\n\nReturns:\n  float10 - Zero value (0.0) as extended precision floating-point\n\nPurpose:\n  This utility function clears the FPU stack and returns zero. It is called within floating-point computation contexts to provide a zero constant or to synchronize FPU state during transcendental function calculations.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:038f21ccadf05fbd1bec4c0181e46e90",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "038f21ccadf05fbd1bec4c0181e46e90",
        "CFG": null,
        "PRO": "c3c38319caaa90934e927a5b8cadf44b"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_bfbfce5166c5": {
      "addresses": {
        "LoD/PD2": "0x7B33BA8D"
      },
      "rvas": {
        "LoD/PD2": "0xBA8D"
      },
      "sizes": {
        "LoD/PD2": 8
      },
      "name": "GetFloatOne",
      "signature": "double GetFloatOne(void)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: double GetFloatOne(void)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bfbfce5166c5415d64e88436de1018c5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bfbfce5166c5415d64e88436de1018c5",
        "CFG": null,
        "PRO": "c3f72db7fa0f934f8ce5ed8d7fda3e1a"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_73604cb44c56": {
      "addresses": {
        "LoD/PD2": "0x7B33BAD0"
      },
      "rvas": {
        "LoD/PD2": "0xBAD0"
      },
      "sizes": {
        "LoD/PD2": 56
      },
      "name": "AccumulateFloatingPointValue",
      "signature": "float10 AccumulateFloatingPointValue(float10 * __return_storage_ptr__)",
      "calling_convention": "__stdcall",
      "comment": "Accumulates floating-point values using FPU stack operations.\\n\\nAlgorithm:\\n1. Exchange ST0 and ST1 to prepare operands\\n2. Store ST1 (extended double) to stack buffer at [EBP - 0x9e]\\n3. Load the stored value back to FPU stack\\n4. Test conditional flag at [EBP - 0x97] bit 0x40\\n5. Clear control byte at [EBP - 0x90] regardless of flag state\\n6. Add ST0 to loaded value (FADDP) and return result\\n\\nParameters:\\nNone. Uses FPU stack:\\n  - ST0: Addend value to accumulate\\n  - ST1: Initial accumulator value\\n\\nReturns:\\n  float10: Sum of accumulator and addend value\\n\\nSpecial Cases:\\n- Conditional test at 0x7b33baec has no effect (both branches identical)\\n- Stack buffer at [EBP - 0x9e] used for intermediate storage\\n- Extended precision floating-point arithmetic throughout",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:73604cb44c56b091d3abe654076d9602",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "73604cb44c56b091d3abe654076d9602",
        "CFG": "e0cc0190add0739fe135c9b9d7285356",
        "PRO": "1070608a1d6b38c0e4cdc560b0216a0b"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_58c3c7e175be": {
      "addresses": {
        "LoD/PD2": "0x7B33BB50"
      },
      "rvas": {
        "LoD/PD2": "0xBB50"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "GetInitializedFloatConstant",
      "signature": "float10 GetInitializedFloatConstant(float10 * __return_storage_ptr__)",
      "calling_convention": "__stdcall",
      "comment": "Initializes a static flag and returns a cached extended double constant.\n\nAlgorithm:\n1. Load extended double value from global data at 0x7b342220\n2. Check if initialization flag at EBP-0x90 is zero\n3. If flag is zero, set it to 1 (mark as initialized)\n4. Return the extended double value\n\nParameters:\nNone\n\nReturns:\nfloat10 - Extended precision floating point constant from 0x7b342220\n\nSpecial Cases:\n- Flag at EBP-0x90 acts as a one-time initialization marker\n- The condition checks if flag < 1 (zero), indicating uninitialized state\n- Returns same constant value on all calls regardless of initialization state",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:58c3c7e175be8c196c57976e375f315f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "58c3c7e175be8c196c57976e375f315f",
        "CFG": "da152f785615d99730162e25e87ddd37",
        "PRO": "40aa118efadca5c887be0079b0099277"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_3c4be6dbcf12": {
      "addresses": {
        "LoD/PD2": "0x7B33BB63"
      },
      "rvas": {
        "LoD/PD2": "0xBB63"
      },
      "sizes": {
        "LoD/PD2": 10
      },
      "name": "SetStackFlag",
      "signature": "void SetStackFlag(void)",
      "calling_convention": "__stdcall",
      "comment": "Sets a flag byte at a fixed offset from the caller's stack frame.\n\nAlgorithm:\n1. Write 0x1 to memory at [EBP - 0x90] to set a flag on the caller's stack\n2. Execute OR CL,CL instruction (flag preservation, no semantic effect)\n3. Return to caller with __stdcall convention\n\nParameters:\nNone - this function modifies the caller's stack frame directly via EBP\n\nReturns:\nvoid - function returns without a value\n\nSpecial Cases:\n- Accesses caller's stack frame using negative EBP offset (-0x90)\n- The OR CL,CL instruction appears to be a no-op that preserves condition flags\n- Assumes caller has properly set up EBP pointing to the previous frame\n- Stack offset -0x90 suggests the caller has significant local variables",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3c4be6dbcf1260e7f12c4f60862ff7d6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3c4be6dbcf1260e7f12c4f60862ff7d6",
        "CFG": "80158248b60f953891e8fc7e6daa7eff",
        "PRO": "07e743cd59663008aa355e28886b82e5"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_3f015c1c75c5": {
      "addresses": {
        "LoD/PD2": "0x7B33BBA0"
      },
      "rvas": {
        "LoD/PD2": "0xBBA0"
      },
      "sizes": {
        "LoD/PD2": 21
      },
      "name": "PowerOfTwo",
      "signature": "longdouble PowerOfTwo(void)",
      "calling_convention": "__stdcall",
      "comment": "Computes 2^x using x87 floating-point instructions.\n\nAlgorithm:\n1. Load input value from FPU stack (ST0)\n2. Round input to nearest integer (FRNDINT)\n3. Subtract rounded value from original to get fractional part\n4. Negate fractional part and apply F2XM1 to compute 2^fractional - 1\n5. Add 1 to get 2^fractional\n6. Multiply by 2^integer_part using FSCALE instruction\n7. Return extended precision result (10 bytes)\n\nParameters:\nInput: Extended precision float in ST0 (x87 stack top)\n\nReturns:\nExtended precision float (long double) containing 2^x\n\nAlgorithm Details:\nUses x87 FPU's built-in exponentiation capabilities:\n- F2XM1: Computes 2^x - 1 for -1.0 <= x < 1.0\n- FSCALE: Multiplies top of stack by 2^exponent (second stack item)\n- Input range: Any valid extended precision value\n- Output: 2^x with full precision\n\nSpecial Cases:\n- Negative exponents produce fractional results (0 < result < 1)\n- Positive exponents produce values >= 1\n- Large exponents may overflow to infinity\n- Zero input returns 1.0 (2^0 = 1)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3f015c1c75c5efb05d68ef52e0407e8b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3f015c1c75c5efb05d68ef52e0407e8b",
        "CFG": null,
        "PRO": "d88336b08af1715c644e9a02a67eb019"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_4994138ab30c": {
      "addresses": {
        "LoD/PD2": "0x7B33BBCC"
      },
      "rvas": {
        "LoD/PD2": "0xBBCC"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "CheckFlagAndReturn",
      "signature": "int CheckFlagAndReturn(void)",
      "calling_convention": "__stdcall",
      "comment": "Checks for 0x80000 flag bit in EAX and returns status code.\n\nAlgorithm:\n1. Test EAX register against 0x80000 bitmask\n2. If bit is clear (zero), jump to zero_flag_path\n3. If bit is set, set EAX to 0 and return\n4. Both paths return 0\n\nReturns:\n- int: Always 0 (status code indicating completion or flag check result)\n\nSpecial Cases:\n- Both code paths return the same value (0)\n- Function assumes EAX is pre-loaded by caller with flag value\n- Flag bit 0x80000 is the condition being tested",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4994138ab30c599075def6763c96b8e4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4994138ab30c599075def6763c96b8e4",
        "CFG": "c28d843778d6313eca5e15ea77ffbb3e",
        "PRO": "c3835a1c4241d090154d6750ba3bb6d9"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_7e73328c30de": {
      "addresses": {
        "LoD/PD2": "0x7B33BBE5"
      },
      "rvas": {
        "LoD/PD2": "0xBBE5"
      },
      "sizes": {
        "LoD/PD2": 67
      },
      "name": "ExtractFloatingPointExponent",
      "signature": "uint ExtractFloatingPointExponent(void * contextPointer, double * doubleValuePointer)",
      "calling_convention": "__fastcall",
      "comment": "Extracts the exponent field from a double-precision floating-point number with special handling for infinity/NaN values.\n\nAlgorithm:\n1. Load high 32-bits (offset +4) of the double value from doubleValuePointer\n2. Extract exponent bits using mask 0x7ff00000 (bits 52-62 in IEEE 754 double format)\n3. Compare extracted exponent against 0x7ff00000 (special value indicator for infinity/NaN)\n4. If exponent is NOT special (normal value): return exponent bits directly in EAX\n5. If exponent IS special (infinity/NaN): perform extended precision conversion\n   - Read both 64-bits of the double value\n   - Set sign extension bit (0x7fff0000) in the exponent\n   - Convert to extended double format using left-shift by 11 bits on both parts\n   - Load extended double into FPU stack\n6. Return the value in EAX\n\nParameters:\n- contextPointer (ECX): Context pointer, unused in this function\n- doubleValuePointer (EDX): Pointer to 64-bit IEEE 754 double value\n\nReturns:\n- EAX: Extracted exponent bits (0x7ff00000 format) or modified value for special cases\n\nSpecial Cases:\n- 0x7ff00000: Indicates infinity (sign + magnitude)\n- 0xfff00000: Negative infinity\n- Values near max exponent range indicate denormalized or special float values\n- Extended precision handling converts IEEE 754 double to 80-bit extended format for FPU processing",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7e73328c30de0e16ec37226d5c0fbaeb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7e73328c30de0e16ec37226d5c0fbaeb",
        "CFG": "51d5ddd4ecc1dafccdeb273dae1d2adf",
        "PRO": "9f8021330ca888b56e19c20ebdb2b790"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_178bf49837b7": {
      "addresses": {
        "LoD/PD2": "0x7B33BC28"
      },
      "rvas": {
        "LoD/PD2": "0xBC28"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "ExtractFloatExponent",
      "signature": "uint ExtractFloatExponent(uint floatBits, uint unused)",
      "calling_convention": "__cdecl",
      "comment": "Extracts the exponent field from an IEEE 754 32-bit floating-point value.\n\nAlgorithm:\n1. Mask input value with 0x7ff00000 to extract exponent bits\n2. Compare masked result with 0x7ff00000 (special value indicator)\n3. If exponent equals 0x7ff00000 (infinity/NaN), return original value\n4. Otherwise, return the masked exponent bits\n\nParameters:\n- floatBits: 32-bit float value (as uint) to extract exponent from\n- unused: Unused parameter (stack alignment)\n\nReturns:\n- If value represents infinity or NaN (0x7ff00000), returns original floatBits\n- Otherwise returns exponent field (bits 30-23) masked as 0x7ff00000\n\nSpecial Cases:\n- Magic constant 0x7ff00000: IEEE 754 representation of all exponent bits set\n- Positive infinity: 0x7f800000 (exponent=0xff, mantissa=0)\n- Negative infinity: 0xff800000 (exponent=0xff, mantissa=0)\n- Quiet NaN: 0x7fc00000 and above\n- Signaling NaN: 0x7f800001 to 0x7fbfffff",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:178bf49837b7e4e6597a7ff702d55d4f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "178bf49837b7e4e6597a7ff702d55d4f",
        "CFG": "2f5c312554ae0544a3bbc9440d62b16b",
        "PRO": "54acfb3eac1eb349f73f37969cdaf67d"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_aa89b192e574": {
      "addresses": {
        "LoD/PD2": "0x7B33BC4B"
      },
      "rvas": {
        "LoD/PD2": "0xBC4B"
      },
      "sizes": {
        "LoD/PD2": 42
      },
      "name": "CheckFPUExceptionStatus",
      "signature": "void CheckFPUExceptionStatus(undefined4 errorCode, int exceptionNum, undefined4 contextPtr, undefined4 param3, undefined4 param4)",
      "calling_convention": "__fastcall",
      "comment": "Checks FPU status flags and error conditions for floating-point operations.\nVerifies that the FPU exception mask is clear and status word has exception flag set.\nIf all conditions are met, calls error handler with error code 0x8.\nOtherwise performs FPU control word restoration and returns.\n\nAlgorithm:\n1. Load return address from stack (FPU control word)\n2. Compare against magic value 0x27f (skip if equal)\n3. Check exception mask bit (0x20) in return address\n4. Store FPU status word and check exception flag (0x20)\n5. If all checks pass, set error code and call __startOneArgErrorHandling\n6. Otherwise restore FPU control word and return\n\nParameters:\n  errorCode (ECX): Error code/string pointer for math function\n  exceptionNum (EDX): Exception number (typically 0x1b for log10)\n  contextPtr (Stack): Additional context pointer\n  param3 (Stack): Reserved parameter\n  param4 (Stack): Reserved parameter\n\nReturns:\n  void - Function either returns directly or calls error handler which may not return\n\nStructure Layout:\nThis function operates on the FPU state and stack context without explicit structure access.\nThe FPU control word is stored at [ESP] and status word is accessed via FSTSW instruction.\n\nMagic Numbers:\n  0x27f - Skip error handling if return address equals this value\n  0x20 - Bitmask for exception flag in both return address and FPU status word\n  0x8 - Error code passed to __startOneArgErrorHandling (FPU exception)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:aa89b192e57490dbcdd29af8440710b1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "aa89b192e57490dbcdd29af8440710b1",
        "CFG": "f31fc5092d131899f5d3fcf66479e1f8",
        "PRO": "5ca46a3c1c1f93519f0f23457ffd62d1"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_d63502919c4c": {
      "addresses": {
        "LoD/PD2": "0x7B33BD30"
      },
      "rvas": {
        "LoD/PD2": "0xBD30"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "RoundDoubleWithExceptionHandling",
      "signature": "double RoundDoubleWithExceptionHandling(double inputValue, int fpuControlWord, ushort fpcwMask, uint param4, uint param5, uint param6, uint param7, uint param8)",
      "calling_convention": "__fastcall",
      "comment": "Wrapper function that prepares parameters and jumps to main FPU exception handler.\n\nAlgorithm:\n1. Save current frame pointer and setup new stack frame\n2. Allocate 32 bytes of local storage for temporary data\n3. Save the input double value (in EAX) to local storage\n4. Load and save param8 (stack offset +0x18) from caller's frame\n5. Load and save param7 (stack offset +0x1c) from caller's frame\n6. Jump to continue_to_handler (0x7b33bd50) which performs exception handling\n\nParameters:\n- inputValue (ECX:EAX in __fastcall): Double precision floating point value to process\n- fpuControlWord (EDX): FPU control word for exception handling\n- fpcwMask (Stack[0x4]): Mask for FPU control word flags\n- param4 (Stack[0x8]): Additional parameter for handler\n- param5 (Stack[0xc]): Additional parameter for handler\n- param6 (Stack[0x10]): Additional parameter for handler\n- param7 (Stack[0x14]): Parameter saved at offset -0xc\n- param8 (Stack[0x18]): Parameter saved at offset -0x10\n\nReturns:\n- Double value in ST0/FPU extended precision register after exception processing\n\nSpecial Cases:\n- This is a trampoline wrapper that saves stack parameters before jumping to the main handler\n- Uses __fastcall convention where first two parameters (inputValue, fpuControlWord) are in ECX:EAX/EDX\n- Stack parameters (param3-param8) are copied to local variables before handler execution\n- The actual exception handling logic continues at address 0x7b33bd50",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d63502919c4c985cfbdccf3184dd15d0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d63502919c4c985cfbdccf3184dd15d0",
        "CFG": "7aacd61a1d81f3299fa55646a3677b47",
        "PRO": "dbecc4592f372f116866c3eeaf6ab0c7"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "PD2_EXT_MNE_9215dd175454": {
      "addresses": {
        "LoD/PD2": "0x7B33BD47"
      },
      "rvas": {
        "LoD/PD2": "0xBD47"
      },
      "sizes": {
        "LoD/PD2": 60
      },
      "name": "__startOneArgErrorHandling",
      "signature": "float10 __startOneArgErrorHandling(undefined4 param_1, int param_2, ushort param_3, undefined4 param_4, undefined4 param_5, undefined4 param_6)",
      "calling_convention": "__fastcall",
      "comment": "Library Function - Single Match\n __startOneArgErrorHandling\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9215dd17545429f5a2114f3f9c06e96c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9215dd17545429f5a2114f3f9c06e96c",
        "CFG": "19c71a436cd9b62cd94468fdd6017761",
        "PRO": "d4534ea44172405569ef7c69e3511570"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "PD2_EXT_MNE_e924fdadf508": {
      "addresses": {
        "LoD/PD2": "0x7B33BD83"
      },
      "rvas": {
        "LoD/PD2": "0xBD83"
      },
      "sizes": {
        "LoD/PD2": 500
      },
      "name": "___libm_error_support",
      "signature": "undefined ___libm_error_support(undefined8 * param_1, undefined8 * param_2, undefined8 * param_3, int param_4)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___libm_error_support\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e924fdadf508c826eed42821cba5fa90",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e924fdadf508c826eed42821cba5fa90",
        "CFG": "6fb7039291d9622a06ea097685f543c1",
        "PRO": "317e6c0692d83e0e1653bc4c81b07f08"
      },
      "basic_block_counts": {
        "LoD/PD2": 45
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "PD2_EXT_MNE_66ca62cf04ca": {
      "addresses": {
        "LoD/PD2": "0x7B33BF77"
      },
      "rvas": {
        "LoD/PD2": "0xBF77"
      },
      "sizes": {
        "LoD/PD2": 190
      },
      "name": "RoundDoubleWithExceptionHandling",
      "signature": "float10 RoundDoubleWithExceptionHandling(float10 * __return_storage_ptr__, double inputValue)",
      "calling_convention": "__cdecl",
      "comment": "Rounds a double-precision floating-point value to the nearest representable value with IEEE 754 exception handling.\\n\\nAlgorithm:\\n1. Save current control flags via __ctrlfp()\\n2. Check if input is a special value (NaN, Infinity, Denormalized) by examining exponent bits (0x7ff0 mask)\\n3. If special value: Classify type using ClassifyFloatingPointSpecialValues() - returns 1 (Quiet NaN), 2 (Signaling NaN), or 3 (Infinity)\\n4. If Quiet/Signaling NaN or Infinity: Return input unchanged, restore control flags, exit\\n5. If normal value: Call __frnd() to round to nearest representable double\\n6. Check if rounded value equals input or if rounding mode bit (0x20) is already set\\n7. If equal or rounding mode set: Restore flags and return rounded value unchanged\\n8. Otherwise call __except1() with exception flags to signal inexact exception:\\n   - Exception flag 0x10 (16): inexact exception during rounding\\n   - Exponent 0xc (12): double-precision format indicator\\n9. Return float10 result via FP stack\\n\\nParameters:\\ninputValue (double) - The floating-point number to round, may be normal, denormalized, or special value\\n\\nReturns:\\nfloat10 - The rounded value as extended precision floating-point (80-bit), matching inputValue for special values, or ClassifyFloatingPointSpecialValues() result for exception handling\\n\\nSpecial Cases:\\n- Input NaN (Quiet or Signaling): Returns unchanged, triggers no exception\\n- Input Infinity: Returns unchanged, triggers no exception\\n- Denormalized values: Treated as special and returned unchanged\\n- Exact values: No exception signal even if rounding mode 0x20 set\\n- Inexact rounding: Calls __except1() with flag 0x10 to raise inexact exception\\n\\nIEEE 754 Exponent Classification:\\n0x0000-0x000f: Denormalized or zero\\n0x0001-0x7fee: Normal numbers\\n0x7ff0-0x7fff: Special values (Infinity and NaN)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:66ca62cf04ca0813652dfb78b071de6f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "66ca62cf04ca0813652dfb78b071de6f",
        "CFG": "a0a06e65e5c6c8b5edc954db64298798",
        "PRO": "81998b2575f8c1c5fa8183126a0389eb"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_16d616b35c33": {
      "addresses": {
        "LoD/PD2": "0x7B33C035"
      },
      "rvas": {
        "LoD/PD2": "0xC035"
      },
      "sizes": {
        "LoD/PD2": 17
      },
      "name": "GetFPUStatusAndClear",
      "signature": "int GetFPUStatusAndClear(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieve x87 FPU status word and clear exceptions.\n\nAlgorithm:\n1. Save current x87 FPU status word to stack variable via FNSTSW\n2. Clear all floating-point exceptions using FNCLEX\n3. Sign-extend the saved status word from word to int\n4. Return the status word as int\n\nReturns:\n- int: The x87 FPU status word before clearing exceptions\n  Bits 0-5: Exception flags (IE, DE, ZE, OE, UE, PE)\n  Bits 6-14: Condition codes and other status flags\n  Negative value indicates exceptions were set\n\nSpecial Cases:\n- FPU status word is captured before clearing, allowing caller to check what exceptions occurred\n- Used by exception handling infrastructure (__raise_exc_ex) to detect floating-point errors\n- FNCLEX is non-waiting clear, does not wait for pending unmasked exceptions",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:16d616b35c333a7dce0bb2e32c0f7126",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "16d616b35c333a7dce0bb2e32c0f7126",
        "CFG": null,
        "PRO": "0d0781a6b7855dd772cc777aef3be52e"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_9265df1b9ee6": {
      "addresses": {
        "LoD/PD2": "0x7B33C046"
      },
      "rvas": {
        "LoD/PD2": "0xC046"
      },
      "sizes": {
        "LoD/PD2": 42
      },
      "name": "__ctrlfp",
      "signature": "int __ctrlfp(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __ctrlfp\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9265df1b9ee675956a8346895fb96853",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9265df1b9ee675956a8346895fb96853",
        "CFG": null,
        "PRO": "7c823a94154ae028884ee703db75aaf4"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_2a80e60ea4bb": {
      "addresses": {
        "LoD/PD2": "0x7B33C070"
      },
      "rvas": {
        "LoD/PD2": "0xC070"
      },
      "sizes": {
        "LoD/PD2": 89
      },
      "name": "RestoreFPUExceptionConstants",
      "signature": "void RestoreFPUExceptionConstants(uint exceptionStateBits)",
      "calling_convention": "__stdcall",
      "comment": "Restores FPU exception state constants based on flag bits\n\nAlgorithm:\n1. Read exception state flag bits from exceptionStateBits parameter in ECX\n2. Test bit 0 (0x1): If set, load extended-precision constant from 0x7b3422d8 and store as DWORD\n3. Test bit 3 (0x8): If set, load extended-precision constant from 0x7b3422d8 and store as double\n4. Test bit 4 (0x10): If set, load extended-precision constant from 0x7b3422e4 and store as double\n5. Test bit 2 (0x4): If set, push 0 and 1 to FPU stack and compute 0/1 (infinity)\n6. Test bit 5 (0x20): If set, load PI constant and store as double\n7. Return to caller via LEAVE/RET\n\nParameters:\n  exceptionStateBits (uint) - Bitfield controlling which FPU constants to restore (bit 0, 2, 3, 4, 5)\n\nReturns:\n  void - No return value, modifies FPU state\n\nSpecial Cases:\n  - Bit 0 (0x1): Restores exception indicator from memory at 0x7b3422d8\n  - Bit 3 (0x8): Restores normalized value from memory at 0x7b3422d8\n  - Bit 4 (0x10): Restores denormalized value from memory at 0x7b3422e4\n  - Bit 2 (0x4): Computes infinity as 1.0/0.0 (special FPU operation)\n  - Bit 5 (0x20): Restores PI mathematical constant\n  - WAIT instructions ensure FPU operation completion before proceeding\n  - Called from HandleFloatingPointRounding to restore FPU after exception handling",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2a80e60ea4bba793c262478138e116cc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2a80e60ea4bba793c262478138e116cc",
        "CFG": "73fc4c394048f9e591d76418eb9935ea",
        "PRO": "b3a0cbf6a4a01a8d5d007f2d718579a0"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_8fd4ad643df3": {
      "addresses": {
        "LoD/PD2": "0x7B33C0C9"
      },
      "rvas": {
        "LoD/PD2": "0xC0C9"
      },
      "sizes": {
        "LoD/PD2": 16
      },
      "name": "GetFPUStatusWord",
      "signature": "ushort GetFPUStatusWord(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the current FPU (Floating Point Unit) status word.\\n\\nAlgorithm:\\n1. Set up stack frame with PUSH EBP and MOV EBP,ESP\\n2. Allocate local variable space on stack\\n3. Execute FSTSW to store FPU status word to stack\\n4. Load status word into EAX register and sign-extend to 32-bit\\n5. Clean up stack frame with LEAVE\\n6. Return status word in EAX\\n\\nReturns:\\n  unsigned short - FPU status word containing exception flags, precision control, and rounding mode bits\\n\\nSpecial Cases:\\n  - FPU status word bit 0: Invalid Operation Exception Flag\\n  - FPU status word bit 2: Zero Divide Exception Flag\\n  - FPU status word bit 3: Overflow Exception Flag\\n  - FPU status word bit 4: Underflow Exception Flag\\n  - FPU status word bit 5: Precision Exception Flag\\n  - Used in __raise_exc_ex to check FPU exception state during exception handling",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8fd4ad643df307067f079fbd4afbbe20",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8fd4ad643df307067f079fbd4afbbe20",
        "CFG": null,
        "PRO": "30b08fa3df6e58fd84593e5aaad2bf55"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_d13997106616": {
      "addresses": {
        "LoD/PD2": "0x7B33C0D9"
      },
      "rvas": {
        "LoD/PD2": "0xC0D9"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "ClassifyAndValidateFloat",
      "signature": "uint ClassifyAndValidateFloat(double value)",
      "calling_convention": "__cdecl",
      "comment": "Classifies and validates a floating-point number based on special cases and rounding behavior.\n\nAlgorithm:\n1. Call __fpclass to get floating-point classification bits\n2. Test if bits 0x90 are set (indicates NaN, infinity, or denormal)\n3. If special class detected, return 0\n4. Round the original value using __frnd\n5. Compare rounded result with original using FUCOM\n6. If not equal, return 0\n7. Load original value and multiply by constant at 0x7b342b10\n8. Round the scaled value using __frnd\n9. Compare scaled rounded with original scaled using FUCOMPP\n10. If not equal, return 1\n11. If equal, return 2\n\nParameters:\n  value (double): Input floating-point value to classify and validate\n\nReturns:\n  0: Value is special class (NaN/infinity/denormal) or rounding check failed\n  1: Original value rounds correctly but scaled value doesn't\n  2: Both original and scaled values round correctly\n\nSpecial Cases:\n  - NaN: Results in special class (return 0)\n  - Infinity: Results in special class (return 0)\n  - Denormal: Results in special class (return 0)\n  - Perfect integer: Rounds to itself, proceeds to scale check\n  - Constant at 0x7b342b10: Used to scale value for secondary validation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d13997106616502d40d002e8b0d3aafe",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d13997106616502d40d002e8b0d3aafe",
        "CFG": "c3cfbbef9502e0df52c91435392e2d73",
        "PRO": "970f47969052e17ab2f35f8f21d3649e"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_be5d86296cfe": {
      "addresses": {
        "LoD/PD2": "0x7B33C141"
      },
      "rvas": {
        "LoD/PD2": "0xC141"
      },
      "sizes": {
        "LoD/PD2": 299
      },
      "name": "HandleSpecialFloatCases",
      "signature": "int HandleSpecialFloatCases(int mantissaLow, int mantissaHigh, int exponentLow, int exponentHigh, double * pResult)",
      "calling_convention": "__cdecl",
      "comment": "Handles special floating-point cases for mathematical operations\\nComputes results for edge cases involving infinity and special exponent values\\n\\nAlgorithm:\\n1. Extract absolute value of the first number (mantissaLow:mantissaHigh as double)\\n2. Check if second number exponent equals 0x7ff00000 (positive infinity)\\n   - If exponent is 0 and abs(first) <= 1.0: return 1.0 if first < 1.0 else 0.0\\n   - Otherwise: return global value at 0x7b342ca0\\n3. Check if second number exponent equals 0xfff00000 (negative infinity)\\n   - If exponent is 0 and abs(first) <= 1.0: return special value based on comparison\\n   - If abs(first) > 1.0: return 0.0\\n4. Check if second number is positive infinity (0x7ff00000:0)\\n   - Validate first number exponent; return 0 if invalid\\n   - Perform range checks: if <= 0.0 and >= 0.0 return 1.0 else 0.0\\n5. Check if second number is negative infinity (0xfff00000:0)\\n   - Validate first number exponent; return 0 if invalid\\n   - Call FUN_7b33c0d9 to classify the exponent value\\n   - Based on classification and range, return: 1.0, 0.0, or negated/global values\\n6. Store computed result in output parameter and return 0\\n\\nParameters:\\n- mantissaLow: Lower 32-bits of first double value\\n- mantissaHigh: Upper 32-bits of first double value (includes exponent and sign)\\n- exponentLow: Lower 32-bits of second double value\\n- exponentHigh: Upper 32-bits of second double value (exponent field at bits 20-30)\\n- pResult: Pointer to double output location for computed result\\n\\nReturns:\\n- Always returns 0 (int); actual result stored in *pResult\\n\\nSpecial Cases:\\n- Positive infinity exponent: 0x7ff00000\\n- Negative infinity exponent: 0xfff00000\\n- Global constants at 0x7b342ca0 (positive base) and 0x7b342cb0 (negative base)\\n- Classification result from FUN_7b33c0d9 determines sign of special value returns\\n- All comparisons use floating-point stack operations with special NaN handling\\n\\nStructure Layout:\\nOffset | Size | Field Name | Type | Description\\n0      | 8    | firstNum   | double | First operand (checked for range/magnitude)\\n8      | 4    | exponentLo | int | Lower 32-bits of second operand exponent field\\n12     | 4    | exponentHi | int | Upper 32-bits with sign and exponent (bits 20-30)\\n16     | 4    | pResult    | double* | Output pointer for computed result\\n20     | 8    | temp       | double | Temporary FP stack variable",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:be5d86296cfe10420ab6ae3acc617a84",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "be5d86296cfe10420ab6ae3acc617a84",
        "CFG": "6496ef2c0cc7bc841d31e4acb3c6aa21",
        "PRO": "b589f944b064ea2e2e1a75f35e528f77"
      },
      "basic_block_counts": {
        "LoD/PD2": 29
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_a7724bd3045b": {
      "addresses": {
        "LoD/PD2": "0x7B33C26C"
      },
      "rvas": {
        "LoD/PD2": "0xC26C"
      },
      "sizes": {
        "LoD/PD2": 272
      },
      "name": "HandleFloatingPointException",
      "signature": "void HandleFloatingPointException(int exceptionCode, int * pExceptionInfo, ushort * pExceptionFlags)",
      "calling_convention": "__cdecl",
      "comment": "Handles floating-point exception errors by mapping exception codes to handler flags and dispatching to appropriate exception handlers.\n\nAlgorithm:\n1. Extract exception flags from ushort parameter (nExceptionMask)\n2. Load exception type code from pExceptionInfo[0]\n3. Map exception type to nExceptionFlags using switch statement (1\u21928, 2\u21924, 3\u21920x11, 4\u21920x12, 5\u21928, 8\u21920x10)\n4. Call HandleFloatingPointRounding with mapped flags and pExceptionInfo[6] (double value)\n5. If return value is 0, check exception code (0x10, 0x16, 0x1d) for special FP control word handling\n6. For special codes: load double from pExceptionInfo[4], mask control word with 0xffffffe3, OR with 0x3\n7. Call __raise_exc with exception context and flags\n8. Call __ctrlfp() to synchronize FP state\n9. Check if exception type is 8, if not check for special handler via FUN_7b337efc\n10. If special handler exists, call FUN_7b337f28(pExceptionInfo) to process exception\n11. Call DispatchExceptionErrorCode with exception type code\n12. Validate stack cookie before return\n\nParameters:\n  exceptionCode (EBX+8): Exception code (0x10, 0x16, 0x1d, etc.) that identifies exception type\n  pExceptionInfo (ESI): Pointer to exception info structure containing exception data and doubles\n  pExceptionFlags (EAX): Pointer to ushort exception mask/flags\n\nReturns:\n  void - No return value; function dispatches to exception handlers\n\nSpecial Cases:\n  - Exception codes 0x10, 0x16, 0x1d trigger FP control word manipulation\n  - Exception type 8 skips special handler check\n  - Stack cookie validation protects against buffer overflow attacks\n  - FP control word bits: mask 0xffffffe3 clears bits 0-4, OR 0x3 sets precision bits",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a7724bd3045b6f0ade7aa6ddff69dccb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a7724bd3045b6f0ade7aa6ddff69dccb",
        "CFG": "dddad7afdb82dd3316e4b0a202e54b16",
        "PRO": "c9d74296e4283e367d1679c90b029df4"
      },
      "basic_block_counts": {
        "LoD/PD2": 24
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_fef66f8b6d0d": {
      "addresses": {
        "LoD/PD2": "0x7B33C37C"
      },
      "rvas": {
        "LoD/PD2": "0xC37C"
      },
      "sizes": {
        "LoD/PD2": 20
      },
      "name": "__frnd",
      "signature": "float10 __frnd(double param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __frnd\n\nLibraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fef66f8b6d0dd97beb2591f0fb3cce26",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fef66f8b6d0dd97beb2591f0fb3cce26",
        "CFG": null,
        "PRO": "61128113a862ffcd5160798c88db3acc"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_d58e5d6011aa": {
      "addresses": {
        "LoD/PD2": "0x7B33C390"
      },
      "rvas": {
        "LoD/PD2": "0xC390"
      },
      "sizes": {
        "LoD/PD2": 52
      },
      "name": "__errcode",
      "signature": "int __errcode(uint param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __errcode\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d58e5d6011aaa0137cdf1e76720ccd98",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d58e5d6011aaa0137cdf1e76720ccd98",
        "CFG": "f9310d93467e6f77bf3bd571c7f5f7e8",
        "PRO": "a368e3eb8f357d9272fd340ea11812a5"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_947f789b8b5a": {
      "addresses": {
        "LoD/PD2": "0x7B33C3C4"
      },
      "rvas": {
        "LoD/PD2": "0xC3C4"
      },
      "sizes": {
        "LoD/PD2": 206
      },
      "name": "__except1",
      "signature": "undefined __except1(uint param_1, int param_2, undefined8 param_3, double param_4, uint param_5)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __except1\n\nLibrary: Visual Studio 2015 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:947f789b8b5a0bd0be304aaaf2cd1bd4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "947f789b8b5a0bd0be304aaaf2cd1bd4",
        "CFG": "d88818743b8d9536d391cc371acc4a2f",
        "PRO": "d96b33b548b1a49c4356d7ebb094fcf6"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "PD2_EXT_MNE_6b40552453a6": {
      "addresses": {
        "LoD/PD2": "0x7B33C492"
      },
      "rvas": {
        "LoD/PD2": "0xC492"
      },
      "sizes": {
        "LoD/PD2": 640
      },
      "name": "HandleFloatingPointRounding",
      "signature": "int HandleFloatingPointRounding(uint exceptionFlags, double * resultValue, uint roundingMode)",
      "calling_convention": "__cdecl",
      "comment": "Handles floating-point rounding operations with exception flag control and rounding mode selection\n\nAlgorithm:\n1. Extract and process exception flags from exceptionFlags parameter using bitwise masks\n2. Perform validation checks on exception and rounding mode combinations\n3. For denormalized numbers (exponentValue < -0x3fd), perform mantissa shifting and rounding\n4. Extract mantissa and exponent from input using FrExp() with offset adjustment\n5. Detect sign bit and initialize rounding control variables\n6. If exponent underflow detected, set result to zero and signal exception\n7. Perform iterative right-shift of mantissa to denormalize based on exponent value\n8. Track guard, round, and sticky bits during mantissa shift\n9. Call fegetround() to retrieve current floating-point rounding mode\n10. Based on rounding mode (TO_NEAREST=0, UPWARD=0x100, DOWNWARD=0x200, TOWARD_ZERO=0xc00)\n11. Apply rounding increment to mantissa if rounding decision indicates carry needed\n12. Store final rounded result back to resultValue pointer\n13. Handle NaN/infinity cases with special constants from _DAT_7b342ca0/_DAT_7b342ca8\n14. Clear exception flags as specified by final flag masks\n15. Return true if all exception processing complete, false if error occurred\n\nParameters:\n  exceptionFlags (uint) - Bitfield controlling floating-point exception handling (bits 0-4: exceptions to process)\n  resultValue (double *) - Pointer to floating-point value to round/denormalize\n  roundingMode (uint) - Bitfield specifying rounding mode and exception routing (0xc00 = rounding mode selector)\n\nReturns:\n  int - Returns 1 (true) if processing successful with no exceptions, 0 (false) if FUN_7b33c070() called\n\nSpecial Cases:\n  - Zero input: Triggers exception handler FUN_7b33c070()\n  - Denormalized exponent (< -0x3fd): Mantissa shifting with guard/round/sticky bit tracking\n  - Rounding mode 0: ROUND_TO_NEAREST (banker's rounding on tie)\n  - Rounding mode 0x100: ROUND_UPWARD (toward positive infinity)\n  - Rounding mode 0x200: ROUND_DOWNWARD (toward negative infinity)\n  - Rounding mode 0xc00: ROUND_TOWARD_ZERO (truncation)\n  - NaN/Infinity: Return special constant adjusted by sign of input",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6b40552453a6c531f9d03ee84dd544ba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6b40552453a6c531f9d03ee84dd544ba",
        "CFG": "8a2b4e21f597a2b2acec712fc3a54eb2",
        "PRO": "c98f1ddb9237829ffc45c73f6c933138"
      },
      "basic_block_counts": {
        "LoD/PD2": 73
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "PD2_EXT_MNE_fe79b846af51": {
      "addresses": {
        "LoD/PD2": "0x7B33C712"
      },
      "rvas": {
        "LoD/PD2": "0xC712"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "__raise_exc",
      "signature": "undefined __raise_exc(uint * param_1, uint * param_2, uint param_3, int param_4, uint * param_5, uint * param_6)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __raise_exc\n\nLibrary: Visual Studio 2015 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fe79b846af51e290fb82c304e25eeacf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fe79b846af51e290fb82c304e25eeacf",
        "CFG": null,
        "PRO": "407117a8ee7092c0804d627a2f0ee33c"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "PD2_EXT_MNE_6655790afa38": {
      "addresses": {
        "LoD/PD2": "0x7B33C735"
      },
      "rvas": {
        "LoD/PD2": "0xC735"
      },
      "sizes": {
        "LoD/PD2": 753
      },
      "name": "__raise_exc_ex",
      "signature": "undefined __raise_exc_ex(uint * param_1, uint * param_2, uint param_3, int param_4, uint * param_5, uint * param_6, int param_7)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __raise_exc_ex\n\nLibrary: Visual Studio 2015 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6655790afa38b68f0b7a1fca3308be94",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6655790afa38b68f0b7a1fca3308be94",
        "CFG": "60b28c48098cc6c7946924eb1dd37295",
        "PRO": "53ccfde4666a6f7f2d7ed6ef70c4bfa5"
      },
      "basic_block_counts": {
        "LoD/PD2": 69
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "PD2_EXT_MNE_dfe41356d07d": {
      "addresses": {
        "LoD/PD2": "0x7B33CA26"
      },
      "rvas": {
        "LoD/PD2": "0xCA26"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "DispatchExceptionErrorCode",
      "signature": "void DispatchExceptionErrorCode(int errorCode)",
      "calling_convention": "__cdecl",
      "comment": "Dispatches exception error codes and sets the error status in the exception context.\n\nAlgorithm:\n1. Extract error code from first parameter (errorCode)\n2. Use subtract-and-jump pattern to dispatch based on error code value\n3. If errorCode == 1: Get exception context, set error status to 0x21\n4. If errorCode == 2 or 3: Get exception context, set error status to 0x22\n5. If errorCode is any other value: Return without modification (no-op)\n6. Return to caller\n\nParameters:\nerrorCode (int) - Exception error code that determines which error status to set.\n                  Valid codes: 1 (sets 0x21), 2-3 (sets 0x22), other (no-op)\n\nReturns:\nvoid - No return value. Side effect is updating error status in exception context.\n\nSpecial Cases:\n- Error code 2 and 3 are treated identically (both set status 0x22)\n- Unrecognized error codes result in no operation\n- Error status is stored at offset 0 of the structure returned by FUN_7b335dc4()\n- 0x21 and 0x22 are likely exception status codes defined elsewhere",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:dfe41356d07ddd03dbb0f505b1c8ef92",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "dfe41356d07ddd03dbb0f505b1c8ef92",
        "CFG": "aca5094624ced9357feaf4941fa0558b",
        "PRO": "0e87f0e83a4f89c0b721e19dbc83b51a"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_e345c6e0575c": {
      "addresses": {
        "LoD/PD2": "0x7B33CA57"
      },
      "rvas": {
        "LoD/PD2": "0xCA57"
      },
      "sizes": {
        "LoD/PD2": 160
      },
      "name": "SearchAndInvokeExceptionHandler",
      "signature": "float10 SearchAndInvokeExceptionHandler(float10 * __return_storage_ptr__, int handlerCode, int exceptionType, uint param3, uint param4, uint param5, uint param6, uint param7, uint param8)",
      "calling_convention": "__cdecl",
      "comment": "Searches exception handler table and invokes matching handler\n\nAlgorithm:\n1. Initialize loop counter to 0\n2. Search handler table (0x7b342b18) for entry matching exceptionType parameter\n3. If match found, load handler pointer from parallel table (0x7b342b1c)\n4. If handler pointer is non-zero:\n   a. Copy all parameters to local variables (stack frame at EBP-0x20)\n   b. Call __ctrlfp() to save FPU control state\n   c. Perform indirect call through FUN_7b337f28() with parameter block\n   d. If return value is 0, call FUN_7b33ca26() to set error code 0x21\n   e. Return float10 value from parameter7:parameter8 (ST0 FPU register)\n5. If handler pointer is zero or no match found:\n   a. Call __ctrlfp() to save FPU control state\n   b. Call FUN_7b33ca26() with handlerCode parameter\n   c. Return float10 value from parameter7:parameter8\n   \nParameters:\n  handlerCode (int) - Exception type code, passed to error handler\n  exceptionType (int) - Exception type to search for in handler table\n  param3-param8 (uint) - Exception context parameters, copied to stack for handler\n  \nReturns:\n  float10 - Floating point result from exception handler (loaded from params 7-8)\n  \nSpecial Cases:\n  - Handler lookup uses table stride of 8 bytes (2 DWORDs per entry)\n  - Table has fixed size of 0x1d entries (29 exception types)\n  - FUN_7b337f28() performs guarded indirect call (control flow guard)\n  - FUN_7b33ca26() sets error codes: 0x21 for code 1, 0x22 for codes 2-3\n  - If handler pointer is zero after table lookup, skips to not-found path",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e345c6e0575c9016ccc3565868ef5d76",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e345c6e0575c9016ccc3565868ef5d76",
        "CFG": "27502b7d68faf645618154eabb3d3cfc",
        "PRO": "14e80a8878be8c25f87800d8ba66f33b"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 9
      }
    },
    "PD2_EXT_MNE_c4f75d1541dd": {
      "addresses": {
        "LoD/PD2": "0x7B33CAF7"
      },
      "rvas": {
        "LoD/PD2": "0xCAF7"
      },
      "sizes": {
        "LoD/PD2": 210
      },
      "name": "FrExp",
      "signature": "double FrExp(double value, int * pExponent)",
      "calling_convention": "__cdecl",
      "comment": "Extracts the binary exponent from a double-precision floating-point number.\n\nAlgorithm:\n1. Load input double value and compare with zero\n2. If input is zero, return exponent 0\n3. If input is subnormal (denormalized), normalize by shifting mantissa and adjusting exponent counter\n4. Extract exponent field from high 32 bits (bits 20-30)\n5. Mask out exponent bits to create normalized mantissa in [0.5, 1.0)\n6. Apply sign bit if number is negative\n7. Call __set_exp to set normalized mantissa with exponent 0\n8. Calculate actual exponent by shifting and masking exponent field, then subtracting bias 0x3fe\n9. Store calculated exponent to output pointer\n\nParameters:\n- value: Input double value to extract exponent from\n- pExponent: Pointer to int where exponent will be stored\n\nReturns:\n- Void; exponent value written via pExponent pointer\n\nSpecial Cases:\n- Zero: Returns exponent 0\n- Subnormal numbers: Normalized via mantissa shifting with exponent counter (0xfffffc03)\n- Negative numbers: Sign bit set in high byte (0x8000)\n- Normal numbers: Exponent extracted from bits [20:30] with bias 0x3fe subtracted",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c4f75d1541ddbbf3fecb4708f2c85536",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c4f75d1541ddbbf3fecb4708f2c85536",
        "CFG": "c75f7684bb6a13190d99ac5176b08fda",
        "PRO": "c745885e846d1b9a58fbe650ad0429a1"
      },
      "basic_block_counts": {
        "LoD/PD2": 55
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_2b2fecda5ab0": {
      "addresses": {
        "LoD/PD2": "0x7B33CBC9"
      },
      "rvas": {
        "LoD/PD2": "0xCBC9"
      },
      "sizes": {
        "LoD/PD2": 45
      },
      "name": "__set_exp",
      "signature": "float10 __set_exp(undefined8 param_1, short param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __set_exp\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2b2fecda5ab0281149b562c16c46c04b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2b2fecda5ab0281149b562c16c46c04b",
        "CFG": null,
        "PRO": "0e6498da51a497ee1e5f983a0afbce57"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_51e50b5336f3": {
      "addresses": {
        "LoD/PD2": "0x7B33CBF6"
      },
      "rvas": {
        "LoD/PD2": "0xCBF6"
      },
      "sizes": {
        "LoD/PD2": 99
      },
      "name": "ClassifyFloatingPointSpecialValues",
      "signature": "byte ClassifyFloatingPointSpecialValues(uint mantissaLow, uint exponentAndMantissaHigh)",
      "calling_convention": "__cdecl",
      "comment": "Classifies special floating-point values (infinity, NaN, denormalized) in IEEE 754 doubles.\n\nAlgorithm:\n1. Load exponent and mantissa from high 32-bit word (bits 52-63 are exponent)\n2. Check for positive infinity (exponent=0x7FF, mantissa=0) \u2192 return 1\n3. Check if low 32-bit is zero, if yes return 1 (positive infinity case)\n4. Check for negative infinity (exponent=0x7FF, mantissa=0) \u2192 return 2\n5. Check if low 32-bit is zero, if yes return 2 (negative infinity case)\n6. Extract exponent field using mask 0x7FF8 from 16-bit value\n7. Test for NaN (exponent=0x7FF, mantissa\u22600) \u2192 return 3\n8. Test for denormalized value (exponent=0x7FF0, mantissa=0 with specific flags) \u2192 return 4\n9. For normal values with zero mantissa, return based on sign bit negation logic\n\nParameters:\n  mantissaLow (uint): Low 32 bits of IEEE 754 double mantissa\n  exponentAndMantissaHigh (uint): High 32 bits containing sign, exponent, and mantissa bits\n\nReturns:\n  byte: Classification code - 1=positive infinity, 2=negative infinity, 3=NaN, 4=denormalized/subnormal, 0=normal\n\nSpecial Cases:\n  - Uses two parameters to represent 64-bit double in 32-bit calling convention\n  - Exponent field stored in bits 52-62 (0x7FF0 mask on high word)\n  - Sign bit in bit 63 (0x80000000 on high word)\n  - Denormalized values have zero exponent but non-zero mantissa\n  - NaN values have exponent 0x7FF with any non-zero mantissa",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:51e50b5336f3c889077b546c8b21c4e8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "51e50b5336f3c889077b546c8b21c4e8",
        "CFG": "b96ab1c046f9dd4b69b39b911715424c",
        "PRO": "7a9d2f2bd54c7fba4ba6d0166c1cd796"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_a1601eec9ec1": {
      "addresses": {
        "LoD/PD2": "0x7B33CC59"
      },
      "rvas": {
        "LoD/PD2": "0xCC59"
      },
      "sizes": {
        "LoD/PD2": 164
      },
      "name": "__fpclass",
      "signature": "int __fpclass(double _X)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __fpclass\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a1601eec9ec1d799d4f529c44cadd20f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a1601eec9ec1d799d4f529c44cadd20f",
        "CFG": "5983940de9a553ac159f82ced5bdfca3",
        "PRO": "d8fda1720f29503a93f3a9c4806ebf51"
      },
      "basic_block_counts": {
        "LoD/PD2": 16
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_74e08dea317b": {
      "addresses": {
        "LoD/PD2": "0x7B33CD00"
      },
      "rvas": {
        "LoD/PD2": "0xCD00"
      },
      "sizes": {
        "LoD/PD2": 67
      },
      "name": "__FindPESection",
      "signature": "PIMAGE_SECTION_HEADER __FindPESection(PBYTE pImageBase, DWORD_PTR rva)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __FindPESection\n\nLibraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:74e08dea317b4f9944f12858794a3365",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "74e08dea317b4f9944f12858794a3365",
        "CFG": "fd32fcbc1bb7eeb18567ac64ddfa5c84",
        "PRO": "ebaf229e6ab3d30073fabb7df59640bb"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_bf802b5c0489": {
      "addresses": {
        "LoD/PD2": "0x7B33CD50"
      },
      "rvas": {
        "LoD/PD2": "0xCD50"
      },
      "sizes": {
        "LoD/PD2": 164
      },
      "name": "__IsNonwritableInCurrentImage",
      "signature": "BOOL __IsNonwritableInCurrentImage(PBYTE pTarget)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __IsNonwritableInCurrentImage\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bf802b5c0489d1a4bda26d6e10c2b196",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bf802b5c0489d1a4bda26d6e10c2b196",
        "CFG": "6065d0e8d4d191a7ef2d41eec7067d6b",
        "PRO": "50986a3612e8e5ba42a0a138b20d047d"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_61cb386da067": {
      "addresses": {
        "LoD/PD2": "0x7B33CE10"
      },
      "rvas": {
        "LoD/PD2": "0xCE10"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "IsValidPEExecutable",
      "signature": "bool IsValidPEExecutable(byte * pPEBuffer)",
      "calling_convention": "__cdecl",
      "comment": "Validates whether a pointer references a valid PE32 executable file.\\n\\nAlgorithm:\\n1. Verify MZ signature (0x5A4D) at offset +0x0\\n2. Read PE header offset from DOS header at offset +0x3C\\n3. Calculate absolute PE header address: offset + buffer base\\n4. Validate PE signature (0x4550) at calculated PE header location\\n5. Read Machine field from PE Optional Header at offset +0x18\\n6. Check if Machine == 0x10B (I386/x86 architecture)\\n7. Return true if all validations pass, false on any failure\\n\\nParameters:\\n- pPEBuffer: Pointer to PE file header (MZ signature start)\\n\\nReturns:\\n- true: Valid PE32 executable for x86 architecture\\n- false: Invalid format or not PE32 x86 executable\\n\\nSpecial Cases:\\n- 0x5A4D: DOS MZ signature constant\\n- 0x3C: DOS header offset to PE header pointer\\n- 0x4550: PE signature constant (ASCII \\\"PE\\\")\\n- 0x10B: PE Machine type for Intel I386 architecture\\n- Function checks for I386 specifically, not ARM or other architectures\\n\\nStructure Layout (PE Format):\\nOffset  Size  Field Name        Type    Description\\n------  ----  ---------------   ----    ----------------\\n0x0     2     e_magic           WORD    DOS signature (0x5A4D = 'MZ')\\n0x3C    4     e_lfanew          DWORD   Offset to PE header\\nPE+0    4     Signature         DWORD   PE signature (0x4550 = 'PE')\\nPE+18   2     Machine           WORD    Machine type (0x10B = I386)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:61cb386da0674c6f91039b7ce52ed495",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "61cb386da0674c6f91039b7ce52ed495",
        "CFG": "b299961a4ff9924d9c5832fc43b80e26",
        "PRO": "0ae9c941390bcf59ac49b87c7367afb8"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_2c3468b423fe": {
      "addresses": {
        "LoD/PD2": "0x7B33CE41"
      },
      "rvas": {
        "LoD/PD2": "0xCE41"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "DestructorWithConditionalDeallocation",
      "signature": "void * DestructorWithConditionalDeallocation(void * this, byte shouldDeallocate)",
      "calling_convention": "__thiscall",
      "comment": "C++ destructor that conditionally deallocates object memory\n\nAlgorithm:\n1. Initialize virtual function table pointer at offset 0x0\n2. Test bit 0 of shouldDeallocate flag\n3. If bit 0 set, call DeallocateObjectMemory to free object\n4. Return pointer to object (this)\n\nParameters:\n  this (ECX) - Pointer to C++ object instance\n  shouldDeallocate (stack) - Byte flag; bit 0 set indicates deallocate\n\nReturns:\n  void * - Pointer to the object (this pointer unchanged)\n\nSpecial Cases:\n  Magic values: 0x1 - Deallocation flag mask (tests bit 0 only)\n  The vftable pointer (0x7b342cbc) is always set regardless of deallocation\n  Conditional deallocation allows object reuse with same destructor\n\nCalling Convention:\n  __thiscall: this implicit in ECX, shouldDeallocate on stack, RET 0x4",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2c3468b423fef34a4bb6fa44360db639",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2c3468b423fef34a4bb6fa44360db639",
        "CFG": "754bfc5d47177c4cbdd43b336248c7ba",
        "PRO": "fa5a308f885e98065f696d6e24086df6"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "PD2_EXT_MNE_f8a90eae4fe7": {
      "addresses": {
        "LoD/PD2": "0x7B33CE64"
      },
      "rvas": {
        "LoD/PD2": "0xCE64"
      },
      "sizes": {
        "LoD/PD2": 20
      },
      "name": "__EH_epilog3",
      "signature": "undefined __EH_epilog3(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __EH_epilog3\n\nLibraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f8a90eae4fe79651b3297724da273c17",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f8a90eae4fe79651b3297724da273c17",
        "CFG": null,
        "PRO": "27e2aba8606ba96c2068ea82b427719b"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_1465ab3b31b1": {
      "addresses": {
        "LoD/PD2": "0x7B33CE78"
      },
      "rvas": {
        "LoD/PD2": "0xCE78"
      },
      "sizes": {
        "LoD/PD2": 51
      },
      "name": "__EH_prolog3",
      "signature": "undefined __EH_prolog3(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __EH_prolog3\n\nLibraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1465ab3b31b1e2b2093dd3939cd9726d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1465ab3b31b1e2b2093dd3939cd9726d",
        "CFG": null,
        "PRO": "3e92ad740017f22106976023eea70ce2"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_d0bb544fe0e5": {
      "addresses": {
        "LoD/PD2": "0x7B33CEAB"
      },
      "rvas": {
        "LoD/PD2": "0xCEAB"
      },
      "sizes": {
        "LoD/PD2": 54
      },
      "name": "__EH_prolog3_catch",
      "signature": "undefined __EH_prolog3_catch(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __EH_prolog3_catch\n\nLibraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d0bb544fe0e5af09bec61fe3e2a7bda3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d0bb544fe0e5af09bec61fe3e2a7bda3",
        "CFG": null,
        "PRO": "ef84f81518294ca890839eff0155a3e6"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_e3e7225badfc": {
      "addresses": {
        "LoD/PD2": "0x7B33CEF0"
      },
      "rvas": {
        "LoD/PD2": "0xCEF0"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "guard_check_icall",
      "signature": "undefined guard_check_icall(void)",
      "calling_convention": "__cdecl",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "0579f88b0875edaf79a0e459979135de"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_0af48c18cc11": {
      "addresses": {
        "LoD/PD2": "0x7B33CEF6"
      },
      "rvas": {
        "LoD/PD2": "0xCEF6"
      },
      "sizes": {
        "LoD/PD2": 14
      },
      "name": "DeallocateObjectMemory",
      "signature": "void DeallocateObjectMemory(void * pObject)",
      "calling_convention": "__cdecl",
      "comment": "Deallocate memory for a C++ object instance\n\nAlgorithm:\n1. Save current stack frame and create new stack frame\n2. Push object pointer parameter onto stack as function argument\n3. Call deallocation thunk to release object memory\n4. Clean up stack by removing function argument\n5. Restore original stack frame and return to caller\n\nParameters:\n  pObject (void*) - Pointer to C++ object instance to deallocate\n\nReturns:\n  void - No return value\n\nPurpose:\nThis is a wrapper function used as a C++ destructor callback. It takes\na pointer to an object and delegates deallocation to thunk_FUN_7b33503d.\nUsed by std::exception and type_info destructors to properly release\nallocated memory when the conditional deallocation flag is set.\n\nCalling Convention:\n__cdecl - All parameters passed on stack, caller cleans up",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0af48c18cc11c2a1b044a6fc47738db2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0af48c18cc11c2a1b044a6fc47738db2",
        "CFG": null,
        "PRO": "f2c382c1b43da424125fba00a6d650ff"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "PD2_EXT_MNE_d2bf5bcb7aed": {
      "addresses": {
        "LoD/PD2": "0x7B33CF26"
      },
      "rvas": {
        "LoD/PD2": "0xCF26"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "__alloca_probe_16",
      "signature": "uint __alloca_probe_16(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __alloca_probe_16\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d2bf5bcb7aedd28dbc8aef58e14d356c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d2bf5bcb7aedd28dbc8aef58e14d356c",
        "CFG": null,
        "PRO": "d2fde8764ddd02ea9c12fd3033449894"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_eaded9c735f8": {
      "addresses": {
        "LoD/PD2": "0x7B33CF40"
      },
      "rvas": {
        "LoD/PD2": "0xCF40"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "__alloca_probe",
      "signature": "undefined __alloca_probe(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __chkstk\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:eaded9c735f89913ca38badb8ea3bbe3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "eaded9c735f89913ca38badb8ea3bbe3",
        "CFG": "ea03c6407b4d091868dce8d0baf95212",
        "PRO": "45554d7d27a2380e7add6286eec75198"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "PD2_EXT_MNE_681b79eef16d": {
      "addresses": {
        "LoD/PD2": "0x7B33CF80"
      },
      "rvas": {
        "LoD/PD2": "0xCF80"
      },
      "sizes": {
        "LoD/PD2": 120
      },
      "name": "__filter_x86_sse2_floating_point_exception_default",
      "signature": "int __filter_x86_sse2_floating_point_exception_default(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __filter_x86_sse2_floating_point_exception_default\n\nLibrary: Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:681b79eef16d05dc2deff0db22e0f0a9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "681b79eef16d05dc2deff0db22e0f0a9",
        "CFG": "ce44a97749827c58d022304ba519a877",
        "PRO": "3fdd0c36c94c34eca4782cd2c9d36912"
      },
      "basic_block_counts": {
        "LoD/PD2": 15
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    }
  }
};

if (typeof FUNCTION_DATA === 'undefined') FUNCTION_DATA = {};
FUNCTION_DATA['PD2_EXT.dll'] = FUNCTIONS_PD2_EXT_dll;
