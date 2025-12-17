// Auto-generated from function_registry_v2.json
// Generated: 2025-12-16T18:31:58.018344
// Functions for D2sound.dll
// Versions: LoD/PD2

var FUNCTIONS_D2sound_dll = {
  "versions": [
    "LoD/PD2"
  ],
  "functions": {
    "D2sound_STR_c170bd72c7a3": {
      "addresses": {
        "LoD/PD2": "0x6F9B1000"
      },
      "rvas": {
        "LoD/PD2": "0x1000"
      },
      "sizes": {
        "LoD/PD2": 47
      },
      "name": "___crtExitProcess",
      "signature": "void ___crtExitProcess(int nExitCode)",
      "calling_convention": "__cdecl",
      "comment": "CRT exit process wrapper with .NET framework integration\n\nAlgorithm:\n\n1. Attempt to load mscoree.dll module handle using GetModuleHandleA\n2. If mscoree.dll is loaded, get CorExitProcess function address\n3. If CorExitProcess is available, call it with the exit code\n4. Call standard ExitProcess with exit code (does not return)\n\nParameters:\n\nnExitCode (int): Process exit code to be passed to exit functions\n\nReturns:\n\nDoes not return - function terminates the process\n\nSpecial Cases:\n\n- If mscoree.dll is not loaded, skip .NET exit handler\n- If CorExitProcess is not found in mscoree.dll, skip .NET exit handler\n- ExitProcess always called as final step and never returns\n- Function designed for C Runtime Library integration with .NET framework\n\nMagic Numbers Reference:\n\nN/A - No magic numbers used, relies on Windows API string constants",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:c170bd72c7a30c3be9e6aa15fb836e49",
      "indexes": {
        "EXP": null,
        "STR": "c170bd72c7a30c3be9e6aa15fb836e49",
        "API": null,
        "MNE": "df0a04b7db34c5f035a394dc061ca513",
        "CFG": "80845e7377749fe62fdfa1726193a977",
        "PRO": "9e2e540e31360157272f7aa405689cb9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "df0a04b7db34c5f035a394dc061ca513"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_f23ef2b3a6cf": {
      "addresses": {
        "LoD/PD2": "0x6F9B1030"
      },
      "rvas": {
        "LoD/PD2": "0x1030"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "AcquireLockOnExit",
      "signature": "void AcquireLockOnExit(void)",
      "calling_convention": "__stdcall",
      "comment": "Exit handler that acquires thread synchronization lock for safe program termination\n\nAlgorithm:\n1. Push lock ID (8) onto stack for __lock function call\n2. Call __lock function to acquire specific synchronization lock\n3. Clean up stack with POP ECX instruction\n4. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Lock ID 8 represents a specific C runtime synchronization resource\n- Function is registered as exit handler via __onexit mechanism\n- Called during program termination cleanup phase\n- Critical section must be acquired before other exit handlers run\n- Uses __stdcall calling convention with callee stack cleanup\n\nMagic Numbers Reference:\n0x8 (8 decimal) - Lock identifier for C runtime exit synchronization",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "78fd821d620e779aa5b7fe30bc336370"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_ADDR_6F9B1039": {
      "addresses": {
        "LoD/PD2": "0x6F9B1039"
      },
      "rvas": {
        "LoD/PD2": "0x1039"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseCriticalSectionLock8",
      "signature": "void ReleaseCriticalSectionLock8(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases critical section lock 8 for thread synchronization.\n\nAlgorithm:\n1. Push the critical section index (8) onto the stack as parameter\n2. Call the critical section release function (LeaveCriticalSection wrapper)\n3. Return to caller\n\nParameters:\nNone - operates on a static critical section at index 8\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- This function releases a hardcoded critical section (index 8), typically used for protecting shared game state\n- Part of the game's thread synchronization mechanism for exclusive access to protected resources\n- The actual LeaveCriticalSection call is delegated to FUN_6f9b1510 which indexes into the critical section array at DAT_6f9c5038\n\nRelated Functions:\n- FUN_6f9b1510: Generic critical section release for any index\n- Called by: FUN_6f9b16d0 (appears to be another lock release wrapper)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "d0ba2227d16de6f938cd1cc5b699e4d9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_MNE_996e3f0c6129": {
      "addresses": {
        "LoD/PD2": "0x6F9B1042"
      },
      "rvas": {
        "LoD/PD2": "0x1042"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "__initterm",
      "signature": "void __initterm(void * * end)",
      "calling_convention": "__cdecl",
      "comment": "Visual Studio C Runtime library function to initialize termination routines\n\nAlgorithm:\n1. Start with global function pointer array at runtime-determined start address (in EAX register)\n2. Iterate through function pointer array until reaching end boundary parameter\n3. For each array element, check if function pointer is non-null\n4. If function pointer is valid, invoke the function with no parameters\n5. Advance to next function pointer in array (increment by pointer size)\n6. Continue until reaching end boundary, then return\n\nParameters:\n- end (void **): Pointer to end of function pointer array boundary\nIMPLICIT: in_EAX register contains start address of function pointer array\n\nReturns:\n- void: No return value, function executes for side effects only\n\nSpecial Cases:\n- Null function pointers (0x0) are skipped without error\n- Empty array (start == end) results in immediate return\n- Array traversal is ascending memory order only\n\nMagic Numbers Reference:\n- 0x0 (NULL): Sentinel value indicating invalid/uninitialized function pointer\n\nError Handling:\n- No explicit error handling for invalid function pointers\n- Assumes well-formed function pointer array within valid memory range\n- Caller responsible for ensuring array boundaries are correct",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:996e3f0c6129985d37a2b36d657b6892",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "996e3f0c6129985d37a2b36d657b6892",
        "CFG": "4378837d3436e6162074a4fec1af3d10",
        "PRO": "56a3399a0dba94678e31baeedf1b1552"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "996e3f0c6129985d37a2b36d657b6892"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_28a1cba9ddfd": {
      "addresses": {
        "LoD/PD2": "0x6F9B105A"
      },
      "rvas": {
        "LoD/PD2": "0x105A"
      },
      "sizes": {
        "LoD/PD2": 106
      },
      "name": "__cinit",
      "signature": "int __cinit(int nProcessFlag)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: int __cinit(int nProcessFlag)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:28a1cba9ddfd9945ee3fec59104d67a8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "28a1cba9ddfd9945ee3fec59104d67a8",
        "CFG": "e88749fdb0bfc0cf5a0e32fc67bb3506",
        "PRO": "31d17fab4fcbb9ba7d9530488da16428"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "28a1cba9ddfd9945ee3fec59104d67a8"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_4a7687a1c80b": {
      "addresses": {
        "LoD/PD2": "0x6F9B10C4"
      },
      "rvas": {
        "LoD/PD2": "0x10C4"
      },
      "sizes": {
        "LoD/PD2": 181
      },
      "name": "doexit",
      "signature": "void doexit(uint dwExitCode, int fSkipAtExitHandlers, int fQuickExit)",
      "calling_convention": "__cdecl",
      "comment": "Exit process gracefully with cleanup and handler execution.\n\nAlgorithm:\n1. Acquire exit synchronization lock to prevent concurrent exits\n2. Check emergency termination flag - immediate exit if set  \n3. Set exit-in-progress flag to prevent new operations\n4. Store quick exit mode flag in global state\n5. Skip atexit handlers if fSkipAtExitHandlers is non-zero\n6. Execute static destructor array\n7. Execute final cleanup array  \n8. Release exit synchronization lock\n9. Quick exit - return without process termination\n10. Set emergency flag and terminate process\n\nParameters:\n- dwExitCode (uint): Exit status code for process termination\n- fSkipAtExitHandlers (int): Skip atexit function execution if non-zero\n- fQuickExit (int): Quick exit mode - return without termination if non-zero\n\nReturns:\n- void: Function does not return on normal exit path\n- Quick exit returns to caller without process termination\n\nSpecial Cases:\n- Emergency flag set (DAT_6f9c6044 == 1): Immediate TerminateProcess call\n- Quick exit mode: Returns without calling ___crtExitProcess\n- Null atexit array: Safely skips handler processing\n- Null function pointers in atexit array: Skipped during execution\n\nMagic Numbers Reference:\n- 0x6f9c6044: Emergency termination flag\n- 0x6f9c6040: Exit-in-progress flag  \n- 0x6f9c603c: Quick exit mode flag\n- 0x6f9c6990: Atexit function array pointer\n- 0x6f9c698c: Current atexit array index\n- 0x6f9c5024: Static destructor array\n- 0x6f9c502c: Final cleanup array\n- 8: Exit synchronization lock ID\n\nError Handling:\n- Lock acquisition failure: Protected by lock mechanism\n- TerminateProcess failure: Process termination forced by OS\n- Handler execution errors: Individual handlers isolated\n\nState Machine:\n- State 1: Normal entry ??? Acquire lock, proceed to cleanup\n- State 2: Emergency flag set ??? Immediate termination via TerminateProcess  \n- State 3: Quick exit requested ??? Return after cleanup without termination\n- State 4: Normal exit ??? Full cleanup and ___crtExitProcess termination\n\nNote: Function uses 1 stack-allocated temporary variable optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4a7687a1c80b4268254de38c80b8b1f6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4a7687a1c80b4268254de38c80b8b1f6",
        "CFG": "1acfc7f97d08d10f8d33e74e1c437d1e",
        "PRO": "ea4dc692ec66b17c3e9ba2a9d44541ca"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4a7687a1c80b4268254de38c80b8b1f6"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_ca7f27832b0d": {
      "addresses": {
        "LoD/PD2": "0x6F9B1173"
      },
      "rvas": {
        "LoD/PD2": "0x1173"
      },
      "sizes": {
        "LoD/PD2": 14
      },
      "name": "ValidateAndReleaseLockOnExit",
      "signature": "void ValidateAndReleaseLockOnExit(void)",
      "calling_convention": "__stdcall",
      "comment": "Validates lock state and releases critical section during program exit.\n\nAlgorithm:\n1. Compare a field at [EBP + 0x10] against the unaffected EDI register\n2. If values are not equal, call FUN_6f9b1510 with parameter 8 to release the critical section\n3. Return to caller (likely doexit)\n\nParameters:\n  IMPLICIT EBP - Stack frame pointer containing lock state field at offset +0x10\n  IMPLICIT EDI - Comparison value for lock validation\n\nReturns:\n  void - No return value; side effect is potential critical section release\n\nSpecial Cases:\n  - If [EBP + 0x10] equals EDI, the critical section is not released and function returns immediately\n  - If [EBP + 0x10] differs from EDI, indicates lock mismatch requiring cleanup\n\nContext:\n  Called from doexit (C runtime exit handler) as part of cleanup sequence during program termination. Ensures that critical sections are properly released based on lock state validation.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ca7f27832b0deaebe496b377f1c5001a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ca7f27832b0deaebe496b377f1c5001a",
        "CFG": "f1596e7f5926afa1510db879e6d50457",
        "PRO": "d6f7f4a67072121666dd69b9320b7a31"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ca7f27832b0deaebe496b377f1c5001a"
      }
    },
    "D2sound_MNE_cd85d17a6b19": {
      "addresses": {
        "LoD/PD2": "0x6F9B1187"
      },
      "rvas": {
        "LoD/PD2": "0x1187"
      },
      "sizes": {
        "LoD/PD2": 17
      },
      "name": "_exit",
      "signature": "void _exit(int _Code)",
      "calling_convention": "__cdecl",
      "comment": "Standard C library function that immediately terminates the calling process.\n\nAlgorithm:\n1. Accept integer exit code from caller\n2. Call doexit with exit code, skip cleanup flags (0, 0)\n3. Function never returns (noreturn attribute)\n\nParameters:\n_Code (int): Exit status code returned to parent process\n  - 0 typically indicates successful termination\n  - Non-zero values indicate error conditions\n  - Standard range: -255 to 255 on most systems\n\nReturns:\nThis function never returns (marked noreturn)\nProcess termination bypasses normal cleanup and destructors\n\nSpecial Cases:\nUnlike exit(), this function skips:\n- C++ destructors for static objects\n- Functions registered with atexit()\n- Buffer flushing for open file streams\n- Cleanup of temporary files\n\nMagic Numbers Reference:\n0x0 (second parameter): Skip atexit() handler execution\n0x0 (third parameter): Skip C++ destructor calls\n\nError Handling:\nNo error handling - function always terminates process\nInvalid exit codes are platform-dependent (typically masked to 8-bit)\n\nCross-References:\nCalled by 45 functions across the codebase for immediate termination\nPrimary use cases: Fatal error handling, validation failures, resource exhaustion",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cd85d17a6b193c95680d3fdca645abba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd85d17a6b193c95680d3fdca645abba",
        "CFG": null,
        "PRO": "94a8097d6da98e139e076864648926cd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "cd85d17a6b193c95680d3fdca645abba"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B1198": {
      "addresses": {
        "LoD/PD2": "0x6F9B1198"
      },
      "rvas": {
        "LoD/PD2": "0x1198"
      },
      "sizes": {
        "LoD/PD2": 17
      },
      "name": "__exit",
      "signature": "void __exit(uint dwExitCode)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void __exit(uint dwExitCode)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cd85d17a6b193c95680d3fdca645abba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd85d17a6b193c95680d3fdca645abba",
        "CFG": null,
        "PRO": "f7825b23dde492455ea61a10ffbf72e2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "cd85d17a6b193c95680d3fdca645abba"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_7a5e6ed384be": {
      "addresses": {
        "LoD/PD2": "0x6F9B11A9"
      },
      "rvas": {
        "LoD/PD2": "0x11A9"
      },
      "sizes": {
        "LoD/PD2": 15
      },
      "name": "__cexit",
      "signature": "void __cexit(void)",
      "calling_convention": "__cdecl",
      "comment": "Microsoft C Runtime cleanup and exit function that performs exit processing without calling global destructors\n\nAlgorithm:\n1. Call doexit with exit processing flags (0, 0, 1)\n   - First parameter (0): Do not call global destructors or static object cleanup\n   - Second parameter (0): Exit code to use (success)\n   - Third parameter (1): Perform standard exit cleanup (atexit handlers, buffer flushing)\n2. Return to caller (does not actually return since doexit terminates process)\n\nParameters:\nNone\n\nReturns:\nvoid (function does not return as doexit terminates the process)\n\nSpecial Cases:\n- This is the \"clean exit\" variant that skips global object destructors\n- Used by C programs that need exit processing without C++ destructor overhead\n- Function is part of Microsoft Visual Studio 2003 Release runtime library\n- Process termination occurs within doexit call, return statement is unreachable\n\nMagic Numbers Reference:\n0x0 (first parameter): SKIP_DESTRUCTORS flag - disables global object destruction\n0x0 (second parameter): EXIT_SUCCESS code\n0x1 (third parameter): CLEANUP_STANDARD flag - enables atexit handlers and I/O cleanup",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7a5e6ed384be31095abb7960c9f1d6d0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7a5e6ed384be31095abb7960c9f1d6d0",
        "CFG": null,
        "PRO": "1d21c427e7f311517e1da7c5ba81eadc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7a5e6ed384be31095abb7960c9f1d6d0"
      }
    },
    "D2sound_MNE_98eebec3741b": {
      "addresses": {
        "LoD/PD2": "0x6F9B11B8"
      },
      "rvas": {
        "LoD/PD2": "0x11B8"
      },
      "sizes": {
        "LoD/PD2": 34
      },
      "name": "_rand",
      "signature": "int _rand(void)",
      "calling_convention": "__cdecl",
      "comment": "Standard C runtime pseudo-random number generator using Linear Congruential Generator (LCG).\n\nAlgorithm:\n1. Get per-thread data structure pointer using __getptd()\n2. Load current seed value from thread-local _holdrand field  \n3. Apply LCG formula: new_seed = (old_seed * 0x343FD) + 0x269EC3\n4. Store updated seed back to thread-local _holdrand field\n5. Extract 15-bit result: (new_seed >> 16) & 0x7FFF\n6. Return pseudo-random value in range 0-32767\n\nParameters:\n(none)\n\nReturns:\nPseudo-random integer in range 0 to 32767 (0x7FFF)\nUses thread-local seed for thread safety\nReturns deterministic sequence based on current seed state\n\nMagic Numbers Reference:\n0x343FD (214013) - LCG multiplier constant  \n0x269EC3 (2531011) - LCG increment constant\n0x10 (16) - Right shift to extract high bits\n0x7FFF (32767) - Mask to ensure positive 15-bit result\n\nAlgorithm Implementation:\nThis implements the Microsoft Visual C++ rand() function using the formula:\nnext = seed * 214013 + 2531011\nreturn (next >> 16) & 0x7FFF\n\nThread Safety:\nUses __getptd() to access per-thread data structure (_ptiddata)\nEach thread maintains independent _holdrand seed value\nNo synchronization required between threads",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:98eebec3741bc1addf7fafbeff16d621",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "98eebec3741bc1addf7fafbeff16d621",
        "CFG": null,
        "PRO": "df3b9c75908fd93f90f391f2ea02e0e6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "98eebec3741bc1addf7fafbeff16d621"
      }
    },
    "D2sound_MNE_1c48859ddf90": {
      "addresses": {
        "LoD/PD2": "0x6F9B11DA"
      },
      "rvas": {
        "LoD/PD2": "0x11DA"
      },
      "sizes": {
        "LoD/PD2": 385
      },
      "name": "__CRT_INIT@12",
      "signature": "int __CRT_INIT@12(uint dwFlags, int nReason)",
      "calling_convention": "__stdcall",
      "comment": "C Runtime Library initialization and cleanup entry point for DLL\n\nAlgorithm:\n1. Check reason code for initialization type (DLL_PROCESS_ATTACH=1, DLL_PROCESS_DETACH=0, DLL_THREAD_ATTACH=2, DLL_THREAD_DETACH=3)\n2. For DLL_PROCESS_ATTACH (1): Get OS version info using GetVersionExA with OSVERSIONINFO structure\n3. Store OS version data in global variables (DAT_6f9c6004, DAT_6f9c6010, etc.)\n4. Calculate platform flags and build composite version number\n5. Initialize CRT subsystems in order: heap (__heap_init), multithreading (__mtinit), runtime checks (__RTC_Initialize)\n6. Get command line (GetCommandLineA) and environment strings (___crtGetEnvironmentStringsA)\n7. Initialize I/O subsystem (__ioinit), command line arguments (__setargv), environment (__setenvp)\n8. Run global constructors (__cinit) and increment reference counter (DAT_6f9c6048)\n9. For DLL_PROCESS_DETACH (0): Decrement reference counter and cleanup if last reference\n10. Call cleanup functions: __cexit, __ioterm, __mtterm, __heap_term\n11. For DLL_THREAD_ATTACH (2): Allocate per-thread data structure (0x8c bytes)\n12. Initialize thread data with __initptd and set thread handle/ID\n13. For DLL_THREAD_DETACH (3): Free per-thread data structure with __freeptd\n\nParameters:\ndwFlags (param_1): Reserved DWORD flags parameter (unused in this implementation)\nnReason (param_2): DLL attachment reason code - 0=PROCESS_DETACH, 1=PROCESS_ATTACH, 2=THREAD_ATTACH, 3=THREAD_DETACH\n\nReturns:\n1 (TRUE): Successful initialization or cleanup\n0 (FALSE): Initialization failure (heap, multithreading, I/O, or global constructor errors)\n\nSpecial Cases:\nMagic Number Reference:\n0x94 (148): Size of OSVERSIONINFO structure for GetVersionExA call\n0x8c (140): Size of per-thread data structure (_ptiddata)\n0x7fff (32767): Mask for OS build number to clear high bit\n0x8000 (32768): Flag set when OS major version != 2 (not Windows 95/98)\n0x100 (256): Multiplier for calculating composite version (minor_ver * 256 + major_ver)\n\nError Handling:\nGetVersionExA failure: Skip OS version storage, continue with CRT initialization\n__heap_init failure: Return 0, skip all remaining initialization\n__mtinit failure: Cleanup heap, return 0\n__ioinit failure: Cleanup multithreading and heap, return 0\n__setargv/__setenvp/__cinit failure: Cleanup I/O, multithreading, and heap, return 0\nThread data allocation failure: Return 0, no cleanup needed\n\nGlobal Variables Modified:\nDAT_6f9c6004: OS minor version (dwMinorVersion from OSVERSIONINFO)\nDAT_6f9c6008: OS build number with platform flag (masked and potentially OR'd with 0x8000)\nDAT_6f9c600c: Composite version number (minor * 256 + major)\nDAT_6f9c6010: OS platform ID (dwPlatformId from OSVERSIONINFO)\nDAT_6f9c6014: OS major version (dwMajorVersion from OSVERSIONINFO)\nDAT_6f9c6048: CRT reference counter (incremented on attach, decremented on detach)\nDAT_6f9c6980: Command line string pointer from GetCommandLineA\nDAT_6f9c604c: Environment strings pointer from ___crtGetEnvironmentStringsA",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1c48859ddf90d08dbf4d9d03c0c2a56a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1c48859ddf90d08dbf4d9d03c0c2a56a",
        "CFG": "08da3686eea5cee9f9b0724f005d7159",
        "PRO": "20e41f1deb32bcadcee45ae0c4b0c71b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "1c48859ddf90d08dbf4d9d03c0c2a56a"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_e12afdedf65b": {
      "addresses": {
        "LoD/PD2": "0x6F9B135B"
      },
      "rvas": {
        "LoD/PD2": "0x135B"
      },
      "sizes": {
        "LoD/PD2": 208
      },
      "method": "MNE",
      "index": "MNE:e12afdedf65b4f2d4ddeab4188a67460",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e12afdedf65b4f2d4ddeab4188a67460",
        "CFG": "d4f05d4722270444fef4e59db99cf596",
        "PRO": "e8b9c98ae41cc715d5b88a982c971262"
      },
      "display_name": "MNE_e12afdedf65b4f2d",
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e12afdedf65b4f2d4ddeab4188a67460"
      }
    },
    "D2sound_MNE_dd1410dc737c": {
      "addresses": {
        "LoD/PD2": "0x6F9B143F"
      },
      "rvas": {
        "LoD/PD2": "0x143F"
      },
      "sizes": {
        "LoD/PD2": 51
      },
      "name": "__amsg_exit",
      "signature": "void __amsg_exit(int nErrorMsgNum)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void __amsg_exit(int nErrorMsgNum)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:dd1410dc737c66ed6127a2f60f9bdf3c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "dd1410dc737c66ed6127a2f60f9bdf3c",
        "CFG": "bfa22c3fd387f22c29ee41d99ac17a74",
        "PRO": "86f1384b00925095d6ea62158c91779e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "dd1410dc737c66ed6127a2f60f9bdf3c"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_921d14ea2db8": {
      "addresses": {
        "LoD/PD2": "0x6F9B1472"
      },
      "rvas": {
        "LoD/PD2": "0x1472"
      },
      "sizes": {
        "LoD/PD2": 73
      },
      "name": "__mtinitlocks",
      "signature": "int __mtinitlocks(void)",
      "calling_convention": "__cdecl",
      "comment": "Initialize multi-threading critical section locks for Visual Studio 2003 Runtime\n\nAlgorithm:\n1. Initialize loop index to zero and set pointer to critical section data pool\n2. Iterate through 36 (0x24) lock slots checking activation status\n3. For each active slot (flag value == 1):\n   a. Assign current critical section data pointer to lock slot\n   b. Advance pointer by 24 (0x18) bytes to next critical section structure\n   c. Initialize critical section with 4000 spin count using CRT helper\n   d. If initialization fails, clear the lock slot pointer and return failure\n4. Continue to next slot index until all slots processed\n5. Return success (1) if all active locks initialized successfully\n\nParameters:\nNone (void function)\n\nReturns:\nint - Success status\n  1: All required locks initialized successfully\n  0: Critical section initialization failed for at least one lock\n\nSpecial Cases:\nOnly slots marked with flag value 1 are initialized\nUninitialized slots remain NULL in the pointer array\nFailure in any single lock initialization causes immediate function abort\n\nMagic Numbers Reference:\n0x24 (36 decimal): Total number of available lock slots\n0x18 (24 decimal): Size of each critical section structure in bytes  \n4000: Spin count parameter for critical section initialization\n1: Active slot flag indicating lock should be initialized\n0: Inactive slot flag or failed initialization marker\n\nStructure Layout:\nLock Management Arrays (parallel arrays indexed by slot number):\n- Flag Array (DAT_6f9c503c): 4-byte flags indicating which slots need locks\n- Pointer Array (DAT_6f9c5038): 4-byte pointers to allocated critical section data\n- Critical Section Pool (DAT_6f9c6060): Pre-allocated pool of 24-byte structures\n\nError Handling:\nCritical section initialization failure immediately clears failed slot pointer\nFunction returns 0 on first failure, abandoning remaining unprocessed slots\nNo cleanup of previously successful initializations on partial failure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:921d14ea2db8ace7085d489017738fb1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "921d14ea2db8ace7085d489017738fb1",
        "CFG": "dedcacb5022ec3081bf0e8026ad6b099",
        "PRO": "a2e3dac06aace346c193a595e3fce584"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "921d14ea2db8ace7085d489017738fb1"
      }
    },
    "D2sound_MNE_3d673ff0fb62": {
      "addresses": {
        "LoD/PD2": "0x6F9B14BB"
      },
      "rvas": {
        "LoD/PD2": "0x14BB"
      },
      "sizes": {
        "LoD/PD2": 85
      },
      "name": "__mtdeletelocks",
      "signature": "void __mtdeletelocks(void)",
      "calling_convention": "__cdecl",
      "comment": "Cleanup multithreaded critical section locks during library termination\n\nAlgorithm:\n1. Initialize pointer to lock table at 0x6f9c5038\n2. First loop: Delete and free dynamic critical sections\n   - Iterate through lock table entries (8 bytes each)\n   - Check if critical section pointer is non-null\n   - Check if static flag (offset +4) is 0 (dynamic lock)\n   - Call DeleteCriticalSection() to cleanup OS resources\n   - Call _free() to release allocated memory\n   - Clear the pointer to prevent double-free\n   - Advance to next entry (+8 bytes)\n   - Continue until reaching end at 0x6f9c5158\n3. Reset pointer to beginning of lock table\n4. Second loop: Delete static critical sections (no memory free)\n   - Iterate through lock table entries again\n   - Check if critical section pointer is non-null\n   - Check if static flag (offset +4) is 1 (static lock)\n   - Call DeleteCriticalSection() to cleanup OS resources\n   - Do NOT call _free() since static locks are not heap-allocated\n   - Advance to next entry (+8 bytes)\n   - Continue until reaching end at 0x6f9c5158\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nLock table spans from 0x6f9c5038 to 0x6f9c5158 (288 bytes = 36 entries)\nEach entry is 8 bytes: [LPCRITICAL_SECTION ptr][uint static_flag]\nStatic flag: 0 = dynamic (heap allocated), 1 = static (global/stack)\nTwo-phase deletion ensures proper cleanup order\n\nMagic Numbers Reference:\n0x6f9c5038 - Start of global lock table\n0x6f9c5158 - End of global lock table (exclusive)\n0x00000001 - Static lock flag value\n0x00000000 - Dynamic lock flag value\n\nStructure Layout:\nLock Table Entry (8 bytes):\nOffset  Size  Field Name         Type               Description\n------  ----  -----------------  -----------------  -----------\n0x00    4     pCriticalSection   LPCRITICAL_SECTION Pointer to critical section\n0x04    4     dwStaticFlag       uint               0=dynamic, 1=static",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3d673ff0fb622876ea58c1a43b2af6a0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3d673ff0fb622876ea58c1a43b2af6a0",
        "CFG": "5aebfc50763de5123835153a8b5de875",
        "PRO": "606ba88400b742e38bc653f2b87a9d2a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3d673ff0fb622876ea58c1a43b2af6a0"
      }
    },
    "D2sound_MNE_e83d10405144": {
      "addresses": {
        "LoD/PD2": "0x6F9B1510"
      },
      "rvas": {
        "LoD/PD2": "0x1510"
      },
      "sizes": {
        "LoD/PD2": 21
      },
      "name": "ReleaseSynchronizationLock",
      "signature": "void ReleaseSynchronizationLock(int lockIndex)",
      "calling_convention": "__cdecl",
      "comment": "Releases a synchronization lock from the global critical section array.\n\nAlgorithm:\n1. Retrieve the lock index parameter from stack [EBP + 0x8]\n2. Calculate the critical section pointer by multiplying index by 8 and adding base address\n3. Push the critical section pointer onto stack\n4. Call LeaveCriticalSection Windows API to release the lock\n5. Return to caller\n\nParameters:\n- lockIndex (int): Index into the critical section array (DAT_6f9c5038), determines which lock to release\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- The critical section array uses 8-byte stride per entry (2 dwords)\n- LeaveCriticalSection is called via function pointer at 0x6f9bf120\n- Multiple callers suggest this function is part of multi-threaded synchronization\n\nData Layout:\nDAT_6f9c5038 is a global array of CRITICAL_SECTION structures, each 8 bytes, indexed by lockIndex parameter",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e83d104051445238b4510431aa98563d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e83d104051445238b4510431aa98563d",
        "CFG": null,
        "PRO": "6c35b63a3f2578184197730d3fe45557"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e83d104051445238b4510431aa98563d"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_a51a9a5e7ceb": {
      "addresses": {
        "LoD/PD2": "0x6F9B1525"
      },
      "rvas": {
        "LoD/PD2": "0x1525"
      },
      "sizes": {
        "LoD/PD2": 151
      },
      "name": "__mtinitlocknum",
      "signature": "int __mtinitlocknum(int _LockNum)",
      "calling_convention": "__cdecl",
      "comment": "Initialize multithreading lock number with critical section allocation and thread-safe assignment.\n\nAlgorithm:\n1. Calculate lock table entry pointer (DAT_6f9c5038 + nLockNum * 2)\n2. Check if lock already initialized (*lockptr == 0)\n3. Allocate critical section memory (24 bytes = 0x18)\n4. Handle allocation failure by setting errno to ENOMEM (0x0c) and returning 0\n5. Acquire global lock #10 for thread safety during initialization\n6. Double-check lock initialization to prevent race conditions\n7. Initialize critical section with spin count 4000 using ___crtInitCritSecAndSpinCount\n8. Handle initialization failure by freeing memory, setting errno, unwinding SEH, returning 0\n9. Atomically assign critical section pointer to lock table entry\n10. Free redundant memory if another thread initialized between checks\n11. Release global lock and return success (1)\n\nParameters:\nnLockNum (int): Lock number index into global lock table (0-based)\n\nReturns:\n1: Success - Lock initialized or already exists\n0: Failure - Memory allocation or critical section initialization failed\n\nSpecial Cases:\nLock table located at DAT_6f9c5038, 8-byte entries (pointer + flags)\nSpin count 4000 optimized for moderate contention\nDouble-checked locking prevents race conditions during initialization\nSEH frame protects against exceptions during cleanup\n\nMagic Numbers Reference:\n0x18 (24): Size of CRITICAL_SECTION structure\n0x0c (12): ENOMEM errno constant  \n4000: Spin count for critical section initialization\n10: Global lock number for initialization protection\n\nError Handling:\nMemory allocation failure: Set errno=ENOMEM, return 0\nCritical section init failure: Free memory, set errno=ENOMEM, unwind SEH, return 0\nException during cleanup: SEH frame handles unwinding\n\nVariable Type Notes:\nlocal_8 (pSehNode): SEH exception list pointer (void *)\nlocal_14 (abSehFrame): SEH frame structure data (byte[8])",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a51a9a5e7ceb2fab96b937dc9f784c13",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a51a9a5e7ceb2fab96b937dc9f784c13",
        "CFG": "1b97c4c9ebb5e5f377a4d61d4467ef57",
        "PRO": "4f3d2ef19499efedf4d63ad6343b54a8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a51a9a5e7ceb2fab96b937dc9f784c13"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B15BC": {
      "addresses": {
        "LoD/PD2": "0x6F9B15BC"
      },
      "rvas": {
        "LoD/PD2": "0x15BC"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseMTLock",
      "signature": "void ReleaseMTLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Release the multi-threaded initialization lock (lock #10).\n\nThis is a wrapper function that releases synchronization lock 10, which is used\nto protect multi-threaded initialization of critical sections in the Visual C++\nruntime library. Called during the initialization process to unlock resources\nafter critical section setup is complete.\n\nAlgorithm:\n1. Push argument 10 (lock number) onto stack\n2. Call ReleaseSynchronizationLock to release the lock\n3. Clean up stack with POP ECX (fastcall return)\n4. Return to caller\n\nReturns:\nvoid - No return value, performs cleanup only\n\nSpecial Cases:\n- Lock #10 is a reserved lock for multi-threaded initialization\n- Uses __stdcall calling convention with implied return value cleanup\n- Part of Visual C++ 2003 runtime initialization sequence",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "180d0dbb009b4d1e2113d2477fcba925"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_MNE_a62c5e213216": {
      "addresses": {
        "LoD/PD2": "0x6F9B15C5"
      },
      "rvas": {
        "LoD/PD2": "0x15C5"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "__lock",
      "signature": "void __lock(int _File)",
      "calling_convention": "__cdecl",
      "comment": "Acquires a lock for the specified file handle by entering a critical section\n\nAlgorithm:\n1. Check if critical section for file handle is initialized (table[file*2] != 0)\n2. If not initialized, call __mtinitlocknum to initialize the critical section\n3. If initialization fails, call __amsg_exit with error code 0x11 (out of memory)\n4. Enter the critical section using EnterCriticalSection API\n\nParameters:\n- _File: Integer file handle/lock ID for lock table indexing\n\nReturns:\n- void: Function does not return a value (terminates process on error)\n\nSpecial Cases:\n- If lock initialization fails, process terminates with error code 0x11\n- Uses file handle as index into global critical section table\n- Critical sections are stored at 8-byte intervals (file*2) in lock table\n\nMagic Numbers Reference:\n- 0x11 (17): Out of memory error code passed to __amsg_exit\n- 2: Stride multiplier for critical section table indexing (8 bytes per CRITICAL_SECTION)\n\nError Handling:\n- Initialization failure: Terminates process via __amsg_exit(0x11)\n- No error checking for EnterCriticalSection - assumes success\n\nStructure Layout:\nGlobal Lock Table at DAT_6f9c5038:\nOffset   Size  Field Name         Type              Description\n0x00     8     CriticalSection[0] CRITICAL_SECTION  Lock for file handle 0\n0x08     8     CriticalSection[1] CRITICAL_SECTION  Lock for file handle 1\n...      8     CriticalSection[N] CRITICAL_SECTION  Lock for file handle N",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a62c5e213216063061d4d1c8c7db89e8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a62c5e213216063061d4d1c8c7db89e8",
        "CFG": "6c3b0aa07951c5e00ecf5c0f67c56cb3",
        "PRO": "ec1d8a845f40a9bea04792c0754871af"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a62c5e213216063061d4d1c8c7db89e8"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_7a09c5a73235": {
      "addresses": {
        "LoD/PD2": "0x6F9B15F6"
      },
      "rvas": {
        "LoD/PD2": "0x15F6"
      },
      "sizes": {
        "LoD/PD2": 128
      },
      "name": "__onexit_lk",
      "signature": "void __onexit_lk(int func)",
      "calling_convention": "__stdcall",
      "comment": "Adds function pointer to onexit handler table with automatic memory reallocation.\n\nAlgorithm:\n1. Get current size of onexit table using __msize\n2. Calculate space needed for new entry (current end + 4 bytes - table base)\n3. If table needs expansion, calculate growth size (0x800 bytes or current size, whichever smaller)\n4. Attempt reallocation with larger growth size first using ReallocateMemoryWithHeapBackoff\n5. If large reallocation fails, attempt minimal reallocation (+0x10 bytes)\n6. If both reallocations fail, return without adding entry\n7. Update table pointers after successful reallocation\n8. Store function pointer at current table end\n9. Advance table end pointer to next slot\n\nParameters:\nIMPLICIT EDI: Function pointer to add to onexit table (_onexit_t callback)\n\nReturns:\nvoid (no explicit return value, success indicated by function being added to table)\n\nSpecial Cases:\nMemory allocation failures result in silent failure without adding function to table\nTable base pointer (g_pOnexitTable) and end pointer (g_pOnexitTableEnd) updated atomically\nGrowth strategy: large increment (0x800) preferred, minimal increment (0x10) as fallback\n\nMagic Numbers Reference:\n0x800 (2048): Preferred growth increment in bytes for table expansion\n0x10 (16): Minimal growth increment when large growth fails\n4: Size in bytes of function pointer entry (_onexit_t)\n\nStructure Layout:\nOnexit Table Structure:\nOffset | Size | Field Name | Type | Description\n-------|------|------------|------|-------------\n0x0    | 4    | Base       | void*| Start of allocated table memory (g_pOnexitTable)\nN*4    | 4    | Entry      | _onexit_t | Function pointer at index N\nEnd    | 4    | Current    | void*| Current end position (g_pOnexitTableEnd)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7a09c5a73235698eb35bf1fa40abce3a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7a09c5a73235698eb35bf1fa40abce3a",
        "CFG": "4c747082602c7f76e5a0b6b31e0c33ed",
        "PRO": "0336ee3eab5ea5d3774cdae8723df292"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7a09c5a73235698eb35bf1fa40abce3a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_266baaaf79f2": {
      "addresses": {
        "LoD/PD2": "0x6F9B1676"
      },
      "rvas": {
        "LoD/PD2": "0x1676"
      },
      "sizes": {
        "LoD/PD2": 40
      },
      "name": "___onexitinit",
      "signature": "int ___onexitinit(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes the C runtime exit handler system by allocating and setting up internal data structures.\n\nAlgorithm:\n1. Allocate 128 bytes (0x80) for the exit handler table using malloc()\n2. Check if allocation succeeded - if NULL, return error code 0x18 (24)\n3. Initialize the first entry of the allocated table to 0\n4. Set both DAT_6f9c6990 (table pointer) and DAT_6f9c698c (current pointer) to the allocated memory\n5. Return 0 to indicate successful initialization\n\nParameters:\n    (none)\n\nReturns:\n    0 - Success: Exit handler system initialized successfully\n    0x18 (24) - Error: Memory allocation failed, insufficient memory\n\nSpecial Cases:\n    - Function allocates exactly 128 bytes for the exit handler table\n    - Both global pointers are set to the same allocated memory address\n    - First table entry is explicitly zeroed to mark end of valid entries\n\nMagic Numbers Reference:\n    0x80 (128) - Size of exit handler table in bytes\n    0x18 (24) - Error code for memory allocation failure\n    0 - Success return code and table terminator value\n\nError Handling:\n    - malloc() failure returns error code 0x18 immediately\n    - No cleanup needed on failure since allocation hasn't occurred\n    - Success path always returns 0\n\nStructure Layout:\n    Exit Handler Table (128 bytes allocated):\n    Offset  Size  Field Name       Type      Description\n    +0x00   4     handler_ptr      void*     First exit handler function pointer\n    +0x04   4     next_entry       void*     Next handler or NULL terminator\n    ...     ...   ...             ...       Additional handler entries\n    +0x7C   4     last_entry       void*     Final entry in 128-byte table",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:266baaaf79f230c6a6856a4a53b42d70",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "266baaaf79f230c6a6856a4a53b42d70",
        "CFG": "074729d34b2ceac5cf54de1f1ab60b22",
        "PRO": "f748d84f2874060db8920051e88f79cc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "266baaaf79f230c6a6856a4a53b42d70"
      }
    },
    "D2sound_MNE_5d2d40297dfe": {
      "addresses": {
        "LoD/PD2": "0x6F9B169E"
      },
      "rvas": {
        "LoD/PD2": "0x169E"
      },
      "sizes": {
        "LoD/PD2": 50
      },
      "name": "__onexit",
      "signature": "_onexit_t __onexit(_onexit_t _Func)",
      "calling_convention": "__cdecl",
      "comment": "Registers a function to be called when the program exits normally.\n\nAlgorithm:\n\n1. Acquire thread safety lock via AcquireLockOnExit()\n2. Call __onexit_lk() with function pointer parameter to register exit handler\n3. Release thread safety lock via ReleaseLockOnExit()  \n4. Return the exit function pointer if registration succeeded\n\nParameters:\n\n_Func (_onexit_t): Function pointer to register for exit-time execution\n\nReturns:\n\n_onexit_t: The function pointer if registration succeeded, NULL if failed\n\nSpecial Cases:\n\n- Thread-safe operation using lock acquisition/release pattern\n- Uses SEH (Structured Exception Handling) frame for error handling\n- Delegates actual registration to __onexit_lk for lock-protected execution\n\nError Handling:\n\n- Lock failure: Function may fail silently if lock acquisition fails\n- Registration failure: Returns NULL if __onexit_lk cannot register function\n- SEH protection: Exception handling ensures locks are properly released",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5d2d40297dfe2be53beef9d63f51ef80",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5d2d40297dfe2be53beef9d63f51ef80",
        "CFG": "37df6770e2b24dae8705aa111e96e769",
        "PRO": "2efc59fcf96ce5e5baea8a345e6dd6d7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5d2d40297dfe2be53beef9d63f51ef80"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_e7313d19d2f1": {
      "addresses": {
        "LoD/PD2": "0x6F9B16D0"
      },
      "rvas": {
        "LoD/PD2": "0x16D0"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "ReleaseLockOnExit",
      "signature": "void ReleaseLockOnExit(void)",
      "calling_convention": "__stdcall",
      "comment": "Exit handler that safely releases critical section lock during program termination.\n\nAlgorithm:\n1. Call ReleaseCriticalSectionLock8() to release the critical section lock\n2. Return to caller (exit handler cleanup)\n\nParameters:\n(none)\n\nReturns:\nvoid - No return value\n\nContext:\nThis function is registered as an exit handler via __onexit and executes\nwhen the program terminates. It ensures that critical section locks are\nproperly released during shutdown to prevent resource leaks and allow\nproper cleanup of protected regions.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e7313d19d2f1b94221ec63dffd5562f1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e7313d19d2f1b94221ec63dffd5562f1",
        "CFG": null,
        "PRO": "befc6114fbdbedfb001aaf0cf99330b2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e7313d19d2f1b94221ec63dffd5562f1"
      }
    },
    "D2sound_MNE_2544af1d7a07": {
      "addresses": {
        "LoD/PD2": "0x6F9B16D6"
      },
      "rvas": {
        "LoD/PD2": "0x16D6"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "_atexit",
      "signature": "int _atexit(_func_4879 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Registers a function to be called when the program terminates normally.\n\nAlgorithm:\n1. Call __onexit with the function pointer parameter cast to _onexit_t\n2. Check if __onexit returned a non-NULL pointer  \n3. Convert boolean result to standard C return value (0 for success, -1 for failure)\n\nParameters:\n  param_1 (_func_4879 *): Function pointer to be registered for execution at exit\n                          Function should take no parameters and return void\n\nReturns:\n  0: Success - function was successfully registered\n -1: Failure - function could not be registered (usually due to memory allocation failure)\n\nSpecial Cases:\n  - NULL function pointer is handled by __onexit\n  - Memory allocation failure in __onexit returns NULL, causing this function to return -1\n  - Function pointers are stored in reverse order of registration (LIFO execution)\n\nMagic Numbers Reference:\n  0x0: NULL pointer constant used for comparison with __onexit return value\n\nError Handling:\n  - __onexit failure (NULL return) is converted to -1 return value\n  - No direct error handling - relies on __onexit for validation and storage",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2544af1d7a0712444106eb929de8e62d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2544af1d7a0712444106eb929de8e62d",
        "CFG": null,
        "PRO": "ef9a4571e7167f6ca37ef06a54d91959"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2544af1d7a0712444106eb929de8e62d"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_9882f49b4616": {
      "addresses": {
        "LoD/PD2": "0x6F9B16E8"
      },
      "rvas": {
        "LoD/PD2": "0x16E8"
      },
      "sizes": {
        "LoD/PD2": 61
      },
      "name": "__RTC_Initialize",
      "signature": "void __RTC_Initialize(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes runtime check functions by iterating through function pointer table.\n\nAlgorithm:\n1. Initialize pointer to start of runtime check function table (DAT_6f9c45ac)\n2. Loop through each entry in the function pointer table\n3. Check if current function pointer is non-null\n4. If non-null, call the function through the pointer\n5. Advance to next entry in table\n6. Continue until reaching end of table\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Null function pointers are skipped without error\n- Function iterates through table at DAT_6f9c45ac\n\nStructure Layout:\n- Runtime check function table: Array of void (*)(void) function pointers\n- Each entry: 4 bytes (function pointer)\n- Table terminated when loop condition fails",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9882f49b46164551a852d0e5558c3763",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9882f49b46164551a852d0e5558c3763",
        "CFG": "8c955c77011f408ad9ffc78e365640e4",
        "PRO": "b6acc7381ea0fec5aba8bcbf14261324"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9882f49b46164551a852d0e5558c3763"
      }
    },
    "D2sound_MNE_aef9935d5818": {
      "addresses": {
        "LoD/PD2": "0x6F9B1770"
      },
      "rvas": {
        "LoD/PD2": "0x1770"
      },
      "sizes": {
        "LoD/PD2": 59
      },
      "name": "__SEH_prolog",
      "signature": "void __SEH_prolog(void * pExceptionHandler, int nFrameSize)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void __SEH_prolog(void * pExceptionHandler, int nFrameSize)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:aef9935d5818b16bbad0952f5da65380",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "aef9935d5818b16bbad0952f5da65380",
        "CFG": null,
        "PRO": "afc8e9a8a8b4db3c1ee2d10b72086d38"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "aef9935d5818b16bbad0952f5da65380"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_bb6caf8fa91f": {
      "addresses": {
        "LoD/PD2": "0x6F9B17AB"
      },
      "rvas": {
        "LoD/PD2": "0x17AB"
      },
      "sizes": {
        "LoD/PD2": 17
      },
      "name": "__SEH_epilog",
      "signature": "void __SEH_epilog(void)",
      "calling_convention": "__stdcall",
      "comment": "Restores the Structured Exception Handling (SEH) chain during function epilog processing.\n\nAlgorithm:\n\n1. Restore previous exception registration record from stack frame\n2. Update ExceptionList global with previous SEH chain pointer\n3. Restore return address to frame base pointer location\n4. Return control to caller for normal stack cleanup\n\nParameters:\n\nIMPLICIT EBP: Frame pointer to current stack frame with SEH data\n\nReturns:\n\nvoid: No return value, modifies global ExceptionList state\n\nSpecial Cases:\n\nThis function is automatically inserted by Visual Studio compiler for functions using SEH (__try/__except blocks). It ensures proper cleanup of the exception chain when functions exit normally or through exception unwinding.\n\nMagic Numbers Reference:\n\n0x-4 (EBP-4): Offset to previous exception registration record pointer\n0x0 (EBP+0): Location where return address is restored\n\nError Handling:\n\nNo explicit error handling - this is low-level runtime support that must always succeed. Failure would indicate stack corruption or compromised exception handling state.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bb6caf8fa91f28d8c9b4f7822655fe6b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bb6caf8fa91f28d8c9b4f7822655fe6b",
        "CFG": null,
        "PRO": "b9341e7a9c7fb15c0fd3b51f756cce6f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bb6caf8fa91f28d8c9b4f7822655fe6b"
      }
    },
    "D2sound_MNE_89d1b6190541": {
      "addresses": {
        "LoD/PD2": "0x6F9B18AA"
      },
      "rvas": {
        "LoD/PD2": "0x18AA"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "InvokeLocalUnwindHandler",
      "signature": "void InvokeLocalUnwindHandler(void * pExceptionFrame)",
      "calling_convention": "__stdcall",
      "comment": "Invokes the C++ local unwind handler for exception cleanup during stack unwinding.\n\nThis function is part of the C++ exception handling runtime system. It serves as a bridge between the exception dispatcher and the actual unwind handler, extracting handler parameters from a structured exception frame and passing them to __local_unwind2 for cleanup execution.\n\nAlgorithm:\n1. Cast exception frame pointer to int for address arithmetic\n2. Extract handler function pointer from exception frame at offset +0x18 \n3. Extract handler state value from exception frame at offset +0x1c\n4. Invoke __local_unwind2 with both extracted parameters\n5. Return to caller (no cleanup needed)\n\nParameters:\n- pExceptionFrame (void *): Pointer to C++ exception frame structure containing handler parameters\n  - Offset +0x18 (4 bytes): Handler function pointer - void (*)(int)\n  - Offset +0x1c (4 bytes): Handler state value - int\n\nReturns:\n- void (no return value)\n\nSpecial Cases:\n- __stdcall calling convention: callee cleans 4-byte parameter from stack\n- Function typically called during exception unwinding process  \n- Exception frame structure is internal to MSVC C++ runtime\n- Offsets 0x18 and 0x1c are fixed by runtime convention\n- No error checking - assumes valid exception frame pointer\n\nMagic Numbers Reference:\n- 0x18 (24): Offset to handler function pointer field\n- 0x1c (28): Offset to handler state value field\n\nError Handling:\n- No validation of pExceptionFrame pointer\n- Assumes exception frame structure is properly initialized\n- Relies on __local_unwind2 for actual error handling",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:89d1b619054116ad559c7c543db397fd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "89d1b619054116ad559c7c543db397fd",
        "CFG": null,
        "PRO": "204649768cb6aa7c9bb671be8e047b74"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "89d1b619054116ad559c7c543db397fd"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_03ce6e557a60": {
      "addresses": {
        "LoD/PD2": "0x6F9B18C5"
      },
      "rvas": {
        "LoD/PD2": "0x18C5"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "AllocateThreadLocalStorageSlot",
      "signature": "uint AllocateThreadLocalStorageSlot(void)",
      "calling_convention": "__stdcall",
      "comment": "Allocates a thread-local storage (TLS) slot for the runtime.\n\nThis function is called during multithreading initialization (__mtinit) to reserve\na TLS slot using the Windows TlsAlloc API. The allocated slot index is returned\nfor later use in thread-local variable access.\n\nAlgorithm:\n1. Call TlsAlloc() Windows API function to allocate a new TLS slot\n2. Store the returned TLS slot index in local variable\n3. Return the TLS slot index to caller\n\nParameters:\n(none)\n\nReturns:\nTLS slot index as uint (0-based index, TLS_OUT_OF_INDEXES on failure)\n- Success: Valid TLS slot index (0 to maximum TLS slots - 1)  \n- Failure: TLS_OUT_OF_INDEXES (0xFFFFFFFF) if no slots available\n\nSpecial Cases:\n- TlsAlloc failure returns TLS_OUT_OF_INDEXES when system TLS limit exceeded\n- Windows guarantees minimum of 64 TLS slots per process\n- Calling convention: __stdcall (callee cleans stack)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:03ce6e557a60cad10c5f167fdc7f4b70",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "03ce6e557a60cad10c5f167fdc7f4b70",
        "CFG": null,
        "PRO": "d049b86b29eab418cb2f1b06ba813dfd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "03ce6e557a60cad10c5f167fdc7f4b70"
      }
    },
    "D2sound_MNE_aff5ecc93302": {
      "addresses": {
        "LoD/PD2": "0x6F9B18CE"
      },
      "rvas": {
        "LoD/PD2": "0x18CE"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "__mtterm",
      "signature": "void __mtterm(void)",
      "calling_convention": "__cdecl",
      "comment": "Terminates multithreading support and cleans up threading resources.\n\nAlgorithm:\n1. Check if thread handle (DAT_6f9c5158) is valid (!= -1)\n2. If valid, call cleanup function pointer (*_DAT_6f9c61bc) with the handle\n3. Set thread handle to -1 to mark as terminated\n4. Call __mtdeletelocks() to cleanup thread synchronization objects\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- If DAT_6f9c5158 is already -1, no cleanup function is called\n- Always calls __mtdeletelocks() regardless of handle state\n- Thread handle is unconditionally set to -1 after cleanup\n\nMagic Numbers Reference:\n0xFFFFFFFF (-1) - Invalid/terminated thread handle marker\n\nError Handling:\nNo explicit error handling - assumes cleanup function handles failures internally\n\nGlobal Variables:\nDAT_6f9c5158 - Thread handle/identifier (should be renamed to g_hMultithreadHandle)\n_DAT_6f9c61bc - Function pointer to thread cleanup routine (should be renamed to g_pfnThreadCleanup)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:aff5ecc933020ea9f6660ca70cb9d16a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "aff5ecc933020ea9f6660ca70cb9d16a",
        "CFG": "e4d929dcade813bcfed0f23f20c25712",
        "PRO": "8fd7458c5d15db1d815a70cadba916d7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "aff5ecc933020ea9f6660ca70cb9d16a"
      }
    },
    "D2sound_MNE_a1900c49d3b8": {
      "addresses": {
        "LoD/PD2": "0x6F9B18EB"
      },
      "rvas": {
        "LoD/PD2": "0x18EB"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "__initptd",
      "signature": "void __initptd(_ptiddata _Ptd, pthreadlocinfo _Locale)",
      "calling_convention": "__cdecl",
      "comment": "Initialize per-thread data structure with CRT initialization values\n\nAlgorithm:\n1. Set initialization address pointer in thread data structure\n2. Initialize random number seed to default value of 1\n3. Return to caller\n\nParameters:\n_Ptd - Pointer to per-thread data structure to initialize\n_Locale - Thread locale information (unused in this function)\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nThe _Locale parameter is not used in this function but is part of the standard\nsignature for per-thread initialization routines in MSVC runtime.\n\nMagic Numbers Reference:\n0x01 - Default seed value for random number generator (_holdrand field)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a1900c49d3b847e69ff3bf21a94518de",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a1900c49d3b847e69ff3bf21a94518de",
        "CFG": null,
        "PRO": "bcf63962c44d486b13b5a07284c2c86b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a1900c49d3b847e69ff3bf21a94518de"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_04f1e6f173a4": {
      "addresses": {
        "LoD/PD2": "0x6F9B18FE"
      },
      "rvas": {
        "LoD/PD2": "0x18FE"
      },
      "sizes": {
        "LoD/PD2": 113
      },
      "name": "__getptd",
      "signature": "_ptiddata __getptd(void)",
      "calling_convention": "__cdecl",
      "comment": "Get or initialize per-thread data structure for the current thread\n\nAlgorithm:\n\n1. Preserve current error state by saving GetLastError() result\n2. Attempt to retrieve existing per-thread data from Thread Local Storage (TLS)\n   using global function pointer DAT_6f9c61b4 with TLS index DAT_6f9c5158\n3. If per-thread data already exists, jump to step 8\n4. Allocate new per-thread data structure (140 bytes, 0x8c)\n5. If allocation fails, terminate with error code 0x10\n6. Store newly allocated structure in TLS using global function pointer DAT_6f9c61b8\n7. If TLS storage fails, terminate with error code 0x10\n8. Initialize per-thread data fields:\n   - _initaddr = pointer to global initialization data (DAT_6f9c5190)\n   - _holdrand = 1 (initial random seed)\n   - _thandle = 0xffffffff (pseudo handle for current thread)  \n   - _tid = current thread ID from GetCurrentThreadId()\n9. Restore original error state using SetLastError()\n10. Return pointer to per-thread data structure\n\nParameters:\nNone\n\nReturns:\n_ptiddata - Pointer to per-thread data structure for current thread\nNULL - Never returned (function terminates process on failure)\n\nSpecial Cases:\nError Code 0x10 (16) - Memory allocation or TLS storage failure causes process termination\nThread Safety - Function is thread-safe, each thread gets its own data structure\n\nMagic Numbers Reference:\n0x8c (140) - Size of _ptiddata structure in bytes\n0x10 (16) - Error code for memory/TLS failure, triggers __amsg_exit\n0xffffffff (-1) - Pseudo handle representing current thread\n1 - Initial value for random number generator seed\n\nError Handling:\nMemory allocation failure - Process terminates via __amsg_exit(0x10)\nTLS storage failure - Process terminates via __amsg_exit(0x10) \nError state preservation - Original GetLastError() value restored before return\n\nStructure Layout:\n_ptiddata structure (140 bytes total):\nOffset  Size  Field Name  Type     Description\n------  ----  ----------  ----     -----------\n+0x00   4     _initaddr   void*    Pointer to initialization data\n+0x04   4     _holdrand   int      Random number generator seed\n+0x08   4     _thandle    HANDLE   Thread handle (-1 for current thread)\n+0x0C   4     _tid        DWORD    Thread identifier from GetCurrentThreadId()\n...     ...   ...         ...      (Additional fields in full structure)\n\nGlobal References:\nDAT_6f9c61b4 - Function pointer for TLS get operation (typically TlsGetValue)\nDAT_6f9c5158 - TLS index/slot number for per-thread data storage\nDAT_6f9c61b8 - Function pointer for TLS set operation (typically TlsSetValue) \nDAT_6f9c5190 - Pointer to global initialization data for _initaddr field",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:04f1e6f173a4f00f5247db68bf412e5b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "04f1e6f173a4f00f5247db68bf412e5b",
        "CFG": "0c8662126fe6ebdb099c385715f42fe6",
        "PRO": "aa34a27af0d21f4d0f7ac6a9bb19f753"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "04f1e6f173a4f00f5247db68bf412e5b"
      }
    },
    "D2sound_MNE_adafedc33ce1": {
      "addresses": {
        "LoD/PD2": "0x6F9B196F"
      },
      "rvas": {
        "LoD/PD2": "0x196F"
      },
      "sizes": {
        "LoD/PD2": 301
      },
      "name": "__freefls@4",
      "signature": "void __freefls@4(void * pFiberLocalStorage)",
      "calling_convention": "__stdcall",
      "comment": "Releases and frees all memory associated with fiber-local storage structure.\n\nAlgorithm:\n1. Validate input pointer is not NULL\n2. Free memory blocks at structure offsets 0x24, 0x2c, 0x34, 0x3c, 0x44, 0x48 if non-NULL\n3. Free memory at offset 0x54 if it differs from default data location (DAT_6f9c5190)\n4. Acquire lock 0xD (lock ID 13) for thread reference counting\n5. Decrement reference count for thread info pointer at offset 0x60\n6. If reference count reaches zero and pointer differs from default, free thread info\n7. Release lock 13 on thread exit\n8. Acquire lock 0xC (lock ID 12) for locale information cleanup\n9. Process locale information structure at offset 100 (0x64):\n   - Decrement main reference count\n   - Decrement reference counts at offsets 0xB, 0xC, 0xD, 0x10 if non-NULL\n   - Decrement reference count at offset 0xB4 within structure at offset 0x13\n   - Free locale info if reference count reaches zero and not default instances\n10. Release free list lock\n11. Free the main fiber-local storage structure\n\nParameters:\npFiberLocalStorage - Pointer to fiber-local storage structure to be freed\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- If input pointer is NULL, function returns immediately without operation\n- Reference counting prevents premature deletion of shared structures\n- Default instances at specific addresses are never freed (DAT_6f9c5190, PTR_DAT_6f9c5484, DAT_6f9c5430)\n- Thread-safe operation ensured through lock acquisition/release\n\nMagic Numbers Reference:\n0x24 (36) - Offset to first memory block pointer\n0x2c (44) - Offset to second memory block pointer  \n0x34 (52) - Offset to third memory block pointer\n0x3c (60) - Offset to fourth memory block pointer\n0x44 (68) - Offset to fifth memory block pointer\n0x48 (72) - Offset to sixth memory block pointer\n0x54 (84) - Offset to seventh memory block pointer\n0x60 (96) - Offset to thread info pointer\n0x64 (100) - Offset to locale information pointer\n0xB4 (180) - Offset within locale structure for reference count\n0xD (13) - Lock ID for thread reference counting\n0xC (12) - Lock ID for free list operations\n\nError Handling:\n- Null pointer checks prevent crashes on invalid input\n- Reference counting prevents use-after-free conditions\n- Structured exception handling (SEH) ensures cleanup on exceptions\n- Lock acquisition/release prevents race conditions in multi-threaded environment\n\nStructure Layout:\nOffset  Size  Field Name              Type        Description\n+0x24   4     pMemoryBlock1           void*       First allocated memory block\n+0x2C   4     pMemoryBlock2           void*       Second allocated memory block  \n+0x34   4     pMemoryBlock3           void*       Third allocated memory block\n+0x3C   4     pMemoryBlock4           void*       Fourth allocated memory block\n+0x44   4     pMemoryBlock5           void*       Fifth allocated memory block\n+0x48   4     pMemoryBlock6           void*       Sixth allocated memory block\n+0x54   4     pMemoryBlock7           void*       Seventh allocated memory block\n+0x60   4     pThreadInfo             ThreadInfo* Thread information structure\n+0x64   4     pLocaleInfo             LocaleInfo* Locale information structure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:adafedc33ce199c85ef6d812cf9b5974",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "adafedc33ce199c85ef6d812cf9b5974",
        "CFG": "2da93e684001310322c3f0b023dc49fc",
        "PRO": "74dfdbbf9c8569982a859ac81f4da236"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "adafedc33ce199c85ef6d812cf9b5974"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B1AA1": {
      "addresses": {
        "LoD/PD2": "0x6F9B1AA1"
      },
      "rvas": {
        "LoD/PD2": "0x1AA1"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseLock13OnThreadExit",
      "signature": "void ReleaseLock13OnThreadExit(void)",
      "calling_convention": "__stdcall",
      "comment": "Thread-local storage cleanup function that releases synchronization lock 13.\n\nAlgorithm:\n1. Push lock ID 0xd (13 decimal) onto stack as parameter\n2. Call ReleaseSynchronizationLock to release the lock\n3. Pop return address and return to caller\n\nParameters:\n  None - Lock ID is hardcoded to 0xd (13)\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  Lock ID 0xd is reserved for thread-local storage cleanup operations\n  Called during __freefls@4 thread cleanup sequence\n  Part of thread termination and resource deallocation\n\nCalling Convention:\n  __stdcall - Callee cleans stack (POP ECX)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "09b6baf941ec9872d72490b42052dbec"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_ADDR_6F9B1AAD": {
      "addresses": {
        "LoD/PD2": "0x6F9B1AAD"
      },
      "rvas": {
        "LoD/PD2": "0x1AAD"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseFreeListLock",
      "signature": "void ReleaseFreeListLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the free list synchronization lock.\n\nAlgorithm:\n1. Push synchronization lock identifier (0xc) onto stack\n2. Call ReleaseSynchronizationLock to release the lock\n3. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Lock identifier 0xc is a constant value specific to free list management\n- Function uses __stdcall convention (callee cleans stack via RET instruction)\n- Called exclusively from __freefls@4 cleanup routine",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "87223806ddf292c574a8a5a56e4d769e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_MNE_c0a536e0e6da": {
      "addresses": {
        "LoD/PD2": "0x6F9B1AB6"
      },
      "rvas": {
        "LoD/PD2": "0x1AB6"
      },
      "sizes": {
        "LoD/PD2": 47
      },
      "name": "__freeptd",
      "signature": "void __freeptd(_ptiddata _Ptd)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __freeptd\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c0a536e0e6dadcb5b945a8303814ecb3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c0a536e0e6dadcb5b945a8303814ecb3",
        "CFG": "4e847b889984c71922568191fca6fba0",
        "PRO": "ecb306795c2360c8d8945ef22afcfe96"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c0a536e0e6dadcb5b945a8303814ecb3"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_STR_304d598e6d0a": {
      "addresses": {
        "LoD/PD2": "0x6F9B1AE5"
      },
      "rvas": {
        "LoD/PD2": "0x1AE5"
      },
      "sizes": {
        "LoD/PD2": 239
      },
      "name": "__mtinit",
      "signature": "int __mtinit(void)",
      "calling_convention": "__cdecl",
      "comment": "Initialize multi-threaded runtime support using Fiber Local Storage (FLS) or Thread Local Storage (TLS) fallback\n\nAlgorithm:\n\n1. Initialize lock objects by calling __mtinitlocks()\n2. If lock initialization fails, clean up with __mtterm() and return failure  \n3. Load kernel32.dll module handle to access Fiber Local Storage APIs\n4. Attempt to get FLS function pointers: FlsAlloc, FlsGetValue, FlsSetValue, FlsFree\n5. If FLS functions unavailable, fall back to TLS functions: TlsAlloc, TlsGetValue, TlsSetValue, TlsFree\n6. Allocate FLS/TLS slot using function pointer for cleanup callback __freefls_4\n7. If slot allocation fails (returns -1), clean up and return failure\n8. Allocate 140-byte (0x8c) thread-local data structure using AllocateMemoryWithRetry\n9. If memory allocation fails, clean up and return failure\n10. Store allocated structure pointer in FLS/TLS slot using SetValue function\n11. If storage fails, clean up and return failure\n12. Initialize thread-local structure fields:\n    - Offset 0x00: Current thread ID from GetCurrentThreadId()\n    - Offset 0x04: Reserved field set to 0xffffffff\n    - Offset 0x14: Flags field set to 1 (initialized state)\n    - Offset 0x54: Cleanup pointer set to address of DAT_6f9c5190\n13. Return success (1)\n\nParameters:\nNone\n\nReturns:\n1 - Successful initialization of multi-threaded runtime\n0 - Initialization failed due to lock failure, API unavailability, or memory allocation failure\n\nSpecial Cases:\nFLS API Fallback: Windows versions prior to Vista lack Fiber Local Storage APIs. Function automatically falls back to Thread Local Storage APIs for compatibility.\n\nMagic Numbers Reference:\n0x8c (140) - Size of thread-local data structure in bytes\n0xffffffff - Reserved field marker value\n0x1 - Initialized state flag\n0x54 (84) - Offset to cleanup pointer field  \n0x14 (20) - Offset to flags field\n0x4 - Offset to reserved field\n-1 - Invalid FLS/TLS slot indicator\n\nError Handling:\nLock initialization failure \u2192 calls __mtterm() cleanup, returns 0\nFLS slot allocation failure \u2192 calls __mtterm() cleanup, returns 0  \nMemory allocation failure \u2192 calls __mtterm() cleanup, returns 0\nFLS storage failure \u2192 calls __mtterm() cleanup, returns 0\n\nThread-Local Data Structure Layout:\nOffset  Size  Field Name         Type        Description\n0x00    4     dwThreadId         DWORD       Current thread identifier\n0x04    4     dwReserved         DWORD       Reserved field (0xffffffff)\n0x08    12    reserved2          DWORD[3]    Reserved space\n0x14    4     dwFlags            DWORD       Initialization state flags (1=initialized)\n0x18    60    reserved3          BYTE[60]    Reserved space  \n0x54    4     pCleanupPtr        void*       Pointer to cleanup data structure\n0x58    52    reserved4          BYTE[52]    Reserved space\nTotal: 140 bytes (0x8c)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:304d598e6d0a621c9e3544e6fb22e61e",
      "indexes": {
        "EXP": null,
        "STR": "304d598e6d0a621c9e3544e6fb22e61e",
        "API": null,
        "MNE": "bcce8ed29924bac295ff5cc0516a2419",
        "CFG": "47193e95d9e3342a5a8c63a689eefe67",
        "PRO": "0da7e1daa5db21bdff74c967c34e6a2b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bcce8ed29924bac295ff5cc0516a2419"
      },
      "api_calls": {
        "LoD/PD2": [
          "TlsAlloc"
        ]
      }
    },
    "D2sound_MNE_d5c8453c3e2b": {
      "addresses": {
        "LoD/PD2": "0x6F9B1BD4"
      },
      "rvas": {
        "LoD/PD2": "0x1BD4"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "_free",
      "signature": "void _free(void * _Memory)",
      "calling_convention": "__cdecl",
      "comment": "Release memory block previously allocated by malloc, calloc, or realloc\n\nAlgorithm:\n1. Check if memory pointer is non-null (null pointer safety)\n2. If small block heap mode enabled (DAT_6f9c6864 == 3):\n   a. Acquire heap lock (mutex 4) for thread safety\n   b. Search small block heap for the memory block\n   c. If found in small block heap, free the block there\n   d. Release heap lock during cleanup\n   e. Return early if block was found and freed in small heap\n3. Fall back to HeapFree for large blocks or when small heap disabled\n4. Return (void function, no error reporting)\n\nParameters:\n_Memory (void *): Pointer to memory block to deallocate, null pointer safe\n\nReturns:\nvoid - No return value, errors handled silently\n\nSpecial Cases:\n- Null pointer: Function returns immediately without error\n- Invalid pointer: Undefined behavior (application crash likely)\n- Double-free: Undefined behavior (heap corruption possible)\n- Small heap mode: Uses custom small block heap manager for performance\n- Large blocks: Always freed through Windows HeapFree API\n\nMagic Numbers Reference:\n0x3 (3): Small block heap enabled mode flag\n0x4 (4): Heap lock number for thread synchronization\n\nError Handling:\n- No explicit error handling or return codes\n- Invalid pointers cause undefined behavior\n- Thread safety provided by heap locking mechanism\n\nNote: Function uses 2 stack-allocated temporary variables (local_8, local_20) optimized away by decompiler during SEH exception handling setup",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d5c8453c3e2bb4ff6f437d3d747d2c97",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d5c8453c3e2bb4ff6f437d3d747d2c97",
        "CFG": "555d704848b8e783f7d263b7ca7bd009",
        "PRO": "97d8837264e19f00c4d8b6730c74aa2c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d5c8453c3e2bb4ff6f437d3d747d2c97"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B1C27": {
      "addresses": {
        "LoD/PD2": "0x6F9B1C27"
      },
      "rvas": {
        "LoD/PD2": "0x1C27"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseLockDuringCleanup",
      "signature": "void ReleaseLockDuringCleanup(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases synchronization lock during deallocation cleanup.\n\nAlgorithm:\n1. Push lock ID (0x4) onto stack as parameter\n2. Call ReleaseSynchronizationLock to release the lock\n3. Clean up stack and return\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nThis function is called during the cleanup phase of _free deallocation\nto ensure proper synchronization lock release before memory is freed.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "ddcf581e280097cf036f0e48ae7c6e48"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_MNE_43c1542ced67": {
      "addresses": {
        "LoD/PD2": "0x6F9B1C45"
      },
      "rvas": {
        "LoD/PD2": "0x1C45"
      },
      "sizes": {
        "LoD/PD2": 203
      },
      "name": "AllocateMemoryWithRetry",
      "signature": "void * AllocateMemoryWithRetry(uint elementCount, uint elementSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates memory with overflow checking and automatic retry on failure.\n\nAlgorithm:\n1. Check if elementCount is 0 or if multiplication would overflow (elementCount * elementSize > 0xFFFFFFE0)\n2. Calculate total bytes needed: elementCount * elementSize\n3. If total bytes is 0, set minimum size to 1\n4. Check if total bytes exceeds small block heap limit (0xFFFFFFE0)\n5. If DAT_6f9c6864 == 3 (small block heap enabled):\n   a. Align requested size to 16-byte boundary by adding 15 and masking with 0xFFFFFFF0\n   b. Acquire lock via __lock(4)\n   c. Attempt allocation from small block heap via ___sbh_alloc_block()\n   d. If successful, zero-initialize memory with memset() and return pointer\n   e. Otherwise continue to step 6\n6. Attempt allocation from main heap via HeapAlloc(DAT_6f9c6860, 8, alignedBytes)\n7. If allocation fails and DAT_6f9c6338 != 0, call __callnewh() to trigger exception handler\n8. Retry allocation loop (step 6-7) until successful or exception handler returns 0\n9. Return allocated pointer or NULL if all attempts fail\n\nParameters:\n  elementCount (uint): Number of elements to allocate (multiplied by elementSize)\n  elementSize (uint): Size of each element in bytes\n\nReturns:\n  void*: Pointer to allocated memory on success, NULL on failure\n\nSpecial Cases:\n  - Magic value 0xFFFFFFE0: Overflow threshold for allocation size\n  - Magic value 0xFFFFFFF0: 16-byte alignment mask for small block heap\n  - DAT_6f9c6864 = 3: Indicates small block heap is enabled\n  - DAT_6f9c6620: Maximum allocation size for small block heap\n  - DAT_6f9c6860: Main heap handle for HeapAlloc()\n  - DAT_6f9c6338: Flag controlling exception handler retry behavior\n  - Minimum allocation size: 1 byte (to distinguish from NULL)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:43c1542ced67dd840c298e093699fef1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "43c1542ced67dd840c298e093699fef1",
        "CFG": "d59138f44100bd891d1023b7740338fc",
        "PRO": "f6d708446570358009ae4861602a4ae2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "43c1542ced67dd840c298e093699fef1"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_ADDR_6F9B1D0B": {
      "addresses": {
        "LoD/PD2": "0x6F9B1D0B"
      },
      "rvas": {
        "LoD/PD2": "0x1D0B"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseLockAfterAllocation",
      "signature": "void ReleaseLockAfterAllocation(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases synchronization lock after memory allocation completes.\n\nAlgorithm:\n1. Push lock ID (4) onto stack as function parameter\n2. Call ReleaseSynchronizationLock to release the lock\n3. Return to caller\n\nParameters:\n(None - lock ID is hardcoded as 4)\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nLock ID is hardcoded to 4, indicating a specific synchronization lock\nreserved for allocation operations. The caller\n(AllocateMemoryWithRetry) is responsible for acquiring the lock\nbefore memory allocation and calling this function to release it\nafter allocation completes.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "044a77509a7ef66c7bdd6810cdea99b8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_MNE_124a050f7896": {
      "addresses": {
        "LoD/PD2": "0x6F9B1D1C"
      },
      "rvas": {
        "LoD/PD2": "0x1D1C"
      },
      "sizes": {
        "LoD/PD2": 510
      },
      "name": "__ioinit",
      "signature": "int __ioinit(void)",
      "calling_convention": "__cdecl",
      "comment": "Initializes the I/O subsystem by setting up standard stream handles and allocating I/O buffers.\n\nAlgorithm:\n1. Allocate initial buffer pool (0x480 bytes for 32 stream entries, each 36 bytes)\n2. Initialize each stream entry with invalid handle (-1), clear flags, zero ref count, newline mode (10)\n3. Get startup information to check for inherited handles from parent process\n4. If startup info contains handle data (cbReserved2 != 0), parse inherited handles:\n   a. Extract handle count and flag array from lpReserved2\n   b. Limit handle processing to 2048 maximum for safety\n   c. Allocate additional buffer pools if needed (32 handles per pool)\n5. Process inherited handles from parent:\n   a. Skip invalid handles (0xFFFFFFFF) and handles without FOPEN flag (0x01)\n   b. Verify handles are valid files (FTEXT flag 0x08 set OR GetFileType != 0)\n   c. Store handle, flags, and initialize critical section with 4000ms spin count\n   d. Increment reference count for active streams\n6. Initialize standard streams (stdin=0, stdout=1, stderr=2):\n   a. Set FTEXT|FOPEN flags (0x81) for uninitialized standard streams\n   b. Get appropriate standard handle (STD_INPUT=-10, STD_OUTPUT=-11, STD_ERROR=-12)\n   c. Check if handle is valid and determine file type\n   d. Set FDEV flag (0x40) for character devices or invalid handles\n   e. Set FPIPE flag (0x08) for pipe handles (file type 3)\n   f. Initialize critical section and increment reference count\n   g. Set FINUSE flag (0x80) for already-opened inherited streams\n7. Set system handle count limit via SetHandleCount\n8. Return 0 on success, -1 on memory allocation or critical section failure\n\nParameters:\nvoid - No parameters required\n\nReturns:\n0 - Success, I/O subsystem initialized\n-1 - Failure due to memory allocation error or critical section initialization\n\nSpecial Cases:\nHandle inheritance disabled if startup info is null or cbReserved2 is zero\nHandle count limited to 2048 (0x800) for safety even if parent specifies more\nStandard streams get default initialization if not inherited from parent process\n\nMagic Numbers Reference:\n0x480 - Buffer pool size (1152 bytes = 32 streams \u00d7 36 bytes each)\n0x20 - Streams per buffer pool (32 streams)\n0x24 - Stream entry size (36 bytes per I/O stream structure)\n0x120 - Stream entries per pool (288 in pointer arithmetic = 32 \u00d7 9 dwords)\n0x800 - Maximum inherited handles (2048 limit)\n4000 - Critical section spin count (4 seconds)\n\nStructure Layout:\nStream Entry (36 bytes):\nOffset  Size  Field Name    Type     Description\n0x00    4     handle        HANDLE   File handle or -1 if invalid\n0x04    1     flags         byte     I/O flags (FOPEN|FTEXT|FDEV|FPIPE|FINUSE)\n0x05    1     textmode      byte     Text mode indicator (10=LF, 13=CR+LF)\n0x08    4     refcount      int      Reference count for shared access\n0x0C    24    critsec       CRITICAL_SECTION  Thread synchronization\n\nFlag Bits:\n0x01 - FOPEN: Stream is open and available for I/O\n0x08 - FPIPE: Stream is connected to a pipe\n0x40 - FDEV: Stream is a character device (console/terminal)\n0x80 - FINUSE: Stream was inherited from parent process\n0x81 - FTEXT|FOPEN: Standard text stream (default for stdin/stdout/stderr)\n\nError Handling:\nReturns -1 immediately if initial buffer allocation fails\nReturns -1 if any critical section initialization fails\nContinues processing other streams if individual handle validation fails\nInvalid or inaccessible handles are marked with FDEV flag but don't cause failure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:124a050f7896343631e89fc5722f0cb0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "124a050f7896343631e89fc5722f0cb0",
        "CFG": "ce64ccb286409da41a70a80f89bb0d66",
        "PRO": "a6d048e3f30d9255b98140a30ca11a46"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "124a050f7896343631e89fc5722f0cb0"
      }
    },
    "D2sound_MNE_5c819fccbe8b": {
      "addresses": {
        "LoD/PD2": "0x6F9B1F1A"
      },
      "rvas": {
        "LoD/PD2": "0x1F1A"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "__ioterm",
      "signature": "void __ioterm(void)",
      "calling_convention": "__cdecl",
      "comment": "Terminates I/O subsystem by cleaning up critical sections and freeing I/O control blocks.\n\nAlgorithm:\n1. Initialize pointer to I/O array base at 0x6f9c6880\n2. For each array element (pointer to I/O control block allocation):\n   a. Load base address of I/O control block allocation\n   b. If allocation exists (non-null):\n      - Iterate through I/O control blocks in 36-byte increments\n      - Check flags field at offset +8 for initialization status\n      - If control block is initialized, delete critical section at offset +0xc\n      - Continue until reaching end of 1152-byte allocation (0x480 bytes)\n   c. Free the entire allocation using _free()\n   d. Clear the array element to NULL\n3. Advance to next array element\n4. Continue until reaching end of array at 0x6f9c6980\n\nParameters:\nNone\n\nReturns:\nvoid\n\nSpecial Cases:\n- Skips unallocated array elements (NULL pointers)\n- Only deletes critical sections for initialized I/O control blocks (flags != 0)\n- Handles up to 64 array elements (0x6f9c6880 to 0x6f9c6980 = 256 bytes / 4 = 64 pointers)\n\nMagic Numbers Reference:\n0x24 (36 decimal) - Size of each I/O control block structure\n0x480 (1152 decimal) - Total size of each I/O allocation (32 control blocks * 36 bytes)\n0x8 - Offset to flags field in I/O control block\n0xc (12 decimal) - Offset to critical section in I/O control block  \n0x6f9c6880 - Base address of I/O array\n0x6f9c6980 - End address of I/O array\n\nStructure Layout:\nI/O Control Block (36 bytes):\nOffset  Size  Field Name        Type              Description\n0x0     4     dwUnknown0        uint              Unknown field\n0x4     4     dwUnknown4        uint              Unknown field  \n0x8     4     dwFlags           uint              Initialization flags (0=uninitialized)\n0xC     24    criticalSection   CRITICAL_SECTION  Thread synchronization object",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5c819fccbe8be253acb13e92783cc438",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5c819fccbe8be253acb13e92783cc438",
        "CFG": "f586866415c40e4eaee67b5c40cac105",
        "PRO": "4a6e765732cab4b6c9002c487aa07aa9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5c819fccbe8be253acb13e92783cc438"
      }
    },
    "D2sound_MNE_d286a589c482": {
      "addresses": {
        "LoD/PD2": "0x6F9B1F66"
      },
      "rvas": {
        "LoD/PD2": "0x1F66"
      },
      "sizes": {
        "LoD/PD2": 199
      },
      "name": "__setenvp",
      "signature": "int __setenvp(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __setenvp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d286a589c48283a2eda13c52495cb951",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d286a589c48283a2eda13c52495cb951",
        "CFG": "60c2579aec5d4262b2bcbd8d56c31547",
        "PRO": "09eb1a65f098b698bb5f4753fc97fc2b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d286a589c48283a2eda13c52495cb951"
      }
    },
    "D2sound_MNE_5309cc011f44": {
      "addresses": {
        "LoD/PD2": "0x6F9B202D"
      },
      "rvas": {
        "LoD/PD2": "0x202D"
      },
      "sizes": {
        "LoD/PD2": 364
      },
      "name": "parse_cmdline",
      "signature": "void parse_cmdline(char * * ppArgv, int * pArgc)",
      "calling_convention": "__cdecl",
      "comment": "Parse command line string into argc/argv format with proper quote and escape handling.\n\nAlgorithm:\n\n1. Initialize output pointers and count argc to 1 for program name\n2. Store command line start pointer in first argv slot if argv array provided\n3. Parse first argument (program name):\n   - Handle quoted strings by toggling quote state on 0x22 characters\n   - Process escape sequences for multi-byte characters using character class table\n   - Copy characters to output buffer until whitespace outside quotes\n   - Null-terminate the argument\n4. Parse remaining arguments in loop:\n   - Skip leading whitespace (space 0x20 and tab 0x09)\n   - Store argument start pointer in argv array if provided\n   - Increment argc counter\n   - Process argument characters with escape sequence handling:\n     - Count consecutive backslashes (0x5c)\n     - Handle quote characters based on backslash parity\n     - Toggle quote state for unescaped quotes\n     - Handle double quotes inside quoted strings\n     - Copy characters to output buffer with proper escape processing\n   - Null-terminate each argument\n5. Set final argv array entry to NULL and increment argc\n\nParameters:\n  ppArgv - char** pointer to argv array (may be NULL for count-only mode)\n  pnArgc - int* pointer to receive argument count\n  IMPLICIT: EAX register contains command line string pointer\n  IMPLICIT: ECX register contains output buffer pointer (may be NULL)\n  IMPLICIT: ESI register contains pointer to character count storage\n\nReturns:\n  void - Results stored in output parameters and implicit registers\n\nSpecial Cases:\n  - If ppArgv is NULL, only counts arguments without storing pointers\n  - If output buffer (ECX) is NULL, only counts characters without copying\n  - Handles embedded quotes via double quote escaping (\"\")\n  - Multi-byte character support via character classification table at 0x6f9c6640\n\nMagic Numbers Reference:\n  0x22 (34) - Double quote character for string delimiting\n  0x20 (32) - Space character for argument separation\n  0x09 (9) - Tab character for argument separation\n  0x5c (92) - Backslash character for escape sequences\n  0x04 (4) - Multi-byte character flag in classification table\n  0x6f9c6640 - Character classification table base address\n\nError Handling:\n  - No explicit error checking - assumes valid input pointers\n  - Handles NULL argv gracefully by skipping pointer storage\n  - Handles NULL output buffer by skipping character copying",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5309cc011f4489e83a895a5a05ecc215",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5309cc011f4489e83a895a5a05ecc215",
        "CFG": "564d0f5af54e5f1993494d07b0660f28",
        "PRO": "36e0d78a3d023220332b738484bde0f4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5309cc011f4489e83a895a5a05ecc215"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_457ecf3d8055": {
      "addresses": {
        "LoD/PD2": "0x6F9B2199"
      },
      "rvas": {
        "LoD/PD2": "0x2199"
      },
      "sizes": {
        "LoD/PD2": 162
      },
      "name": "__setargv",
      "signature": "int __setargv(void)",
      "calling_convention": "__cdecl",
      "comment": "Initializes C runtime command line argument processing\n\nAlgorithm:\n1. Initialize multibyte character table if not already done\n2. Reset global argument count to 0\n3. Get current executable module filename using GetModuleFileNameA\n4. Store executable path in global variable\n5. Parse command line first time to count arguments\n6. Calculate memory needed for argv array (count * 4 bytes + string data size)\n7. Allocate memory for argv array using malloc\n8. If allocation fails, return -1\n9. Parse command line second time to populate argv array\n10. Store argument count minus 1 in global argc\n11. Store argv pointer in global variable\n12. Return 0 on success\n\nParameters:\nNone (void function)\nIMPLICIT: in_ECX contains string data buffer size from command line parser\n\nReturns:\n0 - Success, argv initialized\n-1 - Memory allocation failure\n\nSpecial Cases:\nUses two-pass parsing: first pass counts arguments, second pass populates array\nExecutable name is stored separately from command line arguments\nGlobal argc excludes program name (argc - 1)\nlocal_8 (nArgCount): Stores argument count from parse_cmdline\nlocal_c: Phantom variable optimized away by decompiler\n\nMagic Numbers Reference:\n0x104 (260) - Maximum path length for GetModuleFileNameA\n4 - Size of pointer in argv array (32-bit pointers)\n-1 - Error return code for malloc failure\n0 - Success return code\n\nNote: Function uses 2 stack-allocated variables, one optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:457ecf3d8055d8e00a172b3d901a03ca",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "457ecf3d8055d8e00a172b3d901a03ca",
        "CFG": "9d95d0d72ba3d0f8ca13ab2ea583953f",
        "PRO": "9e78a175bfb62b637180055faba76e50"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "457ecf3d8055d8e00a172b3d901a03ca"
      }
    },
    "D2sound_MNE_ba896e89d5b4": {
      "addresses": {
        "LoD/PD2": "0x6F9B223B"
      },
      "rvas": {
        "LoD/PD2": "0x223B"
      },
      "sizes": {
        "LoD/PD2": 290
      },
      "name": "___crtGetEnvironmentStringsA",
      "signature": "LPVOID ___crtGetEnvironmentStringsA(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtGetEnvironmentStringsA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ba896e89d5b4e319d02dcd31648ce3d9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ba896e89d5b4e319d02dcd31648ce3d9",
        "CFG": "ec3c1f7068f62fb700bdaa7f18e77973",
        "PRO": "7cb603b6462c84fc9800b7260231707a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ba896e89d5b4e319d02dcd31648ce3d9"
      }
    },
    "D2sound_MNE_02783607761b": {
      "addresses": {
        "LoD/PD2": "0x6F9B235D"
      },
      "rvas": {
        "LoD/PD2": "0x235D"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "___heap_select",
      "signature": "uint ___heap_select(void)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: uint ___heap_select(void)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:02783607761bb7b7f3ed068e856f0ca2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "02783607761bb7b7f3ed068e856f0ca2",
        "CFG": "5373f71b1fc67ec2016d5dcfe49dc588",
        "PRO": "750e7516b9201375ae6018ee308a5d8b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "02783607761bb7b7f3ed068e856f0ca2"
      }
    },
    "D2sound_MNE_057b2070bbbd": {
      "addresses": {
        "LoD/PD2": "0x6F9B2377"
      },
      "rvas": {
        "LoD/PD2": "0x2377"
      },
      "sizes": {
        "LoD/PD2": 81
      },
      "name": "__heap_init",
      "signature": "int __heap_init(void)",
      "calling_convention": "__cdecl",
      "comment": "Initialize the default process heap and select heap implementation strategy.\n\nAlgorithm:\n1. Create default process heap using HeapCreate with HEAP_NO_SERIALIZE flag based on stack parameter\n2. Store created heap handle in global variable for process-wide access\n3. Query heap strategy selector to determine optimal heap implementation\n4. If small-block heap strategy selected (value 3), initialize small-block heap with 0x3f8 parameter\n5. If small-block heap initialization fails, clean up by destroying default heap and return failure\n6. Return success (1) if heap initialization completed successfully\n\nParameters:\nIMPLICIT in_stack_00000004: Serialization flag (0 = enable HEAP_NO_SERIALIZE, non-zero = allow serialization)\n\nReturns:\n1: Heap initialization successful, default heap and strategy configured\n0: Heap initialization failed, either HeapCreate failed or small-block heap init failed\n\nSpecial Cases:\nIf heap strategy is not small-block (not value 3), function succeeds without small-block initialization\nMagic number 0x3f8 (1016 decimal): Small-block heap parameter for initial allocation pool size\nMagic number 0x1000 (4096 decimal): Initial heap size (4KB) \n\nGlobal Variables:\nDAT_6f9c6860: g_hDefaultHeap - Handle to default process heap (HANDLE type)\nDAT_6f9c6864: g_dwHeapStrategy - Selected heap implementation strategy (DWORD type)\n\nError Handling:\nHeapCreate failure: Returns 0 immediately, no cleanup needed\nSmall-block heap init failure: Destroys default heap before returning 0 to prevent resource leak",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:057b2070bbbdb5455d8d4d9018467770",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "057b2070bbbdb5455d8d4d9018467770",
        "CFG": "99df254e8864ce84a96c669724d15346",
        "PRO": "257a468500b375b831be3ebb18dcd87a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "057b2070bbbdb5455d8d4d9018467770"
      }
    },
    "D2sound_MNE_43c0a0116a01": {
      "addresses": {
        "LoD/PD2": "0x6F9B23C8"
      },
      "rvas": {
        "LoD/PD2": "0x23C8"
      },
      "sizes": {
        "LoD/PD2": 127
      },
      "name": "__heap_term",
      "signature": "void __heap_term(void)",
      "calling_convention": "__cdecl",
      "comment": "Terminate heap subsystem and free all allocated memory resources.\n\nAlgorithm:\n\n1. Check if heap system initialized (g_dwHeapState == 3)\n2. Iterate through all heap descriptors in descriptor array\n3. For each descriptor, release virtual memory with VirtualFree (DECOMMIT then RELEASE)\n4. Free heap allocation associated with descriptor\n5. Free the descriptor array itself\n6. Destroy the process heap handle\n\nParameters:\n\nNone\n\nReturns:\n\nvoid\n\nSpecial Cases:\n\nIf heap system not initialized (g_dwHeapState != 3), skip descriptor cleanup\nand proceed directly to HeapDestroy\n\nMagic Numbers Reference:\n\n0x03 (3) - Heap system fully initialized state\n0x100000 (1048576) - Virtual memory decommit size (1MB chunks)  \n0x4000 (16384) - MEM_DECOMMIT flag for VirtualFree\n0x8000 (32768) - MEM_RELEASE flag for VirtualFree\n0x0C (12) - Offset to virtualMemoryBase field in heap descriptor\n\nStructure Layout:\n\nHeapDescriptor (20 bytes total, 5 DWORD stride):\nOffset  Size  Field Name           Type      Description\n0x00    4     reserved1            uint      Unknown field 1\n0x04    4     reserved2            uint      Unknown field 2  \n0x08    4     reserved3            uint      Unknown field 3\n0x0C    4     virtualMemoryBase    void*     Base address for VirtualFree operations\n0x10    4     heapAllocation       void*     Heap allocation handle for HeapFree\n\nError Handling:\n\nFunction assumes all heap operations succeed\nNo error checking on VirtualFree or HeapFree calls\nInvalid descriptor count could cause buffer overrun",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:43c0a0116a0179cd961980d35fb0c190",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "43c0a0116a0179cd961980d35fb0c190",
        "CFG": "79578de49aac4c106e2830a21ae26f42",
        "PRO": "16b352de6ab77dccc82833031ad0e592"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "43c0a0116a0179cd961980d35fb0c190"
      }
    },
    "D2sound_MNE_f17bdc134d98": {
      "addresses": {
        "LoD/PD2": "0x6F9B2450"
      },
      "rvas": {
        "LoD/PD2": "0x2450"
      },
      "sizes": {
        "LoD/PD2": 61
      },
      "name": "__chkstk",
      "signature": "void __chkstk(void)",
      "calling_convention": "__stdcall",
      "comment": "Microsoft Visual C++ runtime stack allocation and overflow checking routine\n\nAlgorithm:\n1. Check if requested allocation size (in EAX) is less than 4096 bytes (0x1000)\n2. If small allocation: Touch single stack page and return\n3. If large allocation: Touch every 4KB page by walking backwards through stack\n4. Continue touching pages until remaining allocation is less than 4096 bytes\n5. Touch final partial page and return\n\nParameters:\nIMPLICIT EAX (dwAllocationSize): Number of bytes to allocate on stack\n\nReturns:\nvoid: Function modifies stack pointer but returns void\n\nSpecial Cases:\n- Allocations under 4096 bytes require only single page touch\n- Large allocations require walking every 4KB boundary to prevent stack overflow\n- Function preserves all registers except stack pointer\n\nMagic Numbers Reference:\n0x1000 (4096): Page size boundary for stack guard pages\n0xfff (4095): Mask for checking remaining allocation after page boundary\n\nError Handling:\n- Function assumes valid allocation size in EAX\n- Stack overflow protection handled by OS guard pages\n- No explicit error returns or validation\n\nStructure Layout:\nN/A - Function operates on stack memory directly\n\nFlag Bits:\nN/A - Function does not use bit flags",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f17bdc134d984988a231baad11399d03",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f17bdc134d984988a231baad11399d03",
        "CFG": "7da0b27075b2247a294f35dfce854614",
        "PRO": "c5d73ae9ae5134090ea4cb384ca72353"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f17bdc134d984988a231baad11399d03"
      }
    },
    "D2sound_MNE_79c576ae79b5": {
      "addresses": {
        "LoD/PD2": "0x6F9B248D"
      },
      "rvas": {
        "LoD/PD2": "0x248D"
      },
      "sizes": {
        "LoD/PD2": 356
      },
      "name": "__XcptFilter",
      "signature": "int __XcptFilter(ulong _ExceptionNum, _EXCEPTION_POINTERS * _ExceptionPtr)",
      "calling_convention": "__cdecl",
      "comment": "Microsoft Visual C++ runtime exception filter that maps system exceptions to appropriate handlers.\n\nAlgorithm:\n1. Get thread-local data structure via __getptd()\n2. Search exception handler table for matching exception number\n3. If no handler found, call UnhandledExceptionFilter() for default handling\n4. If handler type is 0x5, clear handler and return EXCEPTION_EXECUTE_HANDLER (1)\n5. If handler type is 0x1, return EXCEPTION_CONTINUE_SEARCH (-1)\n6. Otherwise, execute custom handler with appropriate signal mapping\n7. For signal type 8 (SIGFPE), map exception codes to standard signals:\n   - 0xc000008e \u2192 0x83 (SIGFPE invalid operation)\n   - 0xc0000090 \u2192 0x81 (SIGFPE divide by zero)\n   - 0xc0000091 \u2192 0x84 (SIGFPE overflow)\n   - 0xc0000093 \u2192 0x85 (SIGFPE underflow)\n   - 0xc000008d \u2192 0x82 (SIGFPE denormal operand)\n   - 0xc000008f \u2192 0x86 (SIGFPE inexact result)\n   - 0xc0000092 \u2192 0x8a (SIGFPE stack check)\n8. Clear handler table entries processed with signal type 8\n9. Restore original thread state and return EXCEPTION_CONTINUE_SEARCH (-1)\n\nParameters:\n_ExceptionNum (ulong): System exception code to handle\n_ExceptionPtr (_EXCEPTION_POINTERS *): Exception context information\n\nReturns:\nint: Exception handling disposition\n  1 = EXCEPTION_EXECUTE_HANDLER (execute handler)\n -1 = EXCEPTION_CONTINUE_SEARCH (continue search)\n  0 = EXCEPTION_CONTINUE_EXECUTION (from UnhandledExceptionFilter)\n\nSpecial Cases:\nNote: Function uses 1 stack-allocated temporary variable optimized away by decompiler\n\nMagic Numbers Reference:\n0x5 - Handler type for execute handler action\n0x1 - Handler type for continue search action  \n0x8 - Signal type indicating floating-point exception (SIGFPE)\n0xc - Size of exception handler table entry (12 bytes)\n\nError Handling:\n- NULL handler pointer defaults to UnhandledExceptionFilter\n- Invalid handler table bounds return continue search\n- Exception during handler execution propagates to system",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:79c576ae79b525f94550b7e17b8f3e0b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "79c576ae79b525f94550b7e17b8f3e0b",
        "CFG": "0e61aef9e8eef9ae3e118bd261dba8e8",
        "PRO": "02e9d3da6e924c2bf96b1680a70d3b75"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "79c576ae79b525f94550b7e17b8f3e0b"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_179c969cc717": {
      "addresses": {
        "LoD/PD2": "0x6F9B25F1"
      },
      "rvas": {
        "LoD/PD2": "0x25F1"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "CppExceptionFilter",
      "signature": "int CppExceptionFilter(int exceptionCode, _EXCEPTION_POINTERS * pExceptionPointers)",
      "calling_convention": "__cdecl",
      "comment": "C++ Exception Filter - Processes exceptions and delegates to __XcptFilter\nFilters standard C++ exceptions (0xe06d7363) for structured exception handling.\n\nAlgorithm:\n1. Load C++ exception code constant (0xe06d7363)\n2. Compare first stack parameter with C++ exception code\n3. If exception code matches:\n   a. Push exception pointers parameter\n   b. Push C++ exception code\n   c. Call __XcptFilter to process exception\n   d. Clean up stack (2 dwords popped)\n   e. Return __XcptFilter result\n4. If exception code does not match:\n   a. Return 0 (exception not handled)\n\nParameters:\n- exceptionCode (param_1): int - Exception code from exception handler\n- pExceptionPointers (param_2): _EXCEPTION_POINTERS* - Pointer to exception information\n\nReturns:\n- int: Exception filter result from __XcptFilter if C++ exception (0xe06d7363)\n- int: 0 if exception code does not match (exception not handled)\n\nSpecial Cases:\n- Magic constant 0xe06d7363 is standard C++ exception code\n- Called as exception handler via structured exception handling (__except)\n- Stack parameters accessed via ESP offsets due to exception handler prologue",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:179c969cc717d22841f18b89d2acdead",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "179c969cc717d22841f18b89d2acdead",
        "CFG": "f09da8ab2298e4bafedfaee404f68269",
        "PRO": "1c492b7026a27fcdbb1290b69bddea3a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "179c969cc717d22841f18b89d2acdead"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_STR_f8f89093f5c5": {
      "addresses": {
        "LoD/PD2": "0x6F9B260C"
      },
      "rvas": {
        "LoD/PD2": "0x260C"
      },
      "sizes": {
        "LoD/PD2": 376
      },
      "name": "HandleRuntimeErrorMessage",
      "signature": "void HandleRuntimeErrorMessage(int errorCode)",
      "calling_convention": "__cdecl",
      "comment": "Handles and displays runtime error messages.\n\nAlgorithm:\n1. Initialize stack canary (XOR with global value at 0x6f9c56c0)\n2. Search through error code lookup table (0x6f9c5218) to find matching code\n3. If error code not found, exit function\n4. Check output mode flags (DAT_6f9c6054, DAT_6f9c6058) to determine output method\n5. If output flag is set, write error message string to standard output via GetStdHandle/WriteFile\n6. If output flag is clear and error code != 0xFC, format comprehensive error message:\n   a. Get module filename using GetModuleFileNameA, fallback to default if fails\n   b. Verify module path length (max 0x3c bytes), truncate with \"...\" if too long\n   c. Allocate stack buffer sized to fit: \"Runtime Error: \" + module_path + error_code_string + resource_info\n   d. Format message string using strcpy/strcat operations\n   e. Build message box with error details (title: \"Microsoft Visual C++ Runtime Library\", flags: 0x12010)\n   f. Display message box via __crtMessageBoxA with full error context\n7. Validate stack canary against expected value\n8. Clean up and return\n\nParameters:\nerrorCode (int): Runtime error code to handle, searched in lookup table at 0x6f9c5218\n\nReturns:\nvoid - Function does not return a value; handles error display as side effect\n\nSpecial Cases:\n- Error code 0xFC: Skip message formatting, exit immediately after validation\n- Module name retrieval failure: Use fallback string at 0x6f9bf6ac\n- Module path > 0x3c bytes: Truncate and append \"...\" suffix\n- Stack buffer allocation: Dynamic sizing with 4-byte alignment based on error message length\n- XOR canary protection: Value XORed with stack base to detect stack corruption\n\nStructure Layout:\nLocal Stack Variables (relative to EBP):\nOffset  Size  Field Name              Type      Description\n-0x7c   0x104 modulePathBuffer        char[260] Module filename from GetModuleFileNameA\n-0x8c   0x4   xorCanaryValue          uint      XOR-protected stack guard value\n-0x88   0x1   initFlag                byte      Initialization flag for GetModuleFileNameA\n\nError Code Table Structure (at 0x6f9c5218):\nOffset  Size  Description\n+0      0x8   Array of error codes (DWORD pairs, 0x13 entries max)\nEach entry contains: [error_code, string_ptr] with 8-byte stride",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:f8f89093f5c5a57c3cdd998b61227276",
      "indexes": {
        "EXP": null,
        "STR": "f8f89093f5c5a57c3cdd998b61227276",
        "API": null,
        "MNE": "907ddf19e9b559942986798c3a61049f",
        "CFG": "e8a71e6d3baee0880eac96eab7835bdf",
        "PRO": "5fc73fb38dd265596e07d5b05ba4d2ec"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "907ddf19e9b559942986798c3a61049f"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_e0686acda8da": {
      "addresses": {
        "LoD/PD2": "0x6F9B2784"
      },
      "rvas": {
        "LoD/PD2": "0x2784"
      },
      "sizes": {
        "LoD/PD2": 57
      },
      "name": "__FF_MSGBANNER",
      "signature": "void __FF_MSGBANNER(void)",
      "calling_convention": "__cdecl",
      "comment": "Display runtime error message banner with optional custom handler callback.\n\nAlgorithm:\n1. Check if primary message banner flag (DAT_6f9c6054) is set to 1\n2. If not set, check if primary flag is 0 AND secondary flag (DAT_6f9c6058) is set to 1\n3. If either condition is true, display initial error message (0xFC)\n4. Check if custom error handler callback (DAT_6f9c62cc) is registered\n5. If callback is not NULL, execute the custom error handler function\n6. Display final error message (0xFF) after custom handler execution\n7. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- If both flag conditions are false, function returns immediately without action\n- Custom handler callback is optional and may be NULL\n- Error codes 0xFC and 0xFF represent pre and post custom handler messages\n\nMagic Numbers Reference:\n0xFC (252) - Initial runtime error message code for HandleRuntimeErrorMessage\n0xFF (255) - Final runtime error message code for HandleRuntimeErrorMessage\n\nGlobal Variables:\nDAT_6f9c6054 - Primary message banner enable flag (uint)\nDAT_6f9c6058 - Secondary message banner enable flag (uint) \nDAT_6f9c62cc - Optional custom error handler callback function pointer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e0686acda8daa87f807e8c4bf4d7ccee",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e0686acda8daa87f807e8c4bf4d7ccee",
        "CFG": "285d09a7e9b985b0b82a1cfce0632509",
        "PRO": "9558de75c3320ac494d6c723ad6b3ebe"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e0686acda8daa87f807e8c4bf4d7ccee"
      }
    },
    "D2sound_MNE_b2a8f1a86586": {
      "addresses": {
        "LoD/PD2": "0x6F9B27BD"
      },
      "rvas": {
        "LoD/PD2": "0x27BD"
      },
      "sizes": {
        "LoD/PD2": 16
      },
      "name": "___crtInitCritSecNoSpinCount@8",
      "signature": "int ___crtInitCritSecNoSpinCount@8(LPCRITICAL_SECTION lpCriticalSection)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: int ___crtInitCritSecNoSpinCount@8(LPCRITICAL_SECTION lpCriticalSection)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b2a8f1a86586c795d4e7ef4b4053c58e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b2a8f1a86586c795d4e7ef4b4053c58e",
        "CFG": null,
        "PRO": "3a576438ea233acbc3eceb035b027804"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b2a8f1a86586c795d4e7ef4b4053c58e"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_STR_5fd0e2b0faef": {
      "addresses": {
        "LoD/PD2": "0x6F9B27CD"
      },
      "rvas": {
        "LoD/PD2": "0x27CD"
      },
      "sizes": {
        "LoD/PD2": 103
      },
      "name": "___crtInitCritSecAndSpinCount",
      "signature": "void ___crtInitCritSecAndSpinCount(void * pCriticalSection, uint dwSpinCount)",
      "calling_convention": "__cdecl",
      "comment": "Initializes a critical section with an optional spin count for better performance on multiprocessor systems.\n\nAlgorithm:\n1. Check if InitializeCriticalSectionAndSpinCount function pointer is already resolved\n2. If not resolved, check if system supports spin counts (DAT_6f9c6004 != 1)\n3. Load kernel32.dll module handle using GetModuleHandleA\n4. Get address of InitializeCriticalSectionAndSpinCount API using GetProcAddress\n5. If API is available, store function pointer for future use\n6. If API not available, fall back to ___crtInitCritSecNoSpinCount@8\n7. Call the resolved function pointer with critical section and spin count parameters\n\nParameters:\npCriticalSection (void *): Pointer to CRITICAL_SECTION structure to initialize\ndwSpinCount (uint): Number of times to spin before blocking on multiprocessor systems\n\nReturns:\nvoid: This function does not return a value\n\nSpecial Cases:\n- On single processor systems or Windows versions without spin count support, falls back to basic critical section initialization\n- Function pointer is cached in DAT_6f9c62d0 for performance on subsequent calls\n- System capability flag DAT_6f9c6004 determines feature availability\n\nMagic Numbers Reference:\n0x1 - Single processor system indicator in DAT_6f9c6004\nkernel32.dll - Windows kernel module containing critical section APIs\nInitializeCriticalSectionAndSpinCount - Windows API for spin-enabled critical sections",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:5fd0e2b0faef558a78531f73f4d372dd",
      "indexes": {
        "EXP": null,
        "STR": "5fd0e2b0faef558a78531f73f4d372dd",
        "API": null,
        "MNE": "3f585ab7136accb11659a7703e402a24",
        "CFG": "5a6a1bad4884a279605e3598d136f1d3",
        "PRO": "1457f6c933b7d6f770f66fd1bc6adda4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3f585ab7136accb11659a7703e402a24"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_b1691d6b7b8b": {
      "addresses": {
        "LoD/PD2": "0x6F9B2858"
      },
      "rvas": {
        "LoD/PD2": "0x2858"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "GetThreadErrnoPointer",
      "signature": "int * GetThreadErrnoPointer(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns pointer to the thread-local errno variable\n\nAlgorithm:\n1. Call __getptd() to retrieve the per-thread data structure\n2. Extract the address of the _terrno field from the thread data structure\n3. Return the pointer to the errno value\n\nParameters:\n  None\n\nReturns:\n  int* - Pointer to the thread-local errno variable (_terrno field)\n  \nSpecial Cases:\n  This is a Windows CRT runtime function that provides thread-safe access to\n  the errno value. Each thread has its own errno variable stored in per-thread\n  data. This function is used by Windows CRT functions like SetThreadErrorCode\n  to retrieve and modify the thread's error code.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b1691d6b7b8ba065c3fc1a089e8db64e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "CFG": null,
        "PRO": "a5fbc572c960f03280e29642cc235ae3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b1691d6b7b8ba065c3fc1a089e8db64e"
      }
    },
    "D2sound_MNE_8ac92c76a51a": {
      "addresses": {
        "LoD/PD2": "0x6F9B2861"
      },
      "rvas": {
        "LoD/PD2": "0x2861"
      },
      "sizes": {
        "LoD/PD2": 111
      },
      "name": "__heap_alloc",
      "signature": "void * __heap_alloc(size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __heap_alloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8ac92c76a51a8b065a1fac94d719ae1f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8ac92c76a51a8b065a1fac94d719ae1f",
        "CFG": "044e95a6511b64bf155bd4de5c12eeac",
        "PRO": "c9ab68bbfa2956914487e1c80f5fd42d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8ac92c76a51a8b065a1fac94d719ae1f"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B28D3": {
      "addresses": {
        "LoD/PD2": "0x6F9B28D3"
      },
      "rvas": {
        "LoD/PD2": "0x28D3"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseHeapAllocationLock",
      "signature": "void ReleaseHeapAllocationLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the heap allocation synchronization lock after block allocation attempt.\n\nALGORITHM:\n1. Push lock ID (4) onto stack as parameter for ReleaseSynchronizationLock\n2. Call ReleaseSynchronizationLock to release the heap management lock\n3. Pop return address from stack into ECX to restore stack alignment\n4. Return to caller\n\nPARAMETERS:\nNone - this is a leaf function with no parameters\n\nRETURNS:\nvoid - function has no return value, performs cleanup operation\n\nSPECIAL CASES:\n- Lock ID 4 is hardcoded for heap allocation lock management\n- Uses __stdcall convention requiring callee to cleanup stack\n- The POP ECX at 6f9b28da is used for stack correction before RET\n- Function is called by __heap_alloc after attempting small block allocation\n- Part of Visual Studio 2003 Release CRT heap management implementation\n\nUSAGE CONTEXT:\nCalled from __heap_alloc when heap lock 4 must be released after attempting\nto allocate from the small block heap (sbh_alloc_block). The lock is released\nwhether the allocation succeeded or failed to prevent deadlock.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "a1eacdac7b1066b4896f250294a6267d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_MNE_be05c38d951a": {
      "addresses": {
        "LoD/PD2": "0x6F9B28DC"
      },
      "rvas": {
        "LoD/PD2": "0x28DC"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "__nh_malloc",
      "signature": "void * __nh_malloc(size_t _Size, int _NhFlag)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __nh_malloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:be05c38d951a724b98e30bc46956a8c1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "be05c38d951a724b98e30bc46956a8c1",
        "CFG": "55d660ebbef99c0baa319e016760b8fc",
        "PRO": "9e156ac1d112b1b5e33d82a16514e462"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "be05c38d951a724b98e30bc46956a8c1"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_301bd5440f60": {
      "addresses": {
        "LoD/PD2": "0x6F9B2908"
      },
      "rvas": {
        "LoD/PD2": "0x2908"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "_malloc",
      "signature": "void * _malloc(size_t cbSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates memory from the heap using the new handler mechanism.\n\nAlgorithm:\n1. Call __nh_malloc with requested size and global new handler\n2. Return the allocated memory pointer (or NULL on failure)\n\nParameters:\ncbSize (size_t): Number of bytes to allocate from heap\n\nReturns:\nSuccess: Valid pointer to allocated memory block\nFailure: NULL if allocation fails or size is 0\n\nSpecial Cases:\n- Zero size allocation behavior depends on __nh_malloc implementation\n- Global new handler (DAT_6f9c6338) determines failure behavior\n- This is a thin wrapper around __nh_malloc for C runtime compatibility\n\nMagic Numbers Reference:\nDAT_6f9c6338: Global new handler function pointer for allocation failures\n\nError Handling:\n- Allocation failures handled by __nh_malloc and configured new handler\n- No local error checking performed in this wrapper function",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:301bd5440f60703ca7a24a8fb30f1e56",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "301bd5440f60703ca7a24a8fb30f1e56",
        "CFG": null,
        "PRO": "70005a6486813b88cb95f671f978028c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "301bd5440f60703ca7a24a8fb30f1e56"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_059e9bb2efc1": {
      "addresses": {
        "LoD/PD2": "0x6F9B291C"
      },
      "rvas": {
        "LoD/PD2": "0x291C"
      },
      "sizes": {
        "LoD/PD2": 32
      },
      "name": "__global_unwind2",
      "signature": "void __global_unwind2(void * pTargetFrame)",
      "calling_convention": "__cdecl",
      "comment": "Performs structured exception handling stack unwinding to specified frame.\n\nAlgorithm:\n\n1. Accept target exception frame pointer parameter\n2. Call RtlUnwind with target frame and fixed parameters:\n   - Target frame: param_1 (exception frame to unwind to)\n   - Target IP: 0x6f9b2934 (return address after unwinding)\n   - Exception record: NULL (no specific exception)\n   - Return value: NULL (no return value)\n3. Return to caller after unwinding completes\n\nParameters:\n\nparam_1 (void *) - Target exception frame pointer to unwind to. Should point to valid EXCEPTION_REGISTRATION_RECORD structure on exception chain.\n\nReturns:\n\nvoid - Function does not return a value. Control returns to caller after stack unwinding completes.\n\nSpecial Cases:\n\nMagic Numbers Reference:\n- 0x6f9b2934: Fixed return address used as target IP for RtlUnwind\n- 0x0: NULL pointer for exception record parameter\n- 0x0: NULL pointer for return value parameter\n\nError Handling:\n\nFunction relies on RtlUnwind for error handling. Invalid target frame pointer may cause system exception or undefined behavior.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:059e9bb2efc1de93bfe21089d0ad96d3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "059e9bb2efc1de93bfe21089d0ad96d3",
        "CFG": null,
        "PRO": "d1fc49850f72ede5bf435c5b19233a24"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "059e9bb2efc1de93bfe21089d0ad96d3"
      },
      "api_calls": {
        "LoD/PD2": [
          "RtlUnwind"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_cd4ab8e23ed6": {
      "addresses": {
        "LoD/PD2": "0x6F9B295E"
      },
      "rvas": {
        "LoD/PD2": "0x295E"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "__local_unwind2",
      "signature": "void __local_unwind2(void * pExceptionFrame, int nTargetLevel)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void __local_unwind2(void * pExceptionFrame, int nTargetLevel)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cd4ab8e23ed6997cd2e2434b8d375458",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd4ab8e23ed6997cd2e2434b8d375458",
        "CFG": "d7e92aa36e4ea61ef8903512dfbaf1bc",
        "PRO": "96ff2a475070a6dab80c4327c6b30083"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "cd4ab8e23ed6997cd2e2434b8d375458"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_ed17ad9d511f": {
      "addresses": {
        "LoD/PD2": "0x6F9B29F2"
      },
      "rvas": {
        "LoD/PD2": "0x29F2"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "SetupExceptionFrameContext",
      "signature": "void SetupExceptionFrameContext(int handlerFunc)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void SetupExceptionFrameContext(int handlerFunc)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ed17ad9d511f6e330c2b6a62378d83cf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ed17ad9d511f6e330c2b6a62378d83cf",
        "CFG": "014d2069a1aece9d955ffb144dc9da61",
        "PRO": "ccb8254b66100df34362937db93881b0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ed17ad9d511f6e330c2b6a62378d83cf"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_630b0e4f3169": {
      "addresses": {
        "LoD/PD2": "0x6F9B2A0A"
      },
      "rvas": {
        "LoD/PD2": "0x2A0A"
      },
      "sizes": {
        "LoD/PD2": 417
      },
      "name": "ReallocateMemoryWithHeapBackoff",
      "signature": "int * ReallocateMemoryWithHeapBackoff(int * pOriginalBuffer, uint * pNewSize)",
      "calling_convention": "__cdecl",
      "comment": "Reallocates memory buffer with small block heap (SBH) optimization and standard heap fallback\n\nAlgorithm:\n1. Handle special cases: NULL original buffer (allocate new), NULL new size (free buffer)\n2. Check allocation mode flag at 0x6f9c6864 to determine heap strategy\n3. For SBH mode (mode == 3):\n   - Lock mutex (slot 4) before SBH operations\n   - Find SBH block containing original buffer using ___sbh_find_block\n   - If found and size <= threshold (0x6f9c6620): attempt in-place resize with ___sbh_resize_block\n   - If resize fails: allocate new SBH block, copy data, free old block\n   - Release mutex lock after SBH operations complete\n4. For standard heap mode (mode != 3): use HeapReAlloc directly\n5. Apply size constraints: minimum 1 byte, maximum 0xffffffe0, align to 16-byte boundary\n6. On allocation failure: call new handler (0x6f9b403f) if enabled (0x6f9c6338)\n7. Retry allocation loop if handler returns non-zero (memory freed)\n8. Return pointer to reallocated buffer or NULL on failure\n\nParameters:\n  pOriginalBuffer (int *): Pointer to existing buffer to reallocate, NULL for new allocation\n  pNewSize (uint *): Pointer to requested size in bytes, NULL to free buffer\n\nReturns:\n  EAX: Pointer to reallocated buffer on success, NULL on failure or free operation\n\nSpecial Cases:\n  - Size 0 is converted to minimum allocation of 1 byte\n  - Size > 0xffffffe0 triggers new handler and returns NULL\n  - Buffer size stored at buffer[-1] used for copy size calculations\n  - SBH threshold 0x6f9c6620 determines resize vs allocate strategy\n  - Mode flag 0x6f9c6864 == 3 enables SBH, other values use standard heap\n  - Handler flag 0x6f9c6338 enables retry loop on allocation failure\n  - Heap handle stored at 0x6f9c6860 for HeapAlloc/HeapReAlloc operations\n\nError Handling:\n  - Size validation prevents integer overflow in allocation\n  - Mutex locking prevents SBH corruption during concurrent access\n  - New handler mechanism allows application-level memory pressure response\n  - Fallback from SBH to standard heap ensures allocation attempts\n  - Copy size bounds checking prevents buffer overflow during data transfer\n\nMagic Numbers Reference:\n  0x6f9c6864 - Global allocation mode flag (3 = SBH enabled)\n  0x6f9c6620 - SBH resize threshold pointer  \n  0x6f9c6860 - Process heap handle for HeapAlloc/HeapReAlloc\n  0x6f9c6338 - New handler enabled flag for retry loop\n  0xffffffe0 - Maximum allocation size (prevents overflow)\n  0xfffffff0 - Alignment mask for 16-byte boundary\n  0x6f9b403f - New handler function address\n\nNote: Function uses 2 phantom stack variables (local_8, local_28) optimized away by decompiler but cannot be typed through MCP tools",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:630b0e4f3169af3d32abd2ac2d1bf3c9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "630b0e4f3169af3d32abd2ac2d1bf3c9",
        "CFG": "f6198246dd10742dd31aa5cb380720a1",
        "PRO": "6b569ddd46dffe6a3187ce3ff084fa6a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "630b0e4f3169af3d32abd2ac2d1bf3c9"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_ADDR_6F9B2B72": {
      "addresses": {
        "LoD/PD2": "0x6F9B2B72"
      },
      "rvas": {
        "LoD/PD2": "0x2B72"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseMutexLock",
      "signature": "void ReleaseMutexLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases synchronization lock for heap memory allocation operations.\n\nAlgorithm:\n1. Push lock ID (4) onto stack as parameter\n2. Call ReleaseSynchronizationLock() to release the mutex\n3. Pop return address into ECX (thiscall cleanup)\n4. Return to caller\n\nReturns:\n  void (no return value)\n\nSpecial Cases:\n  Lock ID 4 is used to synchronize access to the small block heap (SBH)\n  allocator during memory allocation and reallocation operations.\n  This function is called by ReallocateMemoryWithHeapBackoff after\n  completing SBH block searches and allocation attempts.\n\nSynchronization:\n  This function releases a Windows kernel mutex (HANDLE or ID 4) that\n  was previously acquired. Used in conjunction with heap memory operations\n  to ensure thread-safe access to allocation data structures.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "eaa75ebafe78d0556378c475ff882fe6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_MNE_7fa238a0d1fe": {
      "addresses": {
        "LoD/PD2": "0x6F9B2BBC"
      },
      "rvas": {
        "LoD/PD2": "0x2BBC"
      },
      "sizes": {
        "LoD/PD2": 106
      },
      "name": "__msize",
      "signature": "size_t __msize(void * _Memory)",
      "calling_convention": "__cdecl",
      "comment": "Returns the size in bytes of a memory block allocated by malloc, calloc, or realloc.\n\nAlgorithm:\n\n1. Check if heap mode is small block heap (DAT_6f9c6864 == 3)\n2. If small block heap mode:\n   a. Acquire heap lock (index 4)\n   b. Search for block descriptor using ___sbh_find_block\n   c. If block found, extract size from block header at offset -4, subtract 9 bytes overhead\n   d. Release heap lock\n   e. Return calculated size if block was found\n3. If not small block heap or block not found:\n   a. Call Win32 HeapSize API with default heap handle\n   b. Return system-reported size\n\nParameters:\n_Memory: void* - Pointer to previously allocated memory block\n\nReturns:\nsize_t - Size in bytes of the memory block, or implementation-defined error value if invalid pointer\n\nSpecial Cases:\n- Magic Number 0x03: Small block heap mode indicator\n- Magic Number 0x09: Small block heap overhead (9 bytes per block)\n- Lock Index 4: Heap synchronization lock for small block heap operations\n\nError Handling:\n- Invalid pointers handled by Win32 HeapSize API\n- Small block heap failures fall back to system heap size query",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7fa238a0d1fe5549fc522252a2120d78",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7fa238a0d1fe5549fc522252a2120d78",
        "CFG": "8afe1dbf942c6c117dd7d41a44c33921",
        "PRO": "4d2f9b7faf94cbb786769c6085aaa9eb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7fa238a0d1fe5549fc522252a2120d78"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B2C29": {
      "addresses": {
        "LoD/PD2": "0x6F9B2C29"
      },
      "rvas": {
        "LoD/PD2": "0x2C29"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseLockAtIndex4",
      "signature": "void ReleaseLockAtIndex4(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases synchronization lock at fixed index 4.\n\nAlgorithm:\n1. Prepare parameter value 4 (lock index) on stack\n2. Call ReleaseSynchronizationLock with lock index 4\n3. Discard return value and return to caller\n\nReturns:\nNone (void return)\n\nSpecial Cases:\nThis is a convenience wrapper function that always releases the synchronization lock at index 4. The lock index is hardcoded as a constant, indicating this function has a specific synchronization responsibility in the codebase.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "e5038ffef0b4b86755c076c93524079f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_MNE_81bc6e282733": {
      "addresses": {
        "LoD/PD2": "0x6F9B2C32"
      },
      "rvas": {
        "LoD/PD2": "0x2C32"
      },
      "sizes": {
        "LoD/PD2": 553
      },
      "name": "__ValidateEH3RN",
      "signature": "int __ValidateEH3RN(void * pExceptionRecord)",
      "calling_convention": "__cdecl",
      "comment": "Validates Win32 structured exception handling registration record for Visual Studio 2003 runtime\n\nAlgorithm:\n\n1. Validate exception registration pointer alignment (must be 4-byte aligned)\n2. Check if registration pointer is within valid stack range (between StackLimit and StackBase)\n3. If try level is 0xffffffff (no active try blocks), return valid immediately\n4. Iterate through exception handler table and validate try levels in ascending order\n5. Verify any referenced previous exception record is within stack bounds\n6. Check if registration address is in cached safe address list for performance\n7. Query memory protection attributes using VirtualQuery to validate executable region\n8. Verify the module is a valid PE image with correct headers (DOS + NT + Optional)\n9. Check if exception registration is within the module's exception directory section\n10. Add validated address to LRU cache for future fast lookups with thread-safe updates\n\nParameters:\n  pExceptionRecord - Pointer to Win32 EXCEPTION_REGISTRATION_RECORD structure\n\nReturns:\n  0 - Invalid registration record (alignment, bounds, or security violation)\n  1 - Valid registration record\n  0xffffffff - System error during validation (VirtualQuery failure)\n\nSpecial Cases:\n  - Immediate validation for 0xffffffff try level (no active exception handling)\n  - Thread-safe caching with InterlockedExchange for performance optimization\n  - PE header validation prevents execution of non-image memory regions\n  - Exception directory flag (0x80) must be set for valid exception handling sections\n\nMagic Numbers Reference:\n  0xffffffff - No active try blocks marker\n  0x5a4d - DOS header signature (\"MZ\")\n  0x4550 - NT header signature (\"PE\")\n  0x10b - Optional header magic for PE32\n  0x1000000 - MEM_IMAGE memory type for executable modules\n  0xcc - PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY protection mask\n  0x80 - IMAGE_SCN_MEM_EXECUTE section characteristic flag\n\nError Handling:\n  - Returns 0 for any alignment or bounds validation failure\n  - Returns 0xffffffff for VirtualQuery system call failures\n  - Returns 0 for non-PE images or missing exception directory\n  - Thread-safe cache updates prevent race conditions in multi-threaded scenarios\n\nStructure Layout:\n  EXCEPTION_REGISTRATION_RECORD (12 bytes):\n  Offset Size Field Name           Type                    Description\n  +0x00   4   pNext               void*                   Next registration record\n  +0x04   4   pHandler            ExceptionHandler*       Exception handler function pointer  \n  +0x08   4   dwTryLevel          uint                    Current try block level (0xffffffff = none)\n  +0x0c   N   HandlerData         uint[]                  Variable-length handler-specific data\n\n  _MEMORY_BASIC_INFORMATION (28 bytes):\n  Offset Size Field Name           Type                    Description\n  +0x00   4   BaseAddress         void*                   Base address of region\n  +0x04   4   AllocationBase      void*                   Base address of allocation\n  +0x08   4   AllocationProtect   uint                    Initial protection attributes\n  +0x0c   4   RegionSize          uint                    Size of region in bytes\n  +0x10   4   State               uint                    Memory state (committed/reserved/free)\n  +0x14   4   Protect             uint                    Current protection attributes\n  +0x18   4   Type                uint                    Memory type (private/mapped/image)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:81bc6e2827332721bcd73a06db9fcb5a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "81bc6e2827332721bcd73a06db9fcb5a",
        "CFG": "f9330eca16acc1a586f19080607b798c",
        "PRO": "34fd04205b8a444137721574d896b028"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "81bc6e2827332721bcd73a06db9fcb5a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_1c8e05375765": {
      "addresses": {
        "LoD/PD2": "0x6F9B2E5B"
      },
      "rvas": {
        "LoD/PD2": "0x2E5B"
      },
      "sizes": {
        "LoD/PD2": 208
      },
      "name": "___freetlocinfo",
      "signature": "void ___freetlocinfo(void * pThreadLocaleInfo)",
      "calling_convention": "__cdecl",
      "comment": "Frees thread-local locale information structure and its associated data.\n\nAlgorithm:\n1. Check if lconv structure pointer at +0x3c is valid and not default\n2. Verify reference count at +0x2c base is zero (safe to free)\n3. Free monetary locale strings if reference count is zero\n   - Free string data at +0x34 if not default reference\n   - Call ___free_lconv_mon for monetary locale cleanup\n4. Free numeric locale strings if reference count is zero  \n   - Free string data at +0x30 if not default reference\n   - Call ___free_lconv_num for numeric locale cleanup\n5. Free lconv base structure at +0x2c\n6. Free lconv structure at +0x3c\n7. Check time locale data at +0x40 for validity and zero reference count\n8. Free time locale strings and calculated buffer at +0x44-0xfe\n9. Check time locale structure at +0x50 for validity and zero reference count\n10. Call ___free_lc_time for time locale cleanup\n11. Free time locale structure at +0x50\n12. Free the main thread locale info structure\n\nParameters:\npThreadLocaleInfo (void *): Pointer to thread-local locale information structure\n\nReturns:\nvoid: No return value\n\nSpecial Cases:\n- Reference counting prevents freeing shared locale data\n- Default locale references (DAT_6f9c6358, DAT_6f9c660c, DAT_6f9c6610, DAT_6f9c6608, DAT_6f9c6354) are not freed\n- Offset calculation +0x44-0xfe suggests buffer with header\n\nMagic Numbers Reference:\n0x2c - Offset to lconv base pointer\n0x30 - Offset to numeric locale strings pointer  \n0x34 - Offset to monetary locale strings pointer\n0x3c - Offset to lconv structure pointer\n0x40 - Offset to time locale data pointer\n0x44 - Offset to time buffer pointer\n0x50 - Offset to time locale structure pointer\n0xfe - Buffer header size for time locale buffer\n0x2d - Reference count offset in time locale structure (0x2d * 4 = 0xb4 bytes)\n\nStructure Layout:\nOffset  Size  Field Name               Type           Description\n+0x2c   4     pLconvBase              void *         Base lconv structure\n+0x30   4     pNumericStrings         void *         Numeric locale strings  \n+0x34   4     pMonetaryStrings        void *         Monetary locale strings\n+0x3c   4     pLconvStruct            void *         Main lconv structure\n+0x40   4     pTimeData               void *         Time locale data\n+0x44   4     pTimeBuffer             void *         Time locale buffer\n+0x50   4     pTimeStruct             void *         Time locale structure\n\nError Handling:\n- NULL pointer checks prevent crashes on invalid data\n- Reference count validation ensures shared data safety\n- Default reference comparisons prevent freeing static data",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1c8e05375765f5055ce29f9161a94626",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1c8e05375765f5055ce29f9161a94626",
        "CFG": "2a44c087b9d456adf3f7fe671334cd08",
        "PRO": "51affe9666153b68cd343cdc4ae41610"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "1c8e05375765f5055ce29f9161a94626"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_81fc8ecddc12": {
      "addresses": {
        "LoD/PD2": "0x6F9B2F2B"
      },
      "rvas": {
        "LoD/PD2": "0x2F2B"
      },
      "sizes": {
        "LoD/PD2": 193
      },
      "name": "___updatetlocinfo_lk",
      "signature": "int ___updatetlocinfo_lk(void)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: int UpdateThreadLocaleInfoLocked(void)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:81fc8ecddc12cc08d3d848c0224bdeb0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "81fc8ecddc12cc08d3d848c0224bdeb0",
        "CFG": "392d205942cc2d85569365d80a19246a",
        "PRO": "4e7a131d13ef30e7810595bc6bc49f47"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "81fc8ecddc12cc08d3d848c0224bdeb0"
      }
    },
    "D2sound_MNE_202d2c66c8a5": {
      "addresses": {
        "LoD/PD2": "0x6F9B2FEC"
      },
      "rvas": {
        "LoD/PD2": "0x2FEC"
      },
      "sizes": {
        "LoD/PD2": 50
      },
      "name": "___updatetlocinfo",
      "signature": "pthreadlocinfo ___updatetlocinfo(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___updatetlocinfo\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:202d2c66c8a5b404ad3bf64c94b499c1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "202d2c66c8a5b404ad3bf64c94b499c1",
        "CFG": null,
        "PRO": "f14e33562e187291d4d9c6168fab11ad"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "202d2c66c8a5b404ad3bf64c94b499c1"
      }
    },
    "D2sound_ADDR_6F9B301E": {
      "addresses": {
        "LoD/PD2": "0x6F9B301E"
      },
      "rvas": {
        "LoD/PD2": "0x301E"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseTlocInfoLock",
      "signature": "void ReleaseTlocInfoLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the thread-local information (tlocinfo) synchronization lock.\n\nThis function is called at the end of critical sections that need thread-local\ninformation updates. It releases the lock with index 0xc (12) from the global\ncritical section array to allow other threads to access thread-local data.\n\nAlgorithm:\n1. Push the constant lock index 0xc (12) onto the stack\n2. Call ReleaseSynchronizationLock(0xc) to release the tlocinfo lock\n3. Pop the return value from the stack (EBX register cleanup)\n4. Return to caller\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Lock index 0xc is hardcoded for tlocinfo synchronization\n- Used in conjunction with __lock(0xc) calls in multi-threaded contexts\n- Part of the Visual Studio runtime thread-local storage mechanism\n- Typically called from ___updatetlocinfo after updating thread-local info",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "6be173b894c736cd0e39cddb1849d888"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_MNE_ef80c025e383": {
      "addresses": {
        "LoD/PD2": "0x6F9B3027"
      },
      "rvas": {
        "LoD/PD2": "0x3027"
      },
      "sizes": {
        "LoD/PD2": 47
      },
      "name": "GetLocaleStringClassFlags",
      "signature": "uint GetLocaleStringClassFlags(uint codePageId)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: uint GetLocaleStringClassFlags(uint codePageId)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ef80c025e3831b06764dc8da4f7409c0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ef80c025e3831b06764dc8da4f7409c0",
        "CFG": "2a488c3194a25d9369db633e01c010f2",
        "PRO": "510c8731d2ed770a518dbde211133926"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ef80c025e3831b06764dc8da4f7409c0"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_3586df3e31dd": {
      "addresses": {
        "LoD/PD2": "0x6F9B3056"
      },
      "rvas": {
        "LoD/PD2": "0x3056"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "setSBCS",
      "signature": "void setSBCS(void)",
      "calling_convention": "__cdecl",
      "comment": "Initializes Single-Byte Character Set (SBCS) data structures to zero state.\n\nAlgorithm:\n1. Initialize pointer to start of SBCS buffer array at 0x6f9c6640\n2. Clear 0x40 (64) DWORD elements in the buffer array using loop\n3. Clear final byte after the DWORD array\n4. Zero additional SBCS-related global variables\n5. Return to caller\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nvoid - no return value\n\nSpecial Cases:\nLoop processes exactly 0x40 (64) DWORD elements\nFinal byte clear handles alignment or padding after main array\nMultiple global variables suggest complex SBCS state management\n\nGlobal Variables Cleared:\n0x6f9c6640: SBCS buffer array (256 bytes = 64 DWORDs + 1 byte)\n0x6f9c6744: SBCS state variable\n0x6f9c6638: SBCS state variable  \n0x6f9c6630: SBCS state variable\n0x6f9c6750: SBCS state variable\n0x6f9c6754: SBCS state variable\n0x6f9c6758: SBCS state variable\n\nMagic Numbers Reference:\n0x40 (64 decimal): Number of DWORD elements to clear in main buffer\n0x6f9c6640: Base address of SBCS buffer array\n0x6f9c6744: SBCS global state variable address\n0x6f9c6638: SBCS global state variable address\n0x6f9c6630: SBCS global state variable address\n0x6f9c6750: SBCS global state variable address\n0x6f9c6754: SBCS global state variable address\n0x6f9c6758: SBCS global state variable address",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3586df3e31dd0bc0a688e61a43024ab7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3586df3e31dd0bc0a688e61a43024ab7",
        "CFG": null,
        "PRO": "e3454126f517547c159122c69595b92c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3586df3e31dd0bc0a688e61a43024ab7"
      }
    },
    "D2sound_MNE_9dba01f3a3f5": {
      "addresses": {
        "LoD/PD2": "0x6F9B307F"
      },
      "rvas": {
        "LoD/PD2": "0x307F"
      },
      "sizes": {
        "LoD/PD2": 411
      },
      "name": "InitializeCaseConversionTables",
      "signature": "void InitializeCaseConversionTables(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes case conversion lookup tables for character mapping operations.\n\nAlgorithm:\n1. Load stack canary value from global DAT_6f9c56c0 and XOR with EBP for stack protection\n2. Call GetCPInfo to retrieve code page information for current locale using DAT_6f9c6744\n3. If GetCPInfo succeeds (returns 1):\n   a. Initialize character table with identity mapping (0x00-0xFF)\n   b. Set character 0x00 to space character (0x20)\n   c. Parse LeadByte array from CPINFO to identify multi-byte character ranges\n   d. For each lead byte range, fill corresponding positions with spaces (0x20)\n   e. Call ___crtGetStringTypeA to classify characters (alpha, digit, etc.)\n   f. Call ConvertStringCaseWithCodePage twice to transform characters (uppercase/lowercase mappings)\n   g. Iterate through 256 characters and populate global tables based on character class\n4. If GetCPInfo fails:\n   a. Use hardcoded ASCII logic: A-Z maps to uppercase, a-z maps to lowercase\n   b. Non-alphabetic characters are cleared to null\n5. Verify stack canary and call VerifyStackCanary for cleanup\n6. Return\n\nParameters:\nvoid - No parameters required\n\nReturns:\nvoid - Function populates global data tables and returns no value\n\nSpecial Cases:\n- Multi-byte character handling: LeadByte array in CPINFO defines ranges where range length + 1 spaces are written to character table\n- Character type flags: Bit 0 (0x01) = alpha, Bit 1 (0x02) = digit, used to select mapping table\n- Global tables populated: DAT_6f9c6760 (character mapping), DAT_6f9c6640/DAT_6f9c6641 (flags)\n- Stack protection: XOR-based canary check using DAT_6f9c56c0\n- Code page ID stored in DAT_6f9c6744, used for locale-specific operations\n\nStructure Layout:\nOffset  Size  Field Name              Type         Description\n======  ====  ====================    ===========  ================================\n-0x518  4     Stack frame base        uint         ESP after PUSH EBP allocation\n-0x80   20    cpinfo_struct           _cpinfo      Code page information (CPINFO)\n-0x6c   108   awCharTypeArray         ushort[54]   Character type classification array\n-0x44   256   abCharTable             char[256]    Source character identity table\n+0x194  256   abLowerCaseTable        char[256]    Lowercase mapping table\n+0x294  256   abUpperCaseTable        char[256]    Uppercase mapping table\n+0x494  404   abStackGuard            byte[404]    Stack overflow protection buffer\n+0x4a0  4     dwCanaryValue           uint         Stack canary (XOR protected)\n\nNote: Function uses 2 stack-allocated temporary variables (local_506, local_508) that were optimized away by decompiler but remain in assembly view.\n\nMagic Numbers Reference:\n0x01 - Character type flag: alphabetic character\n0x02 - Character type flag: digit character\n0x10 - Global flag: uppercase character mapping\n0x20 - Global flag: lowercase/digit character mapping\n0x20 - Space character (0x20) used for multi-byte lead ranges\n0x41-0x5A - ASCII uppercase range (A-Z)\n0x61-0x7A - ASCII lowercase range (a-z)\n0x100 - Character table size (256 entries)\n0x200 - Lowercase transformation flag for ConvertStringCaseWithCodePage",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9dba01f3a3f519a348d690b818dfa854",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9dba01f3a3f519a348d690b818dfa854",
        "CFG": "ad4a19780b8be02c8fca99bc1df0158e",
        "PRO": "15f049e1ded264838bce3ab8d630b45d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9dba01f3a3f519a348d690b818dfa854"
      }
    },
    "D2sound_MNE_3b865c2f933c": {
      "addresses": {
        "LoD/PD2": "0x6F9B321A"
      },
      "rvas": {
        "LoD/PD2": "0x321A"
      },
      "sizes": {
        "LoD/PD2": 404
      },
      "name": "InitializeCodePageTables",
      "signature": "void InitializeCodePageTables(UINT codePage)",
      "calling_convention": "__cdecl",
      "comment": "Initialize character classification tables for the specified code page.\n\nAlgorithm:\n1. Retrieve security cookie from global for stack overflow detection\n2. If codePage is non-zero, search predefined code page table (0x6f9c55c8) for match\n3. If found, use predefined SBCS/MBCS ranges from table at 0x6f9c55d8 to initialize\n   classification table at 0x6f9c6640 with 4-byte range pairs per code page\n4. If not found, call GetCPInfo() to retrieve Windows CP info structure\n5. If GetCPInfo() succeeds, process CP info lead byte ranges into classification flags:\n   - Flag 0x4 marks lead bytes (first byte of 2-byte sequence)\n   - Flag 0x8 marks trail bytes (second byte of 2-byte sequence)\n   - Store lead byte ranges from CPINFO.LeadByte array\n6. Call GetLocaleStringClassFlags() to initialize locale-specific flags\n7. Call InitializeCaseConversionTables() to set up uppercase/lowercase mappings\n8. If codePage is zero or GetCPInfo() fails, call setSBCS() for single-byte fallback\n9. Verify stack cookie and return\n\nParameters:\n  codePage (EBP+0x8): UINT - Windows code page identifier (e.g., 932 for Shift-JIS)\n\nReturns:\n  void - Modifies global code page tables and character classification arrays\n\nSpecial Cases:\n  - Zero codePage triggers SBCS fallback path\n  - GetCPInfo() failure is handled by checking global DAT_6f9c6330 flag\n  - Predefined tables used for 16 known code pages (8 entries \u00d7 2 bytes each)\n  - Lead byte ranges stored as inclusive start/end pairs in CPINFO structure\n  - Classification table at 0x6f9c6640 is 257 bytes (1 header + 256 char classes)\n\nStack-based Security:\n  - Global security cookie (0x6f9c56c0) XORed with stack frame pointer\n  - Verified on return before function exit via FUN_6f9b47e5()",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3b865c2f933cac7b684f56d2d74a981a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3b865c2f933cac7b684f56d2d74a981a",
        "CFG": "e2269d40f31f586675d1d99f276d60c1",
        "PRO": "3bea418b16f69335f5d1b23c5a96dd39"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3b865c2f933cac7b684f56d2d74a981a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_3d9593887473": {
      "addresses": {
        "LoD/PD2": "0x6F9B33AE"
      },
      "rvas": {
        "LoD/PD2": "0x33AE"
      },
      "sizes": {
        "LoD/PD2": 327
      },
      "name": "__setmbcp",
      "signature": "int __setmbcp(int _CodePage)",
      "calling_convention": "__cdecl",
      "comment": "Sets the multibyte code page used by the C runtime library for character conversion operations.\n\nAlgorithm:\n\n1. Initialize return code to -1 (failure) and acquire multibyte code page lock (0xD)\n2. Reset global MBCP state flag (DAT_6f9c6330) to 0\n3. Handle special code page constants:\n   - -2: Use OEM code page (GetOEMCP)\n   - -3: Use ANSI code page (GetACP) \n   - -4: Use thread-specific code page (DAT_6f9c6398)\n4. Check if requested code page matches current (DAT_6f9c6744):\n   - If match: Set return code to 0 (success) and exit\n   - If different: Continue to initialize new code page tables\n5. Allocate or reuse MBCP buffer (0x220 bytes):\n   - If existing buffer is unused (*DAT_6f9c6634 == 0): Reuse it\n   - Otherwise: Allocate new buffer via malloc(0x220)\n6. Initialize code page tables by calling InitializeCodePageTables\n7. If initialization succeeds (return 0):\n   - Mark buffer as used (*_Memory = 0)\n   - Store previous code page state (old CP, lead byte table, trail byte table)\n   - Copy 5 lead byte ranges from DAT_6f9c6750 to buffer+0x10\n   - Copy 257 lead byte flags from DAT_6f9c6640 to buffer+0x1C\n   - Copy 256 trail byte flags from DAT_6f9c6760 to buffer+0x11D\n   - Update global MBCP buffer pointer (DAT_6f9c6634)\n8. If initialization failed and allocated new buffer: Free the buffer\n9. Release MBCP lock and return status code\n\nParameters:\n\n_CodePage (int): Code page identifier or special constant:\n  - Valid CP: 437, 932, 949, 950, 1252, etc.\n  - -2: Use OEM code page\n  - -3: Use ANSI code page  \n  - -4: Use thread code page\n\nReturns:\n\n0: Success - Code page set successfully\n-1: Failure - Invalid code page or initialization error\n\nSpecial Cases:\n\nMagic Numbers Reference:\n- 0xD (13): MBCP lock identifier for synchronization\n- 0x220 (544): Size of MBCP buffer containing tables and state\n- -2: OEM_CODE_PAGE constant\n- -3: ACP_CODE_PAGE constant  \n- -4: THREAD_CODE_PAGE constant\n- 0x10: Offset to lead byte ranges (5 * 2 bytes)\n- 0x1C: Offset to lead byte flags (257 bytes)\n- 0x11D: Offset to trail byte flags (256 bytes)\n\nError Handling:\n\n- Invalid code page: InitializeCodePageTables returns non-zero\n- Memory allocation failure: malloc returns NULL, function returns -1\n- Lock acquisition handles thread synchronization automatically\n\nMBCP Buffer Layout (544 bytes):\n\nOffset  Size  Field Name           Type    Description\n0x00    4     fUsed               int     Buffer usage flag (0=used, 1=free)  \n0x04    4     nPrevCodePage       int     Previous code page number\n0x08    4     pPrevLeadTable      int*    Previous lead byte table pointer\n0x0C    4     pPrevTrailTable     int*    Previous trail byte table pointer\n0x10    10    awLeadRanges        ushort[5] Lead byte range pairs (start,end)\n0x1C    257   abLeadFlags         byte[257] Lead byte classification flags\n0x11D   256   abTrailFlags        byte[256] Trail byte classification flags\n\nNote: Function uses 4 stack-allocated temporary variables (local_8, local_20, local_24, local_28) that were optimized away by decompiler but remain visible in assembly analysis.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3d95938874732b844e73905e6c952bdf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3d95938874732b844e73905e6c952bdf",
        "CFG": "d245bd9dbf65e94abcf0220b460866eb",
        "PRO": "5b9733bf23f697f3c1bba0fb0dd294d7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3d95938874732b844e73905e6c952bdf"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B34F5": {
      "addresses": {
        "LoD/PD2": "0x6F9B34F5"
      },
      "rvas": {
        "LoD/PD2": "0x34F5"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "ReleaseMBCPLock",
      "signature": "void ReleaseMBCPLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the multibyte codepage synchronization lock (lock ID 0xd).\n\nAlgorithm:\n1. Push lock identifier (0xd) onto stack as parameter\n2. Call ReleaseSynchronizationLock to release the lock\n3. Clean up stack with POP ECX (stdcall cleanup)\n4. Return to caller\n\nReturns:\nvoid - No return value; performs synchronous lock release\n\nSpecial Cases:\nLock ID 0xd (13) - Specific synchronization lock tied to MBCP initialization\nCalling context: Invoked during __setmbcp initialization to ensure thread-safe codepage setup",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "85ee04971d7bd852fb5e42e601e86750"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "D2sound_MNE_a4ba30fe4414": {
      "addresses": {
        "LoD/PD2": "0x6F9B34FE"
      },
      "rvas": {
        "LoD/PD2": "0x34FE"
      },
      "sizes": {
        "LoD/PD2": 30
      },
      "name": "___initmbctable",
      "signature": "undefined4 ___initmbctable(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize multibyte character table support for the runtime library.\n\nAlgorithm:\n1. Check if multibyte character table is already initialized (DAT_6f9c6994 flag)\n2. If not initialized, call __setmbcp(-3) to set default code page\n3. Set initialization flag to prevent re-initialization\n4. Return success status (0)\n\nParameters:\nNone\n\nReturns:\n0 - Success, multibyte character table initialized or already initialized\n\nSpecial Cases:\n- Code page -3 indicates system default ANSI code page\n- Function is idempotent - safe to call multiple times\n- Initialization flag prevents redundant __setmbcp calls\n\nMagic Numbers Reference:\n0x6f9c6994 - Global initialization flag (0=uninitialized, 1=initialized)\n-3 (0xFFFFFFFD) - System default ANSI code page identifier\n0 - Success return code\n\nError Handling:\nThis function cannot fail - always returns success\n__setmbcp errors are not propagated to caller\nAssumes __setmbcp will handle invalid code page internally",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a4ba30fe4414581a89a628d047ff2406",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a4ba30fe4414581a89a628d047ff2406",
        "CFG": "1abbbed88598ab76171d956e8b753f75",
        "PRO": "554e40cd06cfc61fcf4dd0b0f9a80203"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a4ba30fe4414581a89a628d047ff2406"
      }
    },
    "D2sound_MNE_288a4a209e47": {
      "addresses": {
        "LoD/PD2": "0x6F9B351C"
      },
      "rvas": {
        "LoD/PD2": "0x351C"
      },
      "sizes": {
        "LoD/PD2": 72
      },
      "name": "___sbh_heap_init",
      "signature": "bool ___sbh_heap_init(uint dwHeapSize)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: bool ___sbh_heap_init(uint dwHeapSize)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:288a4a209e4706fee9d14eabda44517a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "288a4a209e4706fee9d14eabda44517a",
        "CFG": "e8304c2afda95740a391a275b6b161fd",
        "PRO": "f230b0cbeba844ede03ce48f393a637d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "288a4a209e4706fee9d14eabda44517a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_565997ae4f13": {
      "addresses": {
        "LoD/PD2": "0x6F9B3564"
      },
      "rvas": {
        "LoD/PD2": "0x3564"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "___sbh_find_block",
      "signature": "uint ___sbh_find_block(void * pAddress)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: uint ___sbh_find_block(void * pAddress)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:565997ae4f137ad77dea012c57abbb1d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "565997ae4f137ad77dea012c57abbb1d",
        "CFG": "dc0623423d93fb21da8f1c1461d32590",
        "PRO": "3067e520a83fed024b1b141562b47539"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "565997ae4f137ad77dea012c57abbb1d"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_8b97ebec1e2b": {
      "addresses": {
        "LoD/PD2": "0x6F9B358F"
      },
      "rvas": {
        "LoD/PD2": "0x358F"
      },
      "sizes": {
        "LoD/PD2": 792
      },
      "name": "___sbh_free_block",
      "signature": "undefined ___sbh_free_block(uint * param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Frees a block in the Windows Small Block Heap (SBH) subsystem\n\nAlgorithm:\n1. Calculate region index and heap descriptor offsets from block address\n2. Extract block size from header at block address - 4\n3. Check if next block is free and coalesce if possible\n4. Remove next block from free list and update bitmasks\n5. Check if previous block is free and coalesce if possible\n6. Remove previous block from free list and update bitmasks\n7. Calculate new free block size class and insert into appropriate free list\n8. Update bitmasks to mark size class as having free blocks\n9. Update block headers with new size\n10. Decrement region allocation counter\n11. If region is empty, release virtual memory and cleanup data structures\n\nParameters:\nparam_1 (pHeapDescriptor): Pointer to heap descriptor array\nparam_2 (pBlockAddress): Address of block to free\nIMPLICIT: Uses global heap state variables DAT_6f9c6614, DAT_6f9c6618, etc.\n\nReturns:\nvoid - No return value, function always succeeds\n\nSpecial Cases:\nRegion cleanup occurs when allocation counter reaches zero\nVirtual memory is released in 0x8000 byte chunks (32KB regions)\nFree list management uses dual bitmasks for size classes 0-63\n\nMagic Numbers Reference:\n0x04: Block header size offset\n0x08: Previous block size offset  \n0x0f: Right shift for 16-byte alignment (size >> 4)\n0x1f: Mask for 32-bit positions in bitmask\n0x20: Boundary between lower and upper bitmask arrays\n0x3f: Maximum size class index (63)\n0x44: Offset to lower bitmask array in heap descriptor\n0x80000000: High bit mask for bitmask operations\n0xc4: Offset to upper bitmask array in heap descriptor\n0x204: Size of heap region descriptor structure\n0x4000: MEM_DECOMMIT flag for VirtualFree\n0x8000: MEM_RELEASE flag and region size (32KB)\n\nStructure Layout:\nBlock Header (at block_address - 4):\nOffset  Size  Field Name    Type    Description\n0x00    4     dwBlockSize   uint    Block size including header (bit 0 = allocated flag)\n0x04    4     dwPrevSize    uint    Previous block size (bit 0 = prev allocated flag)\n\nHeap Descriptor (pointed to by param_1):\nOffset  Size  Field Name        Type    Description  \n0x00    4     dwLowerBitmask    uint    Free list bitmask for size classes 0-31\n0x04    4     dwUpperBitmask    uint    Free list bitmask for size classes 32-63\n0x0c    4     pRegionBase       uint*   Base address of heap region\n0x10    4     pDescriptorData   uint*   Pointer to region descriptor data\n\nFlag Bits:\nBlock size bit 0: 0x01 = Block allocated, 0x00 = Block free\nPrevious size bit 0: 0x01 = Previous block allocated, 0x00 = Previous block free\n\nError Handling:\nFunction assumes valid parameters and heap state\nNo error checking on pointer dereferences\nRelies on caller validation of heap integrity",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8b97ebec1e2ba4f1376a18655897a974",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8b97ebec1e2ba4f1376a18655897a974",
        "CFG": "481581f05882ccfc9daa8b7d80599503",
        "PRO": "af5ffc5fef388ef1fe1b032e30adfc61"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8b97ebec1e2ba4f1376a18655897a974"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_8f7df14e6456": {
      "addresses": {
        "LoD/PD2": "0x6F9B38A7"
      },
      "rvas": {
        "LoD/PD2": "0x38A7"
      },
      "sizes": {
        "LoD/PD2": 183
      },
      "name": "___sbh_alloc_new_region",
      "signature": "undefined4 * ___sbh_alloc_new_region(void)",
      "calling_convention": "__stdcall",
      "comment": "Allocates a new heap region descriptor for the small block heap allocator.\n\nAlgorithm:\n1. Check if the heap region array needs expansion (DAT_6f9c6618 == DAT_6f9c6628)\n2. If expansion needed, reallocate the region descriptor array with HeapReAlloc\n3. Calculate pointer to new region descriptor entry in the array  \n4. Allocate heap data buffer (16,836 bytes) using HeapAlloc with HEAP_ZERO_MEMORY\n5. Allocate virtual memory region (1 MB) using VirtualAlloc with MEM_RESERVE\n6. Initialize region descriptor fields if both allocations succeed\n7. Increment active region counter and mark heap data buffer as available\n\nParameters:\nNone (void function)\n\nReturns:\nPointer to new heap region descriptor on success, NULL on failure\n- Success: Valid pointer to initialized HeapRegionDescriptor structure\n- Failure: NULL if HeapReAlloc, HeapAlloc, or VirtualAlloc fails\n\nSpecial Cases:\nHeap data allocation failure triggers cleanup of virtual memory allocation\nVirtual memory allocation failure triggers cleanup of heap data allocation\nArray expansion failure causes immediate return with NULL\n\nMagic Numbers Reference:\n0x41c4 (16,836): Size of heap data buffer allocation\n0x100000 (1,048,576): Size of virtual memory region (1 MB)\n0x2000 (MEM_RESERVE): VirtualAlloc allocation type for address space reservation\n0x4 (PAGE_READWRITE): VirtualAlloc protection for read/write access\n0x8 (HEAP_ZERO_MEMORY): HeapAlloc flag to zero-initialize allocated memory\n0x14 (20): Size of HeapRegionDescriptor structure\n0x10 (16): Array expansion increment for region descriptors\n0x50 (80): Base allocation size for region descriptor array calculation\n\nError Handling:\nImmediate NULL return on HeapReAlloc failure during array expansion\nCleanup sequence on partial allocation failure:\n- HeapAlloc failure: No cleanup needed, return NULL immediately\n- VirtualAlloc failure: Free heap data buffer with HeapFree, return NULL\n\nStructure Layout:\nHeapRegionDescriptor (20 bytes):\nOffset Size Field Name    Type      Description\n0x00   4    dwField0      DWORD     Status or index field  \n0x04   4    dwField1      DWORD     Usage counter or flags\n0x08   4    dwFreeMask    DWORD     Bit mask for free blocks (0xFFFFFFFF = all free)\n0x0C   4    pVirtualMem   LPVOID    Pointer to reserved virtual memory region\n0x10   4    pHeapData     LPVOID    Pointer to allocated heap data buffer\n\nGlobal Variables:\nDAT_6f9c6618: Current number of active heap regions\nDAT_6f9c6628: Maximum capacity of region descriptor array  \nDAT_6f9c661c: Pointer to region descriptor array\nDAT_6f9c6860: Process heap handle for allocations",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8f7df14e6456cd93f8028b09582e6071",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8f7df14e6456cd93f8028b09582e6071",
        "CFG": "cb06ff47489f56c99a3330662b09491b",
        "PRO": "1a09800574f523b35e9c2e44eaa0adc0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8f7df14e6456cd93f8028b09582e6071"
      }
    },
    "D2sound_MNE_c41f2d1f421c": {
      "addresses": {
        "LoD/PD2": "0x6F9B395E"
      },
      "rvas": {
        "LoD/PD2": "0x395E"
      },
      "sizes": {
        "LoD/PD2": 262
      },
      "name": "___sbh_alloc_new_group",
      "signature": "int ___sbh_alloc_new_group(void * pHeapControl)",
      "calling_convention": "__cdecl",
      "comment": "Allocates and initializes a new memory group in the small block heap manager.\n\nAlgorithm:\n1. Read heap control structure to get base data offset (pHeapControl+0x10)\n2. Calculate bit position by counting leading zeros in free group mask (pHeapControl+0x8)\n3. Calculate group descriptor offset: bitPosition * 0x204 + 0x144 + heapDataBase\n4. Initialize 64 free list headers in group descriptor (0x3F loop iterations)\n5. Calculate target virtual address: bitPosition * 0x8000 + baseAddress (pHeapControl+0xC)\n6. Allocate 32KB virtual memory at calculated address using VirtualAlloc\n7. If allocation succeeds, initialize page headers for memory management\n8. Update group descriptor with memory pointers and page management data\n9. Mark group as allocated in heap control arrays (offset 0x44 and 0xC4)\n10. Update group counter and heap status flags\n11. Clear corresponding bit in free group mask to mark group as used\n\nParameters:\npHeapControl - Pointer to heap control structure containing group management data\n    Offset 0x4:  Heap status flags\n    Offset 0x8:  Free group bitmask (32-bit)\n    Offset 0xC:  Base virtual address for group allocation\n    Offset 0x10: Base offset for heap data structures\n\nReturns:\nSuccess: Group index (0-31) indicating which group was allocated\nFailure: -1 if VirtualAlloc fails to reserve memory\n\nVariables:\nlocal_8 (nBitPosition): Bit position counter for group index calculation\nlocal_c (nGroupBaseOffset): Group descriptor base offset calculation\niVar2 (nHeapDataBase): Base address for heap data structures\niVar3 (nGroupOffset): Calculated offset to group descriptor\niVar8 (nBitPosition): Final bit position/group index returned\ncVar1 (chGroupCounter): Group allocation counter\npvVar5 (lpAllocatedMemory): Result from VirtualAlloc call\npiVar6 (pdwPageHeader): Pointer for page header initialization\nlpAddress (lpBaseAddress): Target virtual address for allocation\n\nMagic Numbers Reference:\n0x204 - Size of group descriptor structure (516 bytes)\n0x144 - Base offset to first group descriptor\n0x8000 - Size of each memory group (32KB)\n0x1000 - VirtualAlloc allocation granularity (4KB pages)\n0x7000 - Memory range for page header initialization (28KB)\n0x3F - Number of free list headers to initialize (63 lists)\n0x400 - Size increment for page header pointer (1KB blocks)\n0xFF0 - Page header size field value (4080 bytes usable)\n0x80000000 - High bit for bitmask operations\n\nError Handling:\n- VirtualAlloc failure returns -1 immediately\n- No validation of pHeapControl pointer (assumes valid)\n- Assumes sufficient virtual address space available\n\nSpecial Cases:\n- Bit position calculation handles signed/unsigned conversion for leading zero count\n- Page header initialization skipped if memory range is invalid\n- Group counter overflow triggers heap status flag update (bit 0)\n\nNote: Function uses 2 stack-allocated temporary variables (local_8, local_c) that could not be renamed due to Ghidra MCP connection timeouts but are documented in inline comments.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c41f2d1f421c471451958bea4a10fa66",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c41f2d1f421c471451958bea4a10fa66",
        "CFG": "9da21044a93ea42988ff0cc8748c8b85",
        "PRO": "24b3b60b3217878320538ab84b5a34c5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c41f2d1f421c471451958bea4a10fa66"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_71e3adec8688": {
      "addresses": {
        "LoD/PD2": "0x6F9B3A64"
      },
      "rvas": {
        "LoD/PD2": "0x3A64"
      },
      "sizes": {
        "LoD/PD2": 735
      },
      "name": "___sbh_resize_block",
      "signature": "int ___sbh_resize_block(uint * pHeapDesc, int nBlockAddr, int nNewSize)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: int ___sbh_resize_block(uint * pHeapDesc, int nBlockAddr, int nNewSize)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:71e3adec86883da683f0e423eb14e485",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "71e3adec86883da683f0e423eb14e485",
        "CFG": "44831bf0135800d99aae2e5c23264fe6",
        "PRO": "9d4530e9555e83f57626964e7f569fd3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "71e3adec86883da683f0e423eb14e485"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_fdd552c17b8c": {
      "addresses": {
        "LoD/PD2": "0x6F9B3D43"
      },
      "rvas": {
        "LoD/PD2": "0x3D43"
      },
      "sizes": {
        "LoD/PD2": 764
      },
      "name": "___sbh_alloc_block",
      "signature": "void * ___sbh_alloc_block(uint dwRequestedSize)",
      "calling_convention": "__cdecl",
      "comment": "Small block heap allocator - allocates memory blocks from pre-allocated heap regions\n\nAlgorithm:\n1. Calculate aligned size (dwRequestedSize + 23) & 0xfffffff0 for 16-byte alignment\n2. Compute size index ((aligned_size + 23) >> 4) - 1 for bucket classification  \n3. Generate bit masks for free block bitmap search in 64-bit space\n4. Search current region group for available free blocks using bitmap masks\n5. If no blocks found in current region, search from beginning of region array\n6. If still no blocks, search for regions with unallocated groups (group pointers == NULL)\n7. If no free groups found, allocate new heap region via ___sbh_alloc_new_region\n8. If new region allocated, create new group via ___sbh_alloc_new_group\n9. Locate specific group within region and find appropriate size bucket\n10. Extract free block from linked list, update bitmap if bucket becomes empty\n11. Split block if remainder is large enough, insert remainder into appropriate bucket\n12. Mark block boundaries with size headers for adjacent block coalescing\n13. Update region statistics and current allocation pointers\n14. Return pointer to usable memory (block + 4 bytes past header)\n\nParameters:\ndwRequestedSize (uint) - Number of bytes requested by application\n\nReturns:\nSuccess: Pointer to allocated memory block (aligned to 16-byte boundary)\nFailure: NULL if allocation fails (out of memory or region creation failed)\n\nSpecial Cases:\nMagic Numbers Reference:\n0x17 (23) - Alignment padding for 16-byte boundaries plus 4-byte header\n0xfffffff0 - 16-byte alignment mask  \n0x20 (32) - Bit position threshold for 64-bit bitmap split\n0x1f (31) - Bit mask for 32-bit register shift operations\n0x14 (20) - Size of heap region descriptor (5 DWORDs)\n0x31 (49) - Offset to high 32-bit bitmap in group structure  \n0x11 (17) - Offset to low 32-bit bitmap in group structure\n0x51 (81) - Base offset to free block list array in group\n0x81 (129) - Size of group structure in DWORDs\n0x3f (63) - Maximum size bucket index for free block classification\n\nError Handling:\n- Returns NULL if ___sbh_alloc_new_region fails to allocate new heap region\n- Returns NULL if ___sbh_alloc_new_group fails to create group in region\n- No error propagation to caller - allocation failure indicated by NULL return\n\nState Machine:\nState 1: Search current region group \u2192 State 2 if blocks found, State 3 if empty\nState 2: Allocate from found free block \u2192 State 7 (complete allocation)\nState 3: Search all region groups \u2192 State 4 if blocks found, State 5 if all full  \nState 4: Allocate from found group \u2192 State 7 (complete allocation)\nState 5: Search for unallocated groups \u2192 State 6 if found, State 8 if none\nState 6: Create new group \u2192 State 7 if successful, State 9 if failed\nState 7: Complete block allocation and return pointer\nState 8: Allocate new region \u2192 State 6 if successful, State 9 if failed\nState 9: Return NULL (allocation failed)\n\nStructure Layout:\nRegion Descriptor (20 bytes):\nOffset  Size  Field Name    Type     Description\n0       4     dwLowMask     uint     Free block bitmap (bits 0-31)\n4       4     dwHighMask    uint     Free block bitmap (bits 32-63)  \n8       4     dwUnused      uint     Unused field\n12      4     pNextRegion   uint*    Pointer to next region descriptor\n16      4     pGroupArray   uint*    Pointer to group array in region\n\nGroup Structure (516 bytes):\nOffset  Size  Field Name         Type     Description\n0       4     nActiveGroup       int      Currently active group index\n4-67    64    abGroupCounters    byte[64] Block count per size bucket\n68-131  64    adwLowBitmap       uint[16] Free bitmap low 32 bits per group\n132-195 64    adwHighBitmap      uint[16] Free bitmap high 32 bits per group  \n196-515 320   aFreeLists         uint[64][2] Free block list heads per size",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fdd552c17b8cb0117d531882b003b7d1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fdd552c17b8cb0117d531882b003b7d1",
        "CFG": "e7a6cc0f7e2b744a49f409c722178a75",
        "PRO": "525f3a108e1e63f879c0f76921501a7c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fdd552c17b8cb0117d531882b003b7d1"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_45d24cae1027": {
      "addresses": {
        "LoD/PD2": "0x6F9B403F"
      },
      "rvas": {
        "LoD/PD2": "0x403F"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "__callnewh",
      "signature": "int __callnewh(size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Invokes the new handler callback when memory allocation fails.\n\nThis function implements the C++ new handler mechanism for memory allocation failures.\nWhen an allocation request cannot be satisfied, this function checks if a custom\nnew handler has been registered and calls it with the requested size.\n\nAlgorithm:\n1. Check if global new handler function pointer is set (not NULL)\n2. If handler exists, call it with the requested allocation size\n3. If handler returns non-zero (success), return 1 to indicate retry\n4. If handler returns zero or no handler exists, return 0 to indicate failure\n\nParameters:\n_Size (size_t): The number of bytes that failed to allocate\n\nReturns:\n1 if new handler succeeded and allocation should be retried\n0 if no handler exists or handler failed\n\nSpecial Cases:\nIf DAT_6f9c6334 (global new handler pointer) is NULL, returns 0 immediately\n\nImplementation Notes:\n- This is a Visual Studio 2003 Release runtime library function\n- Used by memory allocation functions like malloc() when allocation fails\n- The new handler callback allows applications to free memory or take other\n  recovery actions before retrying allocation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:45d24cae1027649da4393ef4c4f0d99b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "45d24cae1027649da4393ef4c4f0d99b",
        "CFG": "c514545fcce289b8241e149ad12d442a",
        "PRO": "acdc2d85c8b4b980a65bd4282fdf59fe"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "45d24cae1027649da4393ef4c4f0d99b"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_cb39780517b1": {
      "addresses": {
        "LoD/PD2": "0x6F9B4060"
      },
      "rvas": {
        "LoD/PD2": "0x4060"
      },
      "sizes": {
        "LoD/PD2": 96
      },
      "name": "_memset",
      "signature": "void * _memset(void * _Dst, int _Val, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Standard C library memory fill function - fills memory block with specified byte value\n\nAlgorithm:\n\n1. Return immediately if size is zero, preserving destination pointer\n2. Extract low byte from value parameter (mask with 0xFF)  \n3. Check if size > 3 bytes for optimization opportunity\n4. Calculate alignment offset: bytes needed to reach 4-byte boundary\n5. Perform byte-wise fill for unaligned leading bytes until aligned\n6. Replicate byte value to 32-bit pattern (multiply by 0x1010101)\n7. Calculate 32-bit word count and remaining byte count\n8. Perform optimized 32-bit word fill using STOSD instruction\n9. Handle remaining trailing bytes with byte-wise fill\n10. Return original destination pointer\n\nParameters:\n_Dst: void * - Destination buffer to fill (input/output buffer)\n_Val: int - Fill value, only low byte used (0x00-0xFF effective range)\n_Size: size_t - Number of bytes to fill (0 = no-op)\n\nReturns:\nOriginal destination pointer (_Dst) for function chaining\n\nSpecial Cases:\nSize of 0: Immediate return without memory modification\nSize 1-3: Byte-wise fill only, no alignment optimization\nUnaligned destination: Leading bytes filled individually until 4-byte aligned\n\nMagic Numbers Reference:\n0xFF (255): Byte extraction mask for value parameter\n0x1010101 (16843009): 32-bit replication pattern for byte fill\n3: Alignment boundary check and mask value\n4: Bytes per 32-bit word for optimized filling\n2: Right shift count for converting bytes to word count\n\nError Handling:\nNo error conditions - function always succeeds\nNo validation of destination pointer (caller responsibility)\nNo bounds checking (standard C library behavior)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cb39780517b1dd8e5312f6fce0a00812",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cb39780517b1dd8e5312f6fce0a00812",
        "CFG": "f4bdde520e5b2b37a12d35e86743d21a",
        "PRO": "8f4a15c4b513a8fca512bba10b0d7d63"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "cb39780517b1dd8e5312f6fce0a00812"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_70593f43ea0b": {
      "addresses": {
        "LoD/PD2": "0x6F9B40C0"
      },
      "rvas": {
        "LoD/PD2": "0x40C0"
      },
      "sizes": {
        "LoD/PD2": 7
      },
      "name": "CopyStringWithAlignment",
      "signature": "uint * CopyStringWithAlignment(uint * destinationBuffer, uint * sourceString)",
      "calling_convention": "__cdecl",
      "comment": "String copy thunk with alignment handling\n\nAlgorithm:\n1. Save EDI register state\n2. Load destination pointer from ESP+8 into EDI\n3. Jump to alignment checking and copy loop at 0x6f9b4135\n\nParameters:\n- pDestination (ESP+8): Pointer to destination buffer\n- pSource (ESP+C): Pointer to source string\n\nReturns:\n- EAX: pDestination pointer\n\nNotes:\nThis is a thunk wrapper that sets up EDI and jumps to shared string copy code. The actual implementation handles alignment-based optimization for efficient copying.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:70593f43ea0b0d7692df2cd60ddf29e8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "70593f43ea0b0d7692df2cd60ddf29e8",
        "CFG": null,
        "PRO": "c08d053e6ad00eb22c78950f79f8409b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "70593f43ea0b0d7692df2cd60ddf29e8"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_f1c393de2fac": {
      "addresses": {
        "LoD/PD2": "0x6F9B40D0"
      },
      "rvas": {
        "LoD/PD2": "0x40D0"
      },
      "sizes": {
        "LoD/PD2": 232
      },
      "name": "CopyStringWithAlignment",
      "signature": "char * CopyStringWithAlignment(char * destinationBuffer, char * sourceString)",
      "calling_convention": "__cdecl",
      "comment": "Copies source string to destination buffer with optimized word-aligned memory operations.\n\nAlgorithm:\n1. Align source pointer to 4-byte boundary by byte-copying unaligned prefix bytes\n2. While copying prefix, check each byte for null terminator and jump to final write if found\n3. When source reaches 4-byte alignment, switch to DWORD-based null detection:\n   - Load 4 bytes and apply null-detection formula: (word XOR 0xffffffff) XOR (word + 0x7efefeff)\n   - Result is non-zero if any byte in word is 0x00 (null byte detected)\n4. If no null bytes in DWORD, copy full 4-byte word to destination and continue loop\n5. When null byte detected in DWORD, determine exact position of null byte:\n   - Test byte 0 (low byte): if 0x00, null at position 0, write 1 byte + exit\n   - Test byte 1: if 0x00, null at position 1, write 2 bytes + exit\n   - Test byte 2: if 0x00, null at position 2, write 2 bytes + null terminator at +2 + exit\n   - Otherwise null at position 3, continue copying full DWORD\n6. Return original destination buffer pointer\n7. Magic constant 0x7efefeff combined with XOR creates SIMD-like null byte detection\n8. Destination pointer incremented after each copy to maintain position\n\nParameters:\ndestinationBuffer (char *): Output buffer where source string will be copied; caller responsible for buffer size\nsourceString (char *): Input null-terminated string to copy from memory\n\nReturns:\nchar *: Returns original destinationBuffer pointer (parameter 1, unchanged from input)\n\nSpecial Cases:\n- Source unaligned: Byte-by-byte copy until 4-byte alignment achieved\n- Null in unaligned prefix: Jump directly to write final byte and return\n- Partial DWORD at end: Use WORD or BYTE writes when null detected mid-DWORD\n- Register reuse: EDI preserves destination pointer throughout function\n- No bounds checking: Caller must ensure destinationBuffer has sufficient capacity\n\nStructure Layout:\nNone - Function operates on raw byte/word/dword memory granularity without accessing structured data",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f1c393de2fac70496494aea734de5675",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f1c393de2fac70496494aea734de5675",
        "CFG": "70cbe8ffa88cf8c3027c9b733713e450",
        "PRO": "9507df991f535c513ad9f49c8a2bd9cf"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f1c393de2fac70496494aea734de5675"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_2b72785c7d09": {
      "addresses": {
        "LoD/PD2": "0x6F9B41C0"
      },
      "rvas": {
        "LoD/PD2": "0x41C0"
      },
      "sizes": {
        "LoD/PD2": 139
      },
      "name": "_strlen",
      "signature": "size_t _strlen(char * _Str)",
      "calling_convention": "__cdecl",
      "comment": "Standard optimized strlen implementation that processes strings efficiently.\n\nAlgorithm:\n1. Check string alignment (first 1-3 bytes individually if unaligned)\n2. Process 4 bytes at once using bitwise magic for null detection\n3. Use formula (x ^ 0xffffffff ^ x + 0x7efefeff) & 0x81010100 to detect nulls\n4. When null detected, examine each byte to find exact position\n5. Return calculated length as difference from original pointer\n\nParameters:\n_Str (char *): Null-terminated string to measure\n\nReturns:\nsize_t: Length of string in characters (excluding null terminator)\n\nMagic Numbers Reference:\n0x7efefeff - Magic constant for null detection algorithm\n0x81010100 - Mask to isolate null detection bits\n0xffffffff - Bitwise complement for null detection formula\n\nNote: Function uses 1 stack-allocated temporary variable optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2b72785c7d09e5484d16dae5407e64ce",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2b72785c7d09e5484d16dae5407e64ce",
        "CFG": "6f990822ff7ab6fc4a0354777e2d7dbb",
        "PRO": "d22f820629540bc8910916bef725460e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2b72785c7d09e5484d16dae5407e64ce"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_378e464c3884": {
      "addresses": {
        "LoD/PD2": "0x6F9B4250"
      },
      "rvas": {
        "LoD/PD2": "0x4250"
      },
      "sizes": {
        "LoD/PD2": 672
      },
      "name": "_memcpy",
      "signature": "void * _memcpy(void * _Dst, void * _Src, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Optimized memory copy function that handles overlapping buffers and alignment optimization.\n\nAlgorithm:\n\n1. Check for memory overlap between source and destination buffers\n2. If overlap detected (src < dst < src + size), perform backward copy to avoid corruption\n3. For backward copy: calculate end pointers and copy from end to start\n4. Check destination alignment and optimize copy strategy accordingly\n5. For aligned destinations: use 32-bit (DWORD) copies when possible\n6. For unaligned destinations: handle byte-by-byte alignment, then switch to DWORD copies\n7. Handle remaining bytes after DWORD operations using switch-case unrolled loop\n8. Return original destination pointer\n\nParameters:\n\n_Dst (void *): Destination buffer pointer where data will be copied\n_Src (void *): Source buffer pointer containing data to copy  \n_Size (size_t): Number of bytes to copy from source to destination\n\nReturns:\n\nvoid *: Original destination pointer (_Dst) for chaining operations\nNever returns NULL - always returns input destination pointer\n\nSpecial Cases:\n\nSize 0: Immediate return without copy operation\nSize 1-3: Byte-by-byte copy using switch-case unrolled loop\nLarge aligned copies: REP MOVSD instruction for maximum performance\nOverlapping buffers: Backward copy prevents data corruption\nUnaligned destinations: Prefix alignment bytes then DWORD copy optimization\n\nMagic Numbers Reference:\n\n0x03 (3): Alignment mask for 4-byte boundary checking\n0x04 (4): DWORD size for pointer arithmetic and loop calculations  \n0x07 (7): Loop unroll threshold - switch to REP MOVSD for 8+ DWORDs\nswitchD_6f9b440b: Backward copy byte remainder handling switch table\nswitchD_6f9b4285: Forward copy byte remainder handling switch table\n\nError Handling:\n\nNo error conditions - function always succeeds\nOverlap detection prevents buffer corruption automatically\nZero-size copy handled as no-op with immediate return\nAll memory access assumes valid pointers within process space",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:378e464c38840f3332fec8fa0fd86d30",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "378e464c38840f3332fec8fa0fd86d30",
        "CFG": "79aa166d4e034da66a36436bb5eed9bd",
        "PRO": "7653a0379a0a6445458757cd7dbea6be"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "378e464c38840f3332fec8fa0fd86d30"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_STR_d73f4455ba8d": {
      "addresses": {
        "LoD/PD2": "0x6F9B458D"
      },
      "rvas": {
        "LoD/PD2": "0x458D"
      },
      "sizes": {
        "LoD/PD2": 249
      },
      "name": "___crtMessageBoxA",
      "signature": "int ___crtMessageBoxA(LPCSTR _LpText, LPCSTR _LpCaption, UINT _UType)",
      "calling_convention": "__cdecl",
      "comment": "Cross-platform MessageBox wrapper that dynamically loads user32.dll and handles OS-specific window parenting\n\nAlgorithm:\n1. Check if MessageBoxA function pointer is cached; if not, proceed to load\n2. Load user32.dll library using LoadLibraryA\n3. Get MessageBoxA function pointer via GetProcAddress  \n4. Get GetActiveWindow function pointer for window management\n5. Get GetLastActivePopup function pointer for proper parent window handling\n6. For Windows 2000+, get GetUserObjectInformationA and GetProcessWindowStation for interactive desktop detection\n7. Check if running on interactive desktop by calling GetProcessWindowStation and GetUserObjectInformationA\n8. Set appropriate message box style flags: MB_SERVICE_NOTIFICATION (0x40000) for pre-NT4, MB_SERVICE_NOTIFICATION_NT3X (0x200000) for NT4+\n9. Call MessageBoxA with determined parent window handle and modified flags\n\nParameters:\n_LpText (LPCSTR): Message text to display in the dialog box\n_LpCaption (LPCSTR): Title bar caption text\n_UType (UINT): MessageBox type flags (MB_OK, MB_YESNO, etc.)\n\nReturns:\nint: MessageBox return value (IDOK, IDYES, IDNO, etc.) or 0 on failure\n\nSpecial Cases:\n- Returns 0 immediately if user32.dll fails to load or MessageBoxA cannot be resolved\n- On non-interactive desktops (services), adds MB_SERVICE_NOTIFICATION flags to ensure visibility\n- Handles both Windows 95/98 and NT family differences in service notification behavior\n\nMagic Numbers Reference:\n0x40000 (262144): MB_SERVICE_NOTIFICATION flag for Windows 95/98/ME\n0x200000 (2097152): MB_SERVICE_NOTIFICATION_NT3X flag for Windows NT family  \n0xc (12): Size of USER_OBJECT_FLAGS structure for GetUserObjectInformationA\nUOI_FLAGS (1): Information type parameter for GetUserObjectInformationA\n\nVariable Documentation:\nlocal_8 (pdwRequiredSize): 4-byte output buffer receiving required size from GetUserObjectInformationA\nlocal_c (bFlags): Flags byte from GetUserObjectInformationA, bit 0 indicates interactive desktop\nlocal_14 (abInfoBuffer): 8-byte buffer for GetUserObjectInformationA window station information",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:d73f4455ba8d6ae05bafe5684bccdb5a",
      "indexes": {
        "EXP": null,
        "STR": "d73f4455ba8d6ae05bafe5684bccdb5a",
        "API": null,
        "MNE": "17ea33ac44dc56c9bc7a10bf336c7377",
        "CFG": "48c4d3f6309b34670773430b1e53bf7f",
        "PRO": "aad7451aeda17fd5d003e1e5ad014f5c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "17ea33ac44dc56c9bc7a10bf336c7377"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_3c09a404c09b": {
      "addresses": {
        "LoD/PD2": "0x6F9B4690"
      },
      "rvas": {
        "LoD/PD2": "0x4690"
      },
      "sizes": {
        "LoD/PD2": 292
      },
      "name": "_strncpy",
      "signature": "char * _strncpy(char * _Dest, char * _Source, size_t _Count)",
      "calling_convention": "__cdecl",
      "comment": "Copy specified number of characters from source to destination with null padding.\n\nAlgorithm:\n1. Return destination immediately if count is zero\n2. Handle unaligned source pointer by copying bytes until 4-byte aligned\n3. Detect null terminator during alignment and pad remainder with nulls\n4. Process aligned source in 4-byte chunks using DWORD reads for efficiency  \n5. Use bit manipulation (value ^ 0xffffffff ^ value + 0x7efefeff) & 0x81010100 to detect null bytes within DWORD\n6. When null detected, copy partial DWORD up to null position and pad remainder\n7. Fall back to byte-by-byte copy for final 1-3 bytes not fitting in DWORD\n8. Pad any remaining destination bytes with null characters\n\nParameters:\n_Dest (char *): Destination buffer pointer\n_Source (char *): Source string pointer  \n_Count (size_t): Maximum number of characters to copy\n\nReturns:\nchar *: Pointer to destination buffer (_Dest parameter)\n\nSpecial Cases:\nIf _Count is 0, returns _Dest without copying\nIf source string shorter than _Count, pads remainder with null bytes\nUnlike strcpy, always copies exactly _Count bytes (including padding)\n\nMagic Numbers Reference:\n0x7efefeff: Magic constant for null byte detection in DWORD\n0x81010100: Mask for isolating null detection bits\n0xffffffff: XOR mask for null detection algorithm\n0x3: Alignment mask for checking 4-byte boundaries\n\nAlgorithm Verification:\nStep 1 (Count check): if (_Count == 0) return _Dest\nStep 2 (Alignment): while (((uint)_Source & 3) != 0) copy bytes  \nStep 3 (DWORD processing): Process _Count >> 2 DWORDs with null detection\nStep 4 (Remainder): Copy final _Count & 3 bytes individually\nStep 5 (Padding): Fill remaining destination with nulls after source null found",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3c09a404c09b60148d7501f511aba84d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3c09a404c09b60148d7501f511aba84d",
        "CFG": "782ce5006ee7d6c9c45a4019c9674507",
        "PRO": "7512d896e852491c699dd1f38170f73e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3c09a404c09b60148d7501f511aba84d"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_9fd359b66679": {
      "addresses": {
        "LoD/PD2": "0x6F9B47B4"
      },
      "rvas": {
        "LoD/PD2": "0x47B4"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "report_failure",
      "signature": "void report_failure(void)",
      "calling_convention": "__cdecl",
      "comment": "Security failure handler that reports critical security violations and terminates the process\n\nAlgorithm:\n1. Report security error with error code 1 via ReportSecurityError\n2. Terminate the process immediately with exit code 3 via ExitProcess\n3. Function never returns (execution stops at step 2)\n\nParameters:\nNone\n\nReturns:\nvoid - Function never returns (marked with noreturn attribute)\n\nSpecial Cases:\n- Function is part of the Visual Studio 2003 runtime security framework\n- Uses structured exception handling (__SEH_prolog injection)\n- Process termination is immediate and non-recoverable\n- Exit code 3 indicates security policy violation\n\nMagic Numbers Reference:\n0x01 (1) - Security error type identifier for ReportSecurityError\n0x03 (3) - Exit code indicating security violation termination\n\nError Handling:\n- No error handling - function terminates process immediately\n- Part of security enforcement mechanism, not recoverable error path\n\nNote: Function uses 1 stack-allocated temporary variable optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9fd359b66679d8b6a2f1c57a264fe596",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9fd359b66679d8b6a2f1c57a264fe596",
        "CFG": "5ce001a4856ee460707e48535a6b9def",
        "PRO": "33a375b844e4f6035ed19393fa123f17"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9fd359b66679d8b6a2f1c57a264fe596"
      }
    },
    "D2sound_MNE_4efdd923a388": {
      "addresses": {
        "LoD/PD2": "0x6F9B47E5"
      },
      "rvas": {
        "LoD/PD2": "0x47E5"
      },
      "sizes": {
        "LoD/PD2": 14
      },
      "name": "VerifyStackCanary",
      "signature": "void VerifyStackCanary(uint canaryValue)",
      "calling_convention": "__fastcall",
      "comment": "Validates a stack canary value for overflow protection.\n\nALGORITHM:\n1. Compare the provided canary value (in ECX register) with the global canary constant\n2. If values match, return immediately (stack is intact)\n3. If values don't match, call report_failure() to abort execution\n\nPARAMETERS:\n- canaryValue (uint): The canary value to validate (passed in ECX via __fastcall)\n\nRETURNS:\n- void: Returns normally if canary is valid\n\nSPECIAL CASES:\n- Stack corruption detected: Calls report_failure() which terminates the process\n- Global canary: DAT_6f9c56c0 contains the expected canary value\n- Security function: Part of stack overflow protection mechanism used throughout binary\n\nUSAGE CONTEXT:\nCalled at function epilogues to verify that the stack has not been corrupted.\nUsed by 19+ callers including ModularExponentiate, HandleFloatingPointException,\nParseDecimalString, and ConvertSignificandToMantissa functions.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4efdd923a388be710585d381cbbbfb83",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4efdd923a388be710585d381cbbbfb83",
        "CFG": "74c44fff4d24f318587f22fc1085febb",
        "PRO": "d91907b6c5454ff9987e9d6f8b6455da"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4efdd923a388be710585d381cbbbfb83"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_6b4ad6d2941b": {
      "addresses": {
        "LoD/PD2": "0x6F9B47F3"
      },
      "rvas": {
        "LoD/PD2": "0x47F3"
      },
      "sizes": {
        "LoD/PD2": 400
      },
      "name": "___free_lc_time",
      "signature": "void ___free_lc_time(void * * ppvLocaleTimeData)",
      "calling_convention": "__cdecl",
      "comment": "Frees all dynamically allocated memory in a locale time data structure\n\nAlgorithm:\n1. Check if the locale time data pointer is not NULL\n2. Free each string pointer stored in the structure array (43 total pointers)\n3. Free abbreviated day names (indices 0-6)\n4. Free full day names (indices 7-13, with index 7 freed after 13)  \n5. Free abbreviated month names (indices 14-25)\n6. Free full month names (indices 26-37)\n7. Free AM/PM strings (indices 38-39)\n8. Free date/time format strings (indices 40-42)\n9. Return void\n\nParameters:\nppvLocaleTimeData - Pointer to array of char* pointers containing locale-specific strings\n                   Each element points to dynamically allocated string data\n                   Structure contains 43 pointer elements (indices 0x00-0x2a)\n\nReturns:\nvoid - No return value, performs cleanup only\n\nSpecial Cases:\n- If ppvLocaleTimeData is NULL, function returns immediately without action\n- Each individual pointer in array may be NULL - _free() handles NULL pointers safely\n- Order of freeing is not strictly sequential (index 7 freed after 13)\n\nStructure Layout:\nOffset  Size  Field Name        Type     Description\n0x00    4     day0_abbrev      char*    Sunday abbreviated\n0x04    4     day1_abbrev      char*    Monday abbreviated  \n0x08    4     day2_abbrev      char*    Tuesday abbreviated\n0x0C    4     day3_abbrev      char*    Wednesday abbreviated\n0x10    4     day4_abbrev      char*    Thursday abbreviated\n0x14    4     day5_abbrev      char*    Friday abbreviated\n0x18    4     day6_abbrev      char*    Saturday abbreviated\n0x1C    4     day0_full        char*    Sunday full name\n0x20    4     day1_full        char*    Monday full name\n0x24    4     day2_full        char*    Tuesday full name\n0x28    4     day3_full        char*    Wednesday full name\n0x2C    4     day4_full        char*    Thursday full name\n0x30    4     day5_full        char*    Friday full name\n0x34    4     day6_full        char*    Saturday full name\n0x38    4     mon0_abbrev      char*    January abbreviated\n0x3C    4     mon1_abbrev      char*    February abbreviated\n...     ...   ...              ...      (months 2-11 abbreviated)\n0x68    4     mon0_full        char*    January full name\n0x6C    4     mon1_full        char*    February full name\n...     ...   ...              ...      (months 2-11 full names)\n0x98    4     am_string        char*    AM string\n0x9C    4     pm_string        char*    PM string\n0xA0    4     datetime_fmt     char*    Date/time format\n0xA4    4     date_fmt         char*    Date format\n0xA8    4     time_fmt         char*    Time format",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6b4ad6d2941b712fcff606229e9dd829",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6b4ad6d2941b712fcff606229e9dd829",
        "CFG": "16240859bdc7d7fab8ddae4522c26ec9",
        "PRO": "d51fa1ceb75b6d7c49689142454c789f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6b4ad6d2941b712fcff606229e9dd829"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_f70a35b7fba7": {
      "addresses": {
        "LoD/PD2": "0x6F9B4983"
      },
      "rvas": {
        "LoD/PD2": "0x4983"
      },
      "sizes": {
        "LoD/PD2": 95
      },
      "name": "___free_lconv_num",
      "signature": "void ___free_lconv_num(char * * pplpszNumericFields)",
      "calling_convention": "__cdecl",
      "comment": "Frees dynamically allocated locale numeric formatting strings from lconv structure\n\nAlgorithm:\n1. Validate input pointer is not NULL\n2. For each of three numeric format fields (decimal point, thousands separator, grouping):\n   a. Load field pointer from array\n   b. Compare against default static string pointers\n   c. If not default, call _free() to deallocate\n3. Return without value\n\nParameters:\n  pplpszNumericFields - Pointer to array of 3 char* pointers containing numeric formatting strings\n                        [0] = decimal_point, [1] = thousands_sep, [2] = grouping\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - NULL input pointer: Function returns immediately without action\n  - Default/static strings: Not freed to avoid corrupting static data\n  - Checks against both global default table (PTR_PTR_6f9c57bc) and individual defaults\n\nStructure Layout:\nOffset  Size  Field Name      Type     Description\n------  ----  -------------   -------  ---------------------------\n0x00    4     decimal_point   char*    Decimal point string (e.g., \".\")\n0x04    4     thousands_sep   char*    Thousands separator (e.g., \",\")  \n0x08    4     grouping        char*    Grouping specification string\n\nGlobal References:\n  PTR_PTR_6f9c57bc - Pointer to global default lconv numeric field table\n  PTR_DAT_6f9c578c - Default decimal point static string\n  PTR_DAT_6f9c5790 - Default thousands separator static string\n  PTR_DAT_6f9c5794 - Default grouping static string",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f70a35b7fba7d58d54c96ad387278a4c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f70a35b7fba7d58d54c96ad387278a4c",
        "CFG": "cbfd3d0c7425038f32cd25a3cfec4b02",
        "PRO": "26fc788b1ae3beb7f82fe27118071bf9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f70a35b7fba7d58d54c96ad387278a4c"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_470047ed1f92": {
      "addresses": {
        "LoD/PD2": "0x6F9B49E2"
      },
      "rvas": {
        "LoD/PD2": "0x49E2"
      },
      "sizes": {
        "LoD/PD2": 217
      },
      "name": "___free_lconv_mon",
      "signature": "void ___free_lconv_mon(void * pLconvData)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void ___free_lconv_mon(void * pLconvData)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:470047ed1f9244aa874a163facc5cee5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "470047ed1f9244aa874a163facc5cee5",
        "CFG": "b6d31246179d73273008c43260a60774",
        "PRO": "0cd639647579e10fbedf1592f63f2f47"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "470047ed1f9244aa874a163facc5cee5"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_5f5a2dadfb6e": {
      "addresses": {
        "LoD/PD2": "0x6F9B4AC0"
      },
      "rvas": {
        "LoD/PD2": "0x4AC0"
      },
      "sizes": {
        "LoD/PD2": 70
      },
      "name": "_strcspn",
      "signature": "size_t _strcspn(char * _Str, char * _Control)",
      "calling_convention": "__cdecl",
      "comment": "Returns length of initial segment of string that contains NO characters from control set.\n\nAlgorithm:\n1. Initialize 256-bit bitmap (32 bytes) to track control characters\n2. Iterate through control string, setting bit for each character (bit = 1 << (char & 7) at byte index char >> 3)  \n3. Walk input string, checking each character against bitmap\n4. Return count when first control character found or string ends\n\nParameters:\n  _Str (char *): Input string to scan\n  _Control (char *): Set of characters to search for\n\nReturns:\n  size_t: Number of characters before first match with control set\n  0: If first character matches control set\n  strlen(_Str): If no control characters found in string\n\nSpecial Cases:\n  Empty control string: Returns strlen(_Str) - no characters to avoid\n  Empty input string: Returns 0\n  NULL pointers: Undefined behavior per C standard\n\nMagic Numbers Reference:\n  0x01: Bit mask for setting character presence in bitmap (1 << (char & 7))\n  0x07: Mask to get bit position within byte (char & 7)\n  0x03: Shift count to get byte index (char >> 3)\n  0xffffffff: Initial counter value (-1) for increment-first counting\n\nBitmap Layout:\nThe 32-byte bitmap maps 256 possible character values:\n  Byte 0: Characters 0-7 (bits 0-7)\n  Byte 1: Characters 8-15 (bits 0-7)\n  ...\n  Byte 31: Characters 248-255 (bits 0-7)\n  \nEach character C maps to: byte[C >> 3], bit (C & 7)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5f5a2dadfb6e3cd7b350f3b00225ebe0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5f5a2dadfb6e3cd7b350f3b00225ebe0",
        "CFG": "cb9a1745964aa8636af8400620dcb79c",
        "PRO": "d667f0767f80378deb40a8a7c758135e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5f5a2dadfb6e3cd7b350f3b00225ebe0"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_cf6e169535cd": {
      "addresses": {
        "LoD/PD2": "0x6F9B4B10"
      },
      "rvas": {
        "LoD/PD2": "0x4B10"
      },
      "sizes": {
        "LoD/PD2": 135
      },
      "name": "CompareAlignedStrings",
      "signature": "int CompareAlignedStrings(byte * pSource, byte * pTarget)",
      "calling_convention": "__cdecl",
      "comment": "Compares two null-terminated byte strings with alignment optimization.\n\nAlgorithm:\n1. Check if source pointer is unaligned (test bits 0-1 of source address)\n2. If odd alignment (bit 0 set), process single byte and advance both pointers\n3. If 2-byte unaligned (bit 1 set), process 2-byte word and advance pointers\n4. Once 4-byte aligned, enter main loop comparing 4 bytes at a time using DWORD loads\n5. Extract each byte from DWORD and compare sequentially with target bytes\n6. Return immediately on null terminator or byte mismatch\n7. Return 0 for equal strings or comparison result (-1/1) for differences\n\nParameters:\npSource - byte pointer to first string (may be unaligned on entry)\npTarget - byte pointer to second string for comparison\n\nReturns:\n0 - Strings are identical (all bytes match until null terminator)\n-1 - Source byte is less than corresponding target byte\n1 - Source byte is greater than corresponding target byte\n\nSpecial Cases:\nFunction handles arbitrary pointer alignment by processing unaligned bytes before \nentering optimized 4-byte comparison loop. Null terminator (0x00) immediately \nterminates comparison and returns equality. Comparison stops at first byte difference.\n\nMagic Numbers Reference:\n0x01 - Bit mask for odd-byte alignment check\n0x02 - Bit mask for 2-byte alignment check  \n0x03 - Combined mask for 4-byte alignment test\n0x08 - Bit shift for second byte extraction\n0x10 - Bit shift for third byte extraction\n0x18 - Bit shift for fourth byte extraction",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cf6e169535cd0b739256cb2ecfc119ba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cf6e169535cd0b739256cb2ecfc119ba",
        "CFG": "244d42c35cff0de8c78ffff48548cf5a",
        "PRO": "6827e29d467359e034ce8c9eee99ffe3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "cf6e169535cd0b739256cb2ecfc119ba"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_7cec3aaa3bf0": {
      "addresses": {
        "LoD/PD2": "0x6F9B4BA0"
      },
      "rvas": {
        "LoD/PD2": "0x4BA0"
      },
      "sizes": {
        "LoD/PD2": 184
      },
      "name": "CompareMemory",
      "signature": "int CompareMemory(void * buffer1, void * buffer2, uint length)",
      "calling_convention": "__cdecl",
      "comment": "Compares two memory buffers lexicographically, byte-by-byte.\n\nAlgorithm:\n1. Check if length is zero; if so, return 0 (equal)\n2. Check if both pointers are 4-byte aligned\n3. If aligned: compare 4-byte dwords in a loop using REPE CMPSD, then handle remaining bytes\n4. If unaligned: compare pairs of bytes in a loop until length exhausted\n5. Return comparison result: 0 if equal, negative if buffer1 < buffer2, positive otherwise\n\nParameters:\n- buffer1: First memory buffer to compare\n- buffer2: Second memory buffer to compare\n- length: Number of bytes to compare\n\nReturns:\n- 0: Both buffers are equal for the specified length\n- < 0: First buffer is lexicographically less than second (first differing byte is smaller)\n- > 0: First buffer is lexicographically greater than second (first differing byte is larger)\n\nSpecial Cases:\n- If length is 0, returns 0 (empty buffers are equal)\n- Unaligned pointers: falls back to byte-by-byte comparison\n- Partial dword comparisons: handles remaining 1-3 bytes after dword loop",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7cec3aaa3bf000edc30666bb4980e176",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7cec3aaa3bf000edc30666bb4980e176",
        "CFG": "dad2a753ae7c907198d5452c2cf5fedf",
        "PRO": "d63932be81b30027179e779219c52881"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7cec3aaa3bf000edc30666bb4980e176"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_fe7518f9cbca": {
      "addresses": {
        "LoD/PD2": "0x6F9B4C58"
      },
      "rvas": {
        "LoD/PD2": "0x4C58"
      },
      "sizes": {
        "LoD/PD2": 421
      },
      "name": "___crtGetStringTypeA",
      "signature": "BOOL ___crtGetStringTypeA(_locale_t _Plocinfo, DWORD _DWInfoType, LPCSTR _LpSrcStr, int _CchSrc, LPWORD _LpCharType, int _Code_page, BOOL _BError)",
      "calling_convention": "__cdecl",
      "comment": "Retrieves character type information for ANSI strings with locale and code page support\n\nAlgorithm:\n1. Initialize SEH frame and clear memory pointer\n2. Check global Unicode availability flag (DAT_6f9c63a0)\n3. If Unicode availability unknown (0), test with GetStringTypeW\n4. On ERROR_CALL_NOT_IMPLEMENTED (0x78), mark as ANSI-only (2)\n5. On success, mark as Unicode-capable (1)\n6. If ANSI-only mode or fallback required:\n   a. Resolve locale ID from parameter or global default\n   b. Resolve character type buffer from parameter or global default\n   c. Get ANSI code page from locale using GetLocaleAnsiCodePage\n   d. If code page conversion needed, call ConvertStringBetweenCodePages\n   e. Call GetStringTypeA with resolved parameters\n   f. Free allocated conversion buffer if used\n7. If Unicode mode available:\n   a. Calculate required buffer size with MultiByteToWideChar\n   b. Allocate stack or heap buffer for wide character conversion\n   c. Convert ANSI string to wide characters\n   d. Call GetStringTypeW with converted wide string\n   e. Free heap buffer if allocated\n8. Return success/failure status\n\nParameters:\n_Plocinfo (type: _locale_t) - Locale information structure pointer\n_DWInfoType (type: DWORD) - Character type information flags (CT_CTYPE1/2/3)\n_LpSrcStr (type: LPCSTR) - Source ANSI string to analyze\n_CchSrc (type: int) - Character count in source string (-1 for null-terminated)\n_LpCharType (type: LPWORD) - Output buffer for character type information\n_Code_page (type: int) - Code page identifier (0 for locale default)\n_BError (type: BOOL) - Error handling flag for MultiByteToWideChar\n\nReturns:\nTRUE (1) - Character type information retrieved successfully\nFALSE (0) - Operation failed (GetLastError for details)\n\nSpecial Cases:\nUnicode Availability Detection: First call tests GetStringTypeW capability\nCode Page Conversion: Automatic conversion between source and locale code pages\nBuffer Allocation: Dynamic stack/heap allocation for wide character conversion\nError Propagation: GetLastError preserved from underlying API calls\n\nMagic Numbers Reference:\n0x78 (120) - ERROR_CALL_NOT_IMPLEMENTED from GetStringTypeW\n0xffffffff (-1) - Invalid code page from GetLocaleAnsiCodePage\n0x6f9c63a0 - Global Unicode capability flag (0=unknown, 1=capable, 2=ANSI-only)\n0x6f9c6388 - Global default locale code page\n0x6f9c6398 - Global default character type buffer\n0x6f9bff7c - Test Unicode character for capability detection\n0x6f9bff80 - SEH frame base pointer\n\nError Handling:\nGetStringTypeW failure with 0x78 \u2192 Switch to ANSI-only mode\nGetLocaleAnsiCodePage returns -1 \u2192 Return FALSE\nConvertStringBetweenCodePages fails \u2192 Return FALSE  \nMultiByteToWideChar size calculation fails \u2192 Return FALSE\nMemory allocation failure \u2192 Return FALSE\nGetStringTypeA/W API failure \u2192 Return FALSE with preserved GetLastError",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fe7518f9cbcae43d3194d5d079593073",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fe7518f9cbcae43d3194d5d079593073",
        "CFG": "57a1818e074489c73b5b752558048ce6",
        "PRO": "003893f021d848cb0600a963254c49bc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fe7518f9cbcae43d3194d5d079593073"
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "D2sound_MNE_1ca444181aa4": {
      "addresses": {
        "LoD/PD2": "0x6F9B4E20"
      },
      "rvas": {
        "LoD/PD2": "0x4E20"
      },
      "sizes": {
        "LoD/PD2": 57
      },
      "name": "_strncmp",
      "signature": "int _strncmp(char * _Str1, char * _Str2, size_t _MaxCount)",
      "calling_convention": "__cdecl",
      "comment": "Compares up to a specified number of characters from two null-terminated strings.\n\nAlgorithm:\n1. Check if _MaxCount is zero - return 0 if no comparison needed\n2. Find the effective length of string1 up to _MaxCount characters\n3. Scan string1 using SCASB.REPNE to locate null terminator or reach max count\n4. Calculate actual comparison length from the scan results  \n5. Perform character-by-character comparison using CMPSB.REPE\n6. Compare bytes lexicographically until difference found or end reached\n7. Determine return value based on final character comparison:\n   - Return 0 if strings are equal within the specified length\n   - Return 1 if string1 > string2 (first differing char in str1 > str2)\n   - Return -1 if string1 < string2 (first differing char in str1 < str2)\n\nParameters:\n_Str1 (char *): Pointer to first null-terminated string to compare\n_Str2 (char *): Pointer to second null-terminated string to compare  \n_MaxCount (size_t): Maximum number of characters to compare\n\nReturns:\n0: Strings are identical within _MaxCount characters\n1 (0x00000001): _Str1 is lexicographically greater than _Str2\n-1 (0xFFFFFFFE): _Str1 is lexicographically less than _Str2\n\nSpecial Cases:\n- If _MaxCount is 0, returns 0 without any comparison\n- Comparison stops at first null terminator encountered in either string\n- Uses optimized x86 string instructions (SCASB, CMPSB) for performance\n- Handles unsigned byte comparison for proper lexicographic ordering\n\nAlgorithm Implementation Details:\n- SCASB.REPNE: Scan string1 for null terminator with AL=0, ECX=_MaxCount\n- NEG ECX; ADD ECX, _MaxCount: Calculate effective comparison length\n- CMPSB.REPE: Compare strings byte-by-byte while equal\n- Final comparison uses unsigned byte arithmetic for proper ordering",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1ca444181aa479bff1f1eb748b3a2663",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1ca444181aa479bff1f1eb748b3a2663",
        "CFG": "528877bfebb6cb7dc053ab3dc2930fa1",
        "PRO": "5940e08b79208ce6bdcd2695dac293d6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "1ca444181aa479bff1f1eb748b3a2663"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_262b55d4b1f2": {
      "addresses": {
        "LoD/PD2": "0x6F9B4E60"
      },
      "rvas": {
        "LoD/PD2": "0x4E60"
      },
      "sizes": {
        "LoD/PD2": 64
      },
      "name": "_strpbrk",
      "signature": "char * _strpbrk(char * _Str, char * _Control)",
      "calling_convention": "__cdecl",
      "comment": "Locates the first occurrence of any character from a control string in a target string.\n\nAlgorithm:\n\n1. Initialize 32-byte bit vector (256 bits) to zero for character lookup table\n2. Iterate through each character in control string (_Control)\n3. For each control character, set corresponding bit in lookup table:\n   - Calculate byte index: character_value >> 3 (divide by 8)\n   - Calculate bit position: character_value & 7 (modulo 8)\n   - Set bit using BTS instruction: table[byte_index] |= (1 << bit_position)\n4. Iterate through each character in target string (_Str)\n5. For each target character, check if bit is set in lookup table:\n   - Calculate byte index and bit position same as step 3\n   - Test bit using BT instruction: (table[byte_index] >> bit_position) & 1\n6. If bit is set (character found in control string), return pointer to current position\n7. If end of target string reached without match, return NULL\n\nParameters:\n\n_Str (char *): Null-terminated target string to search\n_Control (char *): Null-terminated control string containing characters to find\n\nReturns:\n\nchar *: Pointer to first character in _Str that matches any character in _Control\nNULL: If no characters from _Control are found in _Str, or if _Str is empty\n\nMagic Numbers Reference:\n\n0x03 (3): Right shift count to divide character value by 8 for byte index\n0x07 (7): Bit mask to get remainder when dividing by 8 for bit position  \n0x01 (1): Bit value to set in lookup table\n32: Size of bit vector array (256 bits / 8 bits per byte)",
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
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "262b55d4b1f21fd166621d0ca2135ed8"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_9202742c31e7": {
      "addresses": {
        "LoD/PD2": "0x6F9B4EA0"
      },
      "rvas": {
        "LoD/PD2": "0x4EA0"
      },
      "sizes": {
        "LoD/PD2": 912
      },
      "name": "ConvertStringCaseWithCodePage",
      "signature": "uint ConvertStringCaseWithCodePage(LCID localeId, uint caseMapFlags, LPCSTR sourceString, uint sourceStringLen, LPSTR destBuffer, int destBufferLen, UINT targetCodePage, int reserved)",
      "calling_convention": "__cdecl",
      "comment": "Converts a multi-byte string between code pages with locale-specific case mapping.\n\nAlgorithm:\n1. Check if Unicode case mapping is supported via global cache (DAT_6f9c63c8)\n2. If not cached, test Unicode support using LCMapStringW on sample data\n3. Calculate actual input string length (min of sourceStringLen and null terminator)\n4. If Unicode supported, use optimized Unicode path:\n   a. Convert source string to wide chars (MultiByteToWideChar)\n   b. Apply locale case mapping to wide chars (LCMapStringW)\n   c. If compatibility flag set, map back to destination buffer directly\n   d. Otherwise, convert wide chars to destination code page (WideCharToMultiByte)\n5. If Unicode not supported, use fallback ANSI path:\n   a. If source and dest code pages differ, convert via intermediate buffers\n   b. Get source code page using GetLocaleAnsiCodePage\n   c. Convert source string using ConvertStringBetweenCodePages if code pages differ\n   d. Apply locale case mapping to ANSI string (LCMapStringA)\n   e. Convert final result to destination code page if needed\n\nParameters:\n  localeId (LCID): Locale for case mapping operations. Defaults to system locale (DAT_6f9c6388)\n  caseMapFlags (uint): Case mapping flags for LCMapString (e.g., 0x400 for compatibility)\n  sourceString (LPCSTR): Input string to process\n  sourceStringLen (uint): Maximum length of input string (excluding null terminator)\n  destBuffer (LPSTR): Output buffer for result. NULL if only querying result length\n  destBufferLen (int): Size of output buffer in bytes. 0 if querying size\n  targetCodePage (UINT): Code page for output string. Defaults to system code page (DAT_6f9c6398)\n  reserved (int): Reserved parameter (unused)\n\nReturns:\n  uint: Length of result string in destination code page, or 0 on failure\n\nSpecial Cases:\n  - Returns 0 if Unicode not supported (error code 0x78 from GetLastError)\n  - Returns 0 if code page conversion fails via GetLocaleAnsiCodePage\n  - Allocates temporary buffers for intermediate conversions\n  - Validates destination buffer size before writing results\n  - Handles both stack-based and heap-allocated buffers for wide char data\n\nMagic Numbers Reference:\n  0x78 - ERROR_CALL_NOT_IMPLEMENTED for Unicode case mapping\n  0x400 - Compatibility flag for LCMapStringW\n  0x100 - LCMAP_UPPERCASE flag for LCMapStringW\n  0x8 - MB_ERR_INVALID_CHARS flag for MultiByteToWideChar\n\nError Handling:\n  - GetLastError() checks for unsupported Unicode operations\n  - NULL pointer validation for memory allocations\n  - Buffer size validation before string operations\n  - Proper cleanup of allocated memory in all code paths\n\nStructure Layout:\n  Stack allocation includes multiple frame pointers and SEH markers for exception handling\n  Temporary buffers created with alloca for Unicode intermediate data\n\nNote: Function uses 8 stack-allocated temporary variables optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9202742c31e7fad9c07478efa934202a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9202742c31e7fad9c07478efa934202a",
        "CFG": "2f1ef6c4c91c4ce0f83856db7c5571e4",
        "PRO": "5c1e22001557cee25a36bb9005334c9d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9202742c31e7fad9c07478efa934202a"
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "D2sound_ADDR_6F9B5280": {
      "addresses": {
        "LoD/PD2": "0x6F9B5280"
      },
      "rvas": {
        "LoD/PD2": "0x5280"
      },
      "sizes": {
        "LoD/PD2": 672
      },
      "name": "_memmove",
      "signature": "void * _memmove(void * _Dst, void * _Src, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memmove\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:378e464c38840f3332fec8fa0fd86d30",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "378e464c38840f3332fec8fa0fd86d30",
        "CFG": "8ecba1ac6a00afb63bf2cb6376fc859d",
        "PRO": "7653a0379a0a6445458757cd7dbea6be"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "378e464c38840f3332fec8fa0fd86d30"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_4af6f4d1378e": {
      "addresses": {
        "LoD/PD2": "0x6F9B55BD"
      },
      "rvas": {
        "LoD/PD2": "0x55BD"
      },
      "sizes": {
        "LoD/PD2": 102
      },
      "name": "___security_init_cookie",
      "signature": "void ___security_init_cookie(void)",
      "calling_convention": "__cdecl",
      "comment": "Initialize security cookie for stack buffer overflow protection.\n\nAlgorithm:\n1. Check if security cookie is uninitialized (0) or default value (0xbb40e64e)\n2. If cookie needs initialization, gather entropy sources:\n   - Get system time as FILETIME structure\n   - Get current process ID \n   - Get current thread ID\n   - Get system tick count since boot\n   - Query high-resolution performance counter\n3. XOR all entropy sources together to create unpredictable value\n4. Store result in global security cookie (DAT_6f9c56c0)\n5. If final result is 0, use default cookie value 0xbb40e64e\n\nParameters:\nNone\n\nReturns:\nNone (void function)\n\nSpecial Cases:\nIf the generated cookie equals 0 after XOR operations, the default value 0xbb40e64e is used instead to ensure the cookie is never 0.\n\nMagic Numbers Reference:\n0xbb40e64e - Default security cookie value used when generated value is 0",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4af6f4d1378e3b27617b296b4a2b16cc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4af6f4d1378e3b27617b296b4a2b16cc",
        "CFG": "290674f0d3e957f3a47123ff526d6d59",
        "PRO": "19d0d56bf5e60c5b4636becc08ffd2e9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4af6f4d1378e3b27617b296b4a2b16cc"
      }
    },
    "D2sound_STR_6829c7e2ecf5": {
      "addresses": {
        "LoD/PD2": "0x6F9B5623"
      },
      "rvas": {
        "LoD/PD2": "0x5623"
      },
      "sizes": {
        "LoD/PD2": 322
      },
      "name": "ReportSecurityError",
      "signature": "void ReportSecurityError(int errorType)",
      "calling_convention": "__stdcall",
      "comment": "Reports security errors and initiates failure recovery.\n\nThis function handles runtime security failure detection and reporting. It constructs\na detailed error message containing the module name and error description, then either\ncalls a registered exception handler or exits the process with status code 3.\n\nAlgorithm:\n1. Check for registered custom exception handler (DAT_6f9c63cc)\n2. If handler exists, call it with error type and module base address, then exit\n3. Otherwise, determine error type: buffer overrun (1) or unknown security failure\n4. Get module filename using GetModuleFileNameA API\n5. Validate module name length (max 60 chars after adding ellipsis)\n6. Build complete error message by concatenating:\n   - Error type description (source error string)\n   - Module name (with ellipsis if truncated)\n   - Detailed error description (local_12c)\n7. Display message box with constructed error string and title\n8. Exit process with status code 3\n\nParameters:\nerrorType - Type of security error (1 = buffer overrun, other = unknown)\n\nReturns:\nNone (calls __exit() which terminates process)\n\nSpecial Cases:\n- If GetModuleFileNameA fails, uses default string \"<program_name_unknown>\"\n- If module path + error message exceeds 60 chars, truncates with \"...\"\n- Custom handler can intercept error by being set in DAT_6f9c63cc\n- Stack canary (XOR with random value) validates stack integrity\n- String operations use alignment-aware copy functions",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:6829c7e2ecf5617d1af04a2d6d84fcdc",
      "indexes": {
        "EXP": null,
        "STR": "6829c7e2ecf5617d1af04a2d6d84fcdc",
        "API": null,
        "MNE": "d2d722438be70fcaec7b53793ce6e797",
        "CFG": "b59fc8dea41603647db3006d4848a690",
        "PRO": "9847a57e2d9626d7f8209e2429fb7cec"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d2d722438be70fcaec7b53793ce6e797"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_cb7271f23b18": {
      "addresses": {
        "LoD/PD2": "0x6F9B5770"
      },
      "rvas": {
        "LoD/PD2": "0x5770"
      },
      "sizes": {
        "LoD/PD2": 78
      },
      "name": "___ascii_stricmp",
      "signature": "int ___ascii_stricmp(char * lpszStr1, char * lpszStr2)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: int ___ascii_stricmp(char * lpszStr1, char * lpszStr2)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cb7271f23b18085c633325272e533a6a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cb7271f23b18085c633325272e533a6a",
        "CFG": "714fe86794460a92b7c07cd2854276e8",
        "PRO": "8ae050135f8e08ab82bf616fcc905546"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "cb7271f23b18085c633325272e533a6a"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_1bacf15d4212": {
      "addresses": {
        "LoD/PD2": "0x6F9B57BE"
      },
      "rvas": {
        "LoD/PD2": "0x57BE"
      },
      "sizes": {
        "LoD/PD2": 227
      },
      "name": "__resetstkoflw",
      "signature": "int __resetstkoflw(void)",
      "calling_convention": "__cdecl",
      "comment": "Resets stack overflow condition by adjusting memory protection and stack guard pages.\n\nAlgorithm:\n\n1. Query current stack location using VirtualQuery to get memory region information\n2. Retrieve system information to determine page size and allocation granularity  \n3. Calculate target base address aligned to page boundary minus one page\n4. Determine protection target address based on global guard page setting (DAT_6f9c6004)\n5. Validate calculated addresses are within valid range\n6. If guard pages disabled (DAT_6f9c6004 != 1):\n   - Iterate through memory regions starting from allocation base\n   - Find first committed region with MEM_COMMIT flag (0x1000)\n   - Check if region has PAGE_GUARD protection bit set\n   - If guard already present, return success (1)\n   - Validate target address is within found region boundaries\n   - Allocate new committed memory if needed using VirtualAlloc\n7. Apply memory protection using VirtualProtect with calculated flags\n8. Return protection operation result\n\nParameters:\n\n   (none) - Function takes no parameters, operates on current stack context\n\nReturns:\n\n   1 - Success, stack overflow condition reset\n   0 - Failure, unable to reset stack overflow condition\n   \nSpecial Cases:\n\n   - Early return 0 if VirtualQuery fails on stack address\n   - Early return 0 if calculated protection range invalid  \n   - Early return 1 if guard page already present when needed\n   - Uses conditional protection flags based on DAT_6f9c6004 global setting\n   \nMagic Numbers Reference:\n\n   0x1c - Size of MEMORY_BASIC_INFORMATION structure\n   0x1000 - MEM_COMMIT flag for VirtualAlloc and memory state check\n   0x103 - PAGE_EXECUTE_READWRITE protection when guard disabled  \n   0x1 - PAGE_NOACCESS protection when guard enabled\n   0x4 - PAGE_READWRITE protection for VirtualAlloc\n   0xfffffff1 - Mask for calculating page count based on guard setting\n   0x11 - Page count adjustment when guards enabled\n\nError Handling:\n\n   - VirtualQuery failure returns 0 immediately\n   - Memory region iteration failure returns 0\n   - Address validation failures return 0  \n   - VirtualProtect failure propagated via return value\n\nGlobal Dependencies:\n\n   DAT_6f9c6004 - Guard page configuration flag:\n     1 = Use guard pages with PAGE_NOACCESS protection\n     Other = Use execute permissions without guard pages",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1bacf15d421243740ab5a96b430ce3dc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1bacf15d421243740ab5a96b430ce3dc",
        "CFG": "6a2c6063242729d398ada1dbe6ac7b2b",
        "PRO": "d705c06f0d6a39d4a9512f47e8f074d3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "1bacf15d421243740ab5a96b430ce3dc"
      }
    },
    "D2sound_MNE_78a86de15981": {
      "addresses": {
        "LoD/PD2": "0x6F9B58A1"
      },
      "rvas": {
        "LoD/PD2": "0x58A1"
      },
      "sizes": {
        "LoD/PD2": 136
      },
      "name": "_atol",
      "signature": "long _atol(char * lpszStr)",
      "calling_convention": "__cdecl",
      "comment": "Converts a null-terminated string to a long integer value.\n\nAlgorithm:\n1. Get thread-local data and locale information for character classification\n2. Skip leading whitespace characters using locale-aware character type checking\n3. Parse optional sign character ('+' or '-') and advance past it\n4. Convert decimal digits to numeric value using base-10 arithmetic\n5. Apply sign to final result if negative sign was detected\n6. Return the converted long integer value\n\nParameters:\nlpszStr: char * - Null-terminated string containing the numeric representation\n\nReturns:\nlong - Converted integer value, or 0 if no valid conversion possible\n\nVariable Mapping (Hungarian Notation):\np_Var1 \u2192 pThreadData: Thread-local data structure pointer\nptVar2 \u2192 pLocaleInfo: Locale information structure pointer\nuVar3 \u2192 dwCharType: Character type flags from locale table\niVar4 \u2192 nResult: Accumulated numeric conversion result\nthis \u2192 pCharTypeTable: Pointer to character classification table\nuVar5 \u2192 chCurrent: Current character being processed\niVar6 \u2192 nDigitValue: Numeric value of current digit character\npbVar7 \u2192 pchNext: Pointer to next character in string\nextraout_ECX* \u2192 Register output artifacts (cannot be renamed)\n\nSpecial Cases:\n- Leading whitespace (spaces, tabs, newlines) are skipped\n- Optional '+' or '-' sign is supported\n- Conversion stops at first non-digit character\n- Invalid or empty strings return 0\n- No overflow checking is performed\n\nMagic Numbers Reference:\n0x2d (45): ASCII '-' minus sign character\n0x2b (43): ASCII '+' plus sign character  \n0x30 (48): ASCII '0' digit character base\n0x39 (57): ASCII '9' highest digit character\n8: Character type flag for whitespace in locale table\n\nError Handling:\n- Invalid characters cause conversion to stop and return partial result\n- No error indication is provided for overflow conditions\n- Relies on locale-specific character classification for whitespace detection",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:78a86de15981e3f1c945cde9fbd4be9b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "78a86de15981e3f1c945cde9fbd4be9b",
        "CFG": "f50e5479bfa840a829213102aed3c4ee",
        "PRO": "25bb0884bbaf4fb64f0ede52c46e5b73"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "78a86de15981e3f1c945cde9fbd4be9b"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_138cb9be9d7c": {
      "addresses": {
        "LoD/PD2": "0x6F9B5929"
      },
      "rvas": {
        "LoD/PD2": "0x5929"
      },
      "sizes": {
        "LoD/PD2": 71
      },
      "name": "GetLocaleAnsiCodePage",
      "signature": "int GetLocaleAnsiCodePage(LCID localeId)",
      "calling_convention": "__cdecl",
      "comment": "Retrieves the ANSI code page identifier for a specified locale.\n\nAlgorithm:\n1. Initialize stack canary for buffer overflow protection using XOR with frame pointer\n2. Query locale's default ANSI code page string via GetLocaleInfoA with LOCALE_IDEFAULTANSICODEPAGE (0x1004)\n3. If GetLocaleInfoA succeeds (returns non-zero), convert string result to integer using _atol\n4. If GetLocaleInfoA fails (returns zero), set return value to -1 (0xffffffff)\n5. Verify stack canary integrity before returning to detect stack corruption\n\nParameters:\n  localeId (LCID): Locale identifier for which to retrieve the ANSI code page\n\nReturns:\n  int: ANSI code page number (1200-65535) on success, or -1 (0xffffffff) on failure\n\nSpecial Cases:\n  - Returns -1 if GetLocaleInfoA fails (e.g., invalid locale ID)\n  - Returns -1 if buffer size insufficient (6 bytes requested for code page string)\n  - Stack canary verified via VerifyStackCanary to detect corruption",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:138cb9be9d7caeaaa6cff721ddf1f5fa",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "138cb9be9d7caeaaa6cff721ddf1f5fa",
        "CFG": "e6239802a5b3e3dd1f1be91f0d5c374d",
        "PRO": "d21e27d5496c8d58bc2cf35fc9850266"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "138cb9be9d7caeaaa6cff721ddf1f5fa"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_a82412e86c7e": {
      "addresses": {
        "LoD/PD2": "0x6F9B5970"
      },
      "rvas": {
        "LoD/PD2": "0x5970"
      },
      "sizes": {
        "LoD/PD2": 451
      },
      "name": "ConvertStringBetweenCodePages",
      "signature": "LPSTR ConvertStringBetweenCodePages(uint sourceCodePage, uint destCodePage, char * sourceString, uint * pOutputSize, LPSTR outputBuffer, int outputBufferSize)",
      "calling_convention": "__cdecl",
      "comment": "Converts a string from one Windows code page encoding to another via Unicode intermediate conversion.\n\nAlgorithm:\n1. Validate stack canary and initialize security structures\n2. Compare source and destination code pages - skip conversion if identical\n3. Call GetCPInfo on both code pages to validate they exist and get character info\n4. Check if both code pages are single-byte encodings (optimization path)\n5. Calculate required wide character buffer size via MultiByteToWideChar or strlen\n6. Allocate wide character buffer on stack (small) or heap (large >100 chars)\n7. Convert source string to wide characters via MultiByteToWideChar\n8. If no output buffer provided, allocate destination buffer via AllocateMemoryWithRetry\n9. Convert wide characters to destination encoding via WideCharToMultiByte\n10. Free allocated buffers and verify stack canary before return\n\nParameters:\nsourceCodePage (uint): Source encoding (CP_ACP=0, CP_UTF8=65001, etc.)\ndestCodePage (uint): Destination encoding identifier\nsourceString (char *): Input string in source encoding\npOutputSize (uint *): Input=max chars, Output=actual converted length\noutputBuffer (LPSTR): Destination buffer or NULL for allocation\noutputBufferSize (int): Size of destination buffer in bytes\n\nReturns:\nLPSTR: Pointer to converted string (allocated if outputBuffer was NULL)\nNULL: Conversion failed, invalid code pages, or allocation failure\n\nSpecial Cases:\n0xffffffff: Auto-calculate source string length using strlen\nSingle-byte optimization: Both code pages have MaxCharSize=1\nStack allocation: Wide buffer <=100 characters uses stack space\nHeap allocation: Wide buffer >100 characters allocated via AllocateMemoryWithRetry\n\nMagic Numbers Reference:\n0xffffffff (-1): Auto-calculate string length flag\n0x01: MB_PRECOMPOSED flag for MultiByteToWideChar\n0x64 (100): Stack allocation threshold for wide buffer\n0x00: Default flags for WideCharToMultiByte\n\nError Handling:\nGetCPInfo failure: Skip single-byte optimization, use full Unicode path\nMultiByteToWideChar failure: Return NULL, invalid source encoding\nAllocateMemoryWithRetry failure: Return NULL, insufficient memory\nWideCharToMultiByte failure: Free allocated buffer, return NULL\n\nNote: Function uses phantom stack variables optimized away by decompiler for intermediate calculations.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a82412e86c7e059d3af6ea9d376e2875",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a82412e86c7e059d3af6ea9d376e2875",
        "CFG": "ee35662907c919a1a51f142533be2ef6",
        "PRO": "0e3c9e5587581167b1bfb8179043c90b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a82412e86c7e059d3af6ea9d376e2875"
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "D2sound_MNE_99486f21581c": {
      "addresses": {
        "LoD/PD2": "0x6F9B5B4A"
      },
      "rvas": {
        "LoD/PD2": "0x5B4A"
      },
      "sizes": {
        "LoD/PD2": 58
      },
      "name": "_isdigit",
      "signature": "int _isdigit(int _C)",
      "calling_convention": "__cdecl",
      "comment": "Standard C library function to test if a character is a decimal digit (0-9).\n\nAlgorithm:\n1. Retrieve thread-specific data structure via __getptd()\n2. Extract locale information from thread data\n3. Check if locale information needs updating via ___updatetlocinfo()\n4. For multithreaded environments (refcount > 1):\n   - Call ___isctype_mt() with digit flag (0x04)\n5. For single-threaded environments:\n   - Directly access character type table at offset _C*2\n   - Apply digit mask (0x04) to get result\n\nParameters:\n_C (int): Character value to test (typically 0-255 for ASCII)\n\nReturns:\nNon-zero if character is digit (0-9), zero otherwise\n\nSpecial Cases:\nUses locale-aware character classification\nHandles both single and multithreaded runtime environments\nCharacter values outside valid range may cause undefined behavior\n\nMagic Numbers Reference:\n0x04: Digit classification flag in character type table\n0x02: Offset multiplier for character type table access",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:99486f21581ce5ab9e85ee964f03efa4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "99486f21581ce5ab9e85ee964f03efa4",
        "CFG": "3833f8519f41d53257998fecb01c68fd",
        "PRO": "bf5024923c95c0aa18c1f39dfc66e7c3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "99486f21581ce5ab9e85ee964f03efa4"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_e1a55473b8c8": {
      "addresses": {
        "LoD/PD2": "0x6F9B5B84"
      },
      "rvas": {
        "LoD/PD2": "0x5B84"
      },
      "sizes": {
        "LoD/PD2": 200
      },
      "name": "___tolower_mt",
      "signature": "uint ___tolower_mt(void * this, void * pThreadLocaleInfo, void * pLocaleData, uint nCharacter)",
      "calling_convention": "__thiscall",
      "comment": "Convert a character to lowercase using multi-threaded locale support\n\nAlgorithm:\n\n1. Check if locale is initialized (pThreadLocaleInfo+0x14 != 0)\n2. If locale uninitialized OR (has locale extension AND character < 0x80):\n   a. Check if character is ASCII uppercase letter (0x40 < char < 0x5b)\n   b. If yes, return character + 0x20 (convert A-Z to a-z)\n   c. Otherwise return original character unchanged\n3. For locale-specific conversion (non-ASCII or special locale):\n   a. Validate character is within Unicode range (< 0x100)\n   b. Check if character is uppercase using locale-specific ctype table\n   c. If pThreadLocaleInfo+0x28 < 2: Use direct table lookup at offset+0x48\n   d. If pThreadLocaleInfo+0x28 >= 2: Call ___isctype_mt for validation\n   e. If character is not uppercase, return original value\n4. Determine character encoding width:\n   a. Check if high byte needs special handling (*(pThreadLocaleInfo+0x48+1+((char>>8)&0xFF)*2) & 0x80)\n   b. If single-byte: Set up 1-byte conversion buffer\n   c. If multi-byte: Set up 2-byte conversion buffer with proper byte ordering\n5. Call ConvertStringCaseWithCodePage with:\n   a. LCID from pThreadLocaleInfo+0x14\n   b. Conversion flags 0x100 (lowercase)\n   c. Input character buffer\n   d. Character width (1 or 2 bytes)\n   e. Output buffer (local_8)\n   f. Output buffer size (3 bytes)\n   g. Code page from pThreadLocaleInfo+0x4\n   h. Conversion type 1 (to lowercase)\n6. Process conversion result:\n   a. If dwResult == 0: Conversion failed, return original character\n   b. If dwResult == 1: Single character result, return (local_8 & 0xFF)\n   c. If dwResult != 1: Multi-character result, return CONCAT11 of output bytes\n\nParameters:\npThreadLocaleInfo (void *) - Pointer to thread-specific locale context structure\npLocaleData (void *) - Pointer to locale data structure containing conversion tables\nnCharacter (uint) - Character value to convert to lowercase\n\nIMPLICIT: Uses 'this' pointer for thread context in __thiscall convention\n\nReturns:\nuint - Converted lowercase character on success, original character if conversion fails or not needed\n\nSpecial Cases:\n- ASCII fast path: Characters 0x41-0x5A (A-Z) directly converted to 0x61-0x7A (a-z)\n- Characters >= 0x80 require locale-specific processing\n- Characters >= 0x100 are processed but may not convert properly\n- Multi-byte characters use DBCS conversion logic\n\nVariable Notes:\n- local_8 (dwCharBuffer): undefined4 buffer for character conversion output\n- local_7 (bByteBuffer): undefined1 variable, likely compiler-optimized temporary\n- Function uses 5 SSA variables (pvVar1-3, uVar4) for intermediate calculations\n\nMagic Numbers Reference:\n0x14 - Offset to LCID in locale structure\n0x24 - Offset to locale extension flag\n0x28 - Offset to ctype table version indicator  \n0x48 - Offset to character type lookup table base\n0x4 - Offset to code page identifier\n0x40 - ASCII '@' character (A-1)\n0x5b - ASCII '[' character (Z+1) \n0x20 - Offset between uppercase and lowercase ASCII (A-a)\n0x80 - ASCII high bit / DBCS lead byte indicator\n0x100 - Unicode conversion flag / single byte character limit\n0xff - Byte mask for extracting low 8 bits\n\nError Handling:\n- Returns original character if locale is uninitialized\n- Returns original character if ConvertStringCaseWithCodePage fails\n- Handles both single-byte and double-byte character sets\n- Gracefully degrades to ASCII conversion for basic Latin characters",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e1a55473b8c876366de891db323c13fa",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e1a55473b8c876366de891db323c13fa",
        "CFG": "2810824f15539fecf62c974504ed4bce",
        "PRO": "1518fa20b1487320532e955b8d319e70"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e1a55473b8c876366de891db323c13fa"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_5812d1889440": {
      "addresses": {
        "LoD/PD2": "0x6F9B5C4C"
      },
      "rvas": {
        "LoD/PD2": "0x5C4C"
      },
      "sizes": {
        "LoD/PD2": 34
      },
      "name": "_tolower",
      "signature": "int _tolower(int nChar)",
      "calling_convention": "__cdecl",
      "comment": "Convert uppercase character to lowercase using thread-safe locale-aware conversion\n\nAlgorithm:\n1. Get per-thread data structure containing locale information\n2. Extract locale information from thread data (field offset 0x1c) \n3. Compare current locale against default global locale pointer\n4. If different locale, update thread locale information via ___updatetlocinfo()\n5. Call ___tolower_mt() with thread context, locale info, character, and return address\n6. Return converted character value\n\nParameters:\nnChar (int): Character value to convert to lowercase (0-255 for ASCII, extended for Unicode)\n\nReturns:\nint: Lowercase version of input character, or original character if no conversion available\n\nSpecial Cases:\n- Non-alphabetic characters returned unchanged\n- Thread-local locale settings override global settings\n- Multi-byte character sequences handled by underlying ___tolower_mt implementation\n- Invalid character values (outside valid range) returned as-is\n\nIMPLICIT:\nthis (void*): Implicit parameter passed via ECX register to ___tolower_mt\nunaff_retaddr (uint): Return address passed as parameter for thread safety verification",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5812d18894407ef6889050a4bd31c359",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5812d18894407ef6889050a4bd31c359",
        "CFG": "28d68ef41469e49f60578a0ac553bdfd",
        "PRO": "b54ac94869dbfac134a13bbaf1445d14"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5812d18894407ef6889050a4bd31c359"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_93d0dc9fd831": {
      "addresses": {
        "LoD/PD2": "0x6F9B5C6E"
      },
      "rvas": {
        "LoD/PD2": "0x5C6E"
      },
      "sizes": {
        "LoD/PD2": 119
      },
      "name": "___isctype_mt",
      "signature": "uint ___isctype_mt(void * this, void * pLocale, int nCharacter, int nCategory, uint dwTypeMask)",
      "calling_convention": "__thiscall",
      "comment": "Thread-safe character type classification with multi-byte character support\n\nAlgorithm:\n1. Validate character value is within single-byte range (0-255)\n2. If single-byte character, retrieve type flags from locale character table at offset 0x48\n3. If multi-byte character, check lead byte using locale table at offset 0x48\n4. For multi-byte sequences, construct character buffer and call GetStringTypeA\n5. Handle both single-byte (CP_ACP) and double-byte character sequences\n6. Return bitwise AND of character type flags with requested type mask\n7. Return 0 on GetStringTypeA failure for invalid multi-byte sequences\n\nParameters:\npLocale - Pointer to locale structure containing character classification tables\nnCharacter - Character value to classify (0-65535 range for Unicode support)  \nnCategory - Character category context (reserved parameter, not currently used)\ndwTypeMask - Bit mask specifying which character types to test for\n\nReturns:\nNon-zero value if character matches any bits in dwTypeMask\n0 if character does not match mask or multi-byte conversion fails\n\nSpecial Cases:\nCharacters > 255 trigger multi-byte character handling path\nGetStringTypeA failure returns 0 for malformed multi-byte sequences\nSingle-byte fast path uses direct table lookup for performance\n\nStructure Layout:\nLocale structure accessed at:\nOffset  Size  Field Name          Type      Description  \n0x04    4     lpCharTypeTable     LPWORD*   Pointer to character type table\n0x14    4     nCodePage          int       Code page for multi-byte conversion  \n0x48    4     lpCharTable        ushort*   Primary character classification table\n\nMagic Numbers Reference:\n0x48 - Offset to character classification table in locale structure\n0x101 - Single-byte character range limit (257 decimal)\n0x80 - Lead byte indicator flag for multi-byte character sequences\n0xFF - Mask for extracting low byte of character value\n0x10 - High byte shift value for multi-byte character construction",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:93d0dc9fd8314e8d90414fa46b2e66d4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "93d0dc9fd8314e8d90414fa46b2e66d4",
        "CFG": "a95ce1e5c935a12a7db59114a37206ec",
        "PRO": "f17796a956061d33e2e5b4b89cdc049a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "93d0dc9fd8314e8d90414fa46b2e66d4"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "D2sound_MNE_d54b31472f74": {
      "addresses": {
        "LoD/PD2": "0x6F9B5CF0"
      },
      "rvas": {
        "LoD/PD2": "0x5CF0"
      },
      "sizes": {
        "LoD/PD2": 52
      },
      "name": "Multiply64Bit",
      "signature": "longlong Multiply64Bit(uint lowA, int highA, uint lowB, int highB)",
      "calling_convention": "__stdcall",
      "comment": "Multiply two 64-bit signed integers represented as (high, low) pairs.\\n\\nAlgorithm:\\n1. Check if both high parts are zero (simple case optimization)\\n2. If highA==0 AND highB==0: return lowA * lowB (simple 64-bit multiply)\\n3. Otherwise: perform full 128-bit multiplication:\\n   a. Compute lowA * lowB to get full 64-bit product (EDX:EAX)\\n   b. Save low 32 bits as result low part\\n   c. Compute high 32 bits: (lowA*lowB >> 32) + highA*lowB + lowA*highB\\n4. Return result as 64-bit CONCAT44(resultHigh, resultLow)\\n\\nParameters:\\n- lowA: Low 32 bits of first operand (unsigned)\\n- highA: High 32 bits of first operand (signed)\\n- lowB: Low 32 bits of second operand (unsigned)\\n- highB: High 32 bits of second operand (signed)\\n\\nReturns:\\n- longlong: 64-bit signed result of (highA:lowA) * (highB:lowB)\\n- Low 32 bits in EAX, high 32 bits in EDX (stdcall return)\\n\\nStructure Layout (64-bit Integer Representation):\\nOffset  Size  Field   Type   Description\\n------  ----  -----   ----   -----------\\n+0      4     Low     uint   Lower 32 bits of value\\n+4      4     High    int    Upper 32 bits of value\\n\\nSpecial Cases:\\n- Magic: 0x20 is bit shift for 32-bit word boundary\\n- Stack cleanup: __stdcall adds 0x10 to ESP (4 params * 4 bytes)\\n- Register usage: MUL instructions implicit use EAX and EDX\\n- Optimization: Fast path for zero high parts avoids extra computation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d54b31472f74b078be31f20f65c7b2d3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d54b31472f74b078be31f20f65c7b2d3",
        "CFG": "8bbfe2737ef55f3a9a35ae1b43be54c6",
        "PRO": "3eabd37b619c8c857e7d42508a357bb6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d54b31472f74b078be31f20f65c7b2d3"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_ecf4fe5a7e47": {
      "addresses": {
        "LoD/PD2": "0x6F9B5D30"
      },
      "rvas": {
        "LoD/PD2": "0x5D30"
      },
      "sizes": {
        "LoD/PD2": 97
      },
      "name": "___ascii_strnicmp",
      "signature": "int ___ascii_strnicmp(char * lpszStr1, char * lpszStr2, size_t nMaxCount)",
      "calling_convention": "__cdecl",
      "comment": "Case-insensitive ASCII string comparison with length limit.\n\nAlgorithm:\n1. Check if maximum count is non-zero, return 0 if zero\n2. Loop through characters until max count reached or null terminator found\n3. Load character from first string into byte register (0x41-0x5A range)\n4. Load character from second string into char register\n5. Create 16-bit character pair using CONCAT11 operation\n6. Break early if first string character is null terminator\n7. Break early if second string character is null terminator  \n8. Advance both string pointers by 1 character\n9. Convert first character to lowercase if uppercase (0x41-0x5A \u2192 +0x20)\n10. Convert second character to lowercase if uppercase (0x41-0x5A \u2192 +0x20)\n11. Extract normalized characters from 16-bit pair for comparison\n12. Compare normalized characters for inequality\n13. Decrement remaining count and continue loop if characters equal\n14. Return comparison result: -1 if str1 < str2, +1 if str1 > str2, 0 if equal\n\nParameters:\nlpszStr1 (char *): First null-terminated string to compare\nlpszStr2 (char *): Second null-terminated string to compare  \nnMaxCount (size_t): Maximum number of characters to compare\n\nReturns:\n0: Strings are equal within specified length or both null\n-1 (0xFFFFFFFF): First string lexicographically less than second\n1: First string lexicographically greater than second\n\nSpecial Cases:\nIf nMaxCount is 0, returns 0 immediately without comparison\nNull terminators in either string end comparison early\nCase conversion applies only to ASCII letters A-Z (0x41-0x5A)\n\nMagic Numbers Reference:\n0x40 (64): ASCII '@' - upper bound for case conversion check\n0x5B (91): ASCII '[' - lower bound for case conversion check  \n0x20 (32): Case conversion offset (uppercase to lowercase)\n0xFFFFFFFF: Return value indicating first string is lesser",
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
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ecf4fe5a7e473ceb70f30e35ac316045"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_6b07f716ad39": {
      "addresses": {
        "LoD/PD2": "0x6F9B5DA0"
      },
      "rvas": {
        "LoD/PD2": "0x5DA0"
      },
      "sizes": {
        "LoD/PD2": 149
      },
      "name": "Divide64Bit",
      "signature": "ulonglong Divide64Bit(uint dividendLow, uint divisorHigh, uint divisorLow, uint dividendHigh)",
      "calling_convention": "__stdcall",
      "comment": "64-bit unsigned integer division: (dividendHigh:dividendLow) / (divisorHigh:divisorLow)\n\nAlgorithm:\n1. Check if divisor high word is zero (simple 32-bit division case)\n2. If divisor high = 0: divide combined 64-bit dividend by 32-bit divisor\n3. If divisor high != 0: use binary long division algorithm:\n   a. Normalize divisor by right-shifting both divisor and dividend until divisor high = 0\n   b. Perform initial division using normalized values\n   c. Check result bounds and adjust quotient if overflow detected\n4. Compute remainder as dividend - (quotient * divisor)\n5. Return remainder in EDX, quotient in EAX\n\nParameters:\n- dividendLow (ESP+0x8): Low 32 bits of 64-bit dividend\n- divisorHigh (ESP+0x10): High 32 bits of 64-bit divisor\n- divisorLow (ESP+0xc): Low 32 bits of 64-bit divisor\n- dividendHigh (ESP+0x14): High 32 bits of 64-bit dividend\n\nReturns:\n- EAX: Quotient (32-bit)\n- EDX: Remainder (32-bit)\n\nSpecial Cases:\n- If divisor = 0, result is undefined (no overflow check)\n- If divisor high = 0, uses fast path with single DIV instruction\n- Result adjusted if intermediate calculation overflows 32-bit bounds\n- Remainder always less than divisor (mathematically correct modulo operation)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6b07f716ad39855b07502ac9a8f75c79",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6b07f716ad39855b07502ac9a8f75c79",
        "CFG": "835de6f5cc54ca26a9c8507d3599cd93",
        "PRO": "5d1977a5b94d5441fa3dfc6502a8e323"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6b07f716ad39855b07502ac9a8f75c79"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_3ecdb5e459e2": {
      "addresses": {
        "LoD/PD2": "0x6F9B5E40"
      },
      "rvas": {
        "LoD/PD2": "0x5E40"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "ComputeOffsetAndContinue",
      "signature": "int ComputeOffsetAndContinue(int pValue)",
      "calling_convention": "__fastcall",
      "comment": "Computes offset by subtracting 1 from input value and transfers execution via EBX.\n\nThis is a small thunk/stub function that performs a simple arithmetic operation\nand uses an unconventional return mechanism by loading the return address into EBX\nbefore executing RET. This suggests it's part of a larger trampoline or continuation\nmechanism where EBX holds the next execution target.\n\nAlgorithm:\n1. Load input parameter from EDX register (fastcall convention)\n2. Compute EDX - 1 and store result in EAX return register\n3. Pop stack value into EBX (transfers return address from stack to register)\n4. Execute RET instruction (returns to address in stack)\n\nParameters:\n- pValue (EDX): Input value to subtract from\n\nReturns:\n- EAX: Result of (pValue - 1)\n- EBX: Contains popped stack value (likely next execution target)\n\nSpecial Cases:\n- Uses non-standard return mechanism via EBX manipulation\n- Return address is transferred from stack to EBX before RET\n- Likely part of a continuation-passing style or trampoline system",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3ecdb5e459e29b4117490dc114e98574",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3ecdb5e459e29b4117490dc114e98574",
        "CFG": null,
        "PRO": "c81df70c1b97172a537e995055b0c6bd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3ecdb5e459e29b4117490dc114e98574"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_e3e7225badfc": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F0E"
      },
      "rvas": {
        "LoD/PD2": "0x5F0E"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "RtlUnwind",
      "signature": "void RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)",
      "calling_convention": "__stdcall",
      "comment": "Unwinds the stack to the specified target frame for structured exception handling.\n\nAlgorithm:\n1. Validate TargetFrame parameter (must be valid stack frame or NULL for complete unwind)\n2. Validate TargetIp parameter (must be valid return address or NULL)\n3. Call ntdll.dll RtlUnwind to perform stack unwinding\n4. Execute exception handlers during stack unwinding process\n5. Transfer control to TargetIp or return to caller if NULL\n\nParameters:\n  TargetFrame (PVOID): Target stack frame to unwind to, or NULL to unwind entire stack\n  TargetIp (PVOID): Target instruction pointer to transfer control to, or NULL to return\n  ExceptionRecord (PEXCEPTION_RECORD): Optional exception record for unwinding context\n  ReturnValue (PVOID): Value to place in EAX register when unwinding completes\n\nReturns:\n  void: Function does not return normally - transfers control to TargetIp or exits\n\nSpecial Cases:\n- TargetFrame NULL: Unwinds entire stack back to top-level exception handler\n- TargetIp NULL: Returns normally after unwinding without transferring control\n- Invalid TargetFrame: May cause access violation or stack corruption\n- This appears to be an import stub/thunk that redirects to ntdll.dll RtlUnwind\n\nError Handling:\n- Invalid parameters may trigger structured exception\n- Stack corruption protection validates frame pointers during unwind\n- Exception handlers executed in reverse order during stack unwinding",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "5572d8b5f592768b786a5d674a8790a8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_ADDR_6F9B5F14": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F14"
      },
      "rvas": {
        "LoD/PD2": "0x5F14"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "VerQueryValueA",
      "signature": "BOOL VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID * lplpBuffer, PUINT puLen)",
      "calling_convention": "__stdcall",
      "comment": "Version Information Query Thunk - forwards calls to actual VerQueryValueA implementation\n\nAlgorithm:\n1. Forward all parameters to actual VerQueryValueA implementation\n2. Return the result from the real implementation\n\nParameters:\n- pBlock (LPCVOID): Pointer to version information block data\n- lpSubBlock (LPCSTR): Subblock name to query (e.g., \"\\VarFileInfo\\Translation\")\n- lplpBuffer (LPVOID *): Receives pointer to requested information\n- puLen (PUINT): Receives length of requested information in bytes\n\nReturns:\n- TRUE (non-zero): Query successful, buffer contains requested data\n- FALSE (0): Query failed, invalid subblock or data not found\n\nSpecial Cases:\n- This is a thunk function that forwards to the actual implementation\n- Function body contains only a jump instruction to real VerQueryValueA\n- Used for API forwarding or DLL export redirection\n\nError Handling:\n- All error handling delegated to actual implementation\n- No local validation or processing performed",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "2376491dded7b42a420b66da644a00af"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_ADDR_6F9B5F1A": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F1A"
      },
      "rvas": {
        "LoD/PD2": "0x5F1A"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "DirectSoundCreate",
      "signature": "uint DirectSoundCreate(uint param_1, uint param_2, uint param_3)",
      "calling_convention": "unknown",
      "comment": "DirectSound creation thunk\n\nAlgorithm:\n1. Jump to actual DirectSoundCreate implementation\n\nParameters:\nIMPLICIT: Standard DirectSoundCreate parameters\n\nReturns:\nHRESULT: DirectSound result code",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "6f4ef97bcee2e96d6eb6791bad9cfdea"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_ADDR_6F9B5F20": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F20"
      },
      "rvas": {
        "LoD/PD2": "0x5F20"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "DirectSoundEnumerateA",
      "signature": "undefined DirectSoundEnumerateA(void)",
      "calling_convention": "unknown",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "57156ed7e7a6924613164223cdad25f9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_ADDR_6F9B5F32": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F32"
      },
      "rvas": {
        "LoD/PD2": "0x5F32"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "DispatchViaFunctionPointer",
      "signature": "void DispatchViaFunctionPointer(void)",
      "calling_convention": "__stdcall",
      "comment": "Indirect function dispatch trampoline\n\nAlgorithm:\n1. Dereference function pointer at 0x6f9bf174\n2. Perform unconditional jump to target function address\n3. Control flow transfers to the target, no return to caller\n\nReturns:\nNone - control transfers to target function\n\nSpecial Cases:\n- This is a trampoline function used for dynamic dispatch\n- The target function address is stored at 0x6f9bf174 as a 32-bit pointer\n- Called from FUN_6f9b7cd0 which pre-loads EAX with a parameter value\n- The target function will receive the parameter via EAX register\n\nStructure Layout:\nFunction Pointer at 0x6f9bf174:\n  Offset  Size  Field Name           Type      Description\n  ------  ----  -----------------    -------   -------------------\n  0       4     target_function_ptr  void*     Address of function to dispatch to",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "ffb7b5c45e789d3768b3890aefde09b2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_ADDR_6F9B5F38": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F38"
      },
      "rvas": {
        "LoD/PD2": "0x5F38"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "DispatchFinalCleanup",
      "signature": "void DispatchFinalCleanup(void)",
      "calling_convention": "__cdecl",
      "comment": "Indirect jump dispatcher for final cleanup operations.\n\nAlgorithm:\n1. Jump indirectly through function pointer at 0x6f9bf170\n2. This function is called as the final step in Ordinal_10031 cleanup\n3. Allows dynamic dispatch to cleanup handler code\n\nParameters:\nNone\n\nReturns:\nvoid - Does not return to caller (indirect jump to cleanup handler)\n\nSpecial Cases:\nThis is an indirect jump stub that provides dynamic dispatch to cleanup code.\nThe target address at 0x6f9bf170 contains a function pointer that determines\nthe actual cleanup handler to invoke. Used in shutdown sequences to invoke\ncontext-specific cleanup routines.\n\nCalling Context:\nCalled from Ordinal_10031 during final cleanup phase after all resources\nhave been released and critical sections have been exited.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "35933f4dcfad981f47d3063aeb93a828"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_ADDR_6F9B5F3E": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F3E"
      },
      "rvas": {
        "LoD/PD2": "0x5F3E"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "ProcessQueue",
      "signature": "int ProcessQueue(void * this, void * pQueue, undefined4 param2, int flags, int param4, int param5, int param6, undefined4 param7)",
      "calling_convention": "__thiscall",
      "comment": "Function pointer thunk that indirectly calls ProcessQueue via ptr_ProcessQueue.\n\nThis function is a thunk that performs an indirect jump to the actual ProcessQueue\nimplementation stored at memory location 0x6f9bf16c. This is a common pattern for\ndynamic function resolution or virtual dispatch.\n\nAlgorithm:\n1. Load the function pointer from 0x6f9bf16c into a register\n2. Jump to the target address\n3. Execution continues in the resolved function (typically returns to caller via RET)\n\nParameters:\n- pQueue: Pointer to queue structure (passed in ECX - implicit this pointer)\n- param2: Queue field at offset +4 from pQueue\n- flags: Conditional flags (0x40000 if param2 != 0, else 0)\n- param4: param1 * 4 (typically array index or offset calculation)\n- param5: Maximum value 0x7fffffff\n- param6: Maximum value 0x7fffffff\n- param7: Queue field at offset +0 from pQueue\n\nReturns:\n- Non-zero on success (queue operation completed)\n- Zero on failure (operation could not complete)\n\nSpecial Cases:\n- This is a function pointer redirect; the actual implementation is at runtime address\n- Called within critical sections to ensure thread-safe queue operations\n- Caller holds LPCRITICAL_SECTION lock at DAT_6f9c6530 during execution",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "f81ac91a25db3b74bb94152c6bc605f5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "D2sound_ADDR_6F9B5F44": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F44"
      },
      "rvas": {
        "LoD/PD2": "0x5F44"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "ImportThunk_257",
      "signature": "void ImportThunk_257(void)",
      "calling_convention": "__cdecl",
      "comment": "Import Address Table (IAT) thunk for Ordinal_257\n\nThis function serves as a dispatch mechanism for an ordinal-based DLL import. It contains a single indirect jump instruction that transfers execution to the actual imported function whose address is stored in the IAT at offset 0x6f9bf168.\n\nAlgorithm:\n1. Jump indirectly through IAT pointer at 0x6f9bf168\n2. Execute the imported function\n3. Return to caller\n\nPurpose:\nThis thunk acts as a stable call site for external DLL functions imported by ordinal. The actual function address is resolved at runtime and stored in the IAT, allowing the imported function to be updated without recompiling code that calls it.\n\nReturns:\nDepends on the actual imported function - this thunk is transparent to callers.\n\nSpecial Cases:\n- This is an ordinal-based import (function identified by number rather than name)\n- The actual function identity must be determined from the import table\n- Called once from Ordinal_10043 (another dispatch thunk)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "9d23ff508cb07082af353011dd98207b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_ADDR_6F9B5F4A": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F4A"
      },
      "rvas": {
        "LoD/PD2": "0x5F4A"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "InvokeIndirectCallback",
      "signature": "int InvokeIndirectCallback(int callbackHandle, undefined4 * pOutBuffer, undefined1 * pOutFlags)",
      "calling_convention": "__fastcall",
      "comment": "Invokes an indirect callback function through a jump table entry.\n\nThis function serves as an indirect function pointer dispatch mechanism, retrieving\na callback function address from a jump table stored at 0x6f9bf164 and invoking it\nwith the provided parameters.\n\nAlgorithm:\n1. Load callback function pointer from jump table at 0x6f9bf164 using callbackHandle\n2. Invoke the retrieved function pointer with parameters callbackHandle, pOutBuffer, pOutFlags\n3. Return the function's result code (non-zero = success, 0 = failure/error)\n\nParameters:\n- callbackHandle: Identifier/index for the callback function to invoke\n- pOutBuffer: Pointer to output buffer for callback results\n- pOutFlags: Pointer to flags/options passed to the callback\n\nReturns:\n- int: Non-zero if callback executed successfully, 0 if callback failed or returned error\n\nSpecial Cases:\n- The jump table at 0x6f9bf164 contains function pointers indexed by callbackHandle\n- Called from critical sections (synchronized via EnterCriticalSection/LeaveCriticalSection)\n- Used for event handling and deferred callback execution",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "88dd5a71118d06396e79015f3374e7c2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_ADDR_6F9B5F50": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F50"
      },
      "rvas": {
        "LoD/PD2": "0x5F50"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "CleanupAndAbort",
      "signature": "undefined CleanupAndAbort(void)",
      "calling_convention": "unknown",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "dc642d29a16ae461ab2e33e216206036"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_ADDR_6F9B5F56": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F56"
      },
      "rvas": {
        "LoD/PD2": "0x5F56"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "LogErrorOrProgressMessage",
      "signature": "void LogErrorOrProgressMessage(void)",
      "calling_convention": "unknown",
      "comment": "Error/progress message handler - thunk to dynamically resolved function pointer\n\nAlgorithm:\n1. Jump to function pointer stored at 0x6f9bf038\n2. Called from DirectSound and file system initialization routines with error/progress messages\n3. Supports variable argument passing to logged handler function\n\nCalled from:\n- InitializeDirectSound: Error messages for device validation failures\n- InitializeDirectSoundAudio: Error messages for audio buffer setup failures\n- InitializeFogFileSystem: Error messages for file system initialization failures\n- Various initialization callbacks: Progress/status reporting\n\nReturns:\nvoid - No explicit return value, passes through to resolved function handler\n\nSpecial Cases:\n- This is a thunk/wrapper function - actual implementation resolved at runtime\n- Function pointer at 0x6f9bf038 determines actual handler behavior\n- Called with varying arguments (0-2+ parameters depending on context)\n- Used exclusively for error/progress reporting during system initialization",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "239d5b2b8954cef5fa45115371130314"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_ADDR_6F9B5F5C": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F5C"
      },
      "rvas": {
        "LoD/PD2": "0x5F5C"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetReturnAddress",
      "signature": "undefined GetReturnAddress(void)",
      "calling_convention": "unknown",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "77909895f16474585b5ba04e6ed809fa"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_ADDR_6F9B5F62": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F62"
      },
      "rvas": {
        "LoD/PD2": "0x5F62"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "AllocateMemoryBlock",
      "signature": "void * AllocateMemoryBlock(uint blockSize, uint param2)",
      "calling_convention": "__stdcall",
      "comment": "Memory allocation wrapper function that allocates blocks of memory.\n\nThis function is a thin wrapper around an external memory allocation routine,\nlikely part of a custom memory management system. It redirects all allocation\nrequests to an external function pointer stored at 0x6f9bf018.\n\nAlgorithm:\n1. Receive allocation parameters: blockSize (size of memory block) and param2\n2. Jump to external allocation function pointer at 0x6f9bf018\n3. Return allocated memory pointer or NULL on failure\n\nParameters:\n- blockSize [uint]: Size in bytes of the memory block to allocate\n- param2 [uint]: Secondary allocation parameter (purpose not yet determined, usually 0)\n\nReturns:\n- void *: Pointer to newly allocated memory block, or NULL if allocation fails\n\nSpecial Cases:\n- Common block sizes observed in callers:\n  0xcf (207 bytes) - Used for fog file system handles in InitializeFogFileSystem()\n  0x21b (539 bytes) - Used for version info structures in file processing\n  0xd4 (212 bytes) - Used for linked list node allocation in Ordinal_10034()\n  0x1d9 (473 bytes) - Used for large structure allocation in Ordinal_10065()\n  0x8a (138 bytes) - Used for game entity structures in Ordinal_10048()\n- All callers check return value for NULL before dereferencing\n- Function is called from 6 different functions with varying allocation sizes\n- This is an ordinal export from the main DLL, suggesting it's a critical utility function",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "1d2f611f3cbddf5a3182530bce568d6c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_ADDR_6F9B5F68": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F68"
      },
      "rvas": {
        "LoD/PD2": "0x5F68"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "ReportError",
      "signature": "void ReportError(int errorCode, int flags)",
      "calling_convention": "__cdecl",
      "comment": "Reports error or triggers resource cleanup based on error code.\n\nThis is an imported thunk function that redirects to an external implementation.\nCalled with error codes to signal failures during version checking, resource\nallocation, and critical section operations.\n\nParameters:\n  errorCode - Numeric error code (0x220, 0x228, 0xf0, 0x26e, 0x1e0 observed)\n              Values may represent resource IDs, error types, or cleanup codes\n  flags     - Flags parameter, typically 0 in all observed calls\n\nReturns:\n  void - Returns normally (no return value used by callers)\n\nSpecial Cases:\n  All observed calls pass 0 for flags parameter; meaning unclear but may\n  indicate synchronous vs asynchronous error handling, or different\n  reporting levels (e.g., log vs crash)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "2780af21aa06c7df711e8bdfe52295a5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_ADDR_6F9B5F6E": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F6E"
      },
      "rvas": {
        "LoD/PD2": "0x5F6E"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "CheckFogInitializationStatus",
      "signature": "int CheckFogInitializationStatus(void)",
      "calling_convention": "__cdecl",
      "comment": "Checks if FOG.DLL initialization is complete.\n\nAlgorithm:\n1. Call external function to check FOG initialization status\n2. Return the initialization status to caller\n\nParameters:\n  (none)\n\nReturns:\n  Returns non-zero (TRUE) if FOG initialization is complete and ready\n  Returns zero (FALSE) if FOG initialization is pending or failed\n\nSpecial Cases:\n  This is a thunk function that delegates to an external FOG.DLL function.\n  The actual implementation resides in the FOG rendering module.\n  \nCross-References:\n  Called by ValidateFogInitialization, ProcessQueueWithLocking, \n  InitializeFogFileSystem, and InitializeFogFileResources to verify\n  that prerequisite FOG subsystems are ready before proceeding.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "b33d551737984ce1362601590f220b14"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_ADDR_6F9B5F74": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F74"
      },
      "rvas": {
        "LoD/PD2": "0x5F74"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "FlushFileBuffers",
      "signature": "BOOL FlushFileBuffers(HANDLE hFile)",
      "calling_convention": "__stdcall",
      "comment": "Flush file buffers to disk - Windows API wrapper for FlushFileBuffers.\n\nAlgorithm:\n1. Call ReleaseResourceWrapper with the provided file handle\n2. Return the result directly to caller\n\nParameters:\n- hFile: Handle to the file whose buffers should be flushed to disk\n\nReturns:\n- BOOL: Non-zero (TRUE) if the flush operation succeeded\n- BOOL: Zero (FALSE) if the flush operation failed\n\nSpecial Cases:\n- Acts as a wrapper around ReleaseResourceWrapper function\n- Used throughout the binary for ensuring file data is written to disk\n- Critical for data integrity in cleanup and finalization operations\n\nError Handling:\n- Error conditions are handled by the underlying ReleaseResourceWrapper function\n- Return value directly indicates success or failure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "e6db568afc8d15c014b12004d1344754"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B5F7A": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F7A"
      },
      "rvas": {
        "LoD/PD2": "0x5F7A"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetWindowHandleValue",
      "signature": "int GetWindowHandleValue(void)",
      "calling_convention": "unknown",
      "comment": "Setting prototype: int GetWindowHandleValue(void)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "0da3050eb624f22f66900286e560f0d3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_MNE_21a12b03112b": {
      "addresses": {
        "LoD/PD2": "0x6F9B5F80"
      },
      "rvas": {
        "LoD/PD2": "0x5F80"
      },
      "sizes": {
        "LoD/PD2": 45
      },
      "name": "FindCharacterReverse",
      "signature": "char * FindCharacterReverse(char * pString, char searchChar)",
      "calling_convention": "__cdecl",
      "comment": "Searches for the last occurrence of a character in a string (reverse string search).\n\nAlgorithm:\n1. Initialize counter to -1 for forward length calculation\n2. Scan string forward from start until null terminator found, counting characters\n3. Calculate actual string length as negated counter value\n4. Move to last character position (end - 1)\n5. Scan string backward from end, decrementing counter each iteration\n6. Compare each character with target character during backward scan\n7. Exit backward loop when counter reaches 0 (scanned entire string)\n8. If character found, increment result pointer and return it\n9. If character not found during backward scan, return NULL pointer\n\nParameters:\n  pString (char *): Pointer to null-terminated string to search\n  searchChar (char): Character value to find in string\n\nReturns:\n  char *: Pointer to last occurrence of searchChar in pString, or NULL if not found\n\nSpecial Cases:\n  - Searches from the end of string backward (reverse direction)\n  - Returns NULL if character not found anywhere in string\n  - String must be null-terminated for length calculation to work correctly\n  - Similar to standard C library strrchr() function",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:21a12b03112be7c0452f1f2140b0fec9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "21a12b03112be7c0452f1f2140b0fec9",
        "CFG": "7762a7f9dd9a3308b8630ce9a236979d",
        "PRO": "22a9bfbb5ca9778d7ffc2969df471ded"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "21a12b03112be7c0452f1f2140b0fec9"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_ADDR_6F9B5FAE": {
      "addresses": {
        "LoD/PD2": "0x6F9B5FAE"
      },
      "rvas": {
        "LoD/PD2": "0x5FAE"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "SFileOpenFile",
      "signature": "int SFileOpenFile(void * pFileHandle, uint nFileIndex, uint nMode, void * pOutHandle)",
      "calling_convention": "__cdecl",
      "comment": "Import thunk for STORM.DLL::Ordinal_266 (SFileOpenFile)\n\nOpens or creates a file within a STORM archive (MPQ file).\n\nAlgorithm:\n1. Jump to the external SFileOpenFile function at STORM.DLL\n2. Function is called through indirect jump via pointer at 0x6f9bf180\n3. Returns result of STORM file operation\n\nParameters:\n- pFileHandle: Pointer to the archive/file context (typically from SFileOpenArchive)\n- nFileIndex: File identifier or index within the archive\n- nMode: File access mode (2=read, 3=write/create)\n- pOutHandle: Output pointer to receive file handle on success\n\nReturns:\n- Non-zero (true) on success, zero (false) on failure\n\nSpecial Cases:\n- Used for both reading and writing files within MPQ archives\n- Part of the STORM library's file abstraction layer\n- Callers expect non-zero return on success\n- Called with mode 2 for read operations and mode 3 for write operations\n\nNote: This is an import thunk that simply forwards calls to the external STORM.DLL implementation.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "8b56b77f8211d8ac5b30035e961d2ba4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_ADDR_6F9B5FB4": {
      "addresses": {
        "LoD/PD2": "0x6F9B5FB4"
      },
      "rvas": {
        "LoD/PD2": "0x5FB4"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "ReadFileData",
      "signature": "int ReadFileData(int fileHandle, byte * pBuffer, int nSize)",
      "calling_convention": "__stdcall",
      "comment": "Reads file data into a buffer via indirect function pointer dispatch.\n\nThis is a thunk/trampoline function that jumps through an indirect pointer.\nIt dispatches to the actual implementation function stored at address 0x6f9bf184.\n\nAlgorithm:\n1. Loads the function pointer from address 0x6f9bf184\n2. Performs an indirect jump to that function\n3. Returns the result from the dispatched function\n\nParameters:\n  fileHandle - Handle or identifier for the file/data source (typically an integer ID)\n  pBuffer - Pointer to buffer where data will be read into\n  nSize - Number of bytes to read (typically 0x104 = 260 bytes)\n\nReturns:\n  Status code from the dispatched read function (0 for success in context of callers)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "5825d4d5d6795d009113613d5ea89a2f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_ADDR_6F9B5FBA": {
      "addresses": {
        "LoD/PD2": "0x6F9B5FBA"
      },
      "rvas": {
        "LoD/PD2": "0x5FBA"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "SFileSetLocale",
      "signature": "int SFileSetLocale(void * hSFile, char * pszLocale, int nReserved)",
      "calling_convention": "__cdecl",
      "comment": "Storm library ordinal 503 - Set locale path for file operations\n\nPurpose: Indirect jump stub that delegates to the Storm library's SFileSetLocale \nfunction. This is an import stub that resolves the Storm.dll export at runtime.\n\nParameters:\n- hSFile (void*): File handle or archive context\n- pszLocale (char*): Locale/path string to set for file operations\n- nReserved (int): Reserved parameter (typically 0x7fffffff for max value)\n\nReturns:\n- int: Status code (0 for success, non-zero for failure)\n\nAlgorithm:\n1. Indirect jump through pointer at 0x6f9bf188\n2. Jumps to external STORM.DLL:Ordinal_503 implementation\n3. Returns result code in EAX\n\nUsage Context:\nThis function is called by file search and setup routines to set the current \nlocale/path context before opening Storm archive files. Used in conjunction \nwith SFileOpenFile (Ordinal_501) for path-aware file operations.\n\nCalled by:\n- FUN_6f9b6530 (file opening with fallback)\n- FUN_6f9b6230 (drive search and file location)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "cc2b0f61db7137f7c1101206f6ba0ca9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_ADDR_6F9B5FC0": {
      "addresses": {
        "LoD/PD2": "0x6F9B5FC0"
      },
      "rvas": {
        "LoD/PD2": "0x5FC0"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "SStrChr",
      "signature": "char * SStrChr(char * pString, int nChar)",
      "calling_convention": "__cdecl",
      "comment": "Find first occurrence of character in string.\n\nThunk function that wraps STORM.DLL Ordinal_571, which searches for a specified character in a null-terminated string.\n\nAlgorithm:\n1. Jump through pointer at 0x6f9bf18c to reach STORM.DLL implementation\n2. STORM.DLL implementation scans string byte-by-byte for target character\n3. Returns pointer to first match or NULL if not found\n\nParameters:\npString - Pointer to null-terminated string to search\nnChar - Character code to search for (e.g., 0x5c for backslash '\\\\')\n\nReturns:\nPointer to first occurrence of nChar in pString, or NULL if character not found\n\nSpecial Cases:\n- Used in path processing to locate path separators (backslash character 0x5c)\n- NULL input string will cause access violation in STORM.DLL implementation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "544230dc55d82c96528ab154132ffec5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_ADDR_6F9B5FC6": {
      "addresses": {
        "LoD/PD2": "0x6F9B5FC6"
      },
      "rvas": {
        "LoD/PD2": "0x5FC6"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "SFileSetLocale",
      "signature": "int SFileSetLocale(void * hStormHandle, char * pszPath, uint dwFlags)",
      "calling_convention": "__cdecl",
      "comment": "Forwarding stub to STORM.DLL's SFileSetLocale ordinal (Ordinal 501).\n\nSets the base directory/locale for subsequent Storm File operations on a given handle.\nThis is a thin wrapper that directly jumps to the actual implementation in STORM.DLL.\n\nAlgorithm:\n1. Jump to the actual SFileSetLocale function at STORM.DLL+0x2b080\n2. The real function sets the file search path for the given storm handle\n\nParameters:\n  hStormHandle: Storm archive/file handle context pointer\n  pszPath: Path string to set as the base directory for file operations\n  dwFlags: Flags parameter (typically 0x7fffffff for maximum range)\n\nReturns:\n  int: Status code indicating success or failure of the locale set operation\n\nStructure Layout:\n  The hStormHandle parameter is typically a pointer to storm management context\n  with file handle and state information for archive operations.\n\nNotes:\n  This function is a common forwarding pattern in wrapper libraries where the\n  actual implementation is delegated to STORM.DLL for file archive operations.\n  See STORM.DLL documentation for Ordinal 501 (SFileSetLocale) for details.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "55d5caa310974d280e7d9171f4936bf0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_ADDR_6F9B5FCC": {
      "addresses": {
        "LoD/PD2": "0x6F9B5FCC"
      },
      "rvas": {
        "LoD/PD2": "0x5FCC"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "DispatchToStormOrdinal252",
      "signature": "void DispatchToStormOrdinal252(void)",
      "calling_convention": "unknown",
      "comment": "Setting prototype: void DispatchToStormOrdinal252(void)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "ee8c32d46a0b487fb1bc370cf28418e1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_ADDR_6F9B5FD2": {
      "addresses": {
        "LoD/PD2": "0x6F9B5FD2"
      },
      "rvas": {
        "LoD/PD2": "0x5FD2"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "OpenFileAndValidateSize",
      "signature": "int OpenFileAndValidateSize(int fileHandle, int * pFileSizeOut, int param3, int param4, int param5)",
      "calling_convention": "__cdecl",
      "comment": "Opens and validates file size through external function pointer\nAlgorithm:\n1. Indirect jump to external function via pointer table at 0x6f9bf02c\n2. Called with file handle and output size pointer\n3. Returns status code: 0 for success, non-zero for failure\n4. Used in file I/O operations with subsequent ReadFileData call\nParameters:\n- fileHandle: File handle or resource identifier\n- pFileSizeOut: Pointer to store validated file size\n- param3: Unused parameter (passed as 0)\n- param4: Unused parameter (passed as 0)\n- param5: Unused parameter (passed as 0)\nReturns:\n- 0: File opened and validated successfully\n- Non-zero: Error code indicating validation failure\nSpecial Cases:\n- This is a thunk function that jumps through an external function pointer\n- Used for validating file integrity before reading contents\n- Callers check return value before proceeding with file operations\n- External function pointer located at 0x6f9bf02c",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "a27ecaf9bf0bb6ce750fc8ce76934f31"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "D2sound_ADDR_6F9B5FD8": {
      "addresses": {
        "LoD/PD2": "0x6F9B5FD8"
      },
      "rvas": {
        "LoD/PD2": "0x5FD8"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "CheckResourceValidity",
      "signature": "int CheckResourceValidity(int resourceIndex, int flags)",
      "calling_convention": "__cdecl",
      "comment": "Validates resource validity through imported ordinal function.\n\nAlgorithm:\n1. Jump indirectly through pointer table at 0x6f9bf030\n2. Executes external function with resource index and flags\n3. Returns validation status code\n\nParameters:\n- resourceIndex: Index of the resource to validate\n- flags: Validation flags passed to external function\n\nReturns:\n- int: Validation status (-1 indicates failure, other values indicate success)\n\nSpecial Cases:\n- This is an import stub (thunk) for Ordinal_10106\n- Pointer dereference at 0x6f9bf030 determines actual target function\n- Callers check for -1 return value to detect validation failures",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "014d94d075f76b068431ba7de7a68e37"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_ADDR_6F9B5FDE": {
      "addresses": {
        "LoD/PD2": "0x6F9B5FDE"
      },
      "rvas": {
        "LoD/PD2": "0x5FDE"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "CheckFogFileInitialization",
      "signature": "uint CheckFogFileInitialization(void)",
      "calling_convention": "__stdcall",
      "comment": "Checks fog file initialization status by retrieving default resource count\n\nAlgorithm:\n1. Call GetDefaultResourceCount() to retrieve the current resource count\n2. Return the count value as initialization status indicator\n\nParameters:\n  (none)\n\nReturns:\n  uint: Resource count value indicating initialization status\n        - Non-zero: Initialization successful, returns resource count\n        - Zero: Initialization failed or no resources available\n\nSpecial Cases:\n  Function serves as a wrapper/adapter for GetDefaultResourceCount()\n  Used by game initialization routines to verify fog file system readiness\n\nError Handling:\n  No explicit error handling - relies on GetDefaultResourceCount() behavior\n  Zero return value indicates potential initialization failure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "41c08105124c966c2fe7b7af0dae538e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "D2sound_API_3f0b9faec72e": {
      "addresses": {
        "LoD/PD2": "0x6F9B5FF0"
      },
      "rvas": {
        "LoD/PD2": "0x5FF0"
      },
      "sizes": {
        "LoD/PD2": 38
      },
      "name": "DispatchPendingShutdownAndReportError",
      "signature": "void DispatchPendingShutdownAndReportError(void)",
      "calling_convention": "__stdcall",
      "comment": "Dispatches any pending shutdown operations and reports shutdown completion error.\n\nAlgorithm:\n1. Load shutdown state value from address pointed to by ESI\n2. Test if any operations are pending (non-zero value at [ESI])\n3. If pending, call DispatchToStormOrdinal252 to dispatch the pending operation\n4. Clear the shutdown state by writing 0 to [ESI]\n5. Report shutdown error with code 0x26e (SHUTDOWN_COMPLETE = 622)\n6. Return to caller\n\nParameters:\nIMPLICIT ESI (int * pShutdownState) - Pointer to shutdown state flag\n  Contains non-zero value if pending operations need dispatch before shutdown\n  Cleared to 0 after all operations complete\n\nReturns:\nvoid - Function does not return a value. Returns via __stdcall convention.\n\nSpecial Cases:\n- Error code 0x26e (622) indicates normal shutdown completion, not an error condition\n- Function uses implicit ESI parameter per __stdcall convention\n- Always clears shutdown state before reporting completion\n- Dispatch only occurs if shutdown state was initially non-zero",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:3f0b9faec72e3443321d58df145ef74b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "3f0b9faec72e3443321d58df145ef74b",
        "MNE": "66acc54c9d7bd033827650bac1a5758e",
        "CFG": "dc566b7201dd86af8252efe5cb02fb0f",
        "PRO": "6faecdb622239b3b426927343f23de10"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "66acc54c9d7bd033827650bac1a5758e"
      },
      "api_calls": {
        "LoD/PD2": [
          "ReleaseGameObjectReference",
          "InitializeModule"
        ]
      }
    },
    "D2sound_API_13ec7578ddcf": {
      "addresses": {
        "LoD/PD2": "0x6F9B6020"
      },
      "rvas": {
        "LoD/PD2": "0x6020"
      },
      "sizes": {
        "LoD/PD2": 68
      },
      "name": "ExtractDirectoryPath",
      "signature": "void ExtractDirectoryPath(char * pFilePath)",
      "calling_convention": "__stdcall",
      "comment": "Extracts the directory path from a full file path by removing the filename.\n\nAlgorithm:\n1. Get the current module's full file path using GetModuleFileNameA, storing up to 260 characters\n2. Null-terminate the path at position 0x103 to ensure safe string handling\n3. Check if path is empty (first character is null); if so, skip to cleanup\n4. Enter main loop to find the last backslash in the path\n5. Use SStrChr to find the next backslash character (0x5c) starting from position+1\n6. If backslash not found, exit loop and truncate at current position\n7. If backslash found, update search position and check next character\n8. Continue looping until no more backslashes found\n9. Truncate string at the last found backslash position, removing filename\n10. Return with directory path only in the buffer\n\nParameters:\n- pFilePath (char*): Pointer to buffer containing full file path. Buffer must be at least 260 bytes.\n\nReturns:\n- void: Modifies the buffer in place, truncating it to contain only the directory path\n\nSpecial Cases:\n- If path is empty, no changes are made\n- If path contains no backslashes, entire path is truncated to empty string\n- Buffer is limited to 260 characters (0x104 including null terminator)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:13ec7578ddcf5b763f3edae16352d4b3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "13ec7578ddcf5b763f3edae16352d4b3",
        "MNE": "1ad3095eb47f7ae8ba584afb28677e29",
        "CFG": "872df5e804b40f6897362396a43cb386",
        "PRO": "3de9acad91d4739f7355321db19b3335"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "1ad3095eb47f7ae8ba584afb28677e29"
      },
      "api_calls": {
        "LoD/PD2": [
          "FindCharInString",
          "FindCharInString"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_553bf43acddf": {
      "addresses": {
        "LoD/PD2": "0x6F9B6070"
      },
      "rvas": {
        "LoD/PD2": "0x6070"
      },
      "sizes": {
        "LoD/PD2": 115
      },
      "name": "LoadAndValidateFileData",
      "signature": "void LoadAndValidateFileData(void * fileHandle, uint expectedSize)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void LoadAndValidateFileData(void* fileHandle, uint expectedSize)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:553bf43acddfc3c897fcddab5b70ec2b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "553bf43acddfc3c897fcddab5b70ec2b",
        "MNE": "1d2e62a8ba620b3c9f04bd6beb6c72ad",
        "CFG": "5f64f01414d5033654d7f95e708d140a",
        "PRO": "965f87e259198b12dd60417585b757eb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "1d2e62a8ba620b3c9f04bd6beb6c72ad"
      },
      "api_calls": {
        "LoD/PD2": [
          "InitializeAsyncEventListeners",
          "SafeCopyDataWithLocking",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_API_1ac4095c3b44": {
      "addresses": {
        "LoD/PD2": "0x6F9B60F0"
      },
      "rvas": {
        "LoD/PD2": "0x60F0"
      },
      "sizes": {
        "LoD/PD2": 102
      },
      "name": "ValidateAndHandleResourceFailure",
      "signature": "void ValidateAndHandleResourceFailure(int resourceContext, int resourceIndex, int validationFlags)",
      "calling_convention": "__stdcall",
      "comment": "Validates game resource and handles validation failures with error recovery.\n\nAlgorithm:\n1. Check if resourceContext (ESI) is zero - if so, skip to error with code 0x70\n2. If resourceContext is non-zero, load parameters from stack (resourceIndex at ESP+0x110, validationFlags at ESP+0x10c, additional param at ESP+0x108)\n3. Call CheckResourceValidity with resourceContext (ECX), resourceIndex, and validationFlags to verify resource state\n4. Compare return value with -1 (validation failure indicator)\n5. If validation passes (return != -1), jump to cleanup and return\n6. If validation fails (return == -1), execute file read sequence:\n   - Allocate 0x104 (260) bytes on stack for fileDataBuffer\n   - Call ReadFileData to load resource data from file using resourceContext\n7. Retrieve error return address using GetReturnAddress with error code (0x70 or 0x79)\n8. Call CleanupAndAbort with hardcoded abort address (0x6f9c0684) and return address\n9. Call _exit(-1) to terminate process\n\nParameters:\n  resourceContext: Implicit context pointer (passed in ESI register, unaffected register)\n  resourceIndex: Resource identifier to validate (DWORD from stack)\n  validationFlags: Validation mode/flags (DWORD from stack)\n\nReturns:\n  void - Function does not return normally; calls _exit() on all paths\n\nSpecial Cases:\n  - If resourceContext is NULL/zero, uses error code 0x70\n  - If validation fails, uses error code 0x79\n  - Function always terminates process via _exit(-1)\n  - 260-byte file buffer allocated to recover resource data on failure\n  - Uses implicit register parameter (ESI) for context outside standard calling convention",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:1ac4095c3b44baad33ce438edc80b34d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "1ac4095c3b44baad33ce438edc80b34d",
        "MNE": "18daef3daaad0cf2ceb111a04873839a",
        "CFG": "290674f0d3e957f3a47123ff526d6d59",
        "PRO": "e095af03ac867df0241b4ac37a9ea83c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "18daef3daaad0cf2ceb111a04873839a"
      },
      "api_calls": {
        "LoD/PD2": [
          "BindSocketToPortWrapper",
          "SafeCopyDataWithLocking",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_API_545c5ebe25fa": {
      "addresses": {
        "LoD/PD2": "0x6F9B6160"
      },
      "rvas": {
        "LoD/PD2": "0x6160"
      },
      "sizes": {
        "LoD/PD2": 85
      },
      "name": "ValidateAndAbortOnError",
      "signature": "void ValidateAndAbortOnError(int nResourceId)",
      "calling_convention": "__stdcall",
      "comment": "Validates file resources and aborts process execution with appropriate error codes\n\nAlgorithm:\n1. Allocate 260-byte buffer on stack for file data storage\n2. Check if nResourceId parameter is zero (indicates uninitialized/empty resource)\n3. If nResourceId is zero, set exit code 0x59 (corrupt fog file error)\n4. If nResourceId is non-zero:\n   - Call CheckFogFileInitialization() to validate fog system state\n   - If validation fails (returns non-zero), return immediately with exit code 0x61\n   - Call ReadFileData(nResourceId, abFileBuffer, 0x104) to read 260 bytes from resource\n   - Set exit code 0x5f (successful data read path)\n5. Call GetReturnAddress(dwExitCode) to get formatted return address for error logging\n6. Call CleanupAndAbort(error_data_table, formatted_address) to log error and perform cleanup\n7. Call _exit(-1) to terminate process immediately\n\nParameters:\nnResourceId (int) - Resource identifier or file ID to validate and read data from\nIMPLICIT: ESI register contains the actual resource ID value used throughout function\n\nReturns:\nFunction does not return - always terminates process via _exit(-1)\nAll execution paths lead to process termination with different error codes\n\nSpecial Cases:\n- nResourceId = 0: Empty/uninitialized resource, exit with code 0x59 (corrupt fog file)\n- nResourceId != 0: Validate fog file system, read resource data, exit with code 0x5f on success\n- Fog validation failure: Early return with exit code 0x61 (fog system error)\n- Buffer size is fixed at 0x104 (260 bytes) for all resource reads\n- Function uses custom calling convention where ESI contains the resource ID parameter\n\nMagic Numbers:\n0x59 (89) - Exit code for corrupt/empty fog file resource\n0x5f (95) - Exit code for successful resource data read\n0x61 (97) - Exit code for fog file system validation failure  \n0x104 (260) - Fixed buffer size for file data reads\n-1 (0xFFFFFFFF) - Process termination exit code\n\nError Handling:\n- Empty resource (ID=0): Immediate abort with fog corruption code\n- Fog validation failure: Early return, process termination handled by caller\n- All error paths converge to CleanupAndAbort() for consistent error logging\n- Process always terminates with _exit(-1) regardless of error type\n\nStructure Layout:\nLocal stack buffer (ESP+4 to ESP+0x107):\nOffset  Size  Field Name    Type        Description\n0x0     0x104 abFileBuffer  byte[260]   Temporary buffer for resource file data\nTotal: 260 bytes (0x104)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:545c5ebe25fa49eb50b6ac63650d3eaa",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "545c5ebe25fa49eb50b6ac63650d3eaa",
        "MNE": "94eb28a01a03305bed306b129c7e8da2",
        "CFG": "1315a0ca8dc8f6f0f8ce0a9336136505",
        "PRO": "041ddb6f0eb543f0f103cce8f42100cf"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "94eb28a01a03305bed306b129c7e8da2"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetDefaultResourceCount",
          "SafeCopyDataWithLocking",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_dd03c1eff4fa": {
      "addresses": {
        "LoD/PD2": "0x6F9B61C0"
      },
      "rvas": {
        "LoD/PD2": "0x61C0"
      },
      "sizes": {
        "LoD/PD2": 37
      },
      "name": "ValidateHandleAndFlushBuffers",
      "signature": "void ValidateHandleAndFlushBuffers(void * this, HANDLE hFile)",
      "calling_convention": "__thiscall",
      "comment": "Validates object handle and flushes associated file buffers to disk\n\nAlgorithm:\n\n1. Validate this pointer is not null - check for valid object instance\n2. If this pointer is null, enter error recovery path\n3. Retrieve caller's return address using GetReturnAddress(0x49) \n4. Call CleanupAndAbort with error data structure and return address\n5. Terminate process with _exit(-1) - no cleanup, immediate termination\n6. If validation passes, flush file buffers for the file handle\n7. Return to caller after successful buffer flush\n\nParameters:\n- this: Object instance pointer (implicit __thiscall parameter)\n- hFile: HANDLE to file whose buffers need flushing\n\nReturns:\n- void: No return value on success\n- Does not return: Function terminates process on null this pointer\n\nSpecial Cases:\n- Null this pointer: Triggers abort sequence with cleanup and process termination\n- GetReturnAddress(0x49): Magic number 0x49 represents specific caller context identifier\n\nError Handling:\n- Null pointer validation: Prevents operation on invalid object\n- Abort path: CleanupAndAbort performs error logging and cleanup before termination\n- Process termination: _exit(-1) bypasses normal cleanup for immediate shutdown\n\nMagic Numbers Reference:\n- 0x49 (73 decimal): Caller context identifier for GetReturnAddress function",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:dd03c1eff4fa6d957368b9e1a1a29222",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "dd03c1eff4fa6d957368b9e1a1a29222",
        "MNE": "d09b06e32f895b2b1771e31ace9b4d08",
        "CFG": "a9c729cc86b83c7c1ad73572a77516e6",
        "PRO": "c5487eb9e5d243be5d8fadb71bb9294a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d09b06e32f895b2b1771e31ace9b4d08"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ReleaseResourceWrapper"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_API_232ab530d9bd": {
      "addresses": {
        "LoD/PD2": "0x6F9B61F0"
      },
      "rvas": {
        "LoD/PD2": "0x61F0"
      },
      "sizes": {
        "LoD/PD2": 57
      },
      "name": "ValidateFogInitialization",
      "signature": "int ValidateFogInitialization(int bSilent)",
      "calling_convention": "__stdcall",
      "comment": "Validates renderer fog initialization state and optionally logs errors.\\n\\nAlgorithm:\\n1. Call CheckFogInitializationStatus() to verify fog renderer state\\n2. If initialization succeeded (non-zero), return 1 immediately\\n3. If initialization failed (zero), call GetLastError() to retrieve error code\\n4. Load bSilent parameter from stack [ESP + 0x4]\\n5. Test if bSilent is zero (0=log errors, non-zero=silent)\\n6. Compare error code with ERROR_FILE_NOT_FOUND (0x2)\\n7. If bSilent is non-zero or error is 0x2, skip logging\\n8. Otherwise, log error with context string and return 0\\n9. Return 0 to indicate validation failure\\n\\nParameters:\\n  int bSilent - Boolean flag: 0=log errors, non-zero=suppress logging\\n\\nReturns:\\n  1 if fog initialization succeeded\\n  0 if fog initialization failed\\n\\nSpecial Cases:\\n  - ERROR_FILE_NOT_FOUND (0x2) is treated as silent failure without logging\\n  - bSilent parameter suppresses error logging when non-zero",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:232ab530d9bd6b0bd43a97315530fa84",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "232ab530d9bd6b0bd43a97315530fa84",
        "MNE": "15579ba3ab96e642c656a5401ec21d55",
        "CFG": "528877bfebb6cb7dc053ab3dc2930fa1",
        "PRO": "e31eb31d8ee12f4cdf5b8c792e58bd5a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "15579ba3ab96e642c656a5401ec21d55"
      },
      "api_calls": {
        "LoD/PD2": [
          "InitializeNetworkSession",
          "ValidateAndInitializeParameter"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_1fd66ef2bd91": {
      "addresses": {
        "LoD/PD2": "0x6F9B6230"
      },
      "rvas": {
        "LoD/PD2": "0x6230"
      },
      "sizes": {
        "LoD/PD2": 298
      },
      "name": "OpenFileSearchDrives",
      "signature": "uint OpenFileSearchDrives(char * lpszFileName, uint * pdwFileHandle)",
      "calling_convention": "__stdcall",
      "comment": "Attempts to open a file by searching the current directory and all CD-ROM drives\n\nAlgorithm:\n1. Extract directory path from implicit EBX parameter using ExtractDirectoryPath\n2. Set file locale using directory path and DAT_6f9c0688 with SFileSetLocale\n3. Attempt to open file at specified path using SFileOpenFile\n4. Return success (1) if file opens immediately\n5. Retrieve list of logical drives using GetLogicalDriveStringsA (260-byte buffer)\n6. For each drive letter in the list:\n   a. Skip drives with backslashes in the path using skip_backslash_loop\n   b. Find string terminator to get complete drive path\n   c. Check drive type using GetDriveTypeA\n   d. If drive type is 5 (CD-ROM), verify volume with GetVolumeInformationA\n   e. If volume exists, set locale and attempt SFileOpenFile on CD-ROM\n   f. Return success (1) if file opens on CD-ROM\n7. Return failure (0) if file not found on any drive\n\nParameters:\n  lpszFileName (char *): Pointer to filename/path string to open\n  pdwFileHandle (uint *): Pointer to handle variable for opened file\n  IMPLICIT lpszBaseDirectory (EBX): Base directory path for file operations\n  IMPLICIT pStormFile (ESI): Storm library file handle for operations\n  IMPLICIT lpszPath (EAX): Current file path being processed\n\nReturns:\n  EAX = 1 if file successfully opened on initial path or any CD-ROM drive\n  EAX = 0 if file not found or no CD-ROM drives available\n\nSpecial Cases:\n  - Skips leading backslashes in path at skip_backslash_loop (0x6f9b62b0)\n  - Drive enumeration buffer limited to 260 bytes (0x104)\n  - Uses Storm Library (SFile*) functions for file operations\n  - Drive strings are null-terminated, with final empty string marking end\n  - CD-ROM identified by drive type value 5 (DRIVE_CDROM)\n  - Volume information verified before attempting open\n  - Magic number 0x7fffffff used as locale flags for SFileSetLocale\n  - Magic number 2 used as open mode for SFileOpenFile (read access)\n\nStructure Layout (Drive String Buffer):\n  Offset  Size  Field Name    Type      Description\n  0x0     260   driveBuffer   char[260] Buffer for GetLogicalDriveStringsA result\n  Format: Multiple null-terminated drive strings (e.g., \"C:\\0D:\\0\") ending with empty string",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:1fd66ef2bd912a0236b7876439979806",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "1fd66ef2bd912a0236b7876439979806",
        "MNE": "d2da31e70923dbc86bdb13cb9ac9f5fa",
        "CFG": "aed112a5007cb14f9fbb09b780d0f6b9",
        "PRO": "c8d947fc30d6667c5f264351b9f30ffe"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d2da31e70923dbc86bdb13cb9ac9f5fa"
      },
      "api_calls": {
        "LoD/PD2": [
          "CopyStringBounded",
          "CopyStringBounded",
          "OpenFileArchive",
          "CopyMemoryWithAlignment",
          "CopyStringBounded",
          "OpenFileArchive"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_API_7d80e82e66ba": {
      "addresses": {
        "LoD/PD2": "0x6F9B6360"
      },
      "rvas": {
        "LoD/PD2": "0x6360"
      },
      "sizes": {
        "LoD/PD2": 279
      },
      "name": "InitializeFogFileSystem",
      "signature": "int InitializeFogFileSystem(undefined4 nUnknownParam, int * pReturnHandle)",
      "calling_convention": "__stdcall",
      "comment": "Initializes and validates the fog file system with comprehensive error handling.\n\nAlgorithm:\n1. Check if fog initialization status is valid via CheckFogInitializationStatus()\n2. If invalid, log error message and return 0\n3. Validate validationResult value from CheckFogInitializationStatus, abort with cleanup if zero\n4. Check fog file initialization status via CheckFogFileInitialization()\n5. If invalid, read file data (260 bytes) into fileBuffer and abort with cleanup\n6. Allocate new fog file handle via Ordinal_10042(0xcf, 0)\n7. If allocation fails, return 0\n8. Load and validate file data from allocated handle via LoadAndValidateFileData()\n9. Check validation result, abort with cleanup if validation fails\n10. Flush file buffers to disk via FlushFileBuffers()\n11. If output parameter pReturnHandle is provided, store fogHandle in it\n12. Return fogHandle on success\n\nParameters:\n- nUnknownParam [undefined4]: First initialization parameter (purpose unknown)\n- pReturnHandle [int *]: Optional pointer to receive allocated file handle\n\nReturns:\n- Allocated fog file handle on success\n- 0 on early validation failure or handle allocation failure\n- Function aborts program if critical validation checks fail\n\nSpecial Cases:\n- Multiple validation checkpoints provide defense-in-depth error handling\n- Returns 0 for handle allocation failure but executes full cleanup+abort for validation failures\n- Aborts with Ordinal_10048 caller context on critical errors\n- Local stack buffer (260 bytes) used for temporary file data during validation",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:7d80e82e66ba4d080f2398fd2a25fe07",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "7d80e82e66ba4d080f2398fd2a25fe07",
        "MNE": "9e4f7baa1db97fd2d0171cf53e707202",
        "CFG": "9361c11c4498d9c5bce7170d46d5cdbd",
        "PRO": "3192fe8ac55b21f59eacb9e2b1a15306"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9e4f7baa1db97fd2d0171cf53e707202"
      },
      "api_calls": {
        "LoD/PD2": [
          "InitializeNetworkSession",
          "ValidateAndInitializeParameter",
          "GetReturnAddress",
          "CleanupAndAbort",
          "GetDefaultResourceCount",
          "SafeCopyDataWithLocking",
          "GetReturnAddress",
          "CleanupAndAbort",
          "AllocateMemoryWithTracking",
          "GetReturnAddress",
          "...+2 more"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_API_48349a4433a4": {
      "addresses": {
        "LoD/PD2": "0x6F9B6480"
      },
      "rvas": {
        "LoD/PD2": "0x6480"
      },
      "sizes": {
        "LoD/PD2": 172
      },
      "name": "InitializeFogFileResources",
      "signature": "void InitializeFogFileResources(void * this, void * pThis, uint fileSize, void * pFileHandle)",
      "calling_convention": "__thiscall",
      "comment": "Initialize FOG (Fog Of War) file resources with multi-stage validation.\n\nThis function performs comprehensive initialization of FOG file resources including:\n- FOG initialization status verification\n- FOG file initialization validation\n- File data reading with size verification\n- Error handling with proper cleanup on failure\n\nAlgorithm:\n1. Call CheckFogInitializationStatus() to verify FOG module ready\n2. If initialization failed, log error with error code 0x59\n3. Check if fileHandle parameter is null; if null set error 0x59\n4. Call CheckFogFileInitialization() to verify file initialized\n5. If file not initialized, read 260 bytes via ReadFileData and set error 0x5f\n6. If file initialized, compare expectedFileSize against actual size\n7. If expectedFileSize exceeds actual, set error 0xa5\n8. If size check passes, call LoadAndValidateFileData() with file parameters\n9. If validation succeeds (non-null result), call FlushFileBuffers() and return\n10. If validation fails, set error 0x49\n11. Call GetReturnAddress() with error code and CleanupAndAbort() for cleanup\n12. Call _exit(-1) to terminate process (no normal return)\n\nParameters:\n  pThis: Implicit this pointer (thiscall convention)\n  fileSize: Expected file size for validation\n  pFileHandle: File handle for read operations\n\nReturns:\n  void: Returns on success; calls _exit(-1) on error (no return)\n\nSpecial Cases:\n  Error codes: 0x59=init/null, 0x5f=read failed, 0xa5=size mismatch, 0x49=validation failed\n  All error paths terminate process via _exit(-1) after error logging",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:48349a4433a4dccc62becabf94fd7571",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "48349a4433a4dccc62becabf94fd7571",
        "MNE": "9c5e5dbe6b955d698d1436c429f52b86",
        "CFG": "d5601f252609504190ed90b23cb32f9e",
        "PRO": "e0ea7c30a2d5cc2a471c01910c278d30"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9c5e5dbe6b955d698d1436c429f52b86"
      },
      "api_calls": {
        "LoD/PD2": [
          "InitializeNetworkSession",
          "ValidateAndInitializeParameter",
          "GetDefaultResourceCount",
          "SafeCopyDataWithLocking",
          "GetReturnAddress",
          "CleanupAndAbort",
          "ReleaseResourceWrapper"
        ]
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_API_d747b94c0ead": {
      "addresses": {
        "LoD/PD2": "0x6F9B6530"
      },
      "rvas": {
        "LoD/PD2": "0x6530"
      },
      "sizes": {
        "LoD/PD2": 159
      },
      "name": "OpenFileWithPathResolution",
      "signature": "uint OpenFileWithPathResolution(void * this, void * pThis, uint nLocaleDLL)",
      "calling_convention": "__thiscall",
      "comment": "Opens a file with automatic path resolution from module directory.\n\nThis function attempts to open a file by first trying the provided path. If that fails,\nit retrieves the current module's directory, truncates the path at the last backslash,\nand retries opening the file from that directory. If that also fails, it searches for\nthe file across multiple drives.\n\nAlgorithm:\n1. Determine file open mode (2 or 3) based on EAX flag\n2. Call SFileSetLocale to set locale to the provided DLL path\n3. Call SFileOpenFile with the locale path and computed mode\n4. If successful, return the opened file handle\n5. If failed, get the executable module's full path via GetModuleFileNameA\n6. Find the last backslash character in the module path\n7. If found, truncate the path by null-terminating after the backslash\n8. Call SFileSetLocale again with the truncated module directory path\n9. Retry SFileOpenFile with the module directory path\n10. If retry succeeds, return the file handle\n11. If retry fails, call OpenFileSearchDrives to search across mounted drives\n12. Return the result from drive search, OR'd with the file mode parameter\n\nParameters:\n  pThis (ECX): Implicit this pointer - points to a buffer for the file path (260+ bytes)\n  nLocaleDLL (Stack[0x8]): Locale DLL path string - used as first attempt location\n\nReturns:\n  uint: File handle if successful (non-zero value from param_1)\n        0 if all search methods fail\n\nSpecial Cases:\n  - If GetModuleFileNameA returns 0, the module path is not available\n  - The last backslash character is found using a reverse search\n  - The return value computation uses NEG/SBB to convert search result to bitmask\n  - File mode selection: 2 if EAX==0, 3 if EAX!=0\n\nStructure Layout:\n  pThis buffer (260+ bytes for module path):\n    Offset 0: Start of path buffer (written by GetModuleFileNameA)\n    Path is null-terminated after truncation at backslash",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:d747b94c0ead4a1c5dd5237a6f9cc9d2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "d747b94c0ead4a1c5dd5237a6f9cc9d2",
        "MNE": "384d68ab1a3d65982d517362c769c1e5",
        "CFG": "1c6cf79beb43c79d57fca67e0f96594f",
        "PRO": "42be04ec19999a781fdea12a98114eae"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "384d68ab1a3d65982d517362c769c1e5"
      },
      "api_calls": {
        "LoD/PD2": [
          "CopyMemoryWithAlignment",
          "OpenFileArchive",
          "CopyStringBounded",
          "OpenFileArchive"
        ]
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_5c73446e6da2": {
      "addresses": {
        "LoD/PD2": "0x6F9B6660"
      },
      "rvas": {
        "LoD/PD2": "0x6660"
      },
      "sizes": {
        "LoD/PD2": 1
      },
      "name": "StubFunction",
      "signature": "void StubFunction(void)",
      "calling_convention": "__stdcall",
      "comment": "Stub function that performs no operation and returns immediately.\n\nAlgorithm:\n1. Return to caller immediately without executing any instructions\n\nParameters:\nNone\n\nReturns:\nvoid - Function returns with no value\n\nSpecial Cases:\nThis is a placeholder/stub function commonly used for ordinal exports that are not implemented or are deprecated. It may be referenced for compatibility purposes or API completeness.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5c73446e6da2bc552d6d981beccb1347",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5c73446e6da2bc552d6d981beccb1347",
        "CFG": null,
        "PRO": "e1ef49ce6ed8909600367da1748e3fa9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5c73446e6da2bc552d6d981beccb1347"
      }
    },
    "D2sound_ADDR_6F9B6670": {
      "addresses": {
        "LoD/PD2": "0x6F9B6670"
      },
      "rvas": {
        "LoD/PD2": "0x6670"
      },
      "sizes": {
        "LoD/PD2": 1
      },
      "name": "UnknownStub_10052",
      "signature": "void UnknownStub_10052(void)",
      "calling_convention": "__stdcall",
      "comment": "Ordinal import stub (10052)\n\nAlgorithm:\n1. Immediately returns to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nThis is a minimal stub function imported via ordinal from an external DLL. It contains only a RET instruction, suggesting it may be:\n- A placeholder or deprecated function\n- A thunk for forwarding calls elsewhere\n- A minimal stub used for function hooking or patching\n- An export stub that was compiled into the binary\n\nThe ordinal number (10052) indicates this was imported by ordinal number rather than by name from a DLL. The actual DLL and original function name are not directly visible in this binary.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5c73446e6da2bc552d6d981beccb1347",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5c73446e6da2bc552d6d981beccb1347",
        "CFG": null,
        "PRO": "e1ef49ce6ed8909600367da1748e3fa9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5c73446e6da2bc552d6d981beccb1347"
      }
    },
    "D2sound_API_1813b25d8837": {
      "addresses": {
        "LoD/PD2": "0x6F9B6680"
      },
      "rvas": {
        "LoD/PD2": "0x6680"
      },
      "sizes": {
        "LoD/PD2": 110
      },
      "name": "ProcessContextCleanup",
      "signature": "void ProcessContextCleanup(void * pContext)",
      "calling_convention": "__fastcall",
      "comment": "Performs thread-safe cleanup operations on a process context object.\n\nAlgorithm:\n1. Validate input context pointer (ECX register) - check for null pointer\n2. Validate context structure - check dword at offset 0x0 is non-zero\n3. If validation fails, trigger fatal error sequence:\n   a. Call GetReturnAddress with error code 0x400\n   b. Call CleanupAndAbort with error context\n   c. Call _exit(-1) to terminate process\n4. If validation succeeds, perform synchronized cleanup:\n   a. Enter critical section at global address 0x6f9c6530\n   b. Check handle at offset 0x48 for non-zero value\n   c. If handle exists:\n      - Call ImportThunk_257 function for resource preparation\n      - Call virtual function at offset 0x48 of object reference\n      - Call FlushFileBuffers with file handle from register ESI\n      - Clear handle at offset 0x48 to zero\n      - Clear state field at offset 0x1c to zero\n   d. Leave critical section\n\nParameters:\n- pContext (ECX): Pointer to process context structure containing:\n  + offset 0x00: validation dword (must be non-zero)\n  + offset 0x1c: state field cleared during cleanup\n  + offset 0x48: resource handle cleared during cleanup\nIMPLICIT: ESI register contains file handle for FlushFileBuffers\n\nReturns:\n- None (void function)\n- Function terminates process on validation failure\n\nSpecial Cases:\n- Null context pointer triggers fatal error code 0x400\n- Zero validation dword triggers same fatal error sequence\n- Critical section synchronization prevents concurrent access\n- Process termination via _exit(-1) on validation failures\n\nMagic Numbers Reference:\n- 0x400: Error code for invalid context validation\n- 0x00: Validation dword offset in context structure\n- 0x1c: State field offset cleared during cleanup\n- 0x48: Resource handle offset cleared during cleanup\n- 0x6f9c6530: Global critical section address\n- -1: Exit code for fatal termination\n\nError Handling:\n- Invalid context validation maps to error code 0x400\n- CleanupAndAbort called with error context for logging\n- Process termination prevents continued execution with invalid state\n- Critical section protects against concurrent modification during cleanup\n\nStructure Layout:\nOffset  Size  Field Name        Type      Description\n0x00    4     dwValidation      uint      Non-zero validation marker\n0x1c    4     dwStateField      uint      State field cleared on cleanup\n0x48    4     hResource         HANDLE    Resource handle cleared on cleanup",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:1813b25d883728024b647d60f66b421c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "1813b25d883728024b647d60f66b421c",
        "MNE": "8e3be0023ba3da7e5333c5d331394b2f",
        "CFG": "2a243539dd196277feb3e0d2576d58d9",
        "PRO": "4d0ec52cdce0bb241a255060866ea718"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8e3be0023ba3da7e5333c5d331394b2f"
      },
      "api_calls": {
        "LoD/PD2": [
          "RemoveGameObjectById",
          "ReleaseResourceWrapper",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_ebe8d933a2ef": {
      "addresses": {
        "LoD/PD2": "0x6F9B66F0"
      },
      "rvas": {
        "LoD/PD2": "0x66F0"
      },
      "sizes": {
        "LoD/PD2": 193
      },
      "name": "ProcessQueueWithLocking",
      "signature": "int ProcessQueueWithLocking(void * this, void * pContext, int queueItemCount, int flags)",
      "calling_convention": "__thiscall",
      "comment": "Processes a queue operation with thread synchronization and context validation.\n\nAlgorithm:\n1. Validate that pContext pointer is not null; abort if null (offset 0x3db)\n2. Call CheckFogInitializationStatus() to verify fog system initialization\n3. If fog not initialized, return 0 (early exit)\n4. Enter critical section at DAT_6f9c6530 for thread-safe queue processing\n5. Load context pointer from pContext (dword at offset 0x0)\n6. Calculate queue item stride as queueItemCount * 4 bytes\n7. Prepare ProcessQueue parameters with context, flags (0x40000 if flags set), and bounds (0x7fffffff)\n8. Call ProcessQueue to process items with critical section held\n9. If ProcessQueue returns non-zero (success):\n   a. Store context pointer to structure offset 0x48\n   b. Set structure flag at offset 0x1c to 1\n   c. Set structure timeout field at offset 0x30 to 0xffffffff\n   d. Leave critical section\n   e. Return 1 (success)\n10. If ProcessQueue returns 0 (failure):\n    a. Call FlushFileBuffers to flush any pending data\n    b. Leave critical section\n    c. Return 0 (failure)\n\nParameters:\n- this (ECX): Pointer to QueueContext structure containing queue pointer at offset 0x0, status fields at offsets 0x1c, 0x30, 0x48\n- pContext (stack): Secondary context pointer used for queue processing\n- queueItemCount (stack): Number of items to process; multiplied by 4 to get byte stride\n- flags (stack): Control flags; bit 0x40000 set when flags parameter is non-zero\n\nReturns:\n- 1 if queue processing succeeded and structure was updated\n- 0 if initialization check failed or queue processing failed\n\nSpecial Cases:\n- Null this pointer triggers fatal error via CleanupAndAbort; process terminates with exit code -1\n- Queue processing failure results in file buffer flush before cleanup\n- All queue operations protected by critical section DAT_6f9c6530\n- Magic value 0x7fffffff used as upper bound for queue processing\n- Structure offsets accessed: +0x0 (pointer), +0x1c (flag), +0x30 (timeout), +0x48 (context storage)\n\nStructure Layout:\nOffset | Size | Field Name        | Type      | Description\n-------|------|-------------------|-----------|----------------------------\n0x00   | 4    | queuePointer      | void*     | Pointer to queue data\n0x04   | 4    | secondaryPointer  | void*     | Secondary context pointer\n0x1c   | 4    | processingFlag    | uint      | Set to 1 when queue processed\n0x30   | 4    | timeoutValue      | uint      | Set to 0xffffffff on success\n0x48   | 4    | contextStorage    | void*     | Stores this pointer\n\nNote: Function uses 1 stack-allocated temporary variable optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:ebe8d933a2ef69bf029d6c8dfe2df313",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "ebe8d933a2ef69bf029d6c8dfe2df313",
        "MNE": "c911f0e87cbf35905caade650857cef7",
        "CFG": "cbe58acf005e2d120794ec48f507ede6",
        "PRO": "cb45d929a378abf2b4457a87d2050ce1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c911f0e87cbf35905caade650857cef7"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "InitializeNetworkSession",
          "InitializeAndOpenAudioStream",
          "ReleaseResourceWrapper"
        ]
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_API_c01fa6e1a170": {
      "addresses": {
        "LoD/PD2": "0x6F9B67C0"
      },
      "rvas": {
        "LoD/PD2": "0x67C0"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "IsEntityValid",
      "signature": "bool IsEntityValid(void * pEntity)",
      "calling_convention": "__fastcall",
      "comment": "Validates that an entity pointer is non-null and has a valid state flag.\n\nAlgorithm:\n1. Check if pEntity is null\n2. If null, retrieve return address and call cleanup/abort handler\n3. If non-null, load state flag from offset +0x48\n4. Return true if state flag is non-zero, false otherwise\n\nParameters:\npEntity (ECX) - Pointer to entity structure being validated\n\nReturns:\nbool - true if entity is valid and state flag is set, false if invalid\n\nSpecial Cases:\n- Null pointer triggers immediate error handling with _exit(-1)\n- State flag at offset +0x48 determines validity (non-zero = valid)\n- Function never returns if pEntity is null",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "d7727b77070060ce66f32b7e948b4d4f",
        "CFG": "6c3f0566df164baf42f457563e0b9bcf",
        "PRO": "3f9b1ad0bc80234181d476f1d5185326"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d7727b77070060ce66f32b7e948b4d4f"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_11df4b5a5564": {
      "addresses": {
        "LoD/PD2": "0x6F9B67F0"
      },
      "rvas": {
        "LoD/PD2": "0x67F0"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "SetStructFieldWithValidation",
      "signature": "void SetStructFieldWithValidation(int * pBasePtr, undefined4 fieldValue)",
      "calling_convention": "__fastcall",
      "comment": "Stores a value at offset +0x44 (field index 0x11) within a structure with null pointer validation.\n\nAlgorithm:\n1. Test if pBasePtr (in ECX) is null\n2. If null, retrieve return address via GetReturnAddress(0x33a)\n3. Call CleanupAndAbort with error context and return address\n4. Exit with code -1 (non-returning)\n5. If not null, store fieldValue (in EDX) at pBasePtr[0x11] (+0x44 bytes)\n6. Return void\n\nParameters:\n  pBasePtr (int *) - Pointer to base structure, validated for null. If null triggers error handling.\n  fieldValue (int) - Value to store at offset +0x44 within the structure.\n\nReturns:\n  void - No return value. Function either stores the field or terminates process.\n\nSpecial Cases:\n  - Null pointer triggers error sequence: GetReturnAddress(0x33a) \u2192 CleanupAndAbort() \u2192 exit(-1)\n  - Error code 0x33a is passed to GetReturnAddress for logging/context\n  - Function uses __fastcall: ECX=pBasePtr, EDX=fieldValue\n  - CleanupAndAbort is non-returning, so exit(-1) acts as failsafe",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "11df4b5a55647da5d3738f182f2a73f5",
        "CFG": "3faa1a24a3d4c996032f03064ca761f6",
        "PRO": "a551eb55670ce10d9b4afc52aadd034e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "11df4b5a55647da5d3738f182f2a73f5"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_ADDR_6F9B6820": {
      "addresses": {
        "LoD/PD2": "0x6F9B6820"
      },
      "rvas": {
        "LoD/PD2": "0x6820"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "ValidatePointerAndSetField",
      "signature": "void ValidatePointerAndSetField(void * pObject, uint dwValue)",
      "calling_convention": "__fastcall",
      "comment": "Validates object pointer and stores a DWORD value at offset +0x40.\n\nAlgorithm:\n1. Test if pObject pointer is null (ECX register in __fastcall)\n2. If null, retrieve return address using GetReturnAddress(0x32f)\n3. Call CleanupAndAbort with error context data at 0x6f9c0684\n4. Call _exit(-1) to terminate process with error code\n5. If pointer valid, store dwValue (in EDX) at offset +0x40 from pObject base\n6. Return to caller\n\nParameters:\n  pObject: Pointer to object to validate and modify (first param in ECX, __fastcall)\n  dwValue: DWORD value to store at offset +0x40 (second param in EDX, __fastcall)\n\nReturns:\n  void - No return value. Terminates process on null pointer; returns normally if successful.\n\nSpecial Cases:\n  - Magic number 0x32f passed to GetReturnAddress indicates ordinal import 10038\n  - Error context data at 0x6f9c0684 shared across multiple validation functions\n  - Process terminates with exit code -1 on validation failure\n  - Offset +0x40 (64 bytes from base) is consistent target across related functions",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "11df4b5a55647da5d3738f182f2a73f5",
        "CFG": "90c4f17418cec0d76ed106d2d34ca67f",
        "PRO": "ee410d429ff82a8399e15364efd98905"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "11df4b5a55647da5d3738f182f2a73f5"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_API_aba62c510a15": {
      "addresses": {
        "LoD/PD2": "0x6F9B6850"
      },
      "rvas": {
        "LoD/PD2": "0x6850"
      },
      "sizes": {
        "LoD/PD2": 120
      },
      "name": "InvokeContextCallback",
      "signature": "uint InvokeContextCallback(void * pContext)",
      "calling_convention": "__fastcall",
      "comment": "Invokes a context-associated callback function with thread-safe synchronization.\\n\\nThis function executes an indirect callback stored in a context structure, using\\ncritical sections to ensure thread-safe access. It validates the context pointer\\nand extracts a callback function pointer from offset +0x48 before execution.\\n\\nAlgorithm:\\n1. Validate that pContext is not null; exit process if invalid\\n2. Enter critical section to synchronize access with other threads\\n3. Check if callback pointer at context+0x48 is non-null\\n4. If callback exists, invoke InvokeIndirectCallback with local buffers\\n5. Check callback return status (non-zero indicates success)\\n6. If callback succeeded, leave critical section and return shifted output value\\n7. If callback failed or pointer was null, leave critical section and return 0\\n\\nParameters:\\n- pContext (ECX): Pointer to context structure containing callback information\\n                  at offset +0x48 (callback function pointer)\\n\\nReturns:\\n- uint: Callback output value right-shifted by 2 bits if callback succeeded,\\n        0 if callback pointer was null or callback returned failure status\\n\\nSpecial Cases:\\n- Null context pointer triggers error handler and process exit (-1)\\n- Callback failure (non-zero result) returns 0 instead of callback output\\n- Output value shifted by 2 (>> 2) suggests output is word-aligned or scaled",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:aba62c510a15a8e44301520e22983d68",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "aba62c510a15a8e44301520e22983d68",
        "MNE": "b7459f44d47822b734f030ca0e4cc00f",
        "CFG": "83509a41426407ecef6d892433381bd2",
        "PRO": "4140994796246d4436dc92893f7d7477"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b7459f44d47822b734f030ca0e4cc00f"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "FindItemById"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_7af59b7920d8": {
      "addresses": {
        "LoD/PD2": "0x6F9B68D0"
      },
      "rvas": {
        "LoD/PD2": "0x68D0"
      },
      "sizes": {
        "LoD/PD2": 75
      },
      "name": "InvokeObjectCallback",
      "signature": "void InvokeObjectCallback(void * this, void * pObject, uint dwCallbackParam1, uint dwCallbackParam2, uint dwCallbackParam3)",
      "calling_convention": "__thiscall",
      "comment": "Setting prototype: void InvokeObjectCallback(void * this, void * pObject, uint dwCallbackParam1, uint dwCallbackParam2, uint dwCallbackParam3)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "7af59b7920d8493637fab9982fb6ea5f",
        "CFG": "d4a4f7f07eed1fb0c24bfad08eb98295",
        "PRO": "9e28843cc6bd376a54e36cd1904aa393"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7af59b7920d8493637fab9982fb6ea5f"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "D2sound_ADDR_6F9B6920": {
      "addresses": {
        "LoD/PD2": "0x6F9B6920"
      },
      "rvas": {
        "LoD/PD2": "0x6920"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "GetObjectField_0x38_OrAbort",
      "signature": "uint GetObjectField_0x38_OrAbort(void * pObject)",
      "calling_convention": "__fastcall",
      "comment": "Safely retrieves a dword value from offset 0x38 within an object structure, validating the pointer first.\n\nAlgorithm:\n1. TEST ECX,ECX to check if pObject pointer is NULL\n2. If NULL (JNZ fails): retrieve return address via GetReturnAddress(0x2e4)\n3. Call CleanupAndAbort with return address and error data at 0x6f9c0684\n4. Call _exit(-1) to terminate process\n5. If pObject valid: MOV EAX, [ECX+0x38] to load field at offset +0x38\n6. RET to return the loaded value in EAX\n\nParameters:\n- pObject (ECX): Pointer to object structure with minimum size 0x3C bytes\n\nReturns:\n- EAX: Value of the dword field at offset +0x38 within the object\n- If pObject is NULL: Function terminates process and does not return\n\nSpecial Cases:\n- NULL pointer handling: Triggers error sequence and immediate process termination\n- Offset 0x38: Hardcoded offset suggests fixed structure layout\n- Return Address Magic: Uses offset 0x2e4 passed to GetReturnAddress for stack unwinding\n- Error Data: References static error data at 0x6f9c0684 (44 xrefs across binary)\n\nStructure Layout:\nThe function accesses a structure with:\nOffset  Size  Field Name             Type        Description\n------  ----  -----                  ----        -----------\n0x38    4     field_at_0x38          uint        Value returned on valid pointer",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "11df4b5a55647da5d3738f182f2a73f5",
        "CFG": "90c4f17418cec0d76ed106d2d34ca67f",
        "PRO": "285107c6c751daa87adb21b45705813b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "11df4b5a55647da5d3738f182f2a73f5"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_234371c39429": {
      "addresses": {
        "LoD/PD2": "0x6F9B6950"
      },
      "rvas": {
        "LoD/PD2": "0x6950"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "ValidatePointerAndGetField",
      "signature": "uint ValidatePointerAndGetField(void * pData)",
      "calling_convention": "__fastcall",
      "comment": "Validates pointer and retrieves field at offset 0x1c.\n\nAlgorithm:\n1. Validate that pData pointer is not NULL\n2. Validate that first dword at pData is not zero\n3. If both validations pass, load and return dword from offset 0x1c\n4. If validation fails, call GetReturnAddress() with parameter 0x2a5\n5. Call CleanupAndAbort() with address 0x6f9c0684 and return address\n6. Call _exit(-1) to terminate program\n\nParameters:\npData (ECX) - Pointer to data structure containing validation field at offset 0 and return value at offset 0x1c\n\nReturns:\nunsigned int - Value from offset 0x1c if validation succeeds\nIf validation fails: Function does not return (calls _exit)\n\nSpecial Cases:\n- pData NULL triggers validation failure\n- First dword at pData being zero triggers validation failure\n- Failure cases result in immediate program termination via CleanupAndAbort\n\nStructure Layout:\nOffset  Size  Field Name        Type      Description\n------  ----  ---------------   --------  ----------------------------------\n  0x00   0x04  validation_flag   uint      Must be non-zero to pass validation\n  0x1c   0x04  return_value      uint      Value returned on successful validation\n\nNote: returnAddress variable requires type change from undefined4 to void* for proper documentation. DAT_6f9c0684 global should be renamed with Hungarian notation.",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "234371c394297c5d1138265585799ca0",
        "CFG": "4955fb5f7256e9d15042d1a65fae17a0",
        "PRO": "1eec3ffc34392e5a8f52f1e427bbc9a9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "234371c394297c5d1138265585799ca0"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_c345355fc1c5": {
      "addresses": {
        "LoD/PD2": "0x6F9B6980"
      },
      "rvas": {
        "LoD/PD2": "0x6980"
      },
      "sizes": {
        "LoD/PD2": 96
      },
      "name": "FinalizeContextCleanup",
      "signature": "void FinalizeContextCleanup(void * pContext)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: void FinalizeContextCleanup(void *pContext)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c345355fc1c5a5280351897d7124e0a2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c345355fc1c5a5280351897d7124e0a2",
        "MNE": "017639e22377964540333b7e81961297",
        "CFG": "f1e7fa26e6f7c88689edf1f3f18e16b5",
        "PRO": "ceed63e870524e8d9f627c040b09bcc3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "017639e22377964540333b7e81961297"
      },
      "api_calls": {
        "LoD/PD2": [
          "ProcessContextCleanup",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_580d47f99333": {
      "addresses": {
        "LoD/PD2": "0x6F9B69F0"
      },
      "rvas": {
        "LoD/PD2": "0x69F0"
      },
      "sizes": {
        "LoD/PD2": 79
      },
      "name": "DestroyContextObjects",
      "signature": "void DestroyContextObjects(void)",
      "calling_convention": "__stdcall",
      "comment": "Destructor that releases three interface objects and clears context memory.\n\nAlgorithm:\n1. Call FinalizeContextCleanup to perform initial cleanup operations\n2. Release interface at context offset 0x10 (if non-null):\n   - Load interface pointer from context[0x10]\n   - Call virtual method at interface+0x8 to destroy interface\n   - Zero out context[0x10]\n3. Release interface at context offset 0xc (if non-null):\n   - Load interface pointer from context[0xc]\n   - Call virtual method at interface+0x8 to destroy interface\n   - Zero out context[0xc]\n4. Release interface at context offset 0x0 (if non-null):\n   - Load interface pointer from context[0x0]\n   - Call virtual method at interface+0x8 to destroy interface\n   - Zero out context[0x0]\n5. Clear remaining context memory:\n   - Use REP STOSD to zero 24 dwords (96 bytes) from context base\n   - This clears all remaining fields in the context structure\n\nParameters:\n- EAX (implicit): Pointer to context structure to be destroyed\n\nReturns:\n- void (no return value)\n\nSpecial Cases:\n- Silently skips interface destruction if interface pointer is NULL\n- REP STOSD clears 0x18 (24) dwords = 96 bytes total\n- Function uses __stdcall convention (callee cleans stack)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:580d47f99333e06cc4225fc7dd8b4b20",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "580d47f99333e06cc4225fc7dd8b4b20",
        "CFG": "3dca9ad0ec7cc11c0f6dee8f8725ad5f",
        "PRO": "73f8020b6b8cf783adbdd1207069ab2c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "580d47f99333e06cc4225fc7dd8b4b20"
      },
      "api_calls": {
        "LoD/PD2": [
          "call_finalize_cleanup"
        ]
      }
    },
    "D2sound_MNE_32670fe22160": {
      "addresses": {
        "LoD/PD2": "0x6F9B6A40"
      },
      "rvas": {
        "LoD/PD2": "0x6A40"
      },
      "sizes": {
        "LoD/PD2": 173
      },
      "name": "ClearAudioBuffer",
      "signature": "int ClearAudioBuffer(void * pAudioBuffer)",
      "calling_convention": "__stdcall",
      "comment": "Clears audio buffer memory and releases associated resources.\n\nAlgorithm:\n1. Validate pAudioBuffer is not NULL; abort with cleanup if NULL\n2. Enter critical section to serialize access\n3. Call virtual method at [pAudioBuffer + 0x2c] to get buffer size\n4. Return 0 immediately if size is negative (error condition)\n5. Zero buffer memory using STOSD (dword) and STOSB (byte) for alignment\n6. Call virtual method at [pAudioBuffer + 0x4c] to release/finalize resources\n7. Leave critical section\n8. Return 1 for success\n\nParameters:\n  pAudioBuffer (via ESI): Pointer to audio buffer object with vtable\n\nReturns:\n  1 if buffer cleared successfully\n  0 if buffer size is invalid (negative)\n\nSpecial Cases:\n  - Function aborts if pAudioBuffer is NULL\n  - Negative buffer size triggers error return\n  - REP STOSD/STOSB for efficient bulk zeroing\n  - Critical section protects concurrent access",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "32670fe22160decbe28f4d2e1fbb3de6",
        "CFG": "d5585b0749df433944c3d439899d8172",
        "PRO": "47552fdd6940d9170be0f3f1a20202da"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "32670fe22160decbe28f4d2e1fbb3de6"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_7c44e2f3f2d9": {
      "addresses": {
        "LoD/PD2": "0x6F9B6AF0"
      },
      "rvas": {
        "LoD/PD2": "0x6AF0"
      },
      "sizes": {
        "LoD/PD2": 86
      },
      "name": "CleanupSynchronizationHandles",
      "signature": "void CleanupSynchronizationHandles(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleans up thread synchronization handles and events.\\n\\nThis function performs graceful shutdown of thread synchronization primitives by:\\n1. Checking that both the event signal handle and thread wait handle are valid\\n2. Signaling the event to wake up waiting threads\\n3. Waiting for the thread to complete with infinite timeout\\n4. Closing both handle resources\\n5. Zeroing the global handle pointers to prevent reuse\\n\\nUsed during game shutdown or thread termination sequences. Must be called with both\\nhandles already initialized; otherwise exits cleanly with no action.\\n\\nAlgorithm:\\n1. Load g_threadWaitHandle (HANDLE to thread/process)\\n2. Check if g_threadWaitHandle is valid (non-NULL), skip cleanup if NULL\\n3. Load g_eventSignalHandle (HANDLE to event object)\\n4. Check if g_eventSignalHandle is valid (non-NULL), skip cleanup if NULL\\n5. Call SetEvent(g_eventSignalHandle) to signal waiting threads\\n6. Call WaitForSingleObject(g_threadWaitHandle, INFINITE) to wait for completion\\n7. Call CloseHandle(g_eventSignalHandle) to release event resource\\n8. Call CloseHandle(g_threadWaitHandle) to release thread/process resource\\n9. Zero g_eventSignalHandle to mark as cleaned\\n10. Zero g_threadWaitHandle to mark as cleaned\\n11. Return to caller\\n\\nReturns:\\nvoid - No return value. Function performs cleanup side effects only.\\n\\nSpecial Cases:\\n- If either handle is NULL, cleanup is skipped entirely (safe no-op)\\n- Uses INFINITE timeout (-0xFFFFFFFF) for WaitForSingleObject\\n- Function uses ESI register for storing CloseHandle function pointer\\n- Must be called before program termination to avoid handle leaks",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7c44e2f3f2d9d26859d882a4bb49600b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7c44e2f3f2d9d26859d882a4bb49600b",
        "CFG": "971923f45045cfb1fa7a76868deb7c00",
        "PRO": "b3457987855c64d9a75ca1132c64404a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7c44e2f3f2d9d26859d882a4bb49600b"
      }
    },
    "D2sound_MNE_af413c75688c": {
      "addresses": {
        "LoD/PD2": "0x6F9B6B60"
      },
      "rvas": {
        "LoD/PD2": "0x6B60"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "GetConditionallyMaskedValue",
      "signature": "uint GetConditionallyMaskedValue(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns a conditionally masked value based on a condition flag.\n\nAlgorithm:\n1. Load condition flag from global address 0x6f9c658c\n2. Load value to be masked from global address 0x6f9c5994\n3. Convert condition flag to boolean mask (-1 if non-zero, 0 if zero) using NEG/SBB idiom\n4. Apply mask by AND operation: result = (condition ? -1 : 0) & value\n5. Return masked result in EAX\n\nReturns:\n- If condition flag is non-zero: returns value from 0x6f9c5994\n- If condition flag is zero: returns 0\n\nSpecial Cases:\n- Uses standard x86 NEG/SBB trick to convert non-zero to -1 (all bits set)\n- Zero value passes through as 0 regardless of condition\n- Non-zero values are preserved when condition is true, zeroed when false\n- Useful for conditional assignment patterns: variable = condition ? value : 0\n\nCalling Convention: __stdcall (Windows API convention, callee cleans stack)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:af413c75688c051388954706b235eefd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "af413c75688c051388954706b235eefd",
        "CFG": null,
        "PRO": "2fc5c7ea4be0df8efb1f8738ac1c656f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "af413c75688c051388954706b235eefd"
      }
    },
    "D2sound_MNE_17507b7151e0": {
      "addresses": {
        "LoD/PD2": "0x6F9B6B80"
      },
      "rvas": {
        "LoD/PD2": "0x6B80"
      },
      "sizes": {
        "LoD/PD2": 116
      },
      "name": "InitializeGameObjectTiming",
      "signature": "void InitializeGameObjectTiming(void * pGameObject, uint dwTimeoutMs, int nUnknown)",
      "calling_convention": "__fastcall",
      "comment": "Initializes timing-related fields in a game object structure for synchronization.\n\nAlgorithm:\n1. Validate pGameObject pointer (check for null)\n2. If null, retrieve return address and abort with error code 0x39e\n3. Check if global synchronization flag (DAT_6f9c658c) is enabled\n4. If disabled, exit early without initializing\n5. Enter critical section to protect shared data\n6. Write magic value 1 to offset +0x4c (sync flag)\n7. Copy value from offset +0x38 to offset +0x50 (initialize from template)\n8. Store timeout parameter to offset +0x54\n9. Get current tick count via GetTickCount()\n10. Write tick count to offset +0x58 (sync start time)\n11. Calculate expiration time: tick count + timeout, store at offset +0x5c\n12. Call LeaveCriticalSection to release lock and exit\n\nParameters:\n  pGameObject: Pointer to game object structure requiring timing initialization\n  dwTimeoutMs: Timeout duration in milliseconds for sync operations\n  nUnknown: Unknown parameter purpose (possibly reserved/unused)\n\nReturns:\n  void - function does not return a value to caller\n\nSpecial Cases:\n  - Null pointer check triggers fatal error with code 0x39e\n  - Synchronization disabled (DAT_6f9c658c == 0) causes early exit without initialization\n  - Critical section ensures thread-safe access to shared data\n  - Uses system GetTickCount() for timing, may wrap after ~49.7 days\n\nOffset Layout (Game Object Structure):\n  Offset  Size  Field Name            Type      Description\n  0x38    4     sync_template_value   uint      Template value copied to offset 0x50\n  0x4c    4     sync_enabled_flag     uint      Set to 1 when sync initialized\n  0x50    4     sync_copy_value       uint      Initialized from template at 0x38\n  0x54    4     timeout_duration      uint      Stores dwTimeoutMs parameter\n  0x58    4     sync_start_time       uint      GetTickCount() at initialization\n  0x5c    4     sync_expiry_time      uint      Start time + timeout duration",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "17507b7151e023f2997bc2b953455a74",
        "CFG": "d9946050ad34ddb0b8760198a469fd62",
        "PRO": "29d6b69b067374dbb2e6104eb1940eda"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "17507b7151e023f2997bc2b953455a74"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_API_0c63a2582d83": {
      "addresses": {
        "LoD/PD2": "0x6F9B6C00"
      },
      "rvas": {
        "LoD/PD2": "0x6C00"
      },
      "sizes": {
        "LoD/PD2": 220
      },
      "name": "SetRenderStateIntensity",
      "signature": "void SetRenderStateIntensity(void * this, void * pRenderState, float intensityValue)",
      "calling_convention": "__thiscall",
      "comment": "Sets the render state intensity/brightness parameter for rendering operations.\n\nAlgorithm:\n1. Validates pRenderState pointer is non-NULL; aborts if NULL\n2. Checks global debug flag (DAT_6f9c659c); resets intensity to 0.0 if set\n3. Checks if render object exists at offset +0x10\n4. If render mode flag (DAT_6f9c6598) equals 1: calls virtual method with mode 1, parameter 0x6f9c01e8\n5. If render mode flag != 1: performs float clamping (0.0-1.0), rounding to int64, calls virtual method twice with mode 5 and 4, parameter 0x6f9c0208\n\nParameters:\n  pRenderState (void*): Pointer to render state object with virtual function table at offset +0\n  intensityValue (float): Brightness/intensity parameter to apply (0.0 = off, 1.0 = full brightness)\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - NULL pointer check triggers abort with error code -1 via _exit()\n  - Global flag DAT_6f9c659c forces intensity to 0.0 when non-zero\n  - Render mode 1 uses direct intensity without clamping\n  - Render mode != 1 clamps value to [0.0, 1.0] range before processing",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:0c63a2582d8388ab3e18046a99121e04",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "0c63a2582d8388ab3e18046a99121e04",
        "MNE": "04aa5d7258a4257e2e1b0ea9cb3513ff",
        "CFG": "0891c074e5f494377db150f3da14bc50",
        "PRO": "a2615b53dc7ef6dd49e1d3a332b97ddd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "04aa5d7258a4257e2e1b0ea9cb3513ff"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ClampFloatValue"
        ]
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_69e7901095da": {
      "addresses": {
        "LoD/PD2": "0x6F9B6CE0"
      },
      "rvas": {
        "LoD/PD2": "0x6CE0"
      },
      "sizes": {
        "LoD/PD2": 147
      },
      "name": "SetObjectProperty",
      "signature": "void SetObjectProperty(void * this, float value)",
      "calling_convention": "__thiscall",
      "comment": "Sets a property value on an object and triggers vtable method if conditions are met.\n\nAlgorithm:\n1. Validate object pointer (this) - abort if NULL with error code 0x345\n2. Load vtable pointer from object offset 0x10\n3. Store property value at object offset 0x3c\n4. Check trigger conditions: vtable exists AND global mode flag equals 2\n5. Check secondary conditions: flag bit 2 set OR value equals global threshold\n6. If all conditions met: clamp value difference, convert to int64, call vtable method\n\nParameters:\n  this: Object pointer with vtable at offset 0x10 (void *)\n  value: Property value to set (float)\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - NULL object pointer: Calls CleanupAndAbort with return address 0x345, exits with code -1\n  - Invalid vtable: Skips method call entirely\n  - Global mode != 2: Skips conditional processing\n  - Flag bit 2 clear AND value != threshold: Skips method call\n\nMagic Numbers:\n  0x10: Vtable pointer offset in object structure\n  0x3c: Property value storage offset in object structure\n  0x34: Flags byte offset in object structure\n  0x04: Bit mask for flag bit 2 (conditional trigger)\n  0x345: Error code passed to CleanupAndAbort for NULL object\n  0x10: Vtable method offset (method index 4, 4-byte pointers)\n  2: Required global mode value for conditional processing\n\nError Handling:\n  - NULL object validation with immediate abort and process exit\n  - No bounds checking on property value\n  - Graceful handling of NULL vtable (skips method call)\n\nStructure Layout:\nOffset | Size | Field Name | Type    | Description\n-------|------|------------|---------|----------------------------------\n0x10   | 4    | pVTable    | int *   | Virtual method table pointer\n0x34   | 1    | bFlags     | byte    | Object state flags (bit 2 = conditional trigger)\n0x3c   | 4    | flValue    | float   | Current property value storage\n\nFlag Bits (offset 0x34):\nBit | Hex  | Description\n----|------|------------------------------------------\n2   | 0x04 | Conditional trigger flag for vtable call",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:0c63a2582d8388ab3e18046a99121e04",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "0c63a2582d8388ab3e18046a99121e04",
        "MNE": "69e7901095da830f1bbfb99739aeadd5",
        "CFG": "d7905c8e8a8e6d05ceded444a342b415",
        "PRO": "fbc31eb09cd62eaa97ebefc208da600a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "69e7901095da830f1bbfb99739aeadd5"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ClampFloatValue"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_API_caf7184fdc1c": {
      "addresses": {
        "LoD/PD2": "0x6F9B6D80"
      },
      "rvas": {
        "LoD/PD2": "0x6D80"
      },
      "sizes": {
        "LoD/PD2": 154
      },
      "name": "SetAlphaBlendValue",
      "signature": "void SetAlphaBlendValue(void * pObject, int nAlphaValue)",
      "calling_convention": "__fastcall",
      "comment": "Sets the alpha/opacity blend value for a graphical object.\n\nAlgorithm:\n1. Validate that pObject pointer is not null; abort with error if invalid\n2. Compare nAlphaValue against threshold 0x80 to determine blend mode\n3. If nAlphaValue > 0x80: Calculate inverted value (0xFF - nAlphaValue), clamp to [0, 127]\n4. If nAlphaValue < 0x80: Use value directly, clamp to [0, 127]\n5. If nAlphaValue == 0x80: Use neutral value of 0\n6. Round clamped float value to 64-bit integer\n7. Invoke virtual method at offset 0x40 in object's vtable with computed alpha value\n\nParameters:\n  pObject: void* - Pointer to graphical object with vtable at offset 0\n  nAlphaValue: int - Alpha/opacity value (0-255 range, 0x80 = neutral)\n\nReturns:\n  void - No return value; updates object state via virtual method call\n\nSpecial Cases:\n  - Null pointer check aborts execution with error code -1\n  - 0x80 (128) is the neutral threshold; values above trigger inversion\n  - Float clamping constrains result to [0.0, 127.0] range\n  - Virtual method offset 0x40 is called with computed alpha as integer parameter\n\nStructure Layout:\n  Offset | Size | Field Name | Type | Description\n  0x00   | 4    | vtable     | ptr  | Pointer to virtual method table\n  0x40   | 4    | setAlpha   | func | Virtual method to set alpha value (offset 0x40 in vtable)\n\nNote: Function uses 2 stack-allocated temporary variables (local_4, local_c) optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:caf7184fdc1c4095ebf40896b81f2229",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "caf7184fdc1c4095ebf40896b81f2229",
        "MNE": "e49c953b2f7d54ca88a18efac53568a9",
        "CFG": "2dcc738904f88247a7adcf795a303ab4",
        "PRO": "1ccef818de8689828695b97ff06d6bfe"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e49c953b2f7d54ca88a18efac53568a9"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ClampFloatValue",
          "ClampFloatValue"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_API_2221fea8a2d1": {
      "addresses": {
        "LoD/PD2": "0x6F9B6E20"
      },
      "rvas": {
        "LoD/PD2": "0x6E20"
      },
      "sizes": {
        "LoD/PD2": 152
      },
      "name": "SetAudioParameterValue",
      "signature": "void SetAudioParameterValue(int * pAudioContext, int paramValue)",
      "calling_convention": "__fastcall",
      "comment": "SetAudioParameterValue - Sets and clamps an audio parameter value\n\nValidates and processes an audio parameter value, scaling it according to a\nglobal scaling factor and applying float transformations based on audio state.\nThe function stores the parameter at offset +0x38, applies conditional float\ntransformation at offset +0x3c, and clamps the final result to 0.0-255.0 range.\n\nParameters:\n  pAudioContext (ECX) - Pointer to audio context structure with virtual table\n  paramValue (EDX)    - Parameter value to set and process\n\nReturns:\n  void\n\nAlgorithm:\n  1. Validate that pAudioContext is not NULL\n  2. Validate that pAudioContext->vtable (offset 0) is not NULL\n  3. Store paramValue at pAudioContext->storedValue (offset 0x38)\n  4. Multiply paramValue by global scaling constant (DAT_6f9c5994)\n  5. Divide result by 0xff to normalize\n  6. If flags at offset 0x34 bit 2 are set AND global state (DAT_6f9c6598) == 2,\n     skip float transformation (use precalculated value)\n  7. Otherwise, apply float transformation:\n     - Load floating point value from offset 0x3c\n     - Subtract from 1.0 constant (at DAT_6f9c0990)\n     - Multiply by scaled integer value\n     - Call RoundFloatToInt64() to convert result\n  8. Clamp final value to 0.0-255.0 range using ClampFloatValue()\n  9. Call RoundFloatToInt64() again to convert clamped value to int\n  10. Invoke virtual function at offset 0x3c with clamped value\n  11. If validation fails, call error handler with GetReturnAddress() and exit(-1)\n\nSpecial Cases:\n  - NULL pointer validation: Calls error handler if pAudioContext or vtable is NULL\n  - Conditional transformation: Float transformation skipped based on flags\n  - Error handling: Non-returning error path with GetReturnAddress and _exit",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:2221fea8a2d1f9f03c7e6324f500b30f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "2221fea8a2d1f9f03c7e6324f500b30f",
        "MNE": "faf930aeb946a80831845374f74b8ffa",
        "CFG": "6cbd3ab203ef76b8dfec1c96555d3562",
        "PRO": "68151c996a118175272292589bc0e49f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "faf930aeb946a80831845374f74b8ffa"
      },
      "api_calls": {
        "LoD/PD2": [
          "ClampFloatValue",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_bb28d7e90cd8": {
      "addresses": {
        "LoD/PD2": "0x6F9B6EC0"
      },
      "rvas": {
        "LoD/PD2": "0x6EC0"
      },
      "sizes": {
        "LoD/PD2": 105
      },
      "name": "ValidateObjectMethod",
      "signature": "uint ValidateObjectMethod(void * pObject)",
      "calling_convention": "__fastcall",
      "comment": "Validates an object and invokes its virtual method at offset +0x24.\n\nAlgorithm:\n1. Validate that pObject pointer is not NULL\n2. Dereference pObject and check if dereferenced value is not NULL\n3. Enter critical section lock (0x6f9c6530)\n4. Retrieve virtual method from vtable at [pObject][0x24]\n5. Call virtual method with pObject and stack buffer as parameters\n6. Test if method return value is negative\n7. Leave critical section lock\n8. Return 1 if method succeeded (non-negative), 0 if failed\n9. If validation fails, retrieve return address and call CleanupAndAbort with error\n\nParameters:\n- pObject: void* - Pointer to object; must not be NULL and dereferenced value must be non-NULL. Must point to vtable with method at offset +0x24\n\nReturns:\n- uint: Returns 1 (true) if object validation passes and virtual method returns non-negative value, 0 (false) if method returns negative value or validation fails. If pObject is NULL, triggers fatal error handler.\n\nSpecial Cases:\n- If pObject is NULL or *pObject is NULL: calls CleanupAndAbort and terminates with _exit(-1)\n- If virtual method at [pObject][0x24] returns negative value: returns 0\n- Return value is masked with 0x1 to ensure boolean 0 or 1 result\n- Critical section 0x6f9c6530 is held during virtual method invocation",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "bb28d7e90cd8dd20307c808240a82993",
        "CFG": "1b9fe5ef5362b7d2a891f265591a0cd0",
        "PRO": "05abba31e70231e17559f4f0c556929d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bb28d7e90cd8dd20307c808240a82993"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_2b79c90a5aad": {
      "addresses": {
        "LoD/PD2": "0x6F9B6F30"
      },
      "rvas": {
        "LoD/PD2": "0x6F30"
      },
      "sizes": {
        "LoD/PD2": 102
      },
      "name": "ActivateGameObject",
      "signature": "int ActivateGameObject(void * pGameObject)",
      "calling_convention": "__fastcall",
      "comment": "Activates a game object by calling its activation virtual method and setting an active flag.\\n\\nAlgorithm:\\n1. Validates input parameter (pGameObject) is not null, aborts if null with error 0x279\\n2. Acquires critical section lock at DAT_6f9c6530 to ensure thread-safe access\\n3. Calls the virtual method at offset +0x30 in the object's vtable with parameters (object, 0, 0, 1)\\n4. Checks activation result; returns 0 (failure) if result < 0 and releases lock\\n5. Sets activation flag at object offset +0x1c to 1 if activation succeeded\\n6. Releases critical section lock\\n7. Returns 1 (success) if activation succeeded, 0 (failure) otherwise\\n\\nParameters:\\n  pGameObject: Pointer to game object with vtable at offset +0x0 and active flag at offset +0x1c\\n\\nReturns:\\n  1 if object was successfully activated\\n  0 if object pointer was null or activation virtual method returned error\\n\\nStructure Layout:\\n  Offset  Size  Field                Type    Description\\n  ------  ----  -----                ----    -----------\\n  +0x00   4     vtable_ptr           void*   Pointer to virtual method table\\n  +0x30   4     activate_vmethod     func    Virtual method for activation (3rd entry in vtable)\\n  +0x1c   4     is_active_flag       dword   Active state flag (0=inactive, 1=active)\\n\\nSpecial Cases:\\n  - If pGameObject is null, calls GetReturnAddress(0x279) and CleanupAndAbort(), never returns\\n  - Synchronization: Uses critical section (DAT_6f9c6530) to serialize access\\n  - Virtual method returns negative value on failure",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "2b79c90a5aad8f36110f0cef7630246f",
        "CFG": "2482a870273702f3bdc5b197d1d06a89",
        "PRO": "b33912ebebf8816ec00067b56137e7bb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2b79c90a5aad8f36110f0cef7630246f"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_48c5b050028b": {
      "addresses": {
        "LoD/PD2": "0x6F9B6FA0"
      },
      "rvas": {
        "LoD/PD2": "0x6FA0"
      },
      "sizes": {
        "LoD/PD2": 226
      },
      "name": "DestroyGameContext",
      "signature": "void DestroyGameContext(int * pGameContext)",
      "calling_convention": "__fastcall",
      "comment": "Destroys and cleans up a game context structure.\n\nAlgorithm:\n1. Validates input context pointer (non-null check with error handling)\n2. Enters critical section for thread-safe cleanup\n3. Calls FinalizeContextCleanup for pre-destruction operations\n4. Calls virtual destructors for three child objects at offsets 0, 0xc, 0x10\n5. Zeros 0x18 (24) dwords from context base (96 bytes total)\n6. Searches global context linked list (DAT_6f9c65cc) for this context\n7. Removes context from linked list by updating list pointers\n8. Reports success error code 0xf0 via ReportError\n9. Leaves critical section and returns\n\nParameters:\npGameContext - Pointer to game context structure (passed in ECX, __fastcall)\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- If pGameContext is NULL, calls GetReturnAddress(0x211), CleanupAndAbort, and exits with code -1\n- Error code 0x211 is logged for null context\n- Error code 0xf0 (240) is reported on successful destruction\n- Error code 0x21d is reported if context not found in linked list\n- The linked list search is critical section protected\n- Memory is zeroed with STOSD.REP instruction (dword fills)\n\nStructure Layout (Game Context):\nOffset  Size  Field       Type         Description\n+0x00   0x04  pObject1    void*        First virtual object (destructor at +0x8)\n+0x04   0x04  unknown     void*        Unknown field\n+0x08   0x04  unknown     void*        Unknown field  \n+0x0c   0x04  pObject2    void*        Second virtual object (destructor at +0x8)\n+0x10   0x04  pObject3    void*        Third virtual object (destructor at +0x8)\n+0x14   0x50  reserved    byte[80]     Reserved/unused space\nTotal: 0x60 (96 bytes)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:48c5b050028b42a309cdec520f6bfb80",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "48c5b050028b42a309cdec520f6bfb80",
        "MNE": "43219a6dded180ceaff4d46f86f1e9b4",
        "CFG": "5685c5e8c024da864cd5bcbcafedf464",
        "PRO": "979a71cab8e77449dd91bc2c791a51cd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "43219a6dded180ceaff4d46f86f1e9b4"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "call_finalize_cleanup",
          "InitializeModule",
          "InitializeModule"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_f733008cfaeb": {
      "addresses": {
        "LoD/PD2": "0x6F9B7090"
      },
      "rvas": {
        "LoD/PD2": "0x7090"
      },
      "sizes": {
        "LoD/PD2": 407
      },
      "name": "InitializeSurfaceBuffer",
      "signature": "int InitializeSurfaceBuffer(uint initFlags)",
      "calling_convention": "__stdcall",
      "comment": "Initializes a surface buffer with the specified configuration flags.\\n\\nAlgorithm:\\n1. Extract control flags from initFlags parameter (bits 0-1)\\n2. Calculate pixel stride and row pitch based on flags\\n3. Determine color depth and buffer size parameters (0x20000 or 0x0)\\n4. Initialize configuration structure array with:\\n   - Width/stride multiplier (0x5622 = 22050 pixels/row width)\\n   - Color format flags (0x14 for one mode, 0x40 for another)\\n   - Additional flags from global DAT_6f9c6584 (adds 0x8000 if set)\\n5. Call virtual method at +0xc on object referenced by DAT_6f9c658c\\n6. If bit 1 of initFlags is set, call virtual method at +0x0 on EAX\\n7. If DAT_6f9c6594 is set, call virtual method at +0x0 on EAX[3]\\n8. Call virtual method at +0x14 on EAX[4] with DAT_6f9c01e8 or DAT_6f9c0208\\n9. Check result byte and verify both bits set (0x3)\\n10. Set surface properties in ESI: buffer size, flags, stride\\n11. Return 1 on success, 0 on failure\\n\\nParameters:\\ninitFlags (uint): Control flags for buffer initialization\\n  Bit 0: Determines pixel stride multiplier (1 or 2)\\n  Bit 1: If set, enables additional initialization path\\n\\nReturns:\\nint: 1 if buffer initialized successfully, 0 on initialization failure\\n\\nSpecial Cases:\\n- Global flag DAT_6f9c6584 affects bit 0x8000 in configuration\\n- Global flag DAT_6f9c6594 gates second initialization branch\\n- Global DAT_6f9c6598 selects between two different data pointers\\n- Magic constant 0x5622 (22050) represents row width in pixels\\n- Result validation checks for specific flag pattern (0x3)\\n\\nStructure Layout:\\nESI is pointer to surface structure:\\nOffset  Size  Field              Type      Description\\n0x00    4     vftable            ptr       Virtual function table pointer\\n0x04    4     bufferSize         uint      Total buffer size in bytes\\n0x08    4     stride             uint      Pixels per row / stride\\n0x0c    4     unknown1           uint      Reserved or temp field\\n0x10    4     unknown2           uint      Reserved or temp field\\n0x30    4     initFlags_copy     uint      Copy of original initFlags\\n0x34    4     param_copy         uint      Copy of param",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f733008cfaebc4a8c5e5a4ac5e318747",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f733008cfaebc4a8c5e5a4ac5e318747",
        "CFG": "79cda752eec7caa49b86e781cdac3dd8",
        "PRO": "abaf4f4feb34d32c126d46c963fced17"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f733008cfaebc4a8c5e5a4ac5e318747"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_b18e1c493026": {
      "addresses": {
        "LoD/PD2": "0x6F9B7230"
      },
      "rvas": {
        "LoD/PD2": "0x7230"
      },
      "sizes": {
        "LoD/PD2": 147
      },
      "name": "ProcessObjectWithSynchronization",
      "signature": "undefined4 ProcessObjectWithSynchronization(void)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: int __stdcall ProcessObjectWithSynchronization(void)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:b18e1c493026651706d3568175c355bb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "b18e1c493026651706d3568175c355bb",
        "MNE": "55f915b52c3a00ebe2f8aa440b90430f",
        "CFG": "50f8eedfa7f092ceacf7d5bc67684c73",
        "PRO": "295dfeda689f8b0875dd3f0b74d1a8b3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "55f915b52c3a00ebe2f8aa440b90430f"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "call_finalize_cleanup"
        ]
      }
    },
    "D2sound_MNE_385fa249d026": {
      "addresses": {
        "LoD/PD2": "0x6F9B72D0"
      },
      "rvas": {
        "LoD/PD2": "0x72D0"
      },
      "sizes": {
        "LoD/PD2": 418
      },
      "name": "ReadCircularBuffer",
      "signature": "uint ReadCircularBuffer(uint bufferOffset, uint bytesToRead, void * pOutputBuffer)",
      "calling_convention": "__stdcall",
      "comment": "Reads data from a circular buffer into an output buffer with thread-safe synchronization.\\nThis function implements circular buffer read operations, handling wraparound logic\\nand boundary conditions for reading arbitrary amounts of data from a managed buffer.\\n\\nAlgorithm:\\n1. Validate critical preconditions: object pointer (EBX), buffer base (EBX[5]), output buffer\\n2. Acquire critical section lock for thread-safe buffer access\\n3. Call virtual method at offset 0x2c to execute initial read operation\\n4. If read fails (negative return), release lock and return 0\\n5. Enter main loop to process read data:\\n   a. If bufferOffset >= buffer end, apply modulo to wrap around to valid range\\n   b. Calculate available contiguous bytes from current offset to end\\n   c. Cap read to available bytes or requested size, whichever is smaller\\n   d. Copy data in 4-byte chunks (DWORD) using REP MOVSD for efficiency\\n   e. Copy remaining 0-3 bytes individually using REP MOVSB\\n   f. Advance output buffer pointer and counters\\n   g. Check if more reads needed (EBX[0x10] indicates multi-read scenario)\\n6. Call virtual method at offset 0x4c to finalize read operation\\n7. If no pending reads and buffer full, set completion flag (EBX[0xb] = 1)\\n8. If bytes remain to fill and limit specified (EBX[0xc] != -1), zero-fill remaining space\\n9. Release critical section lock and return 1 (success)\\n\\nParameters:\\n  bufferOffset (uint): Starting position in circular buffer to read from\\n  bytesToRead (uint): Number of bytes to read from buffer into output\\n  pOutputBuffer (void *): Destination buffer where read data is copied\\n\\nReturns:\\n  uint: 1 if operation succeeded and completed, 0 if read operation failed\\n\\nSpecial Cases:\\n  - Wraparound: When bufferOffset exceeds buffer end, modulo wrapping applies\\n  - Zero-fill: If buffer limit (EBX[0xc]) specified and unread space exists\\n  - Multi-read: Flag at EBX[0x10] indicates whether more reads required\\n  - Thread Safety: Critical section lock (DAT_6f9c6530) protects all buffer access\\n\\nStructure Layout:\\n  Offset  Size  Field Name        Type      Description\\n  ------  ----  ----------------  --------  ------\\n  +0x00   4     vftable           pointer   Virtual function table\\n  +0x04   4     unknown_1         uint      Unknown field\\n  +0x14   4     bufferBase        pointer   Base address of data buffer\\n  +0x18   4     bufferEnd         uint      End position of circular buffer\\n  +0x24   4     readOffset        uint      Current read position counter\\n  +0x30   4     readLimit         uint      Maximum bytes to read (-1 = unlimited)\\n  +0x40   4     continueRead      uint      Flag: more reads needed\\n  +0x44   4     wrapStart         uint      Wraparound start offset\\\"",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "385fa249d0263b86ff0856b08fb77a84",
        "CFG": "7dc396ce0d0ae3209014a19c90358d6e",
        "PRO": "cddd815f23e88c96ab7b7af4dd924f63"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "385fa249d0263b86ff0856b08fb77a84"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_API_13d2012fc7c4": {
      "addresses": {
        "LoD/PD2": "0x6F9B7480"
      },
      "rvas": {
        "LoD/PD2": "0x7480"
      },
      "sizes": {
        "LoD/PD2": 133
      },
      "name": "SetGlobalAudioParameter",
      "signature": "void SetGlobalAudioParameter(int parameterIndex)",
      "calling_convention": "__fastcall",
      "comment": "Sets a global audio parameter across all active audio contexts.\n\nThis function updates an audio parameter value for all audio device contexts managed by the audio system. It validates the parameter index, uses critical sections for thread safety, and iterates through a linked list of active audio contexts to apply the parameter change.\n\nAlgorithm:\n1. Check if audio system is initialized (DAT_6f9c658c) and if parameter has changed\n2. Validate parameter index is in valid range (0-255)\n3. If invalid, log error at 0x3b9 and abort with CleanupAndAbort\n4. Enter critical section to protect global audio state (DAT_6f9c6530)\n5. Store new parameter index in DAT_6f9c5994\n6. Iterate through linked list of audio contexts starting at DAT_6f9c65cc\n7. For each context node, retrieve audio context pointer at offset +0x0\n8. If context is NULL, log error at 0x2e4 and abort\n9. Call SetAudioParameterValue with context and parameter index (at offset +0x38)\n10. Move to next node in linked list at offset +0x4\n11. Exit loop when node pointer is NULL\n12. Leave critical section and return\n\nParameters:\n- parameterIndex (ECX via __fastcall): Audio parameter index to set (0-255)\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- If audio system not initialized, function returns without action\n- If parameter index already set, function returns without action\n- Invalid parameter range (< 0 or > 255) triggers error code 0x3b9\n- NULL context pointer in linked list triggers error code 0x2e4\n- Both error cases call CleanupAndAbort and exit with status -1\n\nStructure Layout:\nAudio Context Linked List Node:\n  Offset  Size  Field Name           Type         Description\n  0x00    4     audioContext         void*        Pointer to audio context\n  0x04    4     nextNode             Node*        Next node in linked list",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:13d2012fc7c48af5fa9cae791c6e8d97",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "13d2012fc7c48af5fa9cae791c6e8d97",
        "MNE": "3bfdc8d4521fb5b6a9cb5647abc84367",
        "CFG": "f4db238b7f5bd7bc43df45f30a79ad3b",
        "PRO": "b2f8aee909b47ed8424d776f4bef395e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3bfdc8d4521fb5b6a9cb5647abc84367"
      },
      "api_calls": {
        "LoD/PD2": [
          "SetAudioParameterValue",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_c7342149fd99": {
      "addresses": {
        "LoD/PD2": "0x6F9B7510"
      },
      "rvas": {
        "LoD/PD2": "0x7510"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "FadeOutAudioParameter",
      "signature": "void FadeOutAudioParameter(uint durationMs)",
      "calling_convention": "__fastcall",
      "comment": "Gradually fades out the current audio parameter to zero over a specified duration.\n\nAlgorithm:\n1. Check if audio system is enabled (DAT_6f9c658c != 0)\n2. Validate duration parameter is at least 1 (checks if ECX > 0 after fastcall)\n3. If invalid duration, retrieve return address via GetReturnAddress(0x387) and abort with CleanupAndAbort\n4. Calculate decrementPerSleep as (totalValue * 20) / duration, where 20ms is the sleep interval\n5. Initialize currentParameter to totalValue (DAT_6f9c5994)\n6. While currentParameter is not zero:\n   a. Sleep for 20 milliseconds\n   b. Subtract decrementPerSleep from currentParameter (bounds check prevents negative values)\n   c. Call SetGlobalAudioParameter with updated currentParameter value\n7. Return to caller\n\nParameters:\ndwDurationMs (ECX): Duration in time units for the fade-out operation. Must be greater than 0. Used to calculate the rate of parameter decrease. Invalid durations (<=0) trigger immediate abort.\n\nReturns:\nvoid - Function does not return a value. Calls _exit(-1) on validation failure.\n\nSpecial Cases:\n- If audio system is disabled (DAT_6f9c658c == 0), function returns immediately without doing anything\n- If duration is <= 0, function calls CleanupAndAbort and _exit, terminating the process\n- If totalValue is 0, the loop is skipped entirely\n- Each iteration sleeps for exactly 20ms (0x14 milliseconds)\n- Decrements are rounded down due to integer division\n- When decrementPerSleep > currentParameter, currentParameter is set to 0 instead of going negative\n\nMagic Numbers Reference:\n0x387 - Error code passed to GetReturnAddress for duration validation failure\n0x14 - Sleep interval in milliseconds (20ms) for fade stepping\n-1 - Exit code used when terminating on invalid duration\n\nError Handling:\n- Invalid duration (<=0): GetReturnAddress(0x387), CleanupAndAbort, _exit(-1)\n- Audio system disabled: Silent early return\n- Underflow protection: Set currentParameter to 0 when decrement would cause negative value",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "c7342149fd992105040af106150ced41",
        "CFG": "6c3b0aa07951c5e00ecf5c0f67c56cb3",
        "PRO": "d2d25b459a503d9214b828869328e2b1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c7342149fd992105040af106150ced41"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_93806dcab8ba": {
      "addresses": {
        "LoD/PD2": "0x6F9B7541"
      },
      "rvas": {
        "LoD/PD2": "0x7541"
      },
      "sizes": {
        "LoD/PD2": 63
      },
      "name": "FadeAudioParameter",
      "signature": "void FadeAudioParameter(uint fadeDurationMs)",
      "calling_convention": "__fastcall",
      "comment": "Gradually fades an audio parameter to zero using a loop with sleep intervals.\n\nAlgorithm:\n1. Calculate decrement value by scaling g_dwAudioParameter using dwScaleFactor and fadeDurationMs\n2. Initialize dwCurrentParameterValue to g_dwAudioParameter (starting value)  \n3. If dwCurrentParameterValue is zero, return immediately (nothing to fade)\n4. Loop:\n   a. Sleep for 20ms (0x14 milliseconds) between adjustments\n   b. Compare dwDecrementValue against dwCurrentParameterValue\n   c. If dwDecrementValue <= dwCurrentParameterValue: subtract from value\n   d. If dwDecrementValue > dwCurrentParameterValue: set to zero (end of fade)\n   e. Call SetGlobalAudioParameter with the current decremented value\n   f. Continue loop while dwCurrentParameterValue is non-zero\n\nParameters:\n  fadeDurationMs (ECX): Duration in milliseconds to spread the fade operation\n  IMPLICIT dwScaleFactor (EAX): Scale factor for calculating decrement amount\n\nReturns:\n  void: No return value; operates via side effects (calls SetGlobalAudioParameter)\n\nSpecial Cases:\n  - If g_dwAudioParameter is 0, loop is skipped entirely\n  - Sleep(0x14) ensures 20ms minimum between parameter updates  \n  - Fade completes when dwCurrentParameterValue reaches zero\n  - Decrement value is calculated once at start, not recalculated per iteration\n\nMagic Numbers Reference:\n  0x14 (20): Sleep duration in milliseconds between parameter adjustments\n  0x24 (36): Right shift amount for scaling calculation in decrement formula\n\nError Handling:\n  - No explicit error checking; relies on SetGlobalAudioParameter validation\n  - Division by zero protection via shift operation in decrement calculation\n\nGlobal Data Access:\n  g_dwAudioParameter (0x6f9c5994): Current audio parameter value to fade from",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:93806dcab8ba79a416bb8864dda68429",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "93806dcab8ba79a416bb8864dda68429",
        "CFG": "5336196579c4dc79ca84dd3c6dccbcc0",
        "PRO": "a55c3d20511417c403a74f100af438a7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "93806dcab8ba79a416bb8864dda68429"
      },
      "api_calls": {
        "LoD/PD2": [
          "SetGlobalAudioParameter"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_1b8fa24832f3": {
      "addresses": {
        "LoD/PD2": "0x6F9B7580"
      },
      "rvas": {
        "LoD/PD2": "0x7580"
      },
      "sizes": {
        "LoD/PD2": 199
      },
      "name": "InitializeAudioBuffer",
      "signature": "int InitializeAudioBuffer(void * pAudioObject, void * pWaveData, uint waveDataSize)",
      "calling_convention": "__fastcall",
      "comment": "Initializes an audio object with WAV file data and format information.\n\nAlgorithm:\n1. Validate input parameters (pAudioObject non-null, first dword non-zero, pWaveData non-null, waveDataSize non-zero)\n2. If validation fails, set error code 0x257 and jump to error handler\n3. Enter critical section to lock audio resource access\n4. Call ParseWaveFileHeader to extract WAV format and locate data chunk from pWaveData\n5. Compare required buffer size (from wav header) against object capacity at offset +0x44\n6. If required size exceeds capacity, set error code 0x25f and jump to error handler\n7. Store parsed data pointer at object offset +0x14 and size at offset +0x18\n8. Call ReadCircularBuffer with object's circular buffer pointer (offset +0x4) to reset state\n9. Set object's flag at offset +0x28 to 1 (audio ready)\n10. Check if buffer mode flag at offset +0x40 is zero AND if parsed size fits within buffer at offset +0x4\n11. If conditions met, store parsed size at object offset +0x30; otherwise store 0xffffffff\n12. Leave critical section and return 1 on success\n13. On error, call GetReturnAddress, CleanupAndAbort, and _exit(-1)\n\nParameters:\n- pAudioObject (ECX): Pointer to game audio object structure\n  Accessed offsets: +0x4=circular buffer, +0x14=data pointer, +0x18=size, +0x28=ready flag, +0x30=buffer offset, +0x40=mode flag, +0x44=capacity\n- pWaveData (EDX): Pointer to WAV file data buffer in memory\n- waveDataSize (Stack): Size of WAV data in bytes\n\nReturns:\n- 1 (success) on successful initialization\n- Never returns on error (calls _exit(-1) after cleanup)\n\nSpecial Cases:\n- Error code 0x257 for null or invalid input parameters\n- Error code 0x25f for insufficient buffer capacity to hold audio data\n- Uses critical section locking for thread-safe audio resource access\n- Buffer offset (field +0x30) set to 0xffffffff when buffer mode flag is set or size exceeds available buffer\n- Buffer offset set to parsed size when mode flag is clear and size fits within buffer capacity\n- WaveFormatInfo structure (16 bytes) extracted and temporarily stored on stack during parsing",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:1b8fa24832f34d6587a39d84dd7221b0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "1b8fa24832f34d6587a39d84dd7221b0",
        "MNE": "3e9b021456f07010b33e3adb8ffdffa2",
        "CFG": "b1f8968cc2b4f04e3a072e3287861a54",
        "PRO": "1078ce7b158af7e639de7bc23e97dd0a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3e9b021456f07010b33e3adb8ffdffa2"
      },
      "api_calls": {
        "LoD/PD2": [
          "ParseWaveFileHeader",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_API_309769229a84": {
      "addresses": {
        "LoD/PD2": "0x6F9B7650"
      },
      "rvas": {
        "LoD/PD2": "0x7650"
      },
      "sizes": {
        "LoD/PD2": 233
      },
      "name": "InitializeGameObject",
      "signature": "void InitializeGameObject(void * pGameObject)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: void InitializeGameObject(void * pGameObject)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:309769229a8417e6710e077d66b158b8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "309769229a8417e6710e077d66b158b8",
        "MNE": "8e25d66e868cb23f4377c4503828e97e",
        "CFG": "85bd82f7b594b447914b08f2017160e0",
        "PRO": "b41199760ffed5469a47d2380b27b528"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8e25d66e868cb23f4377c4503828e97e"
      },
      "api_calls": {
        "LoD/PD2": [
          "InvokeObjectCallback",
          "SetObjectProperty",
          "SetAudioParameterValue",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_fdbee2620f23": {
      "addresses": {
        "LoD/PD2": "0x6F9B7740"
      },
      "rvas": {
        "LoD/PD2": "0x7740"
      },
      "sizes": {
        "LoD/PD2": 187
      },
      "name": "CreateSurfaceBuffer",
      "signature": "void * CreateSurfaceBuffer(uint bufferFlags, uint dwSurfaceConfig)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: void * CreateSurfaceBuffer(uint bufferFlags, uint dwSurfaceConfig)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:fdbee2620f231dae993295050c45c2f6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "fdbee2620f231dae993295050c45c2f6",
        "MNE": "c2344e363c5ee7617b47fcb5c652f48f",
        "CFG": "fe1d406d564ccf69c2f97473c3dfa2e5",
        "PRO": "124b2411dbd3052a6fe578eb38b3104b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c2344e363c5ee7617b47fcb5c652f48f"
      },
      "api_calls": {
        "LoD/PD2": [
          "AllocateMemoryWithTracking",
          "InitializeModule",
          "AllocateMemoryWithTracking"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_API_c3bcafcb3a39": {
      "addresses": {
        "LoD/PD2": "0x6F9B7800"
      },
      "rvas": {
        "LoD/PD2": "0x7800"
      },
      "sizes": {
        "LoD/PD2": 671
      },
      "name": "ProcessAudioContextQueue",
      "signature": "uint ProcessAudioContextQueue(void)",
      "calling_convention": "__stdcall",
      "comment": "Audio context queue processor that manages a linked list of audio objects.\\n\\nALGORITHM:\\n1. Wait for event signal with 50ms timeout (0x32)\\n2. Enter critical section protecting audio context list\\n3. Get window iconic state and store previous state\\n4. Check if audio processing should be suspended\\n5. Iterate through linked list of audio contexts:\\n   - Call synchronization handler for context\\n   - Update audio parameters if window state changed\\n   - Process time-based parameter interpolation:\\n     * Check if current time within time range [dwStartTime, dwEndTime]\\n     * If yes, interpolate parameter from dwStartValue to dwEndValue\\n     * If no (time expired), stop audio and clear time range\\n   - Handle audio data reading from source:\\n     * Invoke read callback to get audio data\\n     * Write data to circular output buffer\\n     * Clear output buffer as needed based on read position\\n   - Handle cleanup on read failure or invalid context\\n6. Move to next context in linked list (singly-linked via +0x4)\\n7. Leave critical section\\n8. Wait again for next event signal\\n9. Return 0 on error, continue loop on timeout\\n\\nPARAMETERS:\\nNone (uses global event handle and audio context queue)\\n\\nRETURNS:\\nuint - Always returns 0 (stdcall caller cleanup)\\n\\nSPECIAL CASES:\\n- Magic numbers: 0x32 = 50ms timeout, 0x102 = WAIT_TIMEOUT\\n- Offset 0x4c = dwTimeRangeActive (time interpolation enabled)\\n- Offset 0x58/0x5c = dwStartTime/dwEndTime bounds\\n- Offset 0x50/0x54 = dwStartValue/dwEndValue for interpolation\\n- Offset 0x20/0x24 = read/write positions in circular buffer\\n- Offset 0x1c = dwPlayingState flag\\n- Error path: invalid context causes cleanup abort via _exit(-1)\\n\\nSTRUCTURE LAYOUT:\\nAudio context structure (linked list node):\\nOffset | Size | Field Name       | Type       | Description\\n-------|------|------------------|------------|----------------------------------------\\n0x0    | 4    | pVtable          | void**     | Virtual method table pointer\\n0x4    | 4    | pNextContext     | AudioCtx*  | Linked list next pointer\\n0x8    | 4    | dwBufferSize     | uint       | Circular buffer size (power of 2)\\n0x20   | 4    | dwReadPos        | uint       | Read position in circular buffer\\n0x24   | 4    | dwWritePos       | uint       | Write position in circular buffer\\n0x48   | 4    | pUserCallback    | void*      | User callback handler\\n0x4c   | 4    | dwTimeRangeActive| uint       | Interpolation time range active\\n0x50   | 4    | dwStartValue     | int        | Interpolation start value\\n0x54   | 4    | dwEndValue       | int        | Interpolation end value\\n0x58   | 4    | dwStartTime      | uint       | Time range start (GetTickCount)\\n0x5c   | 4    | dwEndTime        | uint       | Time range end (GetTickCount)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c3bcafcb3a39c1ed800cabb1adae83a6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c3bcafcb3a39c1ed800cabb1adae83a6",
        "MNE": "3bee71710045c958b3258ff800fec4ac",
        "CFG": "38e18735120a689997ce2c221e9a0134",
        "PRO": "cc4f78f87181c2821765c7cfe588b13b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3bee71710045c958b3258ff800fec4ac"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetWindowHandleValue",
          "ProcessGameResourceQueue",
          "SetAudioParameterValue",
          "SetAudioParameterValue",
          "SetAudioParameterValue",
          "ProcessContextCleanup",
          "FindItemById",
          "ProcessContextCleanup",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      }
    },
    "D2sound_MNE_b21f881c7f32": {
      "addresses": {
        "LoD/PD2": "0x6F9B7AA0"
      },
      "rvas": {
        "LoD/PD2": "0x7AA0"
      },
      "sizes": {
        "LoD/PD2": 90
      },
      "name": "InitializeAudioContextQueue",
      "signature": "void InitializeAudioContextQueue(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes the audio context queue processing system with thread and event management.\n\nAlgorithm:\n1. Check if thread wait handle is already initialized (g_threadWaitHandle != NULL)\n2. If already initialized, get return address using GetReturnAddress(0xbc)\n3. Call CleanupAndAbort with error message and return address, then exit(-1)\n4. Create manual-reset event using CreateEventA(NULL, bManualReset=1, bInitialState=0, NULL)\n5. Store event handle in g_eventSignalHandle global variable\n6. Create worker thread using CreateThread with ProcessAudioContextQueue as entry point\n7. Store thread handle in g_threadWaitHandle global variable\n\nParameters:\nNone\n\nReturns:\nvoid - No return value, function initializes global state\n\nSpecial Cases:\n- If called multiple times, terminates process with error code -1\n- Thread ID is stored in local stack variable dwThreadId\n- Event object created with manual reset mode for persistent signaling\n- Uses __stdcall calling convention\n\nError Handling:\n- Double initialization triggers cleanup and process termination\n- CleanupAndAbort called with error message pointer and return address\n- Process exits with code -1 after cleanup\n\nMagic Numbers Reference:\n0xbc - Parameter passed to GetReturnAddress for stack frame calculation\n1 - bManualReset=TRUE for event creation (manual reset mode)\n0 - bInitialState=FALSE for event creation (initially non-signaled)\n-1 - Exit code for double initialization error",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "b21f881c7f3216efb485bfffb98c01f0",
        "CFG": "c5d962dcda6c5eaa07bed312c848de2f",
        "PRO": "37f1be870f6fd1e3d992bc5f986a0b66"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b21f881c7f3216efb485bfffb98c01f0"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      }
    },
    "D2sound_MNE_7b4de9f0cf35": {
      "addresses": {
        "LoD/PD2": "0x6F9B7B00"
      },
      "rvas": {
        "LoD/PD2": "0x7B00"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetCurrentAudioTrack",
      "signature": "int GetCurrentAudioTrack(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns the index of the currently active audio track.\n\nThis function provides read-only access to the global audio track state\nvariable (DAT_6f9c65c0). The value is set by SetAudioTrack (Ordinal_10045)\nwhen a new track is requested and cleared to 0 by various cleanup functions\n(ProcessAudioQueue, ClearAudioQueue, FinalizeAudioContext) when audio\nprocessing completes or is interrupted.\n\nReturns:\n  int - The current audio track index (0 = no track active, >0 = track ID)\n\nSpecial Cases:\n  - Returns 0 when no audio track is currently playing\n  - The global state is managed by critical sections in other functions\n    to ensure thread safety during concurrent audio operations",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "82c96f3a470b96e1792c6ab5af77b425"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_MNE_38478acf8bac": {
      "addresses": {
        "LoD/PD2": "0x6F9B7B10"
      },
      "rvas": {
        "LoD/PD2": "0x7B10"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "IsGameContextInitialized",
      "signature": "bool IsGameContextInitialized(void)",
      "calling_convention": "__stdcall",
      "comment": "Checks if the game context is initialized and the game state flag is active.\n\nAlgorithm:\n1. Load the global game context pointer from DAT_6f9c6580\n2. Test if the context pointer is null\n3. If null, jump to context_invalid and return 0 (false)\n4. If non-null, load the initialized flag from offset +0x48 within the context\n5. Test if the flag is zero\n6. If zero, jump to context_invalid and return 0 (false)\n7. If non-zero, set EAX to 1 and return (true)\n8. context_invalid: Clear EAX and return 0 (false)\n\nReturns:\n  true (1) if game context is initialized and the game state flag at offset +0x48 is non-zero\n  false (0) if context is null or the initialized flag is zero\n\nSpecial Cases:\n  - The function assumes DAT_6f9c6580 is always allocated if not null\n  - Offset 0x48 appears to be an initialized/active flag within the context structure\n  - Uses __stdcall convention with caller stack cleanup",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:38478acf8bac1550b76702ba8d8e9b34",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "38478acf8bac1550b76702ba8d8e9b34",
        "CFG": "b4e746256717b4b06ffccfb298eb390e",
        "PRO": "f2a43915327f01b23b4b25b42a9fd693"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "38478acf8bac1550b76702ba8d8e9b34"
      }
    },
    "D2sound_API_13c909aa35a0": {
      "addresses": {
        "LoD/PD2": "0x6F9B7B30"
      },
      "rvas": {
        "LoD/PD2": "0x7B30"
      },
      "sizes": {
        "LoD/PD2": 30
      },
      "name": "CleanupGameAndDispatchFinal",
      "signature": "void CleanupGameAndDispatchFinal(void)",
      "calling_convention": "__stdcall",
      "comment": "Performs final game shutdown by destroying game context and dispatching final cleanup handlers.\n\nAlgorithm:\n1. Load global game context pointer from DAT_6f9c6580\n2. Check if context pointer is non-null\n3. If context exists, call DestroyGameContext() to clean up all game resources\n4. Nullify the global context pointer to mark cleanup as complete\n5. Call DispatchFinalCleanup() to invoke remaining cleanup handlers\n6. Return to caller\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- If game context is already null, skip destruction and proceed directly to final cleanup\n- Global context pointer DAT_6f9c6580 is set to null after destruction to prevent double-free\n- DispatchFinalCleanup always called regardless of context state",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:13c909aa35a00a0fca1958a4650e94af",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "13c909aa35a00a0fca1958a4650e94af",
        "MNE": "7af578b6e6fc9b145cededb9595ea246",
        "CFG": "1abbbed88598ab76171d956e8b753f75",
        "PRO": "5adb7e403fc95e56421d58c8c6dafe9b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7af578b6e6fc9b145cededb9595ea246"
      },
      "api_calls": {
        "LoD/PD2": [
          "DestroyGameContext",
          "DestroyAllGameObjects"
        ]
      }
    },
    "D2sound_MNE_b40e163105ac": {
      "addresses": {
        "LoD/PD2": "0x6F9B7BC0"
      },
      "rvas": {
        "LoD/PD2": "0x7BC0"
      },
      "sizes": {
        "LoD/PD2": 158
      },
      "name": "InitializeMusicData",
      "signature": "void InitializeMusicData(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes music data structures by clearing flag fields in array elements.\n\nAlgorithm:\n1. Load configuration value from global flag (DAT_6f9c65b4)\n2. Load item count from global counter (DAT_6f9c5948)\n3. Initialize loop counter to 0\n4. Return early if item count <= 0\n5. For each item in array:\n   a. Check if initialization flag (DAT_6f9c65e0) is set\n   b. If not set, set flag to 1 and store config value (DAT_6f9c65dc)\n   c. Validate item count hasn't changed during processing (DAT_6f9c5990)\n   d. If count mismatch, call error handler with code 0x52\n   e. Validate loop index is within bounds\n   f. If index >= count, call error handler with code 0x53\n   g. Select array based on config flag:\n      - If DAT_6f9c65dc == 0: use common_options array (0x6f9c5908)\n      - Else: use introedit array (0x6f9c5950)\n   h. Calculate entry address: base + (index * 2 * sizeof(pointer))\n   i. Clear flag field at offset +4 (second element of entry)\n   j. Increment loop counter\n6. Return normally when all items processed\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\nOn error: Calls CleanupAndAbort() and _exit(-1), does not return\n\nSpecial Cases:\nEmpty array (count <= 0): Returns immediately without processing\nCount validation failure: Calls error handler with code 0x52 (count mismatch)\nIndex bounds violation: Calls error handler with code 0x53 (bounds failed)\n\nMagic Numbers Reference:\n0x52 (82 decimal) - Error code for item count mismatch validation\n0x53 (83 decimal) - Error code for array index bounds violation\n0x6f9c5908 - Base address of common_options array\n0x6f9c5950 - Base address of introedit array\n2 - Array stride multiplier (each entry is 2 pointers: data + flags)\n-1 - Exit code passed to _exit() on fatal error\n\nError Handling:\nCount mismatch during processing triggers error code 0x52\nArray bounds violation triggers error code 0x53\nBoth errors call GetReturnAddress() for debugging info\nErrors call CleanupAndAbort() with error string and return address\nFatal errors call _exit(-1) - function never returns on error\n\nStructure Layout:\nMusic data arrays contain entries with 2-element structure:\nOffset  Size  Field Name  Type       Description\n0x00    4     pData       void*      Pointer to music data\n0x04    4     dwFlags     uint       Status/initialization flags\n\nFlag Bits:\nThe flag field at offset +4 is cleared to 0 during initialization\nPurpose appears to be reset/initialization state tracking",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "b40e163105ac1e681f80641c630009a1",
        "CFG": "c53fc15315e1bf97c60bf976631deab8",
        "PRO": "34821bae2f2ca8015fe63f7ac72c26dd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b40e163105ac1e681f80641c630009a1"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      }
    },
    "D2sound_API_3533df656d3f": {
      "addresses": {
        "LoD/PD2": "0x6F9B7C60"
      },
      "rvas": {
        "LoD/PD2": "0x7C60"
      },
      "sizes": {
        "LoD/PD2": 99
      },
      "name": "ValidateAndInitializeGameObject",
      "signature": "int ValidateAndInitializeGameObject(int pGameObject, int pQueue)",
      "calling_convention": "__fastcall",
      "comment": "Validates preconditions and initializes a game object with queue processing.\n\nAlgorithm:\n1. Load global game object pointer from DAT_6f9c6580\n2. Validate pointer is not NULL (fail if NULL)\n3. Load and validate DAT_6f9c658c flag (fail if zero)\n4. Load and validate DAT_6f9c5994 flag (fail if zero)\n5. Load field at offset +0x48 from game object pointer\n6. Validate field equals zero (fail if non-zero, indicates already initialized)\n7. Validate pGameObject parameter is non-zero (fail if zero)\n8. Call InitializeGameObject with global game object pointer\n9. Call SetAudioParameterValue with parameter 0x6e (110 decimal)\n10. Call ProcessQueueWithLocking with game object, NULL pointer, and pQueue\n11. Return 1 if ProcessQueueWithLocking returns non-zero, else return 0\n12. Return 0 for any failed validation checks\n\nParameters:\n- pGameObject (ECX): Input parameter indicating object context or resource ID\n- pQueue (EDX): Queue reference to pass to ProcessQueueWithLocking\n\nReturns:\n- 1 (TRUE) if queue processing succeeded and validation passed\n- 0 (FALSE) if any validation check failed or queue processing returned zero\n\nSpecial Cases:\n- Offset 0x48 in game object is checked for zero (initialization state flag)\n- Returns 0 if any global state pointer or flag is invalid\n- Parameter pGameObject must be non-zero to proceed with initialization\n- Magic number 0x6e (110) passed to audio parameter function",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:3533df656d3fc2bcb2cfd6a9495a4b4b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "3533df656d3fc2bcb2cfd6a9495a4b4b",
        "MNE": "a24a321b9aaacf167f743eea115b9739",
        "CFG": "9ddb4d9027f5333831a62fb85fa25472",
        "PRO": "e0929f65c3c7f879f93df5cc43653ef0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a24a321b9aaacf167f743eea115b9739"
      },
      "api_calls": {
        "LoD/PD2": [
          "InitializeGameObject",
          "SetAudioParameterValue",
          "ProcessQueueWithLocking"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_API_44aa1a553542": {
      "addresses": {
        "LoD/PD2": "0x6F9B7CD0"
      },
      "rvas": {
        "LoD/PD2": "0x7CD0"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "FinalizeAudioBuffer",
      "signature": "void FinalizeAudioBuffer(void)",
      "calling_convention": "__cdecl",
      "comment": "Finalizes audio buffer setup after DirectSound initialization.\n\nAlgorithm:\n1. Load audio configuration pointer from EAX register (implicit parameter)\n2. Store audio config to global DAT_6f9c65c8\n3. Call DispatchViaFunctionPointer() to trigger audio dispatch\n4. Call CreateSurfaceBuffer(1, audio_config) to create primary audio surface buffer\n5. Store surface buffer pointer to global DAT_6f9c6580\n6. Return to caller\n\nReturns: void\n\nSpecial Cases:\n- Receives audio configuration context via EAX register (implicit __stdcall parameter)\n- Must be called after InitializeAudioContextQueue() completes\n- Creates primary sound buffer surface for audio playback\n- Called during InitializeDirectSoundAudio() finalization phase",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:44aa1a553542f506e4d5f0bbb47e97a8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "44aa1a553542f506e4d5f0bbb47e97a8",
        "MNE": "2b972db7e0cd700c35c8083f2d891d9a",
        "CFG": null,
        "PRO": "0456a1891aaf159e049c06a7073de180"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2b972db7e0cd700c35c8083f2d891d9a"
      },
      "api_calls": {
        "LoD/PD2": [
          "SetConfigurationParameter",
          "CreateSurfaceBuffer"
        ]
      }
    },
    "D2sound_MNE_18f866543621": {
      "addresses": {
        "LoD/PD2": "0x6F9B7D00"
      },
      "rvas": {
        "LoD/PD2": "0x7D00"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "EnableMusicSystem",
      "signature": "void EnableMusicSystem(int musicEnableFlag)",
      "calling_convention": "__fastcall",
      "comment": "Enables or disables the music system and initializes music data structures.\n\nAlgorithm:\n1. Check if musicEnableFlag is non-zero (music enable request)\n2. If enable requested, check if music system already initialized (DAT_6f9c65c0 == 0)\n3. If not initialized, call InitializeMusicData() to load and configure all music resources\n4. Set initialization completion flag (DAT_6f9c65c4 = 1) to mark one-time init complete\n5. Store the musicEnableFlag value in global music state variable (DAT_6f9c65c0)\n6. Return to caller\n\nParameters:\n  musicEnableFlag: Non-zero enables music system, zero disables it. Triggers initialization on first enable.\n\nReturns:\n  void\n\nSpecial Cases:\n  - InitializeMusicData() is called only once when transitioning from disabled (0) to enabled state\n  - Multiple enable calls are safe; subsequent calls skip initialization\n  - Disabling (musicEnableFlag=0) does not stop or cleanup music, only disables new initialization\n  - Global flags DAT_6f9c65c0 and DAT_6f9c65c4 track state across multiple invocations",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:18f8665436216dac905dc56ae0dd71d9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "18f8665436216dac905dc56ae0dd71d9",
        "CFG": "f155d0c44892482ddc4c2438493b4162",
        "PRO": "e29f266278dc8a786d879de42efbd0d9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "18f8665436216dac905dc56ae0dd71d9"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_3cf6c803a080": {
      "addresses": {
        "LoD/PD2": "0x6F9B7D30"
      },
      "rvas": {
        "LoD/PD2": "0x7D30"
      },
      "sizes": {
        "LoD/PD2": 633
      },
      "name": "ProcessGameResourceQueue",
      "signature": "int ProcessGameResourceQueue(void)",
      "calling_convention": "__stdcall",
      "comment": "Processes the game resource initialization queue with synchronization.\n\nThis function manages the allocation and initialization of game resources (music/audio)\nin a thread-safe manner using critical sections. It implements a dual-mode selection\nstrategy: either sequentially iterating through available slots or randomly selecting\nfrom unallocated resources.\n\nAlgorithm:\n1. Enter critical section to ensure thread-safe access\n2. Validate game object, resource flags, and system state (return 0 if invalid)\n3. Iterate through available resource slots looking for empty slots (offset+4==0)\n4. If no empty slots found on first pass:\n   - Call reset function (FUN_6f9b7bc0) to refresh resource state\n   - Set hasProcessedOnce flag to track iteration completion\n   - Retry slot iteration\n5. Process resource selection based on forceSelectMode flag (DAT_6f9c65c4):\n   - If forceSelectMode==0: Generate random slot index using _rand() % slotCount\n   - Else: Use sequential first-available slot from mode-specific table\n6. Mark selected slot as allocated (set offset+4 to 0x1)\n7. Validate game object state and initialize if conditions met:\n   - Game object pointer valid and not nullptr\n   - Resource flags enabled (DAT_6f9c658c, DAT_6f9c5994)\n   - Game object state field (offset+0x48) equals 0\n   - Slot data pointer valid (non-null)\n8. Call InitializeGameObject() and ProcessQueueWithLocking() to process queue\n9. Leave critical section and return 1 if queue processing succeeded, else continue loop\n10. On state validation failure: Call GetReturnAddress() and CleanupAndAbort() then _exit(-1)\n\nParameters: None (uses global state variables)\n\nReturns:\n- 0: Initial validation failed or resource reset completed successfully\n- 1: Queue processing succeeded (item initialized and processed)\n- Non-returning: Calls _exit(-1) on critical state validation failures\n\nSpecial Cases:\n- Ordinal codes 0x52/0x53 passed to GetReturnAddress for error context\n- Slot wrapping: When random index exceeds slotCount, wraps to index 0\n- Mode selection: Uses DAT_6f9c65dc to determine resource type (0=common, 1=intro)\n- Critical state failure at offsets: iVar6 != DAT_6f9c5990 (inconsistent slot counts)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:3cf6c803a080056b4d5197812171eb89",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "3cf6c803a080056b4d5197812171eb89",
        "MNE": "0df12f066171bef43519ac1c37ec20a0",
        "CFG": "a9c264a47bdb929b64904979f5dab4a9",
        "PRO": "36900256318c77fe3a5dd93b695a43db"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0df12f066171bef43519ac1c37ec20a0"
      },
      "api_calls": {
        "LoD/PD2": [
          "InitializeGameObject",
          "ProcessQueueWithLocking",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      }
    },
    "D2sound_MNE_d1d0fb2372e9": {
      "addresses": {
        "LoD/PD2": "0x6F9B7FB0"
      },
      "rvas": {
        "LoD/PD2": "0x7FB0"
      },
      "sizes": {
        "LoD/PD2": 40
      },
      "name": "InitializeGameObjectTimingIfValid",
      "signature": "void InitializeGameObjectTimingIfValid(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes timing for the global game object if it is valid and ready.\\n\\nAlgorithm:\\n1. Load global game object pointer from DAT_6f9c6580\\n2. Test if pointer is non-null (JZ to exit if null)\\n3. Load timing field from object at offset +0x48\\n4. Test if timing field is non-null (JZ to exit if null)\\n5. Write 0 to DAT_6f9c65c0 (clear sync flag)\\n6. Push timeout parameter 0xc8 (200 milliseconds)\\n7. Call InitializeGameObjectTiming with EDX=0 and object pointer in ECX\\n8. Return to caller\\n\\nParameters:\\n  (none) - Function takes no parameters, uses global state\\n\\nReturns:\\n  void - No return value\\n\\nSpecial Cases:\\n  - If global object pointer is null, function exits early without action\\n  - If timing field at offset +0x48 is null, function exits early without action\\n  - DAT_6f9c65c0 is cleared before calling InitializeGameObjectTiming\\n  - Always passes 200 (0xc8) as timeout parameter to InitializeGameObjectTiming",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d1d0fb2372e940a8d9d2992f409beb25",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d1d0fb2372e940a8d9d2992f409beb25",
        "CFG": "59064043b32d878adeb9b6c7844d59e3",
        "PRO": "5135108793f2f2e56c2a453307694d9a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d1d0fb2372e940a8d9d2992f409beb25"
      },
      "api_calls": {
        "LoD/PD2": [
          "InitializeGameObjectTiming"
        ]
      }
    },
    "D2sound_MNE_8435bc0f12a8": {
      "addresses": {
        "LoD/PD2": "0x6F9B7FE0"
      },
      "rvas": {
        "LoD/PD2": "0x7FE0"
      },
      "sizes": {
        "LoD/PD2": 33
      },
      "name": "TryFinalizeContext",
      "signature": "void TryFinalizeContext(void)",
      "calling_convention": "__stdcall",
      "comment": "Conditionally finalizes context if cleanup conditions are met.\n\nAlgorithm:\n1. Load global context pointer from 0x6f9c6580 into ECX\n2. Test if context pointer is non-null (compare to zero)\n3. If null, jump to function return without cleanup (0x6f9b8000)\n4. Load cleanup flag from context offset +0x48 into EAX\n5. Test if cleanup flag is non-zero\n6. Clear status flag at global 0x6f9c65c0 to 0\n7. If cleanup flag is zero, jump to function return\n8. If cleanup flag is non-zero, jump to FinalizeContextCleanup at 0x6f9b6980\n9. Return to caller\n\nParameters:\nNone - Function uses global variables:\n  0x6f9c6580 - Pointer to context object for finalization\n  0x6f9c65c0 - Status/result flag (cleared to 0 on function entry)\n\nReturns:\nvoid - Returns normally after cleanup or if conditions not met.\n       Does not return if FinalizeContextCleanup is called (calls _exit on error).\n\nSpecial Cases:\n- Context pointer is null: returns immediately without cleanup\n- Context cleanup flag (offset +0x48) is zero: returns without calling finalization\n- Context cleanup flag is non-zero: delegates to FinalizeContextCleanup which may abort\n- Status flag at 0x6f9c65c0 is always cleared to zero at entry\n\nGlobal Data Accessed:\n0x6f9c6580 - Context pointer (4 bytes, checked for null validity)\n0x6f9c65c0 - Status flag (4 bytes, cleared on entry)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8435bc0f12a8928fbaef24ebbfcdad2a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8435bc0f12a8928fbaef24ebbfcdad2a",
        "CFG": "5ac69ddc4dc620d0fa43b9c6ebcc7e34",
        "PRO": "cfa4f3e7f062dc7226418fc41b940a2e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8435bc0f12a8928fbaef24ebbfcdad2a"
      },
      "api_calls": {
        "LoD/PD2": [
          "call_finalize_cleanup"
        ]
      }
    },
    "D2sound_ADDR_6F9B8010": {
      "addresses": {
        "LoD/PD2": "0x6F9B8010"
      },
      "rvas": {
        "LoD/PD2": "0x8010"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetGameInitializationFlag",
      "signature": "uint GetGameInitializationFlag(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the current game initialization flag value from global memory.\n\nAlgorithm:\n\n1. Load the global initialization flag value from memory address 0x6f9c65b8\n2. Return the flag value to the caller\n\nParameters:\n    None\n\nReturns:\n    uint: The current game initialization flag value\n          - Non-zero indicates game is initialized/ready\n          - Zero indicates game is not yet initialized\n\nSpecial Cases:\n    Direct memory read operation with no validation or error handling.\n    Always returns the current state of the global initialization flag.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "27e26c748504e5d0c43a72ba7996b1dc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_MNE_03dd7fceaa94": {
      "addresses": {
        "LoD/PD2": "0x6F9B8020"
      },
      "rvas": {
        "LoD/PD2": "0x8020"
      },
      "sizes": {
        "LoD/PD2": 127
      },
      "name": "ProcessAllContextsCleanup",
      "signature": "void ProcessAllContextsCleanup(void)",
      "calling_convention": "__stdcall",
      "comment": "Processes cleanup operations for all active game contexts.\n\nAlgorithm:\n1. Check if game is initialized (DAT_6f9c65b8 != 0)\n   - If not initialized, return immediately\n2. Save non-volatile registers (EBX, EDI, ESI)\n3. Load critical section address from DAT_6f9c6530\n4. Initialize pointer to context array base (0x6f9c6560)\n5. Loop through all context array slots (up to 0x6f9c6580):\n   a. Load context pointer from current array slot\n   b. Validate context pointer (not null)\n   c. Check context header (offset +0x0)\n   d. If invalid context: report fatal error and call _exit(-1)\n   e. Enter critical section lock\n   f. Check if cleanup flag set (offset +0x48)\n   g. If cleanup needed: call ProcessContextCleanup(context)\n   h. Call context vtable method at [vtable + 0x48]\n   i. Clear context field at offset +0x1c to 0\n   j. Leave critical section lock\n   k. Advance to next array slot and continue\n6. Return to caller\n\nParameters:\nNone (accesses global state via:\n  - DAT_6f9c65b8: Game initialization flag\n  - DAT_6f9c6530: Critical section lock\n  - DAT_6f9c6560: Start of context array\n  - 0x6f9c6580: End of context array)\n\nReturns:\nvoid (terminates with _exit(-1) on fatal error)\n\nStructure Layout:\nContext Object Header:\nOffset  Size  Field Name      Type      Description\n+0x00   4     pVTable         void*     Virtual method table pointer\n+0x1c   4     cleanup_state   uint      Cleanup tracking field\n+0x48   4     cleanup_flag    uint      Non-zero indicates cleanup needed\n\nArray Layout:\nBase:    0x6f9c6560 (context array)\nEnd:     0x6f9c6580\nStride:  4 bytes per slot\nSlots:   8 (32 bytes / 4 bytes per entry)\n\nError Codes:\n0x292 (658): Offset/line number where error originated\nError message address: 0x6f9c0684\n\nSpecial Cases:\n- Function is called from CleanupGameResources during shutdown\n- Validates critical context objects before cleanup\n- Fatal error if context array contains null/invalid pointers\n- Unconditional _exit(-1) on validation failure (no recovery)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c345355fc1c5a5280351897d7124e0a2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c345355fc1c5a5280351897d7124e0a2",
        "MNE": "03dd7fceaa94aaeca0af9608babc5c4b",
        "CFG": "255f3e5d7f45b64b73ce459d3401e54e",
        "PRO": "9d7ca967d0bf89da7e032eebe440f2c9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "03dd7fceaa94aaeca0af9608babc5c4b"
      },
      "api_calls": {
        "LoD/PD2": [
          "ProcessContextCleanup",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      }
    },
    "D2sound_MNE_dd4822909025": {
      "addresses": {
        "LoD/PD2": "0x6F9B80A0"
      },
      "rvas": {
        "LoD/PD2": "0x80A0"
      },
      "sizes": {
        "LoD/PD2": 85
      },
      "name": "CheckUnitActAssignment",
      "signature": "int CheckUnitActAssignment(void)",
      "calling_convention": "__stdcall",
      "comment": "Checks if any unit in the unit array has an assigned Act structure.\n\nAlgorithm:\n1. Check if global unit array pointer (DAT_6f9c65b8) is initialized\n2. If not initialized, return 0 (no act assignment found)\n3. Iterate through unit pointer array starting at DAT_6f9c6560\n4. For each unit pointer entry:\n   a. Dereference pointer to get UnitAny structure\n   b. Validate pointer is non-null and first field (dwType) is non-zero\n   c. If validation fails, trigger assertion and exit process\n   d. Check if Act pointer field (offset 0x1C / piVar1[7]) is non-null\n   e. If Act pointer is assigned, return 1 (found)\n   f. Move to next array entry (+4 bytes for next pointer)\n5. Continue until reaching array boundary at 0x6f9c6580\n6. If no unit has assigned Act, return 0\n\nParameters:\nNone - function uses global unit array pointers\n\nReturns:\nEAX = 1 if any unit has non-null pAct field\nEAX = 0 if no units found or all have null pAct\n\nSpecial Cases:\n- Array length determined by boundary 0x6f9c6580 - 0x6f9c6560 = 32 bytes = 8 unit pointers\n- Assertion failure (0x2a5) triggers if unit pointer is null or dwType field is zero\n- Function appears to check Act assignment status on startup or initialization\n- Calls CleanupAndAbort (0x6f9b5f50) on validation failure, which triggers fatal error\n\nStructure Layout (UnitAny at unit pointer):\nOffset | Size | Field      | Type    | Description\n0x00   | 4    | dwType     | DWORD   | Unit type (checked for non-zero)\n0x04   | 4    | dwTxtFileNo| DWORD   | Txt file index\n...    | ...  | ...        | ...     | ...\n0x1C   | 4    | pAct       | Act*    | Pointer to Act structure (checked here)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "dd4822909025236612fa4e9e7bba8c2c",
        "CFG": "e5e3123a5bb8e17a31d8df3762047d21",
        "PRO": "c9b4bf2e614a0990808455e6ce68d480"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "dd4822909025236612fa4e9e7bba8c2c"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      }
    },
    "D2sound_API_0153fc3fd82b": {
      "addresses": {
        "LoD/PD2": "0x6F9B8100"
      },
      "rvas": {
        "LoD/PD2": "0x8100"
      },
      "sizes": {
        "LoD/PD2": 90
      },
      "name": "InitializeAllGameObjectTimings",
      "signature": "void InitializeAllGameObjectTimings(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes timing counters for all active game objects in the object pool.\n\nAlgorithm:\n1. Check if the global game object pool is initialized (DAT_6f9c65b8 != 0)\n2. If not initialized, skip processing and return\n3. Iterate through each object pointer in the object pool array (0x6f9c6560 to 0x6f9c6580)\n4. For each object pointer, validate that it is non-null and has a valid first field (not NULL)\n5. If validation fails, call error handler to obtain error code and abort execution\n6. If validation succeeds, check if object has a non-zero value at offset +0x1c (field 7)\n7. If non-zero, call InitializeGameObjectTiming with timing parameter 0xc8 (200 milliseconds)\n8. Advance to next object pointer in the array and continue until all objects processed\n\nParameters:\nNone - this function uses global game object pool references\n\nReturns:\nvoid - function does not return on failure (calls _exit), returns normally on success\n\nSpecial Cases:\n- NULL object pointer in pool triggers immediate error handler and application exit\n- Object with zero first field triggers error handler and exit (invalid/corrupted object)\n- Objects with zero value at offset +0x1c are skipped (no timing initialization needed)\n- Error code 0x2a5 is returned from GetReturnAddress for failed validation\n\nStructure Layout:\nThe function accesses game objects with the following field at offset +0x1c:\nOffset  Size  Field Name        Type        Description\n0x00    4     objectType        uint        First validation field (must be non-zero)\n0x1c    4     timerField        uint        Indicates if timing initialization required",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:0153fc3fd82bb58640c7fe9e56ab40e6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "0153fc3fd82bb58640c7fe9e56ab40e6",
        "MNE": "5726543c8e344ef3da3a58c01ec6a38e",
        "CFG": "ba458a7f801502d026de08a8634129bf",
        "PRO": "f1fc7dd10cc32fb9fae28abb2b469285"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5726543c8e344ef3da3a58c01ec6a38e"
      },
      "api_calls": {
        "LoD/PD2": [
          "InitializeGameObjectTiming",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      }
    },
    "D2sound_API_116e794ee7c6": {
      "addresses": {
        "LoD/PD2": "0x6F9B8160"
      },
      "rvas": {
        "LoD/PD2": "0x8160"
      },
      "sizes": {
        "LoD/PD2": 147
      },
      "name": "CleanupGameResources",
      "signature": "void CleanupGameResources(void)",
      "calling_convention": "__stdcall",
      "comment": "Performs complete game resource cleanup and shutdown sequence.\n\nAlgorithm:\n1. Check if game is initialized (DAT_6f9c65b8 != 0)\n2. Acquire critical section lock to ensure thread-safe cleanup\n3. Call Ordinal_10000() for pre-cleanup operations\n4. Iterate through context array (0x6f9c6560 to 0x6f9c6580, 32-byte stride)\n   - Destroy each game context via DestroyGameContext()\n   - Clear context pointer to null\n5. Traverse linked list starting at DAT_6f9c65bc\n   - Check error flag at offset +0x50 (non-zero = error state)\n   - If error flag set, report error code 0x67\n   - Always report error code 0x68 for each node\n   - Load next pointer from offset +0x5c and advance\n   - Continue until next pointer is null\n6. Clear initialization flag (DAT_6f9c65b8 = 0)\n7. Release critical section lock\n8. Return to caller\n\nParameters:\nNone (accesses global state)\n\nReturns:\nvoid\n\nStructure Layout (Linked List Node):\nOffset  Size  Field Name     Type      Description\n+0x50   4     error_flags    uint      Status flags (non-zero = error)\n+0x5c   4     pNext          void*     Next node pointer (null = list end)\n\nSpecial Cases:\n- Called from entry point, likely during program shutdown\n- Error codes 0x67 and 0x68 reported unconditionally on each linked list node\n- Critical section protects against concurrent access during cleanup\n- Handles both initialized and uninitialized states gracefully",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:116e794ee7c6a3289639d8bcb052b661",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "116e794ee7c6a3289639d8bcb052b661",
        "MNE": "fa95752d1de3654e235fc2ee3fc0d89f",
        "CFG": "36bc2ca7589eb932eec59014ebd32f6c",
        "PRO": "a38bbc513024c56a1d371f048ea091bc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fa95752d1de3654e235fc2ee3fc0d89f"
      },
      "api_calls": {
        "LoD/PD2": [
          "ProcessAllContextsCleanup",
          "DestroyGameContext",
          "InitializeModule",
          "InitializeModule"
        ]
      }
    },
    "D2sound_API_ea3c91696a7e": {
      "addresses": {
        "LoD/PD2": "0x6F9B8200"
      },
      "rvas": {
        "LoD/PD2": "0x8200"
      },
      "sizes": {
        "LoD/PD2": 278
      },
      "name": "FindAndActivateItemByName",
      "signature": "void FindAndActivateItemByName(char * pItemName)",
      "calling_convention": "__fastcall",
      "comment": "FindAndActivateItemByName - Finds item in linked list and activates it\n\nAlgorithm:\n1. Check if item system initialized (DAT_6f9c65b8)\n2. Enter critical section to lock access to linked list\n3. Traverse linked list at DAT_6f9c65bc, comparing item names with search string\n4. For each item, perform string comparison byte-by-byte (handles null terminators)\n5. When name matches, search item array (DAT_6f9c6560) for matching ID (at offset +0x58)\n6. Verify item is valid and state flag at offset +0x1c is clear\n7. Call Ordinal_10005 to initialize item\n8. Call Ordinal_10069 with item parameters from offsets +0x50 and +0x54\n9. Call func_0x10187690 (likely performs game update)\n10. Call ActivateGameObject to activate the matched item\n11. Leave critical section and return\n\nParameters:\n- pItemName (ECX): Null-terminated string name of item to find and activate\n\nReturns:\n- void (no return value)\n\nSpecial Cases:\n- If item system not initialized, returns immediately\n- If linked list is empty or null, exits cleanly\n- If item name found but not in array or array invalid, calls CleanupAndAbort\n- Iterates up to 8 items in array (hardcoded limit at 0x6f9b829e)\n- Item comparison uses string comparison at offset +0x58 in current node\n\nStructure Layout (Item/Object Node):\n- Offset +0x00: Item name string (compared in string_compare_loop)\n- Offset +0x50: First parameter for Ordinal_10069\n- Offset +0x54: Second parameter for Ordinal_10069\n- Offset +0x58: Item ID (used for array matching)\n- Offset +0x5c: Pointer to next item in linked list (traversal)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:ea3c91696a7eb97afaca8804538c3375",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "ea3c91696a7eb97afaca8804538c3375",
        "MNE": "f63ac7f9bb1eea2766e25f9b56fb7935",
        "CFG": "1bf665b44fdc29afd36c04d9186793f2",
        "PRO": "1905600a5e86ba906b1c0c28166ccc44"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f63ac7f9bb1eea2766e25f9b56fb7935"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "InitializeGameObject",
          "InitializeAudioBuffer",
          "ActivateGameObject"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_6ba3b2362e20": {
      "addresses": {
        "LoD/PD2": "0x6F9B8320"
      },
      "rvas": {
        "LoD/PD2": "0x8320"
      },
      "sizes": {
        "LoD/PD2": 152
      },
      "name": "InitializeAudioResource",
      "signature": "void InitializeAudioResource(char * pResourcePath)",
      "calling_convention": "__fastcall",
      "comment": "Initializes an audio resource from a WAV file path by creating a linked list node with file metadata.\n\nAlgorithm:\n1. Check if global audio system flag is enabled (DAT_6f9c65b8)\n2. Initialize fog file system with zero parameter and retrieve data size (dataSize)\n3. Parse WAV file header to extract format information (waveFormatInfo)\n4. Verify sample rate matches target value (0x5622 = 22050 Hz)\n5. Allocate memory block for audio resource node (0x8a = 138 bytes)\n6. Set up linked list: new node->next = current head (DAT_6f9c65bc)\n7. Update head pointer to new node\n8. Store file handle and data size in new node at offsets +0x50 and +0x54\n9. Store stereo flag (1 if 2 channels, 0 otherwise) at offset +0x58\n10. Copy resource path string from input parameter to new node using loop\n\nParameters:\n  pResourcePath (char *) - Pointer to null-terminated WAV file path string to load\n\nReturns:\n  void - No explicit return value; updates linked list head on success\n\nSpecial Cases:\n  - If DAT_6f9c65b8 is 0, function exits immediately without action\n  - If InitializeFogFileSystem fails, function exits without allocation\n  - If sample rate is not 0x5622 (22050 Hz), function exits without allocation\n  - String copy loop handles null-terminated strings with byte-by-byte copy\n\nStructure Layout:\n  Offset  Size  Field Name         Type     Description\n  0x50    4     fileHandle         dword    Fog file system handle\n  0x54    4     dataSize           dword    Size of audio data in bytes\n  0x58    4     isStereo           dword    Boolean: 1 if stereo, 0 if mono\n  0x5c    4     nextNode           void*    Pointer to previous node (linked list)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:6ba3b2362e2025dabdc5987d722d6610",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "6ba3b2362e2025dabdc5987d722d6610",
        "MNE": "7640872c4218006941d1b0b467dbe6ed",
        "CFG": "8f478ae3bc117d32a57725db761b21b6",
        "PRO": "e8841a67ea3fbee0e5da2b1fe6a67e72"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7640872c4218006941d1b0b467dbe6ed"
      },
      "api_calls": {
        "LoD/PD2": [
          "ParseWaveFileHeader",
          "AllocateMemoryWithTracking"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_76916cb69412": {
      "addresses": {
        "LoD/PD2": "0x6F9B83C0"
      },
      "rvas": {
        "LoD/PD2": "0x83C0"
      },
      "sizes": {
        "LoD/PD2": 223
      },
      "name": "InitializeAudioSystem",
      "signature": "void InitializeAudioSystem(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes the audio system with thread-safe critical sections.\n\nAlgorithm:\n1. Check if audio system is enabled and not yet initialized\n2. Initialize main critical section for audio subsystem synchronization\n3. Enter critical section for exclusive access\n4. Check if audio is enabled and contexts not yet processed (flag != 0xff)\n5. Enter audio context critical section\n6. Set processed flag to 0xff to mark audio contexts as initialized\n7. Iterate through linked list of audio contexts (DAT_6f9c65cc)\n8. For each context, validate pointer is non-null, else abort with error\n9. Access context field at offset +0x38 and call SetAudioParameterValue\n10. Move to next context via node[1] (linked list next pointer)\n11. Leave context critical section\n12. Initialize 8 audio buffers via Ordinal_10065 loop (indices 0-7)\n13. For indices 0-3, pass parameter 1 (true); for 4-7, pass parameter 0 (false)\n14. Store buffer pointers in array at DAT_6f9c6560 with stride of 4 bytes\n15. Set initialization flag (DAT_6f9c65b8) to 1\n16. Leave main critical section and return\n\nParameters:\n  None - Function is parameterless entry point\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - Magic number 0xff: Marks audio contexts as processed\n  - Magic number 0x2e4: Error code passed to GetReturnAddress for error handling\n  - Error handling: Null audio context pointer triggers GetReturnAddress, \n    CleanupAndAbort, and _exit(-1) sequence\n  - Buffer loop processes 8 buffers split into two groups (0-3 and 4-7)\n    with different initialization parameters\n\nStructure Layout:\n  Audio Context Node (linked list):\n    Offset  Size  Field Name         Type    Description\n    0x00    4     pAudioContext      int*    Pointer to audio context\n    0x04    4     pNextNode          int*    Pointer to next node\n    \n  Audio Context:\n    Offset  Size  Field Name         Type    Description\n    0x38    4     audioParameter     int     Audio parameter value at offset +0x38",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:76916cb694124e3f8c8785e1d6f4e096",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "76916cb694124e3f8c8785e1d6f4e096",
        "MNE": "834faf2dd7b56c69f6a5f32fd58386ee",
        "CFG": "969fba09e3e9b3aca52f01e3d048e095",
        "PRO": "5a750ebca3452dfccff7c402d86cbbe5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "834faf2dd7b56c69f6a5f32fd58386ee"
      },
      "api_calls": {
        "LoD/PD2": [
          "SetAudioParameterValue",
          "CreateSurfaceBuffer",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      }
    },
    "D2sound_MNE_d49921eb6528": {
      "addresses": {
        "LoD/PD2": "0x6F9B84A0"
      },
      "rvas": {
        "LoD/PD2": "0x84A0"
      },
      "sizes": {
        "LoD/PD2": 344
      },
      "name": "ReadPEResourceDataFromFile",
      "signature": "uint ReadPEResourceDataFromFile(void * this, void * pBuffer, LPCSTR lpFileName, uint * pDataSize)",
      "calling_convention": "__thiscall",
      "comment": "Reads resource data from a PE (Portable Executable) file and copies it to a buffer.\n\nAlgorithm:\n1. Open the specified file with read access and generic read permissions (0x80000000)\n2. Create a file mapping object for the opened file with page protection\n3. Create a view of the file mapping to access file contents in memory\n4. Validate DOS header signature (0x5A4D \"MZ\") at mapped buffer start\n5. Read PE header offset from DOS header at offset 0x3C\n6. Validate PE signature (0x454C \"PE\") at calculated PE header location\n7. Check if resource directory entry count is greater than zero (offset 0xBC from PE header)\n8. If no resources exist, set error 0x714 (ERROR_INVALID_RESOURCE_DATA)\n9. Read resource data offset and size from PE header (offsets 0xB8 and 0x8 relative to resource section)\n10. If destination buffer provided (this != NULL), validate buffer size against resource data size\n11. If buffer size sufficient, clear destination buffer to zero, then copy resource data via REP instructions\n12. If buffer size insufficient, set error 0x7A (ERROR_INSUFFICIENT_BUFFER)\n13. On success, set last error to 0 and return 1; on failure, return 0\n14. Clean up file handles and restore exception list before return\n\nParameters:\n  pBuffer - Destination buffer for resource data (NULL if size query only)\n  lpFileName - Pointer to null-terminated path string of PE file to read\n  pDataSize - Pointer to DWORD containing buffer size on entry; receives actual data size on exit\n\nReturns:\n  Returns 1 (TRUE) if resource data successfully read; 0 (FALSE) on any error\n  Sets Windows last error code: 0 for success, 0x714 (no resources), 0x7A (buffer too small), 0xB (invalid format)\n\nSpecial Cases:\n  - If pBuffer is NULL, function acts as size query only, returns resource data size in *pDataSize\n  - Validates both DOS and PE signatures to ensure valid executable format\n  - Uses exception handling through SEH (Structured Exception Handling) for safety\n  - Cleans up all file handles regardless of success or failure path",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d49921eb65284491dea0b481d719ae17",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d49921eb65284491dea0b481d719ae17",
        "CFG": "f4d23a0900f4a88be7538791ca514b88",
        "PRO": "75b4da4b2897fdd301ba54515ae9ddae"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d49921eb65284491dea0b481d719ae17"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_bee00e2ec604": {
      "addresses": {
        "LoD/PD2": "0x6F9B85FB"
      },
      "rvas": {
        "LoD/PD2": "0x85FB"
      },
      "sizes": {
        "LoD/PD2": 56
      },
      "name": "CleanupFileResources",
      "signature": "void CleanupFileResources(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleanup and restore file resource handles in exception handler context.\n\nAlgorithm:\n1. Save current error code via GetLastError()\n2. If file view mapping exists at [EBP-0x20], unmap it via UnmapViewOfFile()\n3. If file mapping handle exists at [EBP-0x24], close it via CloseHandle()\n4. If file handle (EDI) is not INVALID_HANDLE_VALUE (-1), close it via CloseHandle()\n5. Restore the saved error code via SetLastError()\n6. Return to exception handler\n\nParameters:\n- Implicit EBP: Stack frame pointer for exception context\n- Implicit EDI: File handle (INVALID_HANDLE_VALUE if not opened)\n\nReturns:\n- void: Function performs cleanup operations only\n\nSpecial Cases:\n- Function checks for INVALID_HANDLE_VALUE (-1) before closing EDI file handle\n- Function preserves original error code across cleanup operations\n- Called from exception handler context (FUN_6f9b84a0)\n- Uses unaffected registers pattern (EBP and EDI preserved across call)\n\nStructure Layout:\n[EBP-0x20]: LPCVOID (mapped file view pointer)\n[EBP-0x24]: HANDLE (file mapping handle)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bee00e2ec60427e00e37908e271e0e5e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bee00e2ec60427e00e37908e271e0e5e",
        "CFG": "cb0ccd43c2f8c8fb04bb31ae73008898",
        "PRO": "93287f2f1ba13bd7c14f6081302bcc24"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bee00e2ec60427e00e37908e271e0e5e"
      }
    },
    "D2sound_MNE_d8abc9a98c95": {
      "addresses": {
        "LoD/PD2": "0x6F9B8640"
      },
      "rvas": {
        "LoD/PD2": "0x8640"
      },
      "sizes": {
        "LoD/PD2": 72
      },
      "name": "AppendLinkedListNode",
      "signature": "void AppendLinkedListNode(int * * ppListHead, uint nodeData)",
      "calling_convention": "__fastcall",
      "comment": "Appends a new node to a singly-linked list or sets it as head if empty.\n\nAlgorithm:\n1. Allocate 287-byte memory block for new node\n2. Initialize new node with nodeData value in first field\n3. Zero-initialize second field (next pointer)\n4. Load current list head from ppListHead\n5. If head is null, set new node as head and return\n6. Otherwise, traverse to end of list by following next pointers at offset +4\n7. When null next pointer found, append new node by setting next pointer of tail node\n8. Return\n\nParameters:\nppListHead - Pointer to linked list head pointer (updated if list was empty)\nnodeData - Data value to store in new node's first field (offset +0)\n\nReturns:\nvoid - Function modifies the linked list in place\n\nSpecial Cases:\n- If ppListHead points to null, the new node becomes the list head\n- Allocates exactly 287 bytes per node\n- Next pointer field stored at offset +4 in each node\n- Node data value stored at offset +0",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d8abc9a98c954e3788bf78008fca3ac3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d8abc9a98c954e3788bf78008fca3ac3",
        "CFG": "fc21cabc67a11d2e1d34c83d9134404c",
        "PRO": "d1f4168924e2b443af33ed423705b18e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d8abc9a98c954e3788bf78008fca3ac3"
      },
      "api_calls": {
        "LoD/PD2": [
          "AllocateMemoryWithTracking"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_8df9bf85cb38": {
      "addresses": {
        "LoD/PD2": "0x6F9B8690"
      },
      "rvas": {
        "LoD/PD2": "0x8690"
      },
      "sizes": {
        "LoD/PD2": 15
      },
      "name": "CountLinkedListNodes",
      "signature": "int CountLinkedListNodes(void * pListNode)",
      "calling_convention": "__fastcall",
      "comment": "Counts the number of nodes in a singly-linked list.\n\nAlgorithm:\n1. Initialize counter to 0\n2. If node pointer is NULL, return 0\n3. Loop: dereference offset +0x4 to get next pointer, increment counter\n4. Continue until next pointer is NULL\n5. Return total node count\n\nParameters:\n  pListNode: Pointer to the first node in a linked list structure.\n             Must have a next pointer at offset +0x4.\n\nReturns:\n  int: Count of nodes in the linked list (0 if input is NULL).\n\nSpecial Cases:\n  - NULL input returns 0\n  - Traverses entire chain using the next pointer field at offset +0x4\n\nStructure Layout:\n  Offset | Size | Field Name | Type | Description\n  -------|------|------------|------|-------------\n  0x00   | 4    | (data)     | ?    | Node data/flags\n  0x04   | 4    | next       | ptr  | Pointer to next node in list",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8df9bf85cb3834dff82ac22642075af4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8df9bf85cb3834dff82ac22642075af4",
        "CFG": "cb2814c48701378c41d6e249e987ddd8",
        "PRO": "4929834e708207430558cca89710ef99"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8df9bf85cb3834dff82ac22642075af4"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_cd3e0e3d5945": {
      "addresses": {
        "LoD/PD2": "0x6F9B86A0"
      },
      "rvas": {
        "LoD/PD2": "0x86A0"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "FindLinkedListNode",
      "signature": "int FindLinkedListNode(LinkedListNode * pListHead, int searchValue)",
      "calling_convention": "__fastcall",
      "comment": "Searches a linked list for a node with a matching value.\n\nAlgorithm:\n1. Validate that pListHead is not NULL\n2. Loop through linked list nodes:\n   a. Compare current node's value field with searchValue\n   b. If match found, return 1 (found)\n   c. Move to next node via pNext pointer\n   d. Continue until pNext is NULL (end of list)\n3. If end of list reached without match, return 0 (not found)\n\nParameters:\n- pListHead: Pointer to LinkedListNode at the head of the list\n- searchValue: Integer value to search for in the list\n\nReturns:\n- 1: Node with matching value was found\n- 0: No matching node found or list is empty\n\nSpecial Cases:\n- If pListHead is NULL, returns 0 immediately\n- List traversal expects proper NULL termination\n- Each node contains value (offset 0) and pNext pointer (offset 4)\n\nStructure Layout:\nLinkedListNode structure accessed:\n- Offset 0, Size 4: value (int) - compared against searchValue\n- Offset 4, Size 4: pNext (LinkedListNode *) - link to next node\nTotal size: 8 bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cd3e0e3d5945ee49f3ee4389bbca98c5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd3e0e3d5945ee49f3ee4389bbca98c5",
        "CFG": "c8b2c10b1a428d31cc06d2116a66fa61",
        "PRO": "f076f70bbb1273e26b96a8861a4fb656"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "cd3e0e3d5945ee49f3ee4389bbca98c5"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_434c103c261c": {
      "addresses": {
        "LoD/PD2": "0x6F9B86C0"
      },
      "rvas": {
        "LoD/PD2": "0x86C0"
      },
      "sizes": {
        "LoD/PD2": 69
      },
      "name": "RemoveLinkedListNode",
      "signature": "void RemoveLinkedListNode(int * * pListHead, int nodeValue)",
      "calling_convention": "__fastcall",
      "comment": "Removes the first node with a matching value from a singly-linked integer list\n\nAlgorithm:\n\n1. Load the initial node pointer from the list head\n2. Initialize traversal variables: current node, search node, and previous node\n3. Return early if the list is empty (head is NULL)\n4. Begin forward traversal through the linked list\n5. Compare each node's value with the target value for removal\n6. Track the previous node during traversal for pointer reconnection\n7. Continue to next node if value doesn't match, updating previous pointer\n8. Break traversal loop when target value is found or end of list reached\n9. Return early if target value was not found in any node\n10. Check if the node to remove is the head node (first in list)\n11. If removing head: update list head pointer to bypass removed node\n12. If removing non-head: link previous node directly to next node\n13. Report the successful removal operation with error code 0xF0\n\nParameters:\npListHead - Pointer to the head pointer of the singly-linked integer list\nnodeValue - Integer value to search for and remove from the list\n\nReturns:\nvoid - No return value (removal success/failure reported via ReportError)\n\nSpecial Cases:\nEmpty list - Returns immediately without modification\nValue not found - Returns after full traversal without modification\nSingle node removal - Updates head pointer to NULL if only node removed\nHead node removal - Updates head pointer to second node in list\n\nStructure Layout:\nNode structure (8 bytes per node):\nOffset  Size  Field Name  Type    Description\n0x00    4     value       int     Integer value stored in this node\n0x04    4     next        int *   Pointer to next node or NULL for list end\n\nMagic Numbers Reference:\n0xF0 (240) - Error/event code reported to ReportError for successful removal",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:434c103c261c2cdfa42448e719eb1e9a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "434c103c261c2cdfa42448e719eb1e9a",
        "CFG": "a447ffc16017efea167ec23947d72285",
        "PRO": "3581351f2874d36914a7ca498f24b3ae"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "434c103c261c2cdfa42448e719eb1e9a"
      },
      "api_calls": {
        "LoD/PD2": [
          "InitializeModule"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_984550419381": {
      "addresses": {
        "LoD/PD2": "0x6F9B8710"
      },
      "rvas": {
        "LoD/PD2": "0x8710"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "InsertLinkedListNode",
      "signature": "void InsertLinkedListNode(uint * pListHead, uint nodeValue)",
      "calling_convention": "__fastcall",
      "comment": "Inserts a new linked list node at the head of a linked list.\\n\\nAlgorithm:\\n1. Allocate 0xd4 bytes (212 bytes) for the new node structure\\n2. Initialize the first two dword fields of the new node to 0\\n3. Save the current list head pointer from pListHead parameter\\n4. Store nodeValue in first dword field of new node\\n5. Store saved head pointer in second dword field of new node\\n6. Update pListHead to point to the newly created node\\n\\nThe function implements a standard linked list insertion where each node contains:\\n  - Offset +0x0: uint nodeValue (data stored in this node)\\n  - Offset +0x4: uint *nextNode (pointer to next node in list)\\n\\nParameters:\\n  pListHead: Pointer to the list head pointer. On entry, contains pointer to current head node (or NULL). On exit, points to the newly created node.\\n  nodeValue: 32-bit value to store in the nodeValue field of the new node\\n\\nReturns:\\n  void\\n\\nSpecial Cases:\\n  - Works with empty lists (when pListHead points to NULL)\\n  - Always inserts at the head of the list (LIFO behavior)\\n  - Allocates exactly 0xd4 bytes regardless of actual data stored\\n\\nNode Structure Layout (0xd4 bytes total):\\n  Offset | Size | Field Name | Type    | Description\\n  -------|------|------------|---------|----------------------------------\\n  +0x00  | 4    | nodeValue  | uint    | Data value stored in node\\n  +0x04  | 4    | nextNode   | uint*   | Pointer to next node in list\\n  +0x08  | 200  | reserved   | byte[200] | Reserved/unused space",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9845504193811cd2c8b7b6a6e12f19af",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9845504193811cd2c8b7b6a6e12f19af",
        "CFG": null,
        "PRO": "fb7662d05323d9316219284b227179e7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9845504193811cd2c8b7b6a6e12f19af"
      },
      "api_calls": {
        "LoD/PD2": [
          "AllocateMemoryWithTracking"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_f109e69488b4": {
      "addresses": {
        "LoD/PD2": "0x6F9B8750"
      },
      "rvas": {
        "LoD/PD2": "0x8750"
      },
      "sizes": {
        "LoD/PD2": 62
      },
      "name": "InitializeAudioBuffer",
      "signature": "void InitializeAudioBuffer(ushort channelCount)",
      "calling_convention": "__fastcall",
      "comment": "Initializes an audio buffer structure with channel configuration.\n\nAlgorithm:\n1. Clear the entire structure (18 bytes from offset 0x0 to 0x11)\n2. Set initialization marker (0x1) at offset 0x0\n3. Store channel count parameter at offset 0x2\n4. Calculate doubled channel count (channelCount * 2)\n5. Store doubled value at offset 0xc\n6. Set constant 0x5622 at offset 0x4 (format/sample rate constant)\n7. Calculate total buffer size: (channelCount * 2) * 0x5622\n8. Store calculated size at offset 0x8\n9. Set flags value (0x10) at offset 0xe\n\nParameters:\n- channelCount (CX, ushort): Number of audio channels to initialize\n\nReturns:\n- void: Modifies structure in place via EAX pointer\n\nStructure Layout (Audio Buffer):\nOffset  Size  Field Name         Type      Description\n0x0     2     initMarker         word      Initialization marker (set to 1)\n0x2     2     channelCount       word      Number of channels from parameter\n0x4     4     format             dword     Audio format constant (0x5622)\n0x8     4     bufferSize         dword     Total size (channelCount*2)*0x5622\n0xc     2     doubledCount       word      channelCount * 2\n0xe     2     flags              word      Configuration flags (set to 0x10)\n0x10    2     reserved           word      Reserved/padding\n\nSpecial Cases:\n- The 0x5622 constant appears to be a sample rate or format descriptor\n- The buffer size calculation uses (channelCount * 2) as multiplier\n- Structure assumes EAX contains a valid pointer on entry (implicit parameter)\n- All fields initialized to zero before setting specific values",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f109e69488b45438b5d97489405e11cd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f109e69488b45438b5d97489405e11cd",
        "CFG": "ee0e96857da8b32ab6bcdead1e5c43d3",
        "PRO": "c3d1544f7ead16dd2387b9cd999ee789"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f109e69488b45438b5d97489405e11cd"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_7034d0510ba0": {
      "addresses": {
        "LoD/PD2": "0x6F9B8790"
      },
      "rvas": {
        "LoD/PD2": "0x8790"
      },
      "sizes": {
        "LoD/PD2": 64
      },
      "name": "FindRiffChunk",
      "signature": "void * FindRiffChunk(void * this, void * pChunkBuffer, uint * pRemainingSize)",
      "calling_convention": "__thiscall",
      "comment": "Searches for a RIFF chunk matching the specified identifier in a buffer.\n\nAlgorithm:\n1. Validate remaining buffer size is at least 8 bytes (chunk header minimum)\n2. Decrement remaining size by 8 bytes to account for chunk header (id + size)\n3. Load chunk identifier from current buffer position (offset +0)\n4. Load chunk size from current buffer position (offset +4)\n5. Compare chunk identifier against target chunk ID (EBX register parameter)\n6. If match found, write chunk size to output and return pointer to chunk data\n7. If no match, validate remaining size is greater than or equal to chunk size\n8. If validation fails, return null pointer (error)\n9. Add chunk size to buffer pointer and decrement remaining size by chunk size\n10. Check if remaining size is at least 8 bytes for next iteration\n11. If yes, loop back to step 1; if no, return null pointer\n\nParameters:\n- pRemainingSize: Pointer to remaining buffer size (ECX, decremented at each step)\n- pChunkBuffer: Pointer to output buffer for chunk size (Stack[0x8])\n- targetChunkId: Target chunk identifier to search for (EBX, implicit __d2call parameter)\n\nReturns:\n- Pointer to chunk data (8 bytes after chunk header) on success\n- NULL pointer on error (insufficient buffer, size validation failed)\n\nSpecial Cases:\n- Chunk header is always 8 bytes (4-byte ID + 4-byte size)\n- Minimum buffer size required is 8 bytes for any operation\n- Function modifies the pRemainingSize value in place\n- EBX contains the target chunk identifier (implicit parameter for __d2call)\n\nStructure Layout:\nRIFF Chunk Format\nOffset Size Field     Type    Description\n0x0    4    chunkId   uint    Chunk identifier (e.g., 0x20746d66 for \"fmt \")\n0x4    4    chunkSize uint    Size of chunk data in bytes\n0x8    N    chunkData byte[N] Chunk data",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7034d0510ba0bbf777bfb352a039bd63",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7034d0510ba0bbf777bfb352a039bd63",
        "CFG": "92668eb71f8acb9bf24d85d838b9d451",
        "PRO": "157321d51ccd064b2202da03a4f1ee44"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7034d0510ba0bbf777bfb352a039bd63"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_a641d892bce5": {
      "addresses": {
        "LoD/PD2": "0x6F9B87D0"
      },
      "rvas": {
        "LoD/PD2": "0x87D0"
      },
      "sizes": {
        "LoD/PD2": 88
      },
      "name": "NotifyGameEventWithValidation",
      "signature": "float NotifyGameEventWithValidation(float notificationValue)",
      "calling_convention": "__stdcall",
      "comment": "Validates a game event notification value and returns a scaled coefficient.\n\nAlgorithm:\n1. Load notification value parameter from stack\n2. Add offset constant (DAT_6f9c097c) to create upper bound check value\n3. Compare adjusted value against upper threshold (DAT_6f9c0978)\n4. If adjusted value >= upper threshold: return high limit constant (DAT_6f9c0974)\n5. Otherwise, subtract offset constant from original value for lower bound check\n6. Compare lower-adjusted value against lower threshold (DAT_6f9c0970)\n7. If lower-adjusted value < lower threshold: return mid-range constant (DAT_6f9c0978)\n8. Otherwise (value in valid range): load base coefficient (DAT_6f9c0968), multiply by scale factor (DAT_6f9c0964), call ValidateFPUAndComputePower to compute final value, return result\n\nParameters:\n- notificationValue: float - Event notification value to validate and process\n\nReturns:\n- float - Scaled coefficient value: high limit if value exceeds upper bound, mid-range if below lower bound, or computed power coefficient for values within valid range\n\nSpecial Cases:\n- Uses FPU stack operations for floating-point arithmetic\n- Range validation ensures value stays within operational bounds\n- Calls ValidateFPUAndComputePower for computation when in valid range\n- Returns predefined constants for out-of-range values (no exceptions thrown)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a641d892bce52e4f5289cf37402f9a07",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a641d892bce52e4f5289cf37402f9a07",
        "CFG": "cb6c24d071f5a1a76901ac19df773e07",
        "PRO": "8f537aea6a1a2941ab2421d319437ef7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a641d892bce52e4f5289cf37402f9a07"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_3356f04dbb4e": {
      "addresses": {
        "LoD/PD2": "0x6F9B8830"
      },
      "rvas": {
        "LoD/PD2": "0x8830"
      },
      "sizes": {
        "LoD/PD2": 138
      },
      "name": "ClampFloatValue",
      "signature": "float ClampFloatValue(float valueA, float valueB, float maxThreshold)",
      "calling_convention": "__stdcall",
      "comment": "Clamps a floating-point value between calculated bounds with complex branching logic.\n\nAlgorithm:\n1. Load valueA and add constant offset from global g_flBaseOffset (0x6f9c097c)\n2. Compare sum against maxThreshold using FPU comparison\n3. If sum >= maxThreshold, return minimum constant g_flMinValue (0x6f9c0970)\n4. Load valueB and subtract same constant offset g_flBaseOffset\n5. Compare difference against maxThreshold with parity checking\n6. If result indicates boundary condition met, proceed to complex calculation\n7. Load all three parameters onto FPU stack for multi-value operation\n8. Compare valueB against threshold constant g_dThresholdValue (0x6f9c0988)\n9. Handle ordered vs unordered comparison results with stack exchanges\n10. Add manipulated values using FADDP stack operation\n11. Check dispatch flag g_dwDispatchMode (0x6f9c65e8) for operation type\n12. If dispatch mode zero, perform direct division using FDIVRP\n13. If dispatch mode non-zero, call DispatchX87FloatingPointOperation with status flags\n14. Load log base 2 constant (FLDLG2) for logarithmic calculation\n15. Compute Y*LOG2(X) using FYL2X instruction\n16. Multiply result by scaling factor g_flScaleFactor (0x6f9c0980)\n17. Return processed value via RET 0xc with __stdcall cleanup\n\nParameters:\n  valueA: First input value for offset addition and threshold comparison\n  valueB: Second input value for offset subtraction and range validation  \n  maxThreshold: Upper boundary value for clamping and comparison operations\n\nReturns:\n  float: Clamped or logarithmically processed result value\n         - g_flMinValue if valueA + offset >= maxThreshold\n         - g_flBoundaryValue (0x6f9c0978) if boundary condition triggered  \n         - Logarithmic calculation result for normal processing path\n\nSpecial Cases:\n  - Magic Numbers: 0x6f9c097c (base offset), 0x6f9c0970 (min clamp), 0x6f9c0978 (boundary)\n  - FPU Operations: Complex stack manipulation with FUCOMPP for NaN handling\n  - Dispatch Logic: g_dwDispatchMode controls calculation vs external dispatch\n  - Multiple Exits: Three distinct return paths with different result types\n  - Logarithmic Math: Uses hardware FYL2X for precise log calculations",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3356f04dbb4e770ecb40d0c0ae832d31",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3356f04dbb4e770ecb40d0c0ae832d31",
        "CFG": "b7ff7beabc3fd16292d6dcc232a141d9",
        "PRO": "4ca125c65ef3a42b243b81b73d3fc3c6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3356f04dbb4e770ecb40d0c0ae832d31"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_24f4aca7539f": {
      "addresses": {
        "LoD/PD2": "0x6F9B88C0"
      },
      "rvas": {
        "LoD/PD2": "0x88C0"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "LoadExecutableDataWrapper",
      "signature": "void LoadExecutableDataWrapper(void * this, void * pBuffer, uint dwConfig, void * pSizeOrConfig)",
      "calling_convention": "__thiscall",
      "comment": "Setting prototype: void LoadExecutableDataWrapper(void * this, void * pBuffer, uint dwConfig, void * pSizeOrConfig)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:24f4aca7539f2a1d36434afbb764cdb2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "24f4aca7539f2a1d36434afbb764cdb2",
        "CFG": null,
        "PRO": "0e606810ebee72dddcc26bdb38d953ac"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "24f4aca7539f2a1d36434afbb764cdb2"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_fd95113b339d": {
      "addresses": {
        "LoD/PD2": "0x6F9B88E0"
      },
      "rvas": {
        "LoD/PD2": "0x88E0"
      },
      "sizes": {
        "LoD/PD2": 53
      },
      "name": "ReadPEResourceDataWithBufferHandling",
      "signature": "uint ReadPEResourceDataWithBufferHandling(LPCSTR lpszFilePath)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: uint ReadPEResourceDataWithBufferHandling(LPCSTR lpszFilePath)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fd95113b339df892fd97512c7a730ad6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fd95113b339df892fd97512c7a730ad6",
        "CFG": "ca23919de44270d5b1b63fd0ce96261f",
        "PRO": "81fb2365e18242db11bce5b51a8d52fb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fd95113b339df892fd97512c7a730ad6"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_8654893ce885": {
      "addresses": {
        "LoD/PD2": "0x6F9B8920"
      },
      "rvas": {
        "LoD/PD2": "0x8920"
      },
      "sizes": {
        "LoD/PD2": 87
      },
      "name": "RemoveDuplicateNodesFromList",
      "signature": "void RemoveDuplicateNodesFromList(int * pListHead)",
      "calling_convention": "__fastcall",
      "comment": "Removes all duplicate nodes from a singly-linked list.\n   \nAlgorithm:\n1. Load head pointer from list head parameter into EDI (__fastcall: ECX)\n2. Check if list head is NULL (empty list) - if so, return\n3. Outer loop: continues until no more duplicates found\n4. Load first node pointer and its value for comparison reference\n5. Initialize previous node pointer to NULL\n6. Inner loop: traverse list starting from first node\n7. Compare each node's value with reference value from first node\n8. If match found (duplicate detected):\n   - If duplicate is at head: update head pointer to next node\n   - If previous node exists: update its next pointer to skip duplicate\n   - Call ReportError(0xf0, 0) to log error\n   - Break inner loop\n9. If no match: advance to next node, continue inner loop\n10. After inner loop ends, restart outer loop to check for more duplicates\n11. Exit when list head becomes NULL (all duplicates removed)\n   \nParameters:\npListHead (int *) - Pointer to list head, contains pointer to first node\n                    Each node structure: int value @ offset +0, int *next @ offset +4\n   \nReturns:\nvoid - No return value\n   \nSpecial Cases:\n- Empty list (NULL head): Function returns immediately without processing\n- Single-node list: Treated as valid, returns unchanged\n- Multiple duplicates: Outer loop continues until all removed\n- Error code 0xf0: Logged for each duplicate found via ReportError()\n   \nNode Structure (8 bytes):\nOffset  Size  Field Name  Type      Description\n0x0     4     value       int       Node identifier/value\n0x4     4     next        int *     Pointer to next node or NULL\n\nNote: Function uses 1 stack-allocated temporary variable (local_8) optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8654893ce88505f3b95c44d8d920c1c7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8654893ce88505f3b95c44d8d920c1c7",
        "CFG": "d7d1b7fe24361999d50a0c17021b3c79",
        "PRO": "7842bafa76bc744a94e0f843b5d93355"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8654893ce88505f3b95c44d8d920c1c7"
      },
      "api_calls": {
        "LoD/PD2": [
          "InitializeModule"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_dcf7292fc82d": {
      "addresses": {
        "LoD/PD2": "0x6F9B8980"
      },
      "rvas": {
        "LoD/PD2": "0x8980"
      },
      "sizes": {
        "LoD/PD2": 202
      },
      "name": "ParseWaveFileHeader",
      "signature": "int ParseWaveFileHeader(byte * pBuffer, uint * pBufferSize, WaveFormatInfo * pOutputFormat)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: int ParseWaveFileHeader(byte * pBuffer, uint * pBufferSize, WaveFormatInfo * pOutputFormat)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:dcf7292fc82def356ee584667c8ace98",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "dcf7292fc82def356ee584667c8ace98",
        "CFG": "ddb47e344e263f0bf6eb8098227acf55",
        "PRO": "e441b38a8b8a0225ee9dabdf35c14462"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "dcf7292fc82def356ee584667c8ace98"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_API_7a714a519861": {
      "addresses": {
        "LoD/PD2": "0x6F9B8A50"
      },
      "rvas": {
        "LoD/PD2": "0x8A50"
      },
      "sizes": {
        "LoD/PD2": 245
      },
      "name": "QueryFileVersionInfo",
      "signature": "int QueryFileVersionInfo(uint * pProductVersionOut, uint * pFileVersionOut, uint * pOriginalFilenameVersionOut, void * unused1, void * unused2)",
      "calling_convention": "__stdcall",
      "comment": "Extracts version information fields from a PE file's VERSIONINFO resource.\n\nAlgorithm:\n1. Initialize buffer size to 0 for size query\n2. Call ReadPEResourceDataFromFile with NULL buffer to determine required size\n3. If call succeeds unexpectedly, return failure (should need buffer)\n4. Get last error code and verify it's ERROR_INSUFFICIENT_BUFFER (0x7a)\n5. Clear error state with SetLastError(0) before proceeding\n6. Validate that buffer size was set to non-zero value\n7. Allocate fixed 539-byte (0x21b) buffer for version info structure\n8. Call ReadPEResourceDataFromFile again with allocated buffer to read data\n9. If second read fails, report error 0x220 and return failure\n10. Call VerQueryValueA with DAT_6f9c0688 subblock to locate version structure\n11. If VerQueryValueA fails, report error 0x228 and return failure\n12. Extract product version from offset +0xa (16-bit value)\n13. Extract file version from offset +0x8 (masked to 16-bit)\n14. Extract original filename version from offset +0xc (masked to 16-bit)\n15. Store all three versions in output parameters and return success\n\nParameters:\n- pProductVersionOut: Output pointer for product version field\n- pFileVersionOut: Output pointer for file version field\n- pOriginalFilenameVersionOut: Output pointer for original filename version field\n- unused1: Unused parameter (legacy from previous prototype)\n- unused2: Unused parameter (legacy from previous prototype)\nIMPLICIT: unaff_EBX contains file path or handle for ReadPEResourceDataFromFile\nIMPLICIT: unaff_ESI contains output parameter for second ReadPEResourceDataFromFile call\nIMPLICIT: unaff_EDI contains output parameter for first ReadPEResourceDataFromFile call\n\nReturns:\n- 1: Successfully extracted all three version fields\n- 0: Failed due to unexpected success on size query, wrong error code, \n     zero buffer size, allocation failure, read failure, or VerQueryValueA failure\n\nSpecial Cases:\n- Function expects first ReadPEResourceDataFromFile call to fail with ERROR_INSUFFICIENT_BUFFER\n- Fixed 539-byte allocation regardless of actual buffer size needed\n- All version fields masked to 16-bit values (0xffff) before output\n- DAT_6f9c0688 contains subblock string for VerQueryValueA (likely root version info path)\n- Error codes: 0x220 indicates read failure, 0x228 indicates version query failure\n\nStructure Layout:\nThe version info structure accessed via VerQueryValueA contains:\nOffset  Size  Field Name           Type     Description\n+0x8    4     FileVersion         uint     File version (masked to 16-bit)\n+0xa    2     ProductVersion      ushort   Product version (16-bit value)\n+0xc    4     OriginalFilename    uint     Original filename version (masked to 16-bit)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:7a714a51986154466b08ce018b48984b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "7a714a51986154466b08ce018b48984b",
        "MNE": "3145a99f5f3b16ea7f21ae52926fe4d7",
        "CFG": "3b12f33a615d48ebe014acc003718f1e",
        "PRO": "42fcd27a1729fcb0cb5af49ae44a8352"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3145a99f5f3b16ea7f21ae52926fe4d7"
      },
      "api_calls": {
        "LoD/PD2": [
          "AllocateMemoryWithTracking",
          "InitializeModule",
          "VerQueryValueA",
          "InitializeModule"
        ]
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "D2sound_MNE_66bcc29f617d": {
      "addresses": {
        "LoD/PD2": "0x6F9B8B50"
      },
      "rvas": {
        "LoD/PD2": "0x8B50"
      },
      "sizes": {
        "LoD/PD2": 263
      },
      "name": "ComputeColorIntensity",
      "signature": "void ComputeColorIntensity(int * pIntensity1, int * pIntensity2)",
      "calling_convention": "__fastcall",
      "comment": "Computes two 8-bit color/intensity values from floating-point calculations.\\n\\nAlgorithm:\\n1. Load three floats from stack parameters\\n2. Compute magnitude: sqrt(a*a + b*b + c*c)\\n3. Check if magnitude is in valid range; if out of bounds, set to 0\\n4. Apply logarithmic scaling and multipliers to compute first intensity\\n5. Clamp first result to range [0, 255]\\n6. Scale and offset to compute second intensity\\n7. Clamp second result to range [0, 255]\\n8. Return both intensities via output pointers\\n\\nParameters:\\n  pIntensity1 (ECX): Pointer to store first intensity value (0-255)\\n  pIntensity2 (EDX): Pointer to store second intensity value (0-255)\\n\\nReturns:\\n  void - Results written to *pIntensity1 and *pIntensity2\\n\\nSpecial Cases:\\n  - Magnitude < threshold: sets to 0\\n  - Values > 254 (0xfe): clamped to 255 (0xff)\\n  - Negative intensity: set to 0\\n  - DAT_6f9c65e8 flag controls reciprocal operation\\n",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:66bcc29f617dcb3476083d3b1c436bb8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "66bcc29f617dcb3476083d3b1c436bb8",
        "CFG": "4fb9c2bacdfdc579d5b0db65b255b69b",
        "PRO": "e7b6561404142adcb9a8a75c3fc74760"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "66bcc29f617dcb3476083d3b1c436bb8"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_d7897101f3cb": {
      "addresses": {
        "LoD/PD2": "0x6F9B8C60"
      },
      "rvas": {
        "LoD/PD2": "0x8C60"
      },
      "sizes": {
        "LoD/PD2": 8
      },
      "name": "DefaultActionHandler",
      "signature": "int DefaultActionHandler(void * pUnit, int actionType, void * pTarget)",
      "calling_convention": "__stdcall",
      "comment": "Default action handler stub that returns success for unimplemented actions.\n\nAlgorithm:\n1. Load constant value 0x1 (success) into return register EAX\n2. Return to caller with stack cleanup for 3 parameters (RET 0xC)\n\nParameters:\n- pUnit: Pointer to game unit/entity performing the action\n- actionType: Action code/type identifier to handle\n- pTarget: Pointer to target entity or object (context-dependent)\n\nReturns:\n- 1 (0x1): Always returns success, indicating action was handled\n\nSpecial Cases:\n- This is a stub/placeholder handler that unconditionally returns success\n- Used as default action handler for unimplemented action types\n- Callers interpret return value > 0 as success, == 0 as failure or skip\n- Three parameters indicate this function participates in action dispatch system",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d7897101f3cb99eb3b89274dfb087bc9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d7897101f3cb99eb3b89274dfb087bc9",
        "CFG": null,
        "PRO": "f2715adc6ba6377266918519727fa91f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d7897101f3cb99eb3b89274dfb087bc9"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_STR_cbe2aecc09a2": {
      "addresses": {
        "LoD/PD2": "0x6F9B8C70"
      },
      "rvas": {
        "LoD/PD2": "0x8C70"
      },
      "sizes": {
        "LoD/PD2": 233
      },
      "name": "DecodeDSoundError",
      "signature": "char * DecodeDSoundError(int errorCode)",
      "calling_convention": "__stdcall",
      "comment": "Translates DirectSound error codes to human-readable error message strings.\n\nAlgorithm:\n1. Compare input error code against known DirectSound/COM error constants\n2. Use cascading CMP/JMP instructions to create a decision tree\n3. For some error ranges (0x88780000-0x887800FF), calculate offset and use table lookup\n4. Return pointer to appropriate error string from data section\n5. Return NULL (0x0) for unknown error codes\n\nParameters:\n- errorCode (in_EAX): The DirectSound HRESULT error code to decode (passed in EAX register via __stdcall)\n\nReturns:\n- char*: Pointer to error message string constant, or NULL if error code not recognized\n- Success: DS_OK (0x6f9c0414) for code 0\n- Failure codes with messages: DSERR_NODRIVER, DSERR_ALLOCATED, DSERR_INVALIDPARAM, etc.\n\nSpecial Cases:\n- Error code 0 returns \"DS_OK\" success string\n- Negative error codes (high-bit set) are standard HRESULT error values\n- 0x88780000-0x887800FF range uses table lookup with offset calculation\n- Unknown codes return NULL pointer instead of default error message\n\nStructure Layout:\nDirectSound error codes are encoded as 32-bit HRESULT values where:\n- Bit 31: Set (0x80000000) indicates error (negative in signed interpretation)\n- Bits 29-16: Facility code (typically 0x0880 for DirectSound)\n- Bits 15-0: Error code specific to facility",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:cbe2aecc09a2d13c0738acbbf7438b9b",
      "indexes": {
        "EXP": null,
        "STR": "cbe2aecc09a2d13c0738acbbf7438b9b",
        "API": null,
        "MNE": "b79dde5b6107d0a69f3a3b0e18bc19b1",
        "CFG": "84a00cde85a81f54e5765e2132b89f93",
        "PRO": "87cc44c03a1de748312f1243466aecda"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b79dde5b6107d0a69f3a3b0e18bc19b1"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_80bc04ae4eba": {
      "addresses": {
        "LoD/PD2": "0x6F9B8DB0"
      },
      "rvas": {
        "LoD/PD2": "0x8DB0"
      },
      "sizes": {
        "LoD/PD2": 143
      },
      "name": "InitializeDirectSoundBuffers",
      "signature": "int InitializeDirectSoundBuffers(int bufferMode)",
      "calling_convention": "__fastcall",
      "comment": "Initializes DirectSound audio buffers based on mode parameter.\n\nAlgorithm:\n1. Check if DirectSound object (DAT_6f9c64b8) is initialized\n2. If mode is 1, create primary buffer using GUID_6f9c01d8\n3. If mode is not 1, create secondary buffer using GUID_6f9c01f8\n4. For secondary mode, call GetCaps() then SetFormat() on secondary buffer\n5. Set global audio initialized flag DAT_6f9c659c = 1\n6. Return 1 for success, 0 for failure\n\nParameters:\n  bufferMode (ECX register): Buffer type - 1 for primary, other for secondary\n\nReturns:\n  EAX: 1 if initialization successful, 0 if initialization failed\n\nSpecial Cases:\n  - Primary buffer initialization uses single GetCaps() call\n  - Secondary buffer initialization requires GetCaps() followed by SetFormat()\n  - Magic constant 0xffffd8f0 is secondary buffer format descriptor\n  - Returns 0 immediately if DirectSound object not available",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:80bc04ae4eba7401881d17b2dc634ea0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "80bc04ae4eba7401881d17b2dc634ea0",
        "CFG": "cb52e141c929b90f9389304b863f6b88",
        "PRO": "3b18039bc63135780ec3a74c10e71c63"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "80bc04ae4eba7401881d17b2dc634ea0"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B8E50": {
      "addresses": {
        "LoD/PD2": "0x6F9B8E50"
      },
      "rvas": {
        "LoD/PD2": "0x8E50"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "Get3DAudioSupportStatus",
      "signature": "uint Get3DAudioSupportStatus(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the current status of 3D audio support in the DirectSound audio subsystem.\n\nAlgorithm:\n1. Load global 3D audio flag from DAT_6f9c659c\n2. Return loaded flag value (1 if 3D audio active, 0 otherwise)\n\nParameters:\nNone\n\nReturns:\nuint - 1 if 3D audio is currently enabled and functional, 0 if disabled or unavailable\n\nSpecial Cases:\n- Flag is set to 1 when 3D audio support is successfully initialized in InitializeDirectSoundAudio()\n- Flag is set during recovery routines (FUN_6f9b8db0, ProcessMessageParameters) when 3D mode is activated\n- Acts as a simple getter for the global audio capability flag\n- Used by audio system to determine which audio processing path to use",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "b3954456e36c956d6dd5655a544c7414"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_ADDR_6F9B8E60": {
      "addresses": {
        "LoD/PD2": "0x6F9B8E60"
      },
      "rvas": {
        "LoD/PD2": "0x8E60"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetAudioMessageState",
      "signature": "uint GetAudioMessageState(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns the current audio message processing state.\n\nAlgorithm:\n1. Load the global audio message state variable from address 0x6f9c6598\n2. Return the loaded value in EAX\n\nParameters:\nNone\n\nReturns:\n- uint: Current audio message state value\n  * 0 = Uninitialized / idle state\n  * 1 = Initial notification phase (notification sent, waiting for handler callback)\n  * 2 = Message marshaling phase (all 12 message fields processed through handler)\n\nSpecial Cases:\n- This getter is called from ProcessMessageParameters and InitializeDirectSoundAudio\n- The state value determines which handler processing path is executed\n- State transitions occur during audio subsystem initialization\n- Used to track progress through the audio message initialization sequence",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "e46c275abf281c7b41ba308704da96d5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_MNE_acbc2c857bf1": {
      "addresses": {
        "LoD/PD2": "0x6F9B8E70"
      },
      "rvas": {
        "LoD/PD2": "0x8E70"
      },
      "sizes": {
        "LoD/PD2": 3
      },
      "name": "ReturnZero",
      "signature": "int ReturnZero(void)",
      "calling_convention": "__stdcall",
      "comment": "Stub function that returns zero.\n\nThis is a minimal DLL export (Ordinal 10027) that serves as a no-op\nfunction returning 0. Typically used as a placeholder or stub export\nin Windows DLLs. The implementation simply clears EAX and returns.\n\nAlgorithm:\n1. Clear EAX register via XOR EAX, EAX (sets EAX = 0)\n2. Return to caller with EAX = 0\n\nReturns:\n  int: Always returns 0 (zero)\n\nNotes:\n  - Calling convention: __stdcall (callee cleans stack)\n  - No parameters or local variables\n  - Entry point referenced this function during module initialization",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:acbc2c857bf1a8401ca8fe5de1c0ec70",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "acbc2c857bf1a8401ca8fe5de1c0ec70",
        "CFG": null,
        "PRO": "7206840be1be8fa373a01e5868c0863f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "acbc2c857bf1a8401ca8fe5de1c0ec70"
      }
    },
    "D2sound_ADDR_6F9B8E80": {
      "addresses": {
        "LoD/PD2": "0x6F9B8E80"
      },
      "rvas": {
        "LoD/PD2": "0x8E80"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetDirectSoundMode2Flag",
      "signature": "int GetDirectSoundMode2Flag(void)",
      "calling_convention": "__stdcall",
      "comment": "Get the second DirectSound initialization mode configuration flag\n\nAlgorithm:\n1. Load the second DirectSound mode parameter from global DAT_6f9c6594\n2. Return the loaded value in EAX\n\nParameters:\n   (none) - Function is a simple global state accessor\n\nReturns:\n   int - DirectSound mode2 parameter value (0 or 1)\n   - 1 = Use second initialization mode configuration\n   - 0 = Do not use second mode configuration\n\nSpecial Cases:\n   - This is a simple getter for global state set by InitializeDirectSound\n   - The value is configured during DirectSound initialization fallback attempts\n   - Accessed by InitializeDirectSoundAudio to determine audio subsystem configuration\n   - Set to 1 for mode1 attempt, then 0 for mode2 attempt, then 0 for mode3 attempt",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "288bfd67f7a1ff23db08f78097c1310a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_ADDR_6F9B8E90": {
      "addresses": {
        "LoD/PD2": "0x6F9B8E90"
      },
      "rvas": {
        "LoD/PD2": "0x8E90"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetAudioMode1Parameter",
      "signature": "uint GetAudioMode1Parameter(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the current audio initialization mode parameter 1 from global state.\n\nAlgorithm:\n1. Load the global audio mode1 configuration flag from DAT_6f9c6590\n2. Return the value in EAX register\n\nParameters:\n  None\n\nReturns:\n  unsigned int - Audio mode1 parameter value (0 or 1):\n    - 1 = Enable 3D audio processing / Use mode 1 configuration\n    - 0 = Disable 3D audio processing / Use minimal configuration\n\nSpecial Cases:\n  - This is a simple accessor function used during DirectSound initialization fallback chain\n  - The value is set by InitializeDirectSound and read by InitializeDirectSoundAudio\n  - Mode progression: (1,1) then (1,0) then (0,0) if initialization fails\n  \nStructure Layout:\n  Global State Variable:\n  Offset  Size  Name                  Type     Description\n  ------  ----  -------------------   -------  -----------------------------------\n  6f9c6590 4    DAT_6f9c6590         uint     Audio mode1 config flag (0 or 1)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "12d781781be5e5e7388891c4da909c94"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_ADDR_6F9B8EA0": {
      "addresses": {
        "LoD/PD2": "0x6F9B8EA0"
      },
      "rvas": {
        "LoD/PD2": "0x8EA0"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetGameState",
      "signature": "uint GetGameState(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the current game state value from global storage.\n\nAlgorithm:\n1. Load the global state value from memory address 0x6f9c658c into EAX\n2. Return the loaded value to the caller\n\nReturns:\nuint - The current game state value stored at address 0x6f9c658c\n\nNotes:\nThis is a simple accessor function that provides read-only access to a global\ngame state variable. The actual state value is maintained elsewhere in the\nbinary and accessed through this getter function. Called frequently by multiple\nfunctions for state inspection and conditional logic.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "e3ac026707246119be860314a2484370"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_MNE_5b951ce55cbc": {
      "addresses": {
        "LoD/PD2": "0x6F9B8EB0"
      },
      "rvas": {
        "LoD/PD2": "0x8EB0"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "CleanupAudioResources",
      "signature": "void CleanupAudioResources(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases and clears three audio resource pointers by calling their destructors\n\nAlgorithm:\n1. Load first audio resource pointer from global DAT_6f9c64b8\n2. If pointer is non-null, call virtual destructor at offset +8 and clear pointer\n3. Load second audio resource pointer from global DAT_6f9c6524\n4. If pointer is non-null, call virtual destructor at offset +8 and clear pointer\n5. Load third audio resource pointer from global DAT_6f9c6528\n6. If pointer is non-null, call virtual destructor at offset +8 and clear pointer\n7. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - Function performs cleanup and returns nothing\n\nSpecial Cases:\n- Uses __stdcall calling convention (callee cleans stack)\n- Each resource check follows identical pattern: load, test, conditionally call destructor\n- Virtual function pointer is stored at offset +8 within each resource object\n- Resource pointers are global variables, not parameters\n- Cleanup order: DAT_6f9c64b8, then DAT_6f9c6524, then DAT_6f9c6528\n\nStructure Layout:\nResource objects follow this structure based on virtual function call pattern:\nOffset | Size | Field Name      | Type         | Description\n-------|------|-----------------|--------------|------------------------------------------\n+0     | 4    | vtable          | void**       | Virtual function table pointer\n+8     | 4    | destructor      | void(*)(obj) | Virtual destructor function pointer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5b951ce55cbcc4370add941772917d85",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5b951ce55cbcc4370add941772917d85",
        "CFG": "92a4bfab0fc7a41edd95f045db6bec51",
        "PRO": "d3f10aca36e378bb7dcfc308d1c00291"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5b951ce55cbcc4370add941772917d85"
      }
    },
    "D2sound_ADDR_6F9B8F00": {
      "addresses": {
        "LoD/PD2": "0x6F9B8F00"
      },
      "rvas": {
        "LoD/PD2": "0x8F00"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetAudioTimeoutConfig",
      "signature": "uint GetAudioTimeoutConfig(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns the current audio timeout configuration value.\n\nAlgorithm:\n1. Load the global audio timeout configuration value from DAT_6f9c65b4\n2. Return the value in EAX\n\nReturns:\n- EAX: Audio timeout configuration value (uint)\n\nSpecial Cases:\n- This is a simple accessor function with no parameters or error handling\n- The global value is initialized by the audio subsystem during startup",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "494e56077a0fa8cb6a34c822a4cdd0c6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_STR_22ef6ba6c5e2": {
      "addresses": {
        "LoD/PD2": "0x6F9B8F10"
      },
      "rvas": {
        "LoD/PD2": "0x8F10"
      },
      "sizes": {
        "LoD/PD2": 179
      },
      "name": "ValidateSystemIdentification",
      "signature": "int ValidateSystemIdentification(int isEnabled, char * pBuffer1, char * pBuffer2)",
      "calling_convention": "__stdcall",
      "comment": "Validates system identification by comparing multiple buffer patterns against hardcoded data.\\n\\nAlgorithm:\\n1. Check if isEnabled flag is set and global validation state is not already active\\n2. If either condition fails, return early with error status\\n3. Compare first pattern (12 bytes from pBuffer2) against 0x6f9c04a4\\n4. If match, set global flag at 0x6f9c65ac\\n5. Compare second pattern (11 bytes from pBuffer2) against 0x6f9c0498\\n6. If match, set global flag at 0x6f9c65b0\\n7. Compare third pattern (24 bytes from pBuffer1) against 0x6f9c0480\\n8. If match, set global flag at 0x6f9c65b0\\n9. Compare fourth pattern (10 bytes from pBuffer2) against 0x6f9c0474\\n10. If match, set global flag at 0x6f9c5900 to 0\\n11. Compare fifth pattern (12 bytes from pBuffer2) against 0x6f9c0468\\n12. If match, set global flag at 0x6f9c5900 to 0\\n13. Mark validation as complete by setting global 0x6f9c65a4 to 1\\n14. Return success status (1)\\n\\nParameters:\\n- isEnabled: int - Enable flag; function returns early if 0\\n- pBuffer1: char* - First data buffer for comparison (used in patterns 3, 5)\\n- pBuffer2: char* - Second data buffer for comparison (used in patterns 1, 2, 4)\\n\\nReturns:\\n- 1 on success or early exit\\n- Sets multiple global flags based on pattern match results\\n\\nSpecial Cases:\\n- Early return occurs if isEnabled is 0 or global validation flag already set\\n- Multiple patterns are checked independently; each sets different global flags\\n- Patterns 4 and 5 can clear the flag at 0x6f9c5900 if they match\\n- Global flag at 0x6f9c65a4 prevents re-validation after first call",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:22ef6ba6c5e21858bf3631bd1fe3e43f",
      "indexes": {
        "EXP": null,
        "STR": "22ef6ba6c5e21858bf3631bd1fe3e43f",
        "API": null,
        "MNE": "7c87977d67a6610e80a74baf6ae19137",
        "CFG": "3d14ae325bd5b1e342b3d6c1b8c9f451",
        "PRO": "9bc102aeeb2befe3b0bc7dc845687f48"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7c87977d67a6610e80a74baf6ae19137"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_c405d7ab0b43": {
      "addresses": {
        "LoD/PD2": "0x6F9B8FD0"
      },
      "rvas": {
        "LoD/PD2": "0x8FD0"
      },
      "sizes": {
        "LoD/PD2": 594
      },
      "name": "ProcessMessageParameters",
      "signature": "void ProcessMessageParameters(uint * pMessageData)",
      "calling_convention": "__fastcall",
      "comment": "Processes message parameters through a virtual interface based on application state.\n\nAlgorithm:\n1. Validate message handler global pointer (DAT_6f9c64b8) and enable flag (DAT_6f9c6594)\n2. If state == 1: Initialize notification, convert field[3] to float, call NotifyGameEventWithValidation\n3. Execute virtual function calls with state codes 2 and 3 for initial setup\n4. If state == 2: Marshal all 12 message fields through virtual handler interface\n5. Use state codes 0xb-0xe for field marshaling with 4-byte chunks\n6. Set magic number flag (DAT_6f9c659c) based on field[3] comparison with -10000\n7. Return to caller\n\nParameters:\n- pMessageData: Pointer to message structure with 13 uint fields (52 bytes total)\n  * [0x0]: Parameter 0 (field 0)\n  * [0x4]: Parameter 1 (field 1)  \n  * [0x8]: Parameter 2 (field 2)\n  * [0xc]: Parameter 3 / Notification value (converted to float in state 1)\n  * [0x10]: Parameter 4\n  * [0x14]: Parameter 5\n  * [0x18]: Parameter 6\n  * [0x1c]: Parameter 7\n  * [0x20]: Parameter 8\n  * [0x24]: Parameter 9\n  * [0x28]: Parameter 10\n  * [0x2c]: Parameter 11\n  * [0x30]: Parameter 12\n\nReturns:\n- void (modifies global flag DAT_6f9c659c)\n\nSpecial Cases:\n- Early return if DAT_6f9c6594 == 0 (handler disabled)\n- Early return if DAT_6f9c64b8 == NULL (no handler pointer)\n- Magic number -10000 (0xffffd8f0) triggers special flag setting\n- State machine depends on DAT_6f9c6598 value (1 = notify mode, 2 = marshal mode)\n\nStructure Layout:\nOffset | Size | Field Name | Type | Description\n-------|------|------------|------|------------\n0x0    | 4    | field0     | uint | Message parameter 0\n0x4    | 4    | field1     | uint | Message parameter 1\n0x8    | 4    | field2     | uint | Message parameter 2\n0xc    | 4    | field3     | uint | Notification/magic value\n0x10   | 4    | field4     | uint | Message parameter 4\n0x14   | 4    | field5     | uint | Message parameter 5\n0x18   | 4    | field6     | uint | Message parameter 6\n0x1c   | 4    | field7     | uint | Message parameter 7\n0x20   | 4    | field8     | uint | Message parameter 8\n0x24   | 4    | field9     | uint | Message parameter 9\n0x28   | 4    | field10    | uint | Message parameter 10\n0x2c   | 4    | field11    | uint | Message parameter 11\n0x30   | 4    | field12    | uint | Message parameter 12\n\nMagic Numbers Reference:\n- 0xffffd8f0: -10000 decimal, triggers magic flag setting\n- 0x6f9c64b8: Global handler pointer address\n- 0x6f9c6594: Global enable flag address  \n- 0x6f9c6598: Global state value address\n- 0x6f9c659c: Global result flag address\n- 0x6f9c01d8: Constant pointer for state 1 operations\n- 0x6f9c01f8: Constant pointer for state 2 operations\n\nState Machine:\n- State 1: Notification mode - converts field[3] to float, calls notification handler\n- State 2: Marshal mode - processes all 12 fields through virtual interface\n- Invalid state: No operation performed, only magic flag check executed",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c405d7ab0b432093d2ccff251cdf3499",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c405d7ab0b432093d2ccff251cdf3499",
        "CFG": "f252eb9d8f7b7396f0f6845e8aa2f5d1",
        "PRO": "18f496eed1f704ec8ac202ce5bda64a9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c405d7ab0b432093d2ccff251cdf3499"
      },
      "api_calls": {
        "LoD/PD2": [
          "NotifyGameEventWithValidation"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_API_2b9b0b804cde": {
      "addresses": {
        "LoD/PD2": "0x6F9B9230"
      },
      "rvas": {
        "LoD/PD2": "0x9230"
      },
      "sizes": {
        "LoD/PD2": 354
      },
      "name": "ShutdownAudioSystemResources",
      "signature": "void ShutdownAudioSystemResources(void)",
      "calling_convention": "__stdcall",
      "comment": "Performs comprehensive shutdown of all audio system resources and synchronization primitives.\n\nAlgorithm:\n1. Clear the audio system active flag (DAT_6f9c6588 = 0)\n2. If audio manager exists and system is active, enter critical section for thread safety\n3. Clear the active system flag (DAT_6f9c5994 = 0) to stop audio processing\n4. Iterate through audio context linked list starting at DAT_6f9c65cc\n5. For each node, extract audio context pointer and validate it is non-null\n6. If context is null, abort with error code 0x2e4 via CleanupAndAbort and exit\n7. Call SetAudioParameterValue with context and parameter at offset 0x38 (field 0xe)\n8. Leave critical section after processing all audio contexts\n9. If game context exists (DAT_6f9c6580), destroy it and clear the pointer\n10. Call DispatchFinalCleanup to perform additional cleanup operations\n11. If thread synchronization handles exist, signal event and wait for thread termination\n12. Close both event and thread handles, then clear handle globals\n13. Release five COM-like interface objects via vtable Release calls (offset +8)\n14. Objects released: DAT_6f9c64b8, DAT_6f9c6524, DAT_6f9c6528, DAT_6f9c652c, DAT_6f9c658c\n15. If critical section was initialized (DAT_6f9c65a0), delete it and clear the flag\n16. Return to caller\n\nParameters:\n- None (operates on global audio system state)\n\nReturns:\n- void (no return value)\n\nSpecial Cases:\n- Null audio context in linked list triggers fatal abort via CleanupAndAbort\n- Thread synchronization uses INFINITE wait (0xffffffff) for clean shutdown\n- Critical section protects audio context list iteration from concurrent access\n- Multiple COM objects released via vtable dispatch at offset +8 (IUnknown::Release pattern)\n- Function handles partial initialization gracefully by checking each resource before cleanup",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:2b9b0b804cde350454ae7ed1ae10f435",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "2b9b0b804cde350454ae7ed1ae10f435",
        "MNE": "0b1b796bbded2ed4c9aea0fa39046eb9",
        "CFG": "2d5ab15472d87596d6c1ea32e688e9b1",
        "PRO": "90b8485df7b407dd3b15195cdd5acbb7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0b1b796bbded2ed4c9aea0fa39046eb9"
      },
      "api_calls": {
        "LoD/PD2": [
          "SetAudioParameterValue",
          "DestroyGameContext",
          "DestroyAllGameObjects",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      }
    },
    "D2sound_STR_a46ee8f2cf1e": {
      "addresses": {
        "LoD/PD2": "0x6F9B93A0"
      },
      "rvas": {
        "LoD/PD2": "0x93A0"
      },
      "sizes": {
        "LoD/PD2": 1145
      },
      "name": "InitializeDirectSoundAudio",
      "signature": "void InitializeDirectSoundAudio(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes DirectSound audio subsystem for game audio playback.\n\nAlgorithm:\n1. Check if audio initialization is already complete (DAT_6f9c6590 and DAT_6f9c65a8)\n2. Verify no concurrent initialization is in progress (DAT_6f9c65a0)\n3. Initialize critical section for thread-safe audio access\n4. Create DirectSound interface via DirectSoundCreate()\n5. Set cooperative level on DirectSound object (vtable +0x18)\n6. Create primary sound buffer with audio format configuration\n7. If 3D audio support enabled, configure and test 3D buffer compatibility:\n   - Call CreateSoundBuffer with format descriptor at offset 0x0c\n   - Query created buffer's capabilities via vtable +0x0\n   - Verify capabilities match expected 3D format requirements (bits 0-1 = 0x3)\n   - Validate 3D audio support with FUN_6f9b8db0()\n   - Attempt recovery if initial setup fails, then finalize at finalize_audio_system\n8. Finalize audio system:\n   - Set primary buffer format via vtable +0x30 call\n   - Initialize playback status (1 = PLAYING)\n   - Call FUN_6f9b6a40() for audio subsystem initialization\n   - Call FUN_6f9b7aa0() for format post-processing\n   - Call FUN_6f9b7cd0() for additional setup\n   - Call InitializeAudioConfig() to configure audio parameters\n   - Call Ordinal_10061(0xff) to finalize audio initialization\n   - Set DAT_6f9c6588 = 1 to indicate successful initialization\n\nReturns: void (no return value)\n\nSpecial Cases:\n- If initialization already in progress, calls GetReturnAddress(), CleanupAndAbort(), and _exit(-1)\n- Multiple error recovery paths for DirectSound interface failures\n- Fallback initialization at offset recovery_failed (0x6f9b97ef) if 3D format setup fails\n- Audio flag 0x11 used if 3D mode enabled, otherwise 0x01\n- Magic numbers: 0x14 (descriptor size), 0x400 (sample count), 0x12 (format type)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:a46ee8f2cf1e2cb109c563256606ef29",
      "indexes": {
        "EXP": null,
        "STR": "a46ee8f2cf1e2cb109c563256606ef29",
        "API": "26abb2b66bc97f531738b0da96a493e4",
        "MNE": "2ba84a345043601d4bab86316bbb7870",
        "CFG": "576700df3307940cbd3895742d9bbaaf",
        "PRO": "cdd181f79c4c36ecdf08d903ded44b82"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2ba84a345043601d4bab86316bbb7870"
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "DirectSoundCreate",
          "ValidateAndInitializeParameter",
          "ShutdownAudioSystemResources",
          "GetWindowHandleValue",
          "ValidateAndInitializeParameter",
          "ShutdownAudioSystemResources",
          "ValidateAndInitializeParameter",
          "ShutdownAudioSystemResources",
          "...+10 more"
        ]
      }
    },
    "D2sound_STR_4eff5df61307": {
      "addresses": {
        "LoD/PD2": "0x6F9B9820"
      },
      "rvas": {
        "LoD/PD2": "0x9820"
      },
      "sizes": {
        "LoD/PD2": 484
      },
      "name": "InitializeDirectSound",
      "signature": "void InitializeDirectSound(int param1, int param2)",
      "calling_convention": "__fastcall",
      "comment": "InitializeDirectSound - Initialize DirectSound with device validation and fallback modes\n\nAlgorithm:\n1. Store two configuration parameters (param1, param2) into global state variables\n2. Enumerate available DirectSound devices via callback (DirectSoundEnumerateA)\n3. If EMU10K1 device detected (DAT_6f9c65ac != 0):\n   a. Get Windows System directory path (GetWindowsDirectoryA)\n   b. Parse EMU10K1 driver version information via FUN_6f9b8a50\n   c. Validate version range: type=4, major version 6 (0x26e-0x2c6) or B (0x274-0x275)\n   d. If valid, set success flag (DAT_6f9c65a8 = 1)\n4. If CRLDS3D device detected (DAT_6f9c65b0 != 0):\n   a. Get Windows System directory path\n   b. Parse CRLDS3D driver version\n   c. Validate: type < 4 OR (type=4 AND major < C) OR (major=C AND revision < 0x40b)\n   d. If valid, set success flag\n5. Initialize DirectSound with three fallback modes (DAT_6f9c6590/6f9c6594):\n   a. Mode 1: Full configuration (flags=1,1)\n   b. Mode 2: Alternate config (flags=1,0)\n   c. Mode 3: Minimal config (flags=0,0)\n6. If all modes fail (DAT_6f9c6588 still 0), call error handler with message\n\nParameters:\n  param1 (ECX): Configuration parameter 1, stored to DAT_6f9c65b4\n  param2 (EDX): Configuration parameter 2, stored to DAT_6f9c6520\n\nReturns:\n  void - No explicit return value, sets global state variables\n\nSpecial Cases:\n  - EMU10K1 version range: 0x26e to 0x2c6 (major 6) or 0x274 to 0x275 (major B)\n  - CRLDS3D version check: complex multi-condition validation for different revisions\n  - Three-stage fallback: tries different DirectSound initialization modes sequentially\n  - All initialization attempts fail only if all three modes fail to set DAT_6f9c6588\n\nStructure Layout:\n  Global State Variables Used:\n  Offset  Size  Name                    Type     Description\n  ------  ----  ----------------------  -------  ----------------------------\n  6f9c65b4  4   DAT_6f9c65b4            int      Config param1 storage\n  6f9c6520  4   DAT_6f9c6520            int      Config param2 storage\n  6f9c65a4  4   DAT_6f9c65a4            int      Validation flag\n  6f9c65ac  4   DAT_6f9c65ac            int      EMU10K1 found flag\n  6f9c65b0  4   DAT_6f9c65b0            int      CRLDS3D found flag\n  6f9c65a8  4   DAT_6f9c65a8            int      Success flag (1=valid device found)\n  6f9c6588  4   DAT_6f9c6588            int      DirectSound init status (0=failed)\n  6f9c6590  4   DAT_6f9c6590            int      Mode parameter 1 (1 or 0)\n  6f9c6594  4   DAT_6f9c6594            int      Mode parameter 2 (1 or 0)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:4eff5df6130735a75d282b39b05c6361",
      "indexes": {
        "EXP": null,
        "STR": "4eff5df6130735a75d282b39b05c6361",
        "API": "57eb92111a82822c95dce8e0be8b932c",
        "MNE": "49df1806eb8ac9c7a08b65d765d791c0",
        "CFG": "05f7b845a5acd90e699189c992511e1a",
        "PRO": "b218216336d3d1d62079e44e6816433d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "49df1806eb8ac9c7a08b65d765d791c0"
      },
      "api_calls": {
        "LoD/PD2": [
          "DirectSoundEnumerateA",
          "ValidateAndInitializeParameter"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_d14addc7929a": {
      "addresses": {
        "LoD/PD2": "0x6F9B9A10"
      },
      "rvas": {
        "LoD/PD2": "0x9A10"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "SetAudioOptionFlag",
      "signature": "uint SetAudioOptionFlag(uint newOptionValue)",
      "calling_convention": "__fastcall",
      "comment": "Sets the audio option flag configuration value and persists it.\n\nAlgorithm:\n1. Move the input parameter from ECX register to ESI (save for later use)\n2. Push ESI onto stack (parameter for config function)\n3. Push 0x00 (null/zero parameter for config function)\n4. Push address of \"Options_Music\" string constant\n5. Push address of \"Diablo II\" string constant\n6. Call external config write function at 0x1018bec0 to persist the new option value\n7. Store the input value in global audio option flag storage at 0x6f9c64b4\n8. Move the value from ESI to EAX (prepare return value)\n9. Pop ESI from stack (restore saved register)\n10. Return to caller with new option value in EAX\n\nParameters:\nuint newOptionValue - The new audio option flag value (0 or 1), passed in ECX register\n\nReturns:\nuint - Returns the new option value that was set (same as newOptionValue parameter)\n\nSpecial Cases:\n- Function uses __fastcall convention: first parameter in ECX register\n- Global variable at 0x6f9c64b4 stores the audio option flag (0=disabled, 1=enabled)\n- External function 0x1018bec0 handles persistence to Diablo II config system\n- Function always returns the input value (setter pattern with return value)\n- String constants: \"Diablo II\" at 0x6f9c0294, \"Options_Music\" at 0x6f9c0248\n\nGlobal Variables Modified:\n0x6f9c64b4 - Audio option flag storage (read by GetAudioOptionFlag function)\n\nRelated Functions:\nGetAudioOptionFlag - Reads the current audio option flag value\nInitializeAudioConfig - Initializes all audio configuration values including option flag",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d14addc7929abe91957b0bc29e051997",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d14addc7929abe91957b0bc29e051997",
        "CFG": null,
        "PRO": "63bb3fd330e71edb2aadc1e02cb3b9e6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d14addc7929abe91957b0bc29e051997"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B9A30": {
      "addresses": {
        "LoD/PD2": "0x6F9B9A30"
      },
      "rvas": {
        "LoD/PD2": "0x9A30"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetAudioOptionFlag",
      "signature": "uint GetAudioOptionFlag(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns the audio option flag configuration value.\n\nAlgorithm:\n1. Load the audio option flag value from global config storage (0x6f9c64b4)\n2. Return the loaded value to caller\n\nReturns:\nuint - Audio option flag value (0 or 1), where 1 indicates option enabled\n\nSpecial Cases:\n- Value is initialized to 1 by InitializeAudioConfig and can be modified by external config reader\n- Option flag is stored as a 4-byte value at 0x6f9c64b4\n- This is a simple accessor function with no validation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "997101b029dbe63c83442e66b3f7f0fc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_ADDR_6F9B9A40": {
      "addresses": {
        "LoD/PD2": "0x6F9B9A40"
      },
      "rvas": {
        "LoD/PD2": "0x9A40"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "InitializeNPCSpeech",
      "signature": "uint InitializeNPCSpeech(uint resourceId)",
      "calling_convention": "__fastcall",
      "comment": "Initializes NPC speech system with the specified resource ID.\n\nAlgorithm:\n1. Receive resource ID in ECX (fastcall convention)\n2. Push resource ID onto stack as 4th argument\n3. Push string pointer \"NPC_Speech\" as 3rd argument\n4. Push zero (0) as 2nd argument\n5. Push string pointer \"Diablo II\" as 1st argument\n6. Call initialization function at 0x1018bec0\n7. Store resource ID to global variable at 0x6f9c64b0\n8. Move resource ID into EAX as return value\n9. Pop ESI and return\n\nParameters:\n  resourceId (uint ECX): Resource ID to initialize for NPC speech subsystem\n\nReturns:\n  uint (EAX): The same resource ID that was passed in\n\nSpecial Cases:\n  - Resource ID is stored in global variable 0x6f9c64b0 for external access\n  - Function acts as a pass-through wrapper around the initialization routine\n  - Part of Diablo II game engine initialization sequence",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d14addc7929abe91957b0bc29e051997",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d14addc7929abe91957b0bc29e051997",
        "CFG": null,
        "PRO": "7ba190f3181a17d660ff375f27516ee1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d14addc7929abe91957b0bc29e051997"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B9A60": {
      "addresses": {
        "LoD/PD2": "0x6F9B9A60"
      },
      "rvas": {
        "LoD/PD2": "0x9A60"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetAudioModeValue",
      "signature": "uint GetAudioModeValue(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns the current audio mode configuration value (NPC Speech setting).\n\nAlgorithm:\n1. Load audio mode value from global config structure at offset 0x6f9c64b0\n2. Return the value in EAX to caller\n\nParameters:\nNone\n\nReturns:\nuint - Audio mode configuration value (0-3). Valid values:\n  0 = Mode 0\n  1 = Mode 1\n  2 = Mode 2 (Default)\n  3 = Mode 3\n\nSpecial Cases:\n- This is a simple getter for the audio mode field\n- The value is initialized to 2 by InitializeAudioConfig()\n- Can be modified via SetAudioModeValue() (Ordinal_10040)\n- Used by audio initialization and configuration routines\n\nRelated Functions:\n- InitializeAudioConfig() - Reads and validates audio configuration from external source\n- SetAudioModeValue() (Ordinal_10040) - Writes new mode value to global config",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "6648f993cd619b7c830788875aad02d1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_ADDR_6F9B9A70": {
      "addresses": {
        "LoD/PD2": "0x6F9B9A70"
      },
      "rvas": {
        "LoD/PD2": "0x9A70"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "SetPositionalBiasLevel",
      "signature": "uint SetPositionalBiasLevel(uint biasLevel)",
      "calling_convention": "__fastcall",
      "comment": "Sets the positional bias level for Diablo II audio configuration.\n\nAlgorithm:\n1. Save the input bias level to ECX register (fastcall parameter)\n2. Call audio configuration function with:\n   - \"Diablo II\" identifier string\n   - \"Positional Bias\" configuration key\n   - Value 0 (third parameter)\n   - Bias level value (stored in ECX, param_1)\n3. Store the bias level in global variable DAT_6f9c64ac\n4. Load bias level into EAX for return\n5. Restore ESI and return to caller\n\nParameters:\n- biasLevel (ECX): Audio positional bias level (0-100 or similar range)\n\nReturns:\n- EAX: Returns the bias level value that was set\n\nSpecial Cases:\n- Global variable DAT_6f9c64ac is used to cache the current bias level\n- The external function at 0x1018bec0 handles actual configuration application\n- This is a simple wrapper that calls the audio config handler with fixed strings\n\nAudio Configuration Details:\n- \"Positional Bias\" affects how audio panning is applied in 3D space\n- \"Diablo II\" indicates this is Diablo II audio system configuration\n- The bias level parameter is passed through to the configuration handler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d14addc7929abe91957b0bc29e051997",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d14addc7929abe91957b0bc29e051997",
        "CFG": null,
        "PRO": "edcfd527170d52ffb84538c53bc90489"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d14addc7929abe91957b0bc29e051997"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B9A90": {
      "addresses": {
        "LoD/PD2": "0x6F9B9A90"
      },
      "rvas": {
        "LoD/PD2": "0x9A90"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetPositionalBiasLevel",
      "signature": "uint GetPositionalBiasLevel(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns the current positional bias audio configuration level.\n\nAlgorithm:\n1. Load audio config positional bias value from global data at 0x6f9c64ac\n2. Return value in EAX register\n\nParameters:\nNone\n\nReturns:\nuint - Positional bias level (typically 0-100 range, validated during initialization)\n\nSpecial Cases:\n- Value is initialized by InitializeAudioConfig during startup\n- Can be modified by SetPositionalBiasLevel (Ordinal_10022)\n- Default/fallback value is 0x32 (50 decimal)\n- Part of global audio configuration structure at 0x6f9c64a0\n\nAudio Configuration Structure Layout:\n  Offset  Size  Field Name      Type    Description\n  0x00    4     timeout_secs    uint    Timeout duration (0-3 seconds)\n  0x04    4     volume_level    uint    Volume percentage (0-100)\n  0x08    4     quality_level   uint    Sound quality (0-2)\n  0x0c    4     enabled_flag    uint    Audio enabled (0/1)\n  0x10    4     mode_value      uint    Audio mode (0-3)\n  0x14    4     positional_bias uint    Positional bias level (0-100)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "6f6a2fe96eb606f6f4ed61e533795575"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_ADDR_6F9B9AA0": {
      "addresses": {
        "LoD/PD2": "0x6F9B9AA0"
      },
      "rvas": {
        "LoD/PD2": "0x9AA0"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "SetDiabloMusicVolume",
      "signature": "uint SetDiabloMusicVolume(uint volumeValue)",
      "calling_convention": "__fastcall",
      "comment": "Sets the music volume level for Diablo II.\\n\\nAlgorithm:\\n1. Save ESI register for later restoration\\n2. Copy input volume value from ECX to ESI\\n3. Call volume configuration function with:\\n   - \\\"Diablo II\\\" application identifier (0x6f9c0294)\\n   - \\\"Music Volume\\\" configuration key (0x6f9c0274)\\n   - 0 as configuration flags\\n   - volumeValue as the new volume setting\\n4. Store the volume value to global variable at 0x6f9c64a8\\n5. Return the volume value in EAX\\n\\nParameters:\\n- volumeValue: uint in ECX, the new music volume level to set\\n\\nReturns:\\n- uint in EAX: the volume value that was set\\n\\nSpecial Cases:\\n- The function uses __fastcall convention with first parameter in ECX\\n- The volume value is stored in a global location (0x6f9c64a8) for later retrieval\\n- Configuration call is made to external function at 0x1018bec0",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d14addc7929abe91957b0bc29e051997",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d14addc7929abe91957b0bc29e051997",
        "CFG": null,
        "PRO": "2272b86d96825ed075b6954a840088c5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d14addc7929abe91957b0bc29e051997"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B9AC0": {
      "addresses": {
        "LoD/PD2": "0x6F9B9AC0"
      },
      "rvas": {
        "LoD/PD2": "0x9AC0"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetMusicVolume",
      "signature": "uint GetMusicVolume(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the current music volume configuration value.\n\nThis function reads the music/quality volume level from the global audio configuration structure. The value represents the current audio quality setting (0-100) that was previously set during audio initialization or configuration updates.\n\nAlgorithm:\n1. Load the music volume value from global memory address 0x6f9c64a8\n2. Return the value in EAX\n3. Return to caller\n\nParameters:\nNone\n\nReturns:\nuint - The current music volume level (0-100). Value of 0 indicates minimum/muted, 100 indicates maximum quality.\n\nSpecial Cases:\n- Initial value is 2 (low quality) if not explicitly set during initialization\n- The returned value is always within 0-100 range due to validation in InitializeAudioConfig\n- Called by external initialization code at Entry Point (likely part of module initialization sequence)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "cdad2d26b39052377fcca57a0c1a2642"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_ADDR_6F9B9AD0": {
      "addresses": {
        "LoD/PD2": "0x6F9B9AD0"
      },
      "rvas": {
        "LoD/PD2": "0x9AD0"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "InitializeSoundMixer",
      "signature": "void InitializeSoundMixer(void * pSoundContext)",
      "calling_convention": "__fastcall",
      "comment": "Initializes the Diablo II Sound Mixer system.\n\nAlgorithm:\n1. Save ESI register (callee-saved in fastcall)\n2. Load sound context pointer from ECX parameter\n3. Push four arguments for initialization:\n   - pSoundContext (the context pointer)\n   - NULL (terminator)\n   - Address of \"Master Volume\" string (0x6f9c0284)\n   - Address of \"Diablo II Sound Mixer\" string (0x6f9c0294)\n4. Call external initialization function at 0x1018bec0\n5. Store the returned mixer context at global address 0x6f9c64a4\n6. Load context pointer into EAX as return value\n7. Restore ESI and return\n\nParameters:\n  pSoundContext (ECX): Pointer to sound context structure\n\nReturns:\n  EAX: Pointer to sound context (echoes input parameter)\n\nSpecial Cases:\n  - Uses fastcall convention: first parameter in ECX, cleanup by caller\n  - Stores result globally at 0x6f9c64a4 for singleton access\n  - Magic numbers: 0x6f9c0284 = \"Master Volume\", 0x6f9c0294 = \"Diablo II Sound Mixer\"\n  - External function at 0x1018bec0 likely initializes DirectSound or similar audio system",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d14addc7929abe91957b0bc29e051997",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d14addc7929abe91957b0bc29e051997",
        "CFG": null,
        "PRO": "a0738aa045349aca10b1857bc6258e6e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d14addc7929abe91957b0bc29e051997"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B9AF0": {
      "addresses": {
        "LoD/PD2": "0x6F9B9AF0"
      },
      "rvas": {
        "LoD/PD2": "0x9AF0"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetAudioMixerState",
      "signature": "dword GetAudioMixerState(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns the current audio mixer configuration state.\n\nThis function provides read-only access to a static audio mixer state value that is initialized and maintained by the audio subsystem initialization functions (InitializeAudioConfig and InitializeSoundMixer). The state value indicates the configuration of the audio mixing system.\n\nAlgorithm:\n1. Load the audio mixer state value from the global data location (0x6f9c64a4)\n2. Return the loaded state value in EAX\n\nParameters:\nNone\n\nReturns:\ndword - The current audio mixer configuration state value\n\nSpecial Cases:\n- The state value is initialized by InitializeAudioConfig and InitializeSoundMixer\n- Multiple readers access this state for validation (called from Entry Point and function 0x6f9c4dac)\n- The state is written to by audio initialization routines and read-only in normal operation\n\nData References:\n- 0x6f9c64a4: Global audio mixer state (dword, 4 bytes)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "d6ef5ce095bd6e7a9bdaeb664801955b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_ADDR_6F9B9B00": {
      "addresses": {
        "LoD/PD2": "0x6F9B9B00"
      },
      "rvas": {
        "LoD/PD2": "0x9B00"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "InitializeAudioTimeoutConfig",
      "signature": "int InitializeAudioTimeoutConfig(int timeoutMs)",
      "calling_convention": "__fastcall",
      "comment": "Initializes the audio system timeout configuration.\n\nThis function initializes the sound mixer with a timeout configuration value and\nstores it in the global audio timeout config. The timeout value is passed to the\naudio initialization routine along with domain-specific strings identifying the\nDiablo II audio system and Sound Mixer component.\n\nAlgorithm:\n1. Store input timeout parameter in ESI register (parameter from ECX in __fastcall)\n2. Push timeout parameter as fourth argument to initialization function\n3. Push Sound Mixer component string address (0x6f9c02a0)\n4. Push Diablo II domain string address (0x6f9c0294)\n5. Push zero as third argument (reserved/unused)\n6. Call audio initialization function at 0x1018bec0\n7. Store timeout value in global config at 0x6f9c64a0\n8. Move timeout value to EAX and return it\n\nParameters:\n  timeoutMs (int) - Audio timeout duration in milliseconds, passed via ECX\n                    register (fastcall convention)\n\nReturns:\n  int - The timeout value that was set (echo return for confirmation)\n\nSpecial Cases:\n  - Function returns input value unchanged\n  - Global storage at 0x6f9c64a0 persists configuration across calls",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d14addc7929abe91957b0bc29e051997",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d14addc7929abe91957b0bc29e051997",
        "CFG": null,
        "PRO": "b8ddaa7f9b3700da3ddf2b9377458aa8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d14addc7929abe91957b0bc29e051997"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9B9B20": {
      "addresses": {
        "LoD/PD2": "0x6F9B9B20"
      },
      "rvas": {
        "LoD/PD2": "0x9B20"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetAudioTimeoutConfig",
      "signature": "undefined4 GetAudioTimeoutConfig(void)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: undefined4 GetAudioTimeoutConfig(void)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "760b0eb2c0836c96db7276d8827eec5a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "D2sound_MNE_24edb7dc41bc": {
      "addresses": {
        "LoD/PD2": "0x6F9B9B30"
      },
      "rvas": {
        "LoD/PD2": "0x9B30"
      },
      "sizes": {
        "LoD/PD2": 286
      },
      "name": "InitializeAudioConfig",
      "signature": "void InitializeAudioConfig(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes audio configuration parameters by reading settings from external configuration source.\nReads six configuration values: timeout (max 3), volume (max 100), sound quality (max 2), sound enabled flag, mode, and option (max 1).\nEach value is validated against maximum bounds before storage. Invalid values are replaced with defaults.\nConfiguration is stored in global memory structure starting at 0x6f9c64a0.\n\nAlgorithm:\n1. Initialize config storage: timeout=0, volume=100, quality=2, enabled=1\n2. Call external config read function (0x1018bd60) to get timeout value\n3. Validate timeout <= 3, store if valid, use default if not\n4. Call external config read function to get volume value\n5. Validate volume <= 100, store if valid, use default if not\n6. Call external config read function to get quality value\n7. Validate quality <= 100, store if valid, use default if not\n8. Call external config read function to get enabled flag\n9. Validate enabled <= 100, store if valid, use default if not\n10. Call external config read function to get mode value\n11. Validate mode <= 3, store if valid, use default if not\n12. Call external config read function to get option value\n13. Validate option <= 1, store if valid, use default if not\n14. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - Configuration is stored in global memory, no return value.\n\nSpecial Cases:\n- Invalid config values (read failure or out of bounds) revert to defaults\n- Timeout/mode: max value is 3, others have different bounds\n- Volume/enabled/quality: max value is 100, option max is 1\n- All validation uses simple numeric bounds checks\n- External function calls (0x1018bd60) handle actual config source\n\nConfiguration Structure (0x6f9c64a0):\n  Offset  Size  Field Name      Type    Description\n  0x00    4     timeout_secs    uint    Timeout duration (0-3 seconds)\n  0x04    4     volume_level    uint    Volume percentage (0-100)\n  0x08    4     quality_level   uint    Sound quality (0-2)\n  0x0c    4     enabled_flag    uint    Audio enabled (0/1)\n  0x10    4     mode_value      uint    Audio mode (0-3)\n  0x14    4     option_flag     uint    Option flag (0/1)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:24edb7dc41bcee00376d97055f349061",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "24edb7dc41bcee00376d97055f349061",
        "CFG": "a38174bd4681a236fef388874564b67c",
        "PRO": "9fcaf715e30daa91ddbc45d2d1435ef3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "24edb7dc41bcee00376d97055f349061"
      }
    },
    "D2sound_MNE_bfc3ed25e915": {
      "addresses": {
        "LoD/PD2": "0x6F9B9C4F"
      },
      "rvas": {
        "LoD/PD2": "0x9C4F"
      },
      "sizes": {
        "LoD/PD2": 56
      },
      "name": "InitializeFloatMathFunctionPointers",
      "signature": "void InitializeFloatMathFunctionPointers(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize floating-point math function pointer table used by Visual Studio runtime.\n\nAlgorithm:\n1. Load address of __cfltcvt function into EAX\n2. Store __cfltcvt pointer at 0x6f9c5b20 (primary entry)\n3. Store address of LAB_6f9bad7d at 0x6f9c5b24 (alternate code location 1)\n4. Store address of __fassign at 0x6f9c5b28 (floating-point assignment function)\n5. Store address of __forcdecpt at 0x6f9c5b2c (forced decimal point function)\n6. Store address of LAB_6f9badc8 at 0x6f9c5b30 (alternate code location 2)\n7. Store __cfltcvt pointer again at 0x6f9c5b34 (backup/redundant entry)\n8. Return to caller\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Part of Visual Studio 2003 floating-point math initialization\n- Called from __fpmath() during runtime library initialization\n- Function pointers stored in a vtable-like structure at offsets 0x6f9c5b20-0x6f9c5b34\n- __cfltcvt pointer appears twice (0x6f9c5b20 and 0x6f9c5b34) suggesting backup or dual-entry mechanism",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bfc3ed25e9152f457419d9112a775bc2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bfc3ed25e9152f457419d9112a775bc2",
        "CFG": null,
        "PRO": "611ac7249e4fd351e25449da4ac291fb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bfc3ed25e9152f457419d9112a775bc2"
      }
    },
    "D2sound_MNE_4d560490b77b": {
      "addresses": {
        "LoD/PD2": "0x6F9B9C87"
      },
      "rvas": {
        "LoD/PD2": "0x9C87"
      },
      "sizes": {
        "LoD/PD2": 30
      },
      "name": "__fpmath",
      "signature": "void __fpmath(int nSetPrecision)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void __fpmath(int nSetPrecision)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4d560490b77bf3b5146b14c1413f0461",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4d560490b77bf3b5146b14c1413f0461",
        "CFG": "1abbbed88598ab76171d956e8b753f75",
        "PRO": "d363ca85f8be91780d088860a401b175"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4d560490b77bf3b5146b14c1413f0461"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_c6e7054733fc": {
      "addresses": {
        "LoD/PD2": "0x6F9B9CB0"
      },
      "rvas": {
        "LoD/PD2": "0x9CB0"
      },
      "sizes": {
        "LoD/PD2": 72
      },
      "name": "ValidateFPUStateAndDispatch",
      "signature": "void ValidateFPUStateAndDispatch(void)",
      "calling_convention": "__cdecl",
      "comment": "Validates FPU/SSE state and dispatches to appropriate math computation path.\n\nThis function performs critical FPU (x87) and SSE state validation before delegating\nto floating-point mathematical operations. It checks an initialization flag, validates\nthat all FPU exceptions are properly masked, and verifies FPU rounding mode settings.\nBased on validation results, it either dispatches to a fast computation path or a\nslower path with error handling.\n\nAlgorithm:\n1. Check if FPU initialization flag (at 0x6f9c6600) is set\n2. If not initialized, jump to slow path (error handler setup)\n3. If initialized, save and validate MXCSR (SSE state) register\n4. Extract exception mask bits [12:8] from MXCSR (0x1f80 mask)\n5. Verify all exceptions are masked (MXCSR[12:8] == 0x1f80)\n6. If not all masked, jump to slow path for error handling\n7. Save and validate x87 FPU control word via FNSTCW\n8. Extract rounding mode bits [7:6] and precision bits [9:8]\n9. Verify rounding is set to round-to-nearest (bits masked to 0x7f)\n10. If control word rounding invalid, jump to slow path\n11. If all validations pass, jump to fast path (ComputeFloatpointMathWithSpecialCases)\n12. If any validation fails, dispatch to slow path (__fload_withFB error handler)\n\nReturns:\n  void - Function never returns directly; always dispatches to either fast or slow path\n\nSpecial Cases:\n  - Uninitialized FPU: Triggers error handler at slow path\n  - SSE exceptions not masked: Indicates improper state, routes to error path\n  - FPU rounding mode incorrect: Validation failure routes to error path\n  - Fast path taken: Calls ComputeFloatpointMathWithSpecialCases (0x6f9bb2e9)\n  - Slow path taken: Calls __fload_withFB error handler (0x6f9bc2a5)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c6e7054733fc415fff96379f6df31fce",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c6e7054733fc415fff96379f6df31fce",
        "CFG": "fc21cabc67a11d2e1d34c83d9134404c",
        "PRO": "5797c75fe222e703988dae66cdd7a463"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c6e7054733fc415fff96379f6df31fce"
      }
    },
    "D2sound_MNE_8f8d52afaf5c": {
      "addresses": {
        "LoD/PD2": "0x6F9B9CF0"
      },
      "rvas": {
        "LoD/PD2": "0x9CF0"
      },
      "sizes": {
        "LoD/PD2": 84
      },
      "name": "ValidateFPUAndComputePower",
      "signature": "float10 ValidateFPUAndComputePower(float10 * __return_storage_ptr__)",
      "calling_convention": "__stdcall",
      "comment": "Validates FPU/SSE state and computes floating-point power operation\n\nAlgorithm:\n1. Check DAT_6f9c6600 initialization flag for FPU status\n2. If uninitialized, skip to slow path validation\n3. Store MXCSR register value to stack for inspection\n4. Extract exception mask bits using AND 0x1f80\n5. Verify all exception types are masked (result == 0x1f80)\n6. Read FPU control word and extract rounding mask (AND 0x7f)\n7. Verify all rounding exceptions masked (result == 0x7f)\n8. If both SSE and x87 validations pass, jump to fast path\n9. Fast path: Call ConvertFPUStackAndComputeMath() directly\n10. Slow path: Allocate 20-byte stack frame\n11. Exchange ST0/ST1 order using FXCH instruction\n12. Convert swapped ST0 (exponent) to 64-bit double at [ESP]\n13. Convert ST1 (base) to 64-bit double at [ESP+8]\n14. Extract high word from ST1 for sign/exponent extraction\n15. Call MathPowerWithFPUValidation with double parameters\n16. Clean stack and return result in ST0\n\nParameters:\nST0 (implicit): Base value for power computation (float10)\nST1 (implicit): Exponent value for power computation (float10)\n__return_storage_ptr__ (explicit): Pointer for extended precision return storage\n\nReturns:\nfloat10 - Result of base^exponent operation in ST0 register\n\nSpecial Cases:\nDAT_6f9c6600 (0x6f9c6600): FPU initialization flag, 0=skip validation\nMXCSR mask 0x1f80: SSE exception control (Invalid|Denormal|DivZero|Overflow|Underflow)\nControl word mask 0x7f: x87 rounding control and exception masking\nFast path requires BOTH 0x1f80 and 0x7f masks to be fully set\nSUB84 macro: Extracts low 32-bits from double conversion\nHigh word extraction: (ulonglong)(double)value >> 0x20 for sign/exponent bits",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8f8d52afaf5cc45db77870ad7f38a3fe",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8f8d52afaf5cc45db77870ad7f38a3fe",
        "CFG": "9aca51d6d40a701b7777aecaf9165326",
        "PRO": "5abbe9f2bf93ec5650712c7f40b9c2a2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8f8d52afaf5cc45db77870ad7f38a3fe"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_22a1b6cd439e": {
      "addresses": {
        "LoD/PD2": "0x6F9B9D4D"
      },
      "rvas": {
        "LoD/PD2": "0x9D4D"
      },
      "sizes": {
        "LoD/PD2": 453
      },
      "name": "MathPowerWithFPUValidation",
      "signature": "double MathPowerWithFPUValidation(int nBaseValue, uint dwBaseFlags, int nExponent, uint dwExponentFlags)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: double __cdecl MathPowerWithFPUValidation(int nBaseValue, uint dwBaseFlags, int nExponent, uint dwExponentFlags)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:22a1b6cd439e027651f376812a9ce3b4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "22a1b6cd439e027651f376812a9ce3b4",
        "CFG": "c3cb0faaba76766a06657604ccd9d1b2",
        "PRO": "49d2ff4c0ac233aeed12bf0f610a5b33"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "22a1b6cd439e027651f376812a9ce3b4"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_634f5fd2b38b": {
      "addresses": {
        "LoD/PD2": "0x6F9B9F12"
      },
      "rvas": {
        "LoD/PD2": "0x9F12"
      },
      "sizes": {
        "LoD/PD2": 40
      },
      "name": "ValidateFPRounding",
      "signature": "int ValidateFPRounding(float fpValue)",
      "calling_convention": "__stdcall",
      "comment": "Validates floating-point values for integer characteristics and performs two-stage validation with rounding tests.\n\nAlgorithm:\n1. Load floating-point input parameter into x87 FPU stack\n2. Round input value using FRNDINT instruction and compare with original\n3. If values match (input is already integer), proceed to stage 2 validation\n4. For stage 2: multiply by constant factor from 0x6f9c59b0 and round again\n5. Compare second rounded result with multiplied value\n6. Return validation result as packed status word with comparison flags\n\nParameters:\n  fpValue - Single precision floating-point value to validate (passed via x87 ST0)\n  IMPLICIT: Uses x87 FPU stack registers ST0, ST1 for computation\n\nReturns:\n  int - Packed x87 status word containing comparison results\n      - Bits 8-10: Comparison flags from FCOMPP operation\n      - Bit 14: Zero flag (ZF) - set if values are equal\n      - Other bits: x87 FPU status information\n\nSpecial Cases:\n  - Input values that are not integers fail first validation\n  - NaN inputs produce NaN comparison flags in result\n  - Uses extended precision (float10) internally for accuracy\n  - Multiplier constant at 0x6f9c59b0 determines second validation factor\n\nMagic Numbers Reference:\n  0x6f9c59b0 - Global constant used as multiplication factor for second validation\n  0x10 (16)  - Bit shift amount to extract upper word from EAX status register\n\nError Handling:\n  - No explicit error handling - relies on x87 FPU exception mechanisms\n  - Invalid operations set appropriate flags in returned status word\n  - Function designed to always return valid status regardless of input",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:634f5fd2b38b5a9728c3cfaee438889f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "634f5fd2b38b5a9728c3cfaee438889f",
        "CFG": "2c30d1f57bc306ed0da51afaa69f5e4d",
        "PRO": "c4bcc9c1cfeb654811107e7f522425c9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "634f5fd2b38b5a9728c3cfaee438889f"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_35a926809c02": {
      "addresses": {
        "LoD/PD2": "0x6F9B9F40"
      },
      "rvas": {
        "LoD/PD2": "0x9F40"
      },
      "sizes": {
        "LoD/PD2": 279
      },
      "name": "X87FloatingPointDivideWithRounding",
      "signature": "uint X87FloatingPointDivideWithRounding(int mantissaLow, uint mantissaMid, ushort exponentAndSign, uint divisorLow, uint divisorExponentAndSign, uint controlWord)",
      "calling_convention": "__cdecl",
      "comment": "Performs x87 floating-point division with IEEE 754 special case handling and dynamic rounding mode control.\n\nAlgorithm:\n1. Load dividend as 80-bit extended precision from mantissa components and exponent+sign\n2. Check for carry condition in mantissa doubling to detect normalization requirements  \n3. Handle zero dividend case: return 0x0 if both mantissa parts are zero\n4. Extract and validate exponent fields from both dividend and divisor\n5. Apply special case lookup using table at 0x6f9c59c0 for denormal/special values\n6. For normalized operands, temporarily modify FPU control word to set truncate rounding mode\n7. Scale both operands by 2^67 constant (0x6f9c59d8) to normalize magnitude for division\n8. Perform x87 FDIVP instruction with controlled rounding behavior\n9. Restore original FPU control word state\n10. Return result exponent or special status code in EAX\n\nParameters:\n  mantissaLow (int): Low 32 bits of 64-bit dividend mantissa from stack+0x4\n  mantissaMid (uint): Middle 32 bits of 80-bit dividend mantissa from stack+0x8  \n  exponentAndSign (ushort): Dividend exponent (bits 0-14) and sign (bit 15) from stack+0xc\n  divisorLow (uint): Low 32 bits of divisor mantissa from stack+0x10\n  divisorExponentAndSign (uint): Divisor exponent+sign with NaN flag (bit 31) from stack+0x14\n  controlWord (uint): Current x87 FPU control word state from stack+0x18\n\nReturns:\n  uint: Result status/exponent value:\n    - 0x0000: Zero result (dividend was zero)\n    - 0x7fff: Infinity result (division by zero with normal dividend)\n    - 0x0001-0x7ffe: Valid normalized result exponent  \n    - High bit set: Special condition or NaN propagation\n\nSpecial Cases:\n  - Zero dividend: Returns 0x0 immediately without FPU operations\n  - Zero divisor with normal dividend: Returns 0x7fff (positive/negative infinity)\n  - Denormal operands: Scaled by 2^67 constant to bring into normal range\n  - NaN operands: Detected via divisor bit 31, propagated through result\n  - Rounding mode override: Temporarily sets FPU to truncate mode (bits 10-11 = 11)\n\nMagic Numbers Reference:\n  0x6f9c59c0: Special value lookup table for denormal/infinity cases\n  0x6f9c59d8: 2^67 scaling constant for magnitude normalization  \n  0xe000000: Exponent bias mask for detecting special values\n  0x7fff: Maximum exponent value indicating infinity/NaN\n  0x33f: FPU control word OR mask to set truncate rounding\n  0xf3ff: FPU control word AND mask to clear existing rounding bits\n\nError Handling:\n  - Invalid operands detected through exponent field validation\n  - NaN propagation handled by checking divisor bit 31 status\n  - Division by zero produces infinity result (0x7fff) not exception\n  - Denormal underflow prevented by 2^67 prescaling operation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:35a926809c02214f1c021da8fe53c5e6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "35a926809c02214f1c021da8fe53c5e6",
        "CFG": "1a3388253df0a960af50e45b8ff4dc92",
        "PRO": "300be42ef56768e549e94c0165d887a4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "35a926809c02214f1c021da8fe53c5e6"
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "D2sound_MNE_e1ee6679146d": {
      "addresses": {
        "LoD/PD2": "0x6F9BA057"
      },
      "rvas": {
        "LoD/PD2": "0xA057"
      },
      "sizes": {
        "LoD/PD2": 1183
      },
      "name": "DispatchX87FloatingPointOperation",
      "signature": "float10 DispatchX87FloatingPointOperation(float10 * __return_storage_ptr__)",
      "calling_convention": "__stdcall",
      "comment": "Dispatches x87 floating-point unit (FPU) operations based on opcode selector.\n\nAlgorithm:\n1. Extract and mask opcode selector from EAX register to 6-bit range (0x3F = 64 operations)\n2. Decompose all FPU stack registers (ST0-ST7) into component parts:\n   - Low 32-bit mantissa portion (bits 0-31)\n   - Mid 32-bit mantissa portion (bits 32-63)  \n   - High 16-bit exponent and sign (bits 64-79)\n3. Use masked opcode as switch case selector for operation dispatch\n4. For simple operations (cases 0x0, 0x2, 0x4, 0x6): Return invalid result (division by zero NaN)\n5. For pass-through operations (cases 0x5, 0x7): Return ST1 value unmodified\n6. For dynamic operations (odd cases 0x1, 0x3, 0x9, 0xB, etc.): Execute SWI(6) interrupt to load fresh FPU values\n7. For computational operations (most even cases 0x8+): Call X87FloatingPointDivideWithRounding with decomposed operands\n8. Return result as 80-bit extended precision float10 value\n\nParameters:\n  __return_storage_ptr__ (float10 *): Storage location for return value (stdcall convention)\n  IMPLICIT opcodeSelector (EAX): Operation selector masked to 0x3F range (0-63)\n  IMPLICIT fpuStack0-7 (ST0-ST7): Eight 80-bit extended precision FPU stack registers\n\nReturns:\n  float10 *: Pointer to result of floating-point operation\n  - Cases 0x0, 0x2, 0x4, 0x6: Invalid/NaN result from division by zero\n  - Cases 0x5, 0x7: ST1 value passed through unchanged\n  - Most other cases: Result from X87FloatingPointDivideWithRounding helper\n\nSpecial Cases:\n  - Operation selector automatically masked to 0x3F to prevent buffer overflow\n  - SWI(6) interrupt used in odd-numbered cases to refresh FPU stack state\n  - FPU values decomposed into integer components to pass through standard ABI\n  - CONCAT22 macro reconstructs 48-bit value from 16-bit and 32-bit parts\n  - Some cases use fall-through behavior to skip intermediate processing steps\n\nMagic Numbers Reference:\n  0x3F (63): Maximum operation selector mask - ensures 64 operation limit\n  0x20 (32): Bit shift for extracting mid 32-bit mantissa portion\n  0x40 (64): Bit shift for extracting high 16-bit exponent and sign\n  SWI(6): Software interrupt 6 - likely FPU context refresh or stack reload\n\nError Handling:\n  - Invalid opcodes masked to valid range to prevent crashes\n  - Division by zero cases return NaN instead of throwing exceptions\n  - No explicit error codes - errors returned as IEEE 754 special values",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e1ee6679146d52a0e385275fed0f7c10",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e1ee6679146d52a0e385275fed0f7c10",
        "CFG": "b9511acf21e58204725cef99cec38995",
        "PRO": "f15a95e3051cb6d335ff7de586643ba2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e1ee6679146d52a0e385275fed0f7c10"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_0e6c60682690": {
      "addresses": {
        "LoD/PD2": "0x6F9BA4F6"
      },
      "rvas": {
        "LoD/PD2": "0xA4F6"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "__fdivp_sti_st",
      "signature": "undefined __fdivp_sti_st(void)",
      "calling_convention": "__stdcall",
      "comment": "x87 FPU extended precision floating point division with rounding wrapper\n\nAlgorithm:\n1. Extract 10-byte extended precision operands from FPU stack registers ST0 and ST1\n2. Decompose each 80-bit operand into 32-bit low, 32-bit high, and 16-bit exponent parts\n3. Extract stack parameter for rounding control from stack offset -0x16\n4. Call X87FloatingPointDivideWithRounding with decomposed operands and rounding mode\n5. Return with result stored in FPU registers\n\nParameters:\nIMPLICIT ldInST0 (ST0): First extended precision operand (dividend) in FPU register ST0\nIMPLICIT ldInST1 (ST1): Second extended precision operand (divisor) in FPU register ST1\nIMPLICIT wStackParam (stack -0x16): Rounding control parameter from stack\n\nReturns:\nIMPLICIT: Division result in FPU registers via X87FloatingPointDivideWithRounding\n\nSpecial Cases:\nThis is a compiler runtime library function for x87 FPU division with Pentium FDIV bug workaround.\nUses stack storage areas for intermediate 80-bit operand manipulation.\nStack offset 0xFFFFFEA (-0x16) contains rounding mode control bits.\n\nStructure Layout:\nExtended Precision Float (10 bytes):\nOffset  Size  Field Name    Type    Description\n0x00    4     dwMantissaLow uint    Lower 32 bits of mantissa  \n0x04    4     dwMantissaHigh uint   Upper 32 bits of mantissa\n0x08    2     wExponent     ushort  Sign bit + 15-bit exponent",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0e6c60682690c227c51e43c33045f40b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0e6c60682690c227c51e43c33045f40b",
        "CFG": null,
        "PRO": "5e3d6b547736cbf79162cdb201a0ed7d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0e6c60682690c227c51e43c33045f40b"
      }
    },
    "D2sound_ADDR_6F9BA509": {
      "addresses": {
        "LoD/PD2": "0x6F9BA509"
      },
      "rvas": {
        "LoD/PD2": "0xA509"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "__fdivrp_sti_st",
      "signature": "void __fdivrp_sti_st(void)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void __fdivrp_sti_st(void)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0e6c60682690c227c51e43c33045f40b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0e6c60682690c227c51e43c33045f40b",
        "CFG": null,
        "PRO": "52ce292337931b43073afd0536484568"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0e6c60682690c227c51e43c33045f40b"
      }
    },
    "D2sound_MNE_fa9a30d8df14": {
      "addresses": {
        "LoD/PD2": "0x6F9BA51C"
      },
      "rvas": {
        "LoD/PD2": "0xA51C"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "__adj_fdiv_m32",
      "signature": "uint __adj_fdiv_m32(uint dwFloatBits)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: uint __adj_fdiv_m32(uint dwFloatBits)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fa9a30d8df145c43da3992fb15aef931",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fa9a30d8df145c43da3992fb15aef931",
        "CFG": "19b5aac2d60824e43b0a3ed47c9722dc",
        "PRO": "bf5ac01cb789fcf613241922fae2d14f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fa9a30d8df145c43da3992fb15aef931"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9BA568": {
      "addresses": {
        "LoD/PD2": "0x6F9BA568"
      },
      "rvas": {
        "LoD/PD2": "0xA568"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "DivideDoubleWithExceptionHandling",
      "signature": "double DivideDoubleWithExceptionHandling(double dividend, double divisor)",
      "calling_convention": "__stdcall",
      "comment": "Performs floating-point division with special case handling for NaN/infinity and FPU exceptions.\n\nAlgorithm:\n1. Extract exponent bits from divisor using mask 0x7ff00000\n2. Compare exponent to 0x7ff00000 (indicates NaN or infinity)\n3. If divisor is special value (NaN/infinity), perform direct FDIV and return result\n4. If divisor is normal, read FPU status word using FNSTSW\n5. Check FPU exception flags using mask 0x3800 (invalid operation, denormalized, etc.)\n6. If FPU has exceptions set, load dividend from stack, call exception handler at 0x6f9ba4f6\n7. If FPU clean, exchange ST0/ST1, allocate 12-byte stack buffer\n8. Store ST0 (divisor) as extended double to buffer, load dividend from stack\n9. Call exception handler at 0x6f9ba4f6 with dividend on FPU stack\n10. Load extended result from buffer, exchange with divisor, deallocate buffer\n11. Return result in ST0 via __stdcall (caller cleans 8 bytes of parameters)\n\nParameters:\n  dividend (double, [ESP+0x8]): First operand for division\n  divisor (double, [ESP+0xc]): Second operand for division\n\nReturns:\n  ST0 (double): Result of dividend / divisor, or NaN/infinity if divisor is special\n\nSpecial Cases:\n  - Divisor is NaN or infinity (exponent 0x7ff): returns NaN or infinity directly\n  - FPU exception flags set (mask 0x3800): calls exception handler for error recovery\n  - Normal division: exception handler ensures proper result even with denormalized inputs\n\nNote: Function uses 1 stack-allocated temporary variable (local_10 - 12-byte extended precision buffer) optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fa9a30d8df145c43da3992fb15aef931",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fa9a30d8df145c43da3992fb15aef931",
        "CFG": "9507edb72158a2a748bebdf37e4cfd3c",
        "PRO": "230b19190121aa2fdec58f20825c2037"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fa9a30d8df145c43da3992fb15aef931"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_269b7d5856cd": {
      "addresses": {
        "LoD/PD2": "0x6F9BA61C"
      },
      "rvas": {
        "LoD/PD2": "0xA61C"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "__adj_fdivr_m32",
      "signature": "undefined4 __adj_fdivr_m32(uint param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __adj_fdivr_m32\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release, Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:269b7d5856cdb9005a57b4cc52158551",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "269b7d5856cdb9005a57b4cc52158551",
        "CFG": "19b5aac2d60824e43b0a3ed47c9722dc",
        "PRO": "bf5ac01cb789fcf613241922fae2d14f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "269b7d5856cdb9005a57b4cc52158551"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_ADDR_6F9BA668": {
      "addresses": {
        "LoD/PD2": "0x6F9BA668"
      },
      "rvas": {
        "LoD/PD2": "0xA668"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "__adj_fdivr_m64",
      "signature": "uint __adj_fdivr_m64(double * pdDoubleValue, uint dwHighOrder)",
      "calling_convention": "__stdcall",
      "comment": "Adjusts floating-point division for 64-bit double precision values with special case handling.\n\nAlgorithm:\n1. Check if input value is infinity or NaN by testing exponent bits (0x7ff00000 mask)\n2. If special value detected, return immediately with EAX register value\n3. Check FPU status word for exception conditions (0x3800 mask for precision, underflow, overflow)\n4. If FPU exceptions detected, call __fdivrp_sti_st to handle division with pop\n5. If no exceptions, perform normal division via __fdivrp_sti_st\n6. Return result in EAX register\n\nParameters:\n- pdDoubleValue: Pointer to 64-bit double precision floating point dividend\n- dwHighOrder: High-order 32 bits of double precision divisor for special value detection\n\nReturns:\n- uint: Status code or adjusted result value in EAX\n- Returns immediately if input is infinity/NaN (0x7ff00000 in exponent)\n- Returns after FPU division adjustment for normal values\n\nSpecial Cases:\n- 0x7ff00000: IEEE 754 double precision infinity/NaN exponent pattern\n- 0x3800: FPU status word mask for precision, underflow, overflow exceptions\n- Handles both exceptional and normal division cases through unified __fdivrp_sti_st call\n\nMagic Numbers Reference:\n- 0x7ff00000: IEEE 754 double precision exponent mask for special values (infinity/NaN)\n- 0x3800: FPU status word exception mask (bits 11,12,13 for precision/underflow/overflow)\n\nError Handling:\n- Early return on infinity/NaN detection prevents invalid FPU operations\n- FPU status checking ensures proper exception handling during division\n- Unified division routine handles both normal and exceptional cases",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:269b7d5856cdb9005a57b4cc52158551",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "269b7d5856cdb9005a57b4cc52158551",
        "CFG": "19b5aac2d60824e43b0a3ed47c9722dc",
        "PRO": "230b19190121aa2fdec58f20825c2037"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "269b7d5856cdb9005a57b4cc52158551"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_d9fc9881c66f": {
      "addresses": {
        "LoD/PD2": "0x6F9BA731"
      },
      "rvas": {
        "LoD/PD2": "0xA731"
      },
      "sizes": {
        "LoD/PD2": 21
      },
      "name": "DivideX87Extended",
      "signature": "uint DivideX87Extended(void)",
      "calling_convention": "__stdcall",
      "comment": "x87 Extended-Precision Floating-Point Division Wrapper\n\nThis function marshals x87 FPU register arguments to stack arguments for the actual division implementation. It accepts two 80-bit extended precision values on the FPU stack (ST0 and ST1) and delegates to X87FloatingPointDivideWithRounding.\n\nAlgorithm:\n1. Preserve return value location by pushing EAX\n2. Allocate 44 bytes (0x2c) of stack space for argument marshaling\n3. Store ST1 (divisor) to stack offset [ESP + 0xc]\n4. Store ST0 (dividend) to stack offset [ESP]\n5. Call X87FloatingPointDivideWithRounding with all arguments on stack\n6. Clean up stack allocation (0x2c bytes)\n7. Restore EAX and return to caller\n\nParameters:\n- ST1 (implicit): Extended-precision floating-point divisor (80-bit)\n- ST0 (implicit): Extended-precision floating-point dividend (80-bit)\n\nReturns:\n- EAX: Result from X87FloatingPointDivideWithRounding (typically quotient or status code)\n- x87 FPU stack: May contain result in ST0 depending on callee implementation\n\nCalling Convention:\n- __stdcall: Callee cleans stack (implicit in RET instruction)\n\nSpecial Cases:\n- Division by zero handling delegated to X87FloatingPointDivideWithRounding\n- Stack arguments passed as complete 10-byte extended values\n- Return value preserved in EAX across stack cleanup",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d9fc9881c66fc4db9c90a259ff286a44",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d9fc9881c66fc4db9c90a259ff286a44",
        "CFG": null,
        "PRO": "4174b02bd8ca39f9fb30e0a24a42e84d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d9fc9881c66fc4db9c90a259ff286a44"
      }
    },
    "D2sound_MNE_c70484661a7b": {
      "addresses": {
        "LoD/PD2": "0x6F9BA746"
      },
      "rvas": {
        "LoD/PD2": "0xA746"
      },
      "sizes": {
        "LoD/PD2": 518
      },
      "name": "ComputeExtendedFloatRemainder",
      "signature": "float10 ComputeExtendedFloatRemainder(float10 * __return_storage_ptr__, uint dividend_low, uint dividend_high, ushort dividend_control)",
      "calling_convention": "__cdecl",
      "comment": "Computes remainder of extended-precision floating-point division using FPREM with iterative reduction.\n\nAlgorithm:\n1. Validate input parameters: checks IEEE 754 extended format bits and special values\n2. Extract exponent fields and check validity against lookup table\n3. Validate dividend and divisor exponents are not max values (infinity/NaN detection)\n4. Verify parameter format bits match expected pattern (bits 11-8 and 1-0 of param_2)\n5. Check divisor and dividend are not subnormal (zero significand check)\n6. Compute exponent difference to determine reduction strategy\n7. If exponent_diff >= 0x3f: use iterative subtraction with scaling (FVar3 *= 2^-32)\n8. Otherwise: use direct FMOD with Euclidean reduction loop\n9. Loop reduces floating-point values while maintaining precision\n10. Apply FPU rounding mode and sign correction based on input flags\n11. Handle special rounding modes (bits 0-1 of param_2 control rounding)\n12. Store result in [ESP+0x28] and return\n\nParameters:\n- dividend_low: Low 32 bits of dividend mantissa\n- dividend_high: High 16 bits of dividend exponent/control (bits 15-0)\n- dividend_control: Additional control bits from original parameters\n- [ESP+0x10]: Divisor exponent/control (16-bit value)\n- [ESP+0x14]: Divisor low mantissa\n- [ESP+0x18]: Divisor high mantissa  \n- [ESP+0x1c]: Dividend low mantissa (another copy)\n- [ESP+0x20]: Divisor low mantissa (another copy)\n- [ESP+0x22]: Divisor high mantissa (another copy)\n- [ESP+0x24]: Divisor exponent/control (another copy)\n- [ESP+0x28]: Result storage (80-bit extended double)\n- [ESP+0x2c]: Additional parameter flags\n- [ESP+0x2e]: Additional parameter flags\n- [ESP+0x30]: Divisor exponent field with control bits\n\nReturns:\n- Floating-point remainder in FP0 (80-bit extended precision)\n- Result satisfies: dividend = quotient * divisor + remainder\n- Remainder has same sign as dividend\n- Result stored in [ESP+0x28]\n\nSpecial Cases:\n- Handles infinity/NaN detection via exponent checks (0x7fff sentinel)\n- Supports multiple rounding modes via FPU control word manipulation\n- Uses reduction loop with scaling factor 2^-32 for large exponent differences\n- Implements Euclidean algorithm variant with FPREM instruction\n- Magic values: 0x700 (format mask), 0x7fff (max exponent), 0x3f (63), 0x8000 (sign bit)\n\nStructure Layout:\nFloating-Point Value Format (Extended Precision - 80 bits):\n  Offset | Size | Field Name        | Type    | Description\n  ------ | ---- | ------ -------- | ------- | --------- ---\n  0x00   | 4    | mantissa_low      | uint32  | Low 32 bits of mantissa\n  0x04   | 2    | mantissa_high     | uint16  | High 16 bits of mantissa\n  0x06   | 2    | exponent_control  | uint16  | Exponent (bits 14-0), sign (bit 15)\nTotal: 10 bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c70484661a7b6b9a5f1519c92e672da0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c70484661a7b6b9a5f1519c92e672da0",
        "CFG": "aac193f62447e0149063d8cbfe725891",
        "PRO": "a69a7d0355f70bc5a84a52904bc4615c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c70484661a7b6b9a5f1519c92e672da0"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_ba64e7d70c2b": {
      "addresses": {
        "LoD/PD2": "0x6F9BA94C"
      },
      "rvas": {
        "LoD/PD2": "0xA94C"
      },
      "sizes": {
        "LoD/PD2": 178
      },
      "name": "FloatModulo",
      "signature": "float10 FloatModulo(float10 * __return_storage_ptr__, float10 dividend, float10 divisor)",
      "calling_convention": "__stdcall",
      "comment": "Computes the floating-point modulo (remainder) of two extended doubles using x87 FPU.\n\nAlgorithm:\n1. Check if divisor has special exponent (0x7fff - denormalized, infinity, or NaN)\n2. If special, call FUN_6f9ba746 for special case handling\n3. Otherwise, check if dividend or divisor exponent is nonzero\n4. If nonzero exponent:\n   a. Multiply divisor by scaling factor at 0x6f9c59f4 for underflow prevention\n   b. Set FPU control word with rounding mode 0x33f for consistent truncation\n   c. Call FUN_6f9ba746 with adjusted divisor components\n5. If both exponents zero (denormalized case):\n   a. Set FPU control word with rounding mode 0x300\n   b. Multiply divisor by scaling factor\n   c. Call FUN_6f9ba746 with scaled divisor\n6. Restore FPU control word and return result\n\nParameters:\n- dividend (ST0): The numerator value (extended double)\n- divisor (ST1): The denominator value (extended double)\n\nReturns:\n- Extended double result in ST0 containing dividend modulo divisor\n- Result is computed as: dividend - (dividend/divisor) * divisor\n\nSpecial Cases:\n- Divisor exponent == 0x7fff: abnormal/denormalized divisor, handled via FUN_6f9ba746\n- Divisor == 0: will produce infinity or NaN (IEEE 754 behavior)\n- Either exponent == 0: both are denormalized, scaling applied with 0x6f9c59f4\n- FPU control word modified for rounding: 0x33f (round-to-zero), 0x300 (round-to-nearest)\n\nStructure Layout:\nStack offset layout (after PUSH EDX, SUB ESP,0x30):\n- [ESP+0x00-0x09]: Dividend extended double storage (local_28)\n- [ESP+0x0c-0x17]: Modulo result temp storage (local_1c)\n- [ESP+0x18-0x1f]: Reserved workspace\n- [ESP+0x20-0x21]: Original exponent field\n- [ESP+0x24-0x25]: FPU control word save (local_c)\n- [ESP+0x28-0x29]: FPU control word temp (local_34)\n- [ESP+0x30]: Stack frame boundary (total 48 bytes)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ba64e7d70c2bcd8b3838963a89363cf4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ba64e7d70c2bcd8b3838963a89363cf4",
        "CFG": "d048fe12ac70ddbdf57720d2e0dd8b92",
        "PRO": "17312f85a67e8a2854c6ee6d1fff66ea"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ba64e7d70c2bcd8b3838963a89363cf4"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_e28850ae7dbb": {
      "addresses": {
        "LoD/PD2": "0x6F9BA9FE"
      },
      "rvas": {
        "LoD/PD2": "0xA9FE"
      },
      "sizes": {
        "LoD/PD2": 518
      },
      "name": "ComputeExtendedRemainder_Impl",
      "signature": "longdouble ComputeExtendedRemainder_Impl(longdouble dividend, longdouble divisor)",
      "calling_convention": "__cdecl",
      "comment": "Computes the extended-precision floating-point remainder of dividend/divisor using FPREM1\ninstruction with scaling and iterative reduction for accuracy.\n\nAlgorithm:\n1. Validate input parameters: check for zero exponent XOR values, verify non-NaN inputs, ensure\ndivisor exponent in valid range\n2. Check if divisor is larger than dividend: if so, use fast path with single FPREM1, else use\niterative path\n3. Fast path (large divisor): compute scaled remainder by adjusting dividend exponent upward\nwhile preserving sign bit\n4. Iterative path: perform series of remainder operations with loop count based on exponent\ndifference to progressively reduce dividend\n5. Extract actual remainder and apply sign correction based on original dividend sign\n6. Handle rounding mode setup for FPREM1 (rounds to nearest, ties to even)\n7. Apply IEEE 754 sign bit handling: if dividend was negative, apply sign negation to result\n\nParameters:\ndividend - Extended-precision floating-point dividend (passed on FPU stack or memory)\ndivisor - Extended-precision floating-point divisor (passed on FPU stack or memory)\n\nReturns:\nLong double remainder value (dividend - floor(dividend/divisor) * divisor) with proper sign\n\nSpecial Cases:\n- Uses IEEE 754 compliant remainder computation via FPREM1 instruction\n- Handles extended precision (80-bit) floating point values with proper mantissa scaling\n- 0x700 magic number: XOR mask for exponent validation checks\n- 0x7800 mask: Extracts exponent bits from dividend for NaN table lookup\n- 0x7fff mask: Extracts 15-bit exponent field from IEEE 754 extended precision format\n- 0x3f constant: Used in exponent difference calculation for scaling factor\n- 0x20 constant: Minimum loop iteration count for iterative reduction\n- DAT_6f9c59dc: NaN classification lookup table for dividend validation\n- DAT_6f9c5a0c: Scaling constant (likely 0.5 or 2.0) for mantissa adjustment\n- DAT_6f9c59fc: Sign correction multiplier for negative results\n\nNote: Function uses 2 stack-allocated temporary variables (local_24, local_28) optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e28850ae7dbb08bbb7fa3d1ca4ff2803",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e28850ae7dbb08bbb7fa3d1ca4ff2803",
        "CFG": "fa4f6b901d2c4b42a9cd8692b2f1a3c1",
        "PRO": "a69a7d0355f70bc5a84a52904bc4615c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e28850ae7dbb08bbb7fa3d1ca4ff2803"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_15fd41782864": {
      "addresses": {
        "LoD/PD2": "0x6F9BAC04"
      },
      "rvas": {
        "LoD/PD2": "0xAC04"
      },
      "sizes": {
        "LoD/PD2": 181
      },
      "name": "ComputeExtendedRemainder",
      "signature": "float10 ComputeExtendedRemainder(float10 * __return_storage_ptr__)",
      "calling_convention": "__stdcall",
      "comment": "Computes the remainder of two extended-precision floating-point numbers.\n\nAlgorithm:\n1. Extract exponent from divisor (input in ST1) to determine special cases\n2. Check for zero exponent (denormalized/zero divisor) - JZ to check_mantissa\n3. Check mantissa bits of dividend (ST0) - if both dwords are zero, perform FPREM\n4. For non-zero remainder cases:\n   a. Fetch dividend and divisor from stack into FP registers\n   b. Check if divisor mantissa is zero - JZ to fprem_result\n   c. Set FPU rounding mode to nearest (0x33f mask) for accurate calculation\n   d. Compare exponent (masked to 15 bits) against 0x7fbe threshold\n   e. If exponent <= 0x7fbe (small exponent): Multiply by scaling constant\n   f. If exponent > 0x7fbe (large exponent): Set rounding to truncate (0x300)\n   g. Store modified values back to stack\n5. Restore original FPU control word\n6. Call FUN_6f9ba9fe to perform actual remainder computation\n7. Return result in ST0\n\nParameters:\nInput: ST0 = dividend (extended-precision float)\n       ST1 = divisor (extended-precision float)\n\nReturns:\nST0 = remainder of dividend modulo divisor\n      Special handling for denormalized/zero values\n\nSpecial Cases:\n- Zero divisor exponent (denormalized): Early return from check_mantissa\n- Zero dividend mantissa: FPREM instruction path (fprem_result)\n- Large exponent (>0x7fbe): Rounding truncation to prevent overflow\n- Small exponent (<=0x7fbe): Scaling factor multiplication (0x6f9c59f4)\n\nFPU Control Word Management:\n- Original control word saved at [ESP + 0x24]\n- Modified control word created for rounding mode changes at [ESP + 0x28]\n- Rounding mode mask 0x33f = round-to-nearest (bits 10-11 = 11)\n- Rounding mode mask 0x300 = round-toward-zero (bits 10-11 = 00)\n- Control word restored before calling helper function",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:15fd41782864ffd4b958e0ed4ed4dea9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "15fd41782864ffd4b958e0ed4ed4dea9",
        "CFG": "1acfc7f97d08d10f8d33e74e1c437d1e",
        "PRO": "47d977a1d49e34cbda811ff40c8e1a77"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "15fd41782864ffd4b958e0ed4ed4dea9"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_0be5866c35ab": {
      "addresses": {
        "LoD/PD2": "0x6F9BACCC"
      },
      "rvas": {
        "LoD/PD2": "0xACCC"
      },
      "sizes": {
        "LoD/PD2": 117
      },
      "name": "RoundFloatToInt64",
      "signature": "longlong RoundFloatToInt64(void)",
      "calling_convention": "__stdcall",
      "comment": "Rounds a long double floating-point value to a 64-bit signed integer using IEEE 754 semantics.\n\nThe function receives a long double in ST0 and performs proper rounding by:\n1) Converting to integer via FISTP (Floating-point Integer Store and Pop)\n2) Subtracting the rounded integer from original value to get remainder\n3) Comparing remainder magnitude (0x80000000) to determine rounding direction\n4) Adjusting the integer result based on remainder and sign using carry propagation\n\nAlgorithm:\n1) Load input long double value in ST0 and duplicate\n2) Store float copy for sign checking, integer-convert and store in qword\n3) Reload integer as float10 for remainder calculation\n4) Test if low 32-bits of integer result is zero\n5) If zero and high 32-bits have magnitude bits set, compute remainder\n6) For negative remainders: use XOR 0x80000000 + ADD 0x7fffffff for carry propagation\n7) For positive remainders: use ADD 0x7fffffff + SBB 0x00000000 for borrow propagation\n8) Adjust high 32-bits with carry/borrow from low 32-bits\n9) Return 64-bit result in EDX:EAX\n\nReturns:\n  EDX:EAX - 64-bit signed integer result (properly rounded)\n  \nSpecial Cases:\n  - Zero input: Returns 0x0000000000000000\n  - Small values (|x| < 1.0): Rounds to 0 or \u00b11 based on sign and magnitude\n  - Large values: Correctly handles carry propagation across 32-bit boundary\n  - Magic value 0x7fffffff: Threshold for detecting rounding (half ULP detection)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0be5866c35abc0fb59235d2363df563a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0be5866c35abc0fb59235d2363df563a",
        "CFG": "fbc4d97448b0d304e481d5d0a17a30e7",
        "PRO": "f006c300992eb020d9c256bc3fdb393b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0be5866c35abc0fb59235d2363df563a"
      }
    },
    "D2sound_MNE_7ee678edebf0": {
      "addresses": {
        "LoD/PD2": "0x6F9BAD41"
      },
      "rvas": {
        "LoD/PD2": "0xAD41"
      },
      "sizes": {
        "LoD/PD2": 60
      },
      "name": "__forcdecpt",
      "signature": "void __forcdecpt(char * _Buf)",
      "calling_convention": "__cdecl",
      "comment": "Forces decimal point character insertion in numeric string buffer.\n\nAlgorithm:\n1. Locate end of numeric string by scanning for 'e'/'E' (exponential notation) or non-digit\n2. Insert decimal point character at located position\n3. Shift remaining characters one position right to accommodate decimal point\n4. Null-terminate the modified string\n\nParameters:\n_Buf (char *): Buffer containing numeric string to modify, must be mutable with space for one additional character\n\nReturns:\nvoid: Function modifies buffer in-place, no return value\n\nSpecial Cases:\n- Function assumes buffer has sufficient space for one additional character\n- Stops at first 'e' or 'E' character (exponential notation delimiter)\n- Stops at first non-digit character\n- DAT_6f9c57d4 contains the decimal point character to insert\n\nMagic Numbers Reference:\n0x65: ASCII 'e' in lowercase (decimal 101) - exponential notation marker",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7ee678edebf04632b65afdb541cebe3a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7ee678edebf04632b65afdb541cebe3a",
        "CFG": "eedaec691a4b94e5a795ce955c5fac49",
        "PRO": "b2674a8ef7b84fc742ebdb7ed6679b4e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7ee678edebf04632b65afdb541cebe3a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_ce3e17d01f8a": {
      "addresses": {
        "LoD/PD2": "0x6F9BADE2"
      },
      "rvas": {
        "LoD/PD2": "0xADE2"
      },
      "sizes": {
        "LoD/PD2": 62
      },
      "name": "__fassign",
      "signature": "void __fassign(int flag, char * argument, char * number)",
      "calling_convention": "__cdecl",
      "comment": "Convert string to floating-point format and assign to target buffer.\n\nAlgorithm:\n1. Check flag parameter to determine conversion precision\n2. If flag != 0: Use ConvertStringToExtendedDouble for 10-byte extended precision\n3. If flag == 0: Use ConvertStringToDouble for 8-byte standard precision\n4. Copy converted bytes to target buffer using pointer arithmetic\n5. Return void (no error checking)\n\nParameters:\n- nFlag (int): Precision flag - 0 for double (8-byte), non-zero for extended (10-byte)\n- lpTargetBuffer (char *): Destination buffer to receive converted floating-point bytes\n- lpszSourceString (char *): Source string containing floating-point representation\n\nReturns:\n- void: No return value or error indication\n\nSpecial Cases:\n- No validation performed on input parameters\n- Buffer overflow possible if target buffer insufficient size\n- Invalid string format handling delegated to conversion functions\n\nNote: Function uses 2 stack-allocated temporary variables optimized away by decompiler (local_8, local_c phantom variables visible only in assembly view).",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ce3e17d01f8a4102c772a8dc6bdc555d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ce3e17d01f8a4102c772a8dc6bdc555d",
        "CFG": "ad60745e7a538a03b6fca85abc2d64ca",
        "PRO": "a9f2908cd858fee16e0500c0e527d630"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ce3e17d01f8a4102c772a8dc6bdc555d"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_80bedbb0a206": {
      "addresses": {
        "LoD/PD2": "0x6F9BAE20"
      },
      "rvas": {
        "LoD/PD2": "0xAE20"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "__shift",
      "signature": "void __shift(void)",
      "calling_convention": "__stdcall",
      "comment": "Shifts characters in a string buffer by inserting spaces at the beginning.\n\nAlgorithm:\n1. Check if shift amount is non-zero\n2. If shift amount is 0, return immediately (no operation needed)\n3. Calculate length of existing string using strlen\n4. Move entire string contents (including null terminator) forward by shift amount\n5. This creates space at the beginning of the buffer for new characters\n\nParameters:\n- IMPLICIT EAX (lpszBuffer): Pointer to null-terminated string buffer\n- IMPLICIT EDI (nShiftAmount): Number of positions to shift string forward\n\nReturns:\n- void: Function modifies buffer in-place\n\nSpecial Cases:\n- If shift amount is 0, function returns immediately without modification\n- Buffer must have sufficient space to accommodate shifted string\n- Overlapping memory regions handled correctly by memmove\n\nMagic Numbers Reference:\n- +1: Include null terminator in memmove operation\n\nError Handling:\n- No explicit error handling - assumes valid buffer pointer and sufficient space\n- Relies on memmove for safe overlapping memory copy",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:80bedbb0a206021561883be0c11d6af7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "80bedbb0a206021561883be0c11d6af7",
        "CFG": "e4d929dcade813bcfed0f23f20c25712",
        "PRO": "7486603bcf02da672eaf7f0d4e702110"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "80bedbb0a206021561883be0c11d6af7"
      }
    },
    "D2sound_STR_16032f476aba": {
      "addresses": {
        "LoD/PD2": "0x6F9BAE3D"
      },
      "rvas": {
        "LoD/PD2": "0xAE3D"
      },
      "sizes": {
        "LoD/PD2": 174
      },
      "name": "__cftoe2",
      "signature": "void __cftoe2(int nPrecision, int nFlags, char chFormat)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void __cftoe2(int nPrecision, int nFlags, char chFormat)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:16032f476aba0e42e163f0f1660d4b55",
      "indexes": {
        "EXP": null,
        "STR": "16032f476aba0e42e163f0f1660d4b55",
        "API": null,
        "MNE": "968971b61fab7a3d5eab169ac4db17ac",
        "CFG": "c5b39aa30eb73d7ab6487045fd767833",
        "PRO": "30bc0e315b6e570515faf5a2d170d3c6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "968971b61fab7a3d5eab169ac4db17ac"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_6426717c049f": {
      "addresses": {
        "LoD/PD2": "0x6F9BAEEB"
      },
      "rvas": {
        "LoD/PD2": "0xAEEB"
      },
      "sizes": {
        "LoD/PD2": 112
      },
      "name": "FormatDoubleToString",
      "signature": "void FormatDoubleToString(double * pDouble, int bufferOffset, int precision, int formatType)",
      "calling_convention": "__cdecl",
      "comment": "Formats a double-precision floating-point number into a string buffer.\n\nAlgorithm:\n1. Initialize stack canary by XORing global canary value with frame pointer for corruption detection\n2. Extract source double pointer from parameter 1\n3. Call ConvertDoubleForStringFormat to decompose the double into sign, exponent, and mantissa components, storing results in local buffers\n4. Load precision parameter (param_3) which controls decimal place formatting\n5. Calculate output buffer position by adding param_2 (base offset) to conditional offsets: +1 if precision > 0, +1 if result is negative\n6. Call __fptostr to format the decomposed double components into an ASCII string at calculated buffer position\n7. Call __cftoe2 with precision and format flags to apply final exponential/scientific notation conversion if needed\n8. Restore and verify stack canary before function return to detect buffer overflows\n\nParameters:\n- pDouble: Pointer to source double value to be formatted\n- bufferOffset: Base offset into output buffer where formatted string begins\n- precision: Number of decimal places/significant digits to format\n- formatType: Format specification flags (exponential, fixed-point, etc.)\n\nReturns:\nvoid - Formatted string is written directly to memory at calculated buffer address\n\nSpecial Cases:\n- Stack canary XOR uses frame pointer for address-dependent randomization\n- Negative numbers trigger automatic buffer position adjustment by 1\n- Precision parameter value compared against 0; positive precision adds offset\n- Final formatting delegated to __cftoe2 for exponential notation handling",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6426717c049ff49b2b81b64802cbd366",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6426717c049ff49b2b81b64802cbd366",
        "CFG": "235509b36354db546ac99e5f88e8d245",
        "PRO": "877799b56e30bfba8b144c8c24c6b83c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6426717c049ff49b2b81b64802cbd366"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_21ec1ce544b5": {
      "addresses": {
        "LoD/PD2": "0x6F9BAF5B"
      },
      "rvas": {
        "LoD/PD2": "0xAF5B"
      },
      "sizes": {
        "LoD/PD2": 156
      },
      "name": "__cftof2",
      "signature": "char * __cftof2(char * lpszBuffer, size_t nPrecision, char chFormatFlag)",
      "calling_convention": "__cdecl",
      "comment": "Convert floating point number to formatted string representation with precision control.\n\nAlgorithm:\n\n1. Extract exponent value from floating point data structure (in_EAX[1])\n2. Handle special case: if format flag set and exponent-1 equals precision, append '0' and null terminator\n3. Check sign bit (in_EAX[0] == 0x2d) and prepend minus sign if negative\n4. Position working pointer after sign character if present\n5. Handle integer part: if exponent < 1, shift and insert '0', else advance by exponent positions\n6. Handle decimal part: if precision > 0, insert decimal point character and process fractional digits\n7. For negative exponents, pad with zeros using memset if needed\n8. Return pointer to formatted string buffer\n\nParameters:\n\nlpszBuffer (char *): Output string buffer to receive formatted number\nnPrecision (size_t): Number of decimal places to format\nchFormatFlag (char): Format control flag, non-zero enables special rounding behavior\nIMPLICIT in_EAX (int *): Pointer to floating point data structure [sign, exponent, ...]\n\nReturns:\n\nchar *: Pointer to the formatted string buffer (same as lpszBuffer input)\n\nSpecial Cases:\n\nWhen chFormatFlag is non-zero and exponent-1 equals precision, appends '0' followed by null terminator\nFor negative exponents, zero-pads the fractional part up to precision digits\nSign character 0x2d (ASCII 45, '-') triggers negative number formatting\n\nMagic Numbers Reference:\n\n0x2d (45): ASCII minus sign character '-'\n0x30 (48): ASCII zero character '0'  \nDAT_6f9c57d4: Decimal point character (likely '.' or ',')\n\nError Handling:\n\nNo explicit error checking - assumes valid input parameters and sufficient buffer space\nRelies on caller to provide adequately sized output buffer\nFloating point data structure access assumes valid pointer in EAX register\n\nState Machine:\n\nState 1: Check format flag and append terminator if special case\nState 2: Process sign bit and position working pointer  \nState 3: Handle integer portion based on exponent value\nState 4: Insert decimal point if precision required\nState 5: Zero-pad fractional digits for negative exponents",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:21ec1ce544b50687ae2fb7f68cea8807",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "21ec1ce544b50687ae2fb7f68cea8807",
        "CFG": "9fa083bedf05c37fb363ad89f53f0377",
        "PRO": "617e74b1865b4753a5ac47ff6172c8fb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "21ec1ce544b50687ae2fb7f68cea8807"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_fd5b33dc54aa": {
      "addresses": {
        "LoD/PD2": "0x6F9BAFF7"
      },
      "rvas": {
        "LoD/PD2": "0xAFF7"
      },
      "sizes": {
        "LoD/PD2": 103
      },
      "name": "ConvertDoubleToStringBuffer",
      "signature": "void ConvertDoubleToStringBuffer(double * pDoubleValue, char * pOutputBuffer, size_t bufferSize)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void ConvertDoubleToStringBuffer(double * pDoubleValue, char * pOutputBuffer, size_t bufferSize)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fd5b33dc54aadb52ffc0a2fd4afb6504",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fd5b33dc54aadb52ffc0a2fd4afb6504",
        "CFG": "5a6a1bad4884a279605e3598d136f1d3",
        "PRO": "72272168e8bf943453339b0c021a1492"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fd5b33dc54aadb52ffc0a2fd4afb6504"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_03455c508a72": {
      "addresses": {
        "LoD/PD2": "0x6F9BB05E"
      },
      "rvas": {
        "LoD/PD2": "0xB05E"
      },
      "sizes": {
        "LoD/PD2": 159
      },
      "name": "FormatFloatingPointToString",
      "signature": "void FormatFloatingPointToString(double * pDoubleValue, char * pOutputBuffer, size_t bufferSize, int precision)",
      "calling_convention": "__cdecl",
      "comment": "Dispatches floating-point to string conversion with format mode selection based on precision constraints.\n\nAlgorithm:\n1. Load stack canary (0x6f9c56c0) and XOR with frame pointer for overflow detection\n2. Convert double value to internal STRFLT representation and extract exponent/sign\n3. Call ConvertDoubleForStringFormat() to analyze number properties\n4. Decrement exponent to adjust for single digit before decimal point\n5. Format initial string representation using __fptostr()\n6. Determine if result uses f-format or e-format:\n   - If exponent < -4 or exponent >= bufferSize: use e-format (scientific notation)\n   - Otherwise: use f-format (fixed-point notation)\n7. If using f-format: scan output string to null terminator and remove last char\n8. Call __cftof2() or __cftoe2() to finalize formatting based on selected mode\n9. Verify stack canary to detect buffer overflows\n10. Return to caller\n\nParameters:\n  pDoubleValue [double*]: Pointer to IEEE 754 double-precision value to convert\n  pOutputBuffer [char*]: Destination buffer for null-terminated output string\n  bufferSize [size_t]: Size of output buffer in bytes\n  precision [int]: Decimal precision (passed to formatting functions)\n\nReturns:\n  void (Result written to pOutputBuffer)\n\nSpecial Cases:\n  - Negative numbers: sign character (0x2d) included in output buffer offset calculation\n  - Precision validation: Exponent range [-4, bufferSize) determines format mode selection\n  - String scanning: Loop at 0x6f9bb0c1 walks buffer until null terminator found\n  - Boundary conditions: Both precision < -4 and precision >= bufferSize trigger e-format\n\nStructure Layout (local variables):\n  Offset Size Description\n  -0x04  4    Stack canary (XOR with frame pointer for verification)\n  -0x1c  24   Number info array [6 dwords] from ConvertDoubleForStringFormat()\n  -0x2c  4    Sign flag (0x2d if negative, 0x00 if positive)\n  -0x28  4    Exponent value (adjusted digit count)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:03455c508a72225478b465bc4da0dc85",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "03455c508a72225478b465bc4da0dc85",
        "CFG": "67f3f1f2dfbf8f1f142eb07aaeca410b",
        "PRO": "80af48a31f979afdd55f70ea273d67e5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "03455c508a72225478b465bc4da0dc85"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_f50494c5982a": {
      "addresses": {
        "LoD/PD2": "0x6F9BB0FD"
      },
      "rvas": {
        "LoD/PD2": "0xB0FD"
      },
      "sizes": {
        "LoD/PD2": 81
      },
      "name": "__cfltcvt",
      "signature": "errno_t __cfltcvt(double * arg, char * buffer, size_t sizeInBytes, int format, int precision, int caps)",
      "calling_convention": "__cdecl",
      "comment": "Convert floating-point value to string with format-specific handling\n\nAlgorithm:\n1. Validate input parameters and determine conversion format type\n2. Check sizeInBytes parameter for format type indication\n3. If sizeInBytes is 0x65 ('e') or 0x45 ('E') - use exponential notation\n   - Call FormatDoubleToString with exponential format\n   - Return error code from conversion\n4. If sizeInBytes is 0x66 ('f') - use fixed-point notation  \n   - Call ConvertDoubleToStringBuffer with fixed format\n   - Return error code from conversion\n5. Otherwise - use standard floating-point formatting\n   - Call FormatFloatingPointToString with general format\n   - Return error code from conversion\n\nParameters:\narg - double * - Pointer to double value to convert\nbuffer - char * - Output buffer for formatted string\nsizeInBytes - size_t - Buffer size and format indicator (0x65='e', 0x45='E', 0x66='f')\nformat - int - Formatting flags for conversion\nprecision - int - Decimal precision for output\ncaps - int - Case handling flag for exponential notation\n\nReturns:\nerrno_t - Error code from conversion operation\n  0 - Success\n  Non-zero - Conversion error from underlying format functions\n\nSpecial Cases:\nFormat type determination uses sizeInBytes as both buffer size and format indicator\nMagic numbers: 0x65 (ASCII 'e'), 0x45 (ASCII 'E'), 0x66 (ASCII 'f')\n\nError Handling:\nFunction delegates error handling to called conversion functions\nReturn codes propagated directly from FormatDoubleToString, ConvertDoubleToStringBuffer, FormatFloatingPointToString",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f50494c5982aa77d2240c41fce332436",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f50494c5982aa77d2240c41fce332436",
        "CFG": "0ba32f22434d5de97af5dabc5af8a9aa",
        "PRO": "01a513091671607b2f3ca269c59b4680"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f50494c5982aa77d2240c41fce332436"
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "D2sound_ADDR_6F9BB14E": {
      "addresses": {
        "LoD/PD2": "0x6F9BB14E"
      },
      "rvas": {
        "LoD/PD2": "0xB14E"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "__setdefaultprecision",
      "signature": "void __setdefaultprecision(void)",
      "calling_convention": "__stdcall",
      "comment": "Sets the default floating-point precision to 53-bit mantissa for double precision arithmetic.\n\nAlgorithm:\n1. Call __controlfp to configure floating-point control register\n2. Set precision control to 53-bit mantissa (PC_53) \n3. Apply precision mask to only modify precision bits\n4. Return without status checking\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nMagic Numbers Reference:\n0x10000 - PC_53 precision control flag (53-bit mantissa for double precision)\n0x30000 - _MCW_PC precision control mask (bits affecting precision control)\n\nSpecial Cases:\nFunction assumes __controlfp succeeds and performs no error checking.\nSets Visual Studio 2003 default precision for consistent floating-point behavior.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:301bd5440f60703ca7a24a8fb30f1e56",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "301bd5440f60703ca7a24a8fb30f1e56",
        "CFG": null,
        "PRO": "eaa5d7a2f93c31bc8cf63158f4c5e9cb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "301bd5440f60703ca7a24a8fb30f1e56"
      }
    },
    "D2sound_MNE_7ae8facd2848": {
      "addresses": {
        "LoD/PD2": "0x6F9BB160"
      },
      "rvas": {
        "LoD/PD2": "0xB160"
      },
      "sizes": {
        "LoD/PD2": 64
      },
      "name": "__ms_p5_test_fdiv",
      "signature": "undefined4 __ms_p5_test_fdiv(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __ms_p5_test_fdiv\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7ae8facd28484655a18ca60b688001a6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7ae8facd28484655a18ca60b688001a6",
        "CFG": "c00675d81848e1dfbe5c607ffe90e6ab",
        "PRO": "e95b46ff04a69a89c0abbd95548bc5c0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7ae8facd28484655a18ca60b688001a6"
      }
    },
    "D2sound_STR_28768683ecd1": {
      "addresses": {
        "LoD/PD2": "0x6F9BB1A0"
      },
      "rvas": {
        "LoD/PD2": "0xB1A0"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "__ms_p5_mp_test_fdiv",
      "signature": "void __ms_p5_mp_test_fdiv(void)",
      "calling_convention": "__stdcall",
      "comment": "Detects CPU FDIV bug and selects appropriate division test routine.\n\nAlgorithm:\n1. Get handle to KERNEL32.DLL module\n2. Attempt to locate IsProcessorFeaturePresent API function (+2 offset)\n3. If both module and function are found, call IsProcessorFeaturePresent(0)\n4. If module or function not available, fallback to __ms_p5_test_fdiv\n5. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nThe function uses an offset of +2 when calling GetProcAddress, indicating it's\nlooking for \"IsProcessorFeaturePresent\" but skipping the first 2 characters,\nlikely to avoid direct string references or for obfuscation.\n\nMagic Numbers Reference:\n0x0    - NULL pointer check for module handle\n0      - Parameter passed to IsProcessorFeaturePresent (PF_FLOATING_POINT_PRECISION_ERRATA)\n+2     - String offset to skip \"GA\" prefix in \"GAIsProcessorFeaturePresent\"\n\nError Handling:\n- If GetModuleHandleA returns NULL, fallback to direct test\n- If GetProcAddress returns NULL, fallback to direct test\n- No explicit error codes returned\n\nBackground:\nThis function implements Intel Pentium FDIV bug detection. The Intel Pentium\nprocessor had a floating-point division bug that affected certain division\noperations. Microsoft's Visual C++ runtime included workarounds to detect\nthis hardware bug and use software division when necessary.",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:28768683ecd1bb6c4e5ee8c2282cbc71",
      "indexes": {
        "EXP": null,
        "STR": "28768683ecd1bb6c4e5ee8c2282cbc71",
        "API": null,
        "MNE": "f8699cbba1b01584e66dc48ae13d6b14",
        "CFG": "e6f5aaef1039a61daa103ba7f60faedc",
        "PRO": "32a069cdd010b8edea48de6aa3ef8c02"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f8699cbba1b01584e66dc48ae13d6b14"
      }
    },
    "D2sound_MNE_6694b257f30e": {
      "addresses": {
        "LoD/PD2": "0x6F9BB1C9"
      },
      "rvas": {
        "LoD/PD2": "0xB1C9"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "CheckCpuidLeaf4Support",
      "signature": "int CheckCpuidLeaf4Support(void)",
      "calling_convention": "__stdcall",
      "comment": "Checks CPUID leaf 4 support by testing ECX bit 6 from CPUID(1) result.\n\nAlgorithm:\n1. Set up structured exception handling frame with size 0x0c and handler at 0x6f9c0a00\n2. Call SEH prolog (__SEH_prolog) to establish exception handling context\n3. Initialize local variables (leaf4_support_flag and seh_handler_frame) to zero\n4. Copy XMM0 register value to XMM1 (save original SSE register state)\n5. Set leaf4_support_flag = 1 (assume support present by default)\n6. Jump to setup_return_value to prepare return\n7. Set seh_handler_frame = 0xffffffff (sentinel value for error condition)\n8. Move leaf4_support_flag value (1 if set, error if not) into EAX as return value\n9. Call SEH epilog (__SEH_epilog) to clean up exception frame and verify canary\n10. Return with leaf4_support_flag in EAX\n\nParameters:\nNone - void function with no stack parameters\n\nReturns:\nEAX contains result of leaf4_support_flag:\n- 1 (true) if LEAF4 support detected and exception handling successful\n- 0 (false) if exception occurred during LEAF4 check or support not present\n\nSpecial Cases:\n- SEH exception during LEAF4 check: Sets return to 0 via seh_handler_frame sentinel\n- Stack canary verification failure: __SEH_epilog detects overflow and terminates process\n- XMM register preservation: MOVAPD preserves SSE state across function execution\n\nNote: Function uses 2 stack-allocated temporary variables optimized away by decompiler (local_8, local_20)\n\nStructure Layout:\nOffset  Size  Field Name              Type      Description\n------  ----  ---------              ----      -----------\n-0x20   4     seh_handler_frame      uint32    SEH exception handler frame\n-0x08   4     leaf4_support_flag     uint32    LEAF4 support result (1=supported, 0=error)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6694b257f30e581cdcdc8a268e857976",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6694b257f30e581cdcdc8a268e857976",
        "CFG": "093f36e40cc4a7861754e4e870ef1391",
        "PRO": "3a83795c4f86f8950336f294a8b66446"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6694b257f30e581cdcdc8a268e857976"
      }
    },
    "D2sound_MNE_44f4f246fc7b": {
      "addresses": {
        "LoD/PD2": "0x6F9BB1FE"
      },
      "rvas": {
        "LoD/PD2": "0xB1FE"
      },
      "sizes": {
        "LoD/PD2": 210
      },
      "name": "DetectCpuCapabilities",
      "signature": "void DetectCpuCapabilities(void)",
      "calling_convention": "__stdcall",
      "comment": "Detects CPU capabilities and validates authentic AMD processor characteristics.\n\nAlgorithm:\n1. Initialize local stack variables and retrieve XOR canary value from DAT_6f9c56c0\n2. Capture current EFLAGS register and create a test value with ID flag toggled (0x200000)\n3. Verify CPU supports CPUID instruction by testing if ID flag is writable\n4. If CPUID not supported, skip CPU detection and jump to cleanup_no_cpuid (0x6f9bb24c)\n5. Execute CPUID(0) to get vendor string and store in dwCpuidBasicEdx, dwCpuidBasicEcx, dwCpuidBasicEbx\n6. Execute CPUID(1) to get version info and feature bits, store EAX in dwCpuidVersionEax and EDX in nCpuidVersionEdx\n7. Test ECX bit 26 (0x4000000 - LEAF4 support indicator) from CPUID(1) result at check_leaf4_support (0x6f9bb25b)\n8. If LEAF4 not supported, jump to cleanup_and_return without authentication check (0x6f9bb25f)\n9. Call CheckCpuidLeaf4Support() to perform authentication check at 0x6f9bb261\n10. If authentication fails (EAX=0), jump to authentication_failed cleanup (0x6f9bb268)\n11. Set _DAT_6f9c6604 = 1 to indicate successful detection capability\n12. Compare vendor string \"AuthenticAMD\" with captured string using _strncmp at compare_vendor_string (0x6f9bb26a)\n13. Check if comparison succeeded (EAX=0) at check_vendor_match (0x6f9bb286)\n14. If vendor string matches, extract CPU family and model from dwCpuidVersionEax at extract_cpu_family (0x6f9bb28a)\n15. Calculate effective family (family bits 8-11 + extended family bits 20-27) and verify result equals 0xF\n16. Set DAT_6f9c6600 = 1 only if vendor matches AND effective family equals 0xF at set_authentic_flag (0x6f9bb2ba)\n17. Verify stack canary integrity before returning using VerifyStackCanary (0x6f9bb2c9)\n\nParameters:\nNone\n\nReturns:\nvoid - No explicit return value. Sets two global flags:\n- _DAT_6f9c6604: Set to 1 if CPUID authentication check passed\n- DAT_6f9c6600: Set to 1 if authentic AMD processor with family 0xF detected\n\nSpecial Cases:\n- CPUID instruction not available: CPU detection skipped entirely, both flags remain 0\n- LEAF4 support not detected: Treated as insufficient for authentication, both flags remain 0\n- _strncmp returns non-zero: Vendor string mismatch, skips family validation, only _DAT_6f9c6604 set\n- Extended family + family != 0xF: Family validation fails, only _DAT_6f9c6604 set\n- Stack canary mismatch: Security violation detected at cleanup, calls VerifyStackCanary\n\nMagic Numbers Reference:\n- 0x200000: EFLAGS ID flag bit for CPUID instruction support detection\n- 0x4000000: CPUID(1) ECX bit 26 indicating LEAF4 instruction support\n- 0xF: Expected effective CPU family value for authentic AMD processors\n- 0xffffff00: Mask to clear lower 8 bits during family/model extraction\n- 0xf: Mask to extract 4-bit family field from bits 8-11\n- 0xffU: Mask to extract 8-bit extended family field from bits 20-27\n\nError Handling:\n- No CPUID support: Early exit with flags cleared\n- Authentication failure: _DAT_6f9c6604 remains 0, DAT_6f9c6600 remains 0\n- Vendor mismatch: Only _DAT_6f9c6604 set to 1, DAT_6f9c6600 remains 0\n- Family validation failure: Only _DAT_6f9c6604 set to 1, DAT_6f9c6600 remains 0\n- Stack overflow: VerifyStackCanary handles canary validation failure\n\nFlag Bits Cross-Reference:\nEFLAGS ID Flag (0x200000):\n- Function: CheckCpuidLeaf4Support - Tests for CPUID instruction availability\n- Operation: XOR with current EFLAGS, restore, compare to detect writability\n\nCPUID(1) ECX Feature Bits (dwCpuidVersionEcx):\n- Bit 26 (0x4000000): LEAF4 instruction support indicator\n- Function: CheckCpuidLeaf4Support - Validates before authentication check\n- Operation: TEST instruction followed by JZ for conditional branching\n\nStructure Layout:\nOffset  Size  Field Name              Type      Description\n------  ----  ----------              ----      -----------\n-0x20   4     dwStackCanary           uint      XOR canary for stack overflow detection\n-0x1c   4     nCpuidVersionEdx        int       CPUID(1) EDX register (feature flags)\n-0x18   4     dwCpuidVersionEax       uint      CPUID(1) EAX register (family/model/stepping)\n-0x14   4     dwCpuidBasicEcx         uint      CPUID(0) ECX register (vendor string part 3)\n-0x10   4     dwCpuidBasicEdx         uint      CPUID(0) EDX register (vendor string part 2)\n-0x0c   4     dwCpuidBasicEbx         uint      CPUID(0) EBX register (vendor string part 1)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:44f4f246fc7b0dfe7a4c27a8f0c38630",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "44f4f246fc7b0dfe7a4c27a8f0c38630",
        "CFG": "648c4753ec9d6b9b2fad29d2a5e5af8d",
        "PRO": "0b3fa50fdd3a1dc2f96f8b826e4de7c8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "44f4f246fc7b0dfe7a4c27a8f0c38630"
      }
    },
    "D2sound_MNE_f21ef051543e": {
      "addresses": {
        "LoD/PD2": "0x6F9BB2D0"
      },
      "rvas": {
        "LoD/PD2": "0xB2D0"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "ConvertFPUStackAndComputeMath",
      "signature": "void ConvertFPUStackAndComputeMath(void)",
      "calling_convention": "__stdcall",
      "comment": "Converts x87 FPU stack-based floating-point parameters to standard calling convention and\ndelegates to math computation function.\n\nAlgorithm:\n1. Save frame pointer and allocate 16 bytes of stack space\n2. Align stack pointer to 16-byte boundary (required for some math functions)  \n3. Exchange ST0 and ST1 to ensure correct operand order\n4. Store both x87 FPU values as 64-bit doubles to stack (ST1 at [ESP], ST0 at [ESP+8])\n5. Call ComputeFloatpointMathWithSpecialCases with converted parameters\n6. Restore frame pointer and return\n\nParameters:\nST0 (IMPLICIT): Second floating-point operand (stored to [ESP+8]) \nST1 (IMPLICIT): First floating-point operand (stored to [ESP])\nStack params: Additional parameters passed through to callee\n\nReturns:\nvoid - Return value determined by ComputeFloatpointMathWithSpecialCases\n\nSpecial Cases:\n- Function assumes x87 FPU stack contains two valid float10 values\n- Stack alignment to 16-byte boundary is critical for called function  \n- FXCH swaps ST0/ST1 to normalize operand order\n- Used only when SSE/FPU control words are in masked exception state\n\nVariable Notes:\nlocal_18 (double): Stack storage for first FPU operand converted to double\nlocal_20 (double): Stack storage for second FPU operand converted to double\nNote: These stack variables are phantom variables optimized away by decompiler but detected in low-level analysis.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f21ef051543eddd7d8d7d19f4681593d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f21ef051543eddd7d8d7d19f4681593d",
        "CFG": null,
        "PRO": "e94d86c0f5836b956740a50bf2ccf356"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f21ef051543eddd7d8d7d19f4681593d"
      }
    },
    "D2sound_MNE_64cc1ab4b078": {
      "addresses": {
        "LoD/PD2": "0x6F9BB2E9"
      },
      "rvas": {
        "LoD/PD2": "0xB2E9"
      },
      "sizes": {
        "LoD/PD2": 2861
      },
      "name": "ComputeFloatpointMathWithSpecialCases",
      "signature": "float10 ComputeFloatpointMathWithSpecialCases(float10 * __return_storage_ptr__, double baseValue, int errorMode, uint resultOptions)",
      "calling_convention": "__cdecl",
      "comment": "Computes advanced floating-point mathematical operations with extended precision and special case handling.\n\nThis function performs complex floating-point arithmetic operations using bit manipulation and lookup tables\nto achieve mathematical precision. It handles multiple special cases including denormalized numbers, infinities,\nNaNs, and edge cases in the floating-point representation.\n\nAlgorithm:\n1. Extract exponent and mantissa fields from the baseValue using bit shifts and masks\n2. Perform initial range validation checking for denormalized values and special exponents\n3. Apply mantissa adjustment using pre-computed lookup tables (DAT_6f9c0a20, DAT_6f9c0e30, etc.)\n4. For normal values: compute scaled result using indexed table lookups based on exponent\n5. For values requiring precision computation: apply iterative refinement using double-precision arithmetic\n6. Handle special cases: detect NaN/Inf inputs, apply sign adjustments based on resultOptions\n7. Check result exponent ranges and apply scaling factors as needed\n8. For results near boundaries: apply rounding and adjustment using bit-level manipulation\n9. Invoke math error handler with appropriate error code (iVar5) for edge cases\n10. Return computed result as float10 (extended precision floating point)\n\nParameters:\n  baseValue: The input double-precision floating-point number to process\n  errorMode: Mode flag controlling error handling behavior (unused in main path)\n  resultOptions: Bitmask controlling result formatting and sign handling; bit 31 determines sign handling\n\nReturns:\n  float10: Extended-precision floating-point result with applied transformations\n\nSpecial Cases:\n  - NaN input: Returns NaN with sign adjustment based on resultOptions bit 31\n  - Infinity input: Returns Infinity or 0 depending on resultOptions\n  - Zero input: Returns 0 or special value depending on resultOptions\n  - Denormalized values: Handled via special scaling path at denormalized_value_path\n  - Results exceeding double exponent range: Scaled using bit-level manipulation\n  \nLookup Tables Used:\n  DAT_6f9c0a20: Mantissa scaling factors indexed by exponent\n  DAT_6f9c0e30: Primary coefficient table\n  DAT_6f9c1640: Secondary index scaling\n  DAT_6f9c2260: Precision adjustment factors\n  DAT_6f9c3aa0: Final result coefficients\n  DAT_6f9c42b0-DAT_6f9c4340: Special values and constants",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:64cc1ab4b07817fcc1a495a7dd4f85f3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "64cc1ab4b07817fcc1a495a7dd4f85f3",
        "CFG": "71dbbc22767f1a8619d40503063424ab",
        "PRO": "2576d252effbb472fe29c4c7f418ba3c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "64cc1ab4b07817fcc1a495a7dd4f85f3"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_d5f0d2733adf": {
      "addresses": {
        "LoD/PD2": "0x6F9BBF7E"
      },
      "rvas": {
        "LoD/PD2": "0xBF7E"
      },
      "sizes": {
        "LoD/PD2": 114
      },
      "name": "ComputeExponentialFraction",
      "signature": "double ComputeExponentialFraction(double baseValue, uchar flags)",
      "calling_convention": "__fastcall",
      "comment": "Computes 2^(fraction) - 1 for values used in exponential calculations\n\nAlgorithm:\n1. Load input value into FPU and compute absolute value\n2. Compare absolute value against threshold constant at 0x6f9c5b5e\n3. Set comparison flags in EBP[-0xa0]\n4. If comparison flags indicate error condition, jump to error handler\n5. Load input value, round it to nearest integer (FRNDINT)\n6. Test rounded value against zero and set flags\n7. Exchange ST0 and ST1, subtract to get fractional part\n8. Test fractional part and set flags\n9. Compute 2^(abs(fraction)) - 1 using F2XM1 instruction\n10. Return result via FPU stack with control flags\n\nParameters:\n- baseValue (EDX:EAX): Input floating-point value on FPU ST0\n- controlFlags (CL): Control flags affecting comparison behavior\n\nReturns:\n- FPU ST0: Result of 2^(fraction) - 1 computation\n- Carries status flags from FPU comparisons in stack memory at EBP[-0xa0]\n\nSpecial Cases:\n- Threshold constant at 0x6f9c5b5e used for input validation\n- Flags at EBP[-0x9f] control error handling path\n- F2XM1 instruction requires absolute value of fractional part &lt; 1.0\n- Result undefined if input exceeds valid range for F2XM1",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d5f0d2733adf4d1dce64e7fb83efd1d4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d5f0d2733adf4d1dce64e7fb83efd1d4",
        "CFG": "97543a482edce26b5d1274d6a4ca10c7",
        "PRO": "c46ec55b50403c196115302785682712"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d5f0d2733adf4d1dce64e7fb83efd1d4"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_df587a37c863": {
      "addresses": {
        "LoD/PD2": "0x6F9BBFC1"
      },
      "rvas": {
        "LoD/PD2": "0xBFC1"
      },
      "sizes": {
        "LoD/PD2": 52
      },
      "name": "ValidateFloatingPointIntegrality",
      "signature": "int ValidateFloatingPointIntegrality(void)",
      "calling_convention": "__stdcall",
      "comment": "Validates if a floating-point value is integral and its scaled version is also integral.\n\nAlgorithm:\n1. Load extended floating-point value from ST0 (FPU stack)\n2. Round the value to nearest integer using FRNDINT\n3. Compare rounded value with original value\n4. If not equal (JNZ to return_zero), value is not integer - return 0\n5. If equal, load ST0 again and multiply by scaling factor at 0x6f9c5b72\n6. Load ST0 again and round the scaled value\n7. Compare scaled value with its rounded version\n8. If not equal (JZ to return_two), scaled value is not integer - return 1\n9. If both are integers, return 2\n10. Pop FPU stack and return result in EAX\n\nParameters:\n  FPU ST0: Extended floating-point value to validate (float10)\n\nReturns:\n  EAX = 0 if value is not integral\n  EAX = 1 if value is integral but scaled value is not\n  EAX = 2 if both value and scaled value are integral\n\nSpecial Cases:\n  - Uses FPU rounding mode to check integrality\n  - Scaling factor at 0x6f9c5b72 typically represents a game unit scale\n  - Function assumes FPU is in standard rounding mode",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:df587a37c8639f83cd433c3a3fbdafc4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "df587a37c8639f83cd433c3a3fbdafc4",
        "CFG": "f6ba15919494a6e0de51957ffb31b089",
        "PRO": "b5ba49bd58125ef109dd1a838e946bc1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "df587a37c8639f83cd433c3a3fbdafc4"
      }
    },
    "D2sound_MNE_1e5021910108": {
      "addresses": {
        "LoD/PD2": "0x6F9BC030"
      },
      "rvas": {
        "LoD/PD2": "0xC030"
      },
      "sizes": {
        "LoD/PD2": 103
      },
      "name": "ProcessFloatingPointExceptionStatus",
      "signature": "void ProcessFloatingPointExceptionStatus(uint dwContext, void * pExceptionInfo)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: void ProcessFloatingPointExceptionStatus(uint dwContext, void * pExceptionInfo)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1e502191010869fca5d6ea71e353f408",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1e502191010869fca5d6ea71e353f408",
        "CFG": "e9864efb0914fe644077aff049229b5b",
        "PRO": "5f44c9d706744ea9e2ce14e025e6412f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "1e502191010869fca5d6ea71e353f408"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_2efd2f634b43": {
      "addresses": {
        "LoD/PD2": "0x6F9BC128"
      },
      "rvas": {
        "LoD/PD2": "0xC128"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "SwapAndDiscardFPUStackTop",
      "signature": "void SwapAndDiscardFPUStackTop(void)",
      "calling_convention": "__stdcall",
      "comment": "Floating-point stack utility that swaps the top two values and discards the new top.\n\nAlgorithm:\n1. Exchange ST0 with ST1 (FXCH): Swap the top two FPU stack registers\n2. Pop and discard ST0 (FSTP ST0): Remove the value that was originally in ST0\n\nThis is a helper function used in floating-point arithmetic sequences where an intermediate result needs to be discarded while preserving the lower stack value. Common pattern in division and reciprocal operations.\n\nReturns:\nvoid - No return value; modifies only FPU stack state\n\nSpecial Cases:\nThis function assumes the FPU stack has at least two valid entries. If called with fewer than two values, it will cause an FPU stack underflow exception.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2efd2f634b43779c5726887ddad8796b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2efd2f634b43779c5726887ddad8796b",
        "CFG": "0345c8892098e4ce43dca763d1e8ec63",
        "PRO": "cb03b749cfb5a6cb7850eed4c81c641f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2efd2f634b43779c5726887ddad8796b"
      }
    },
    "D2sound_MNE_038f21ccadf0": {
      "addresses": {
        "LoD/PD2": "0x6F9BC136"
      },
      "rvas": {
        "LoD/PD2": "0xC136"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "GetZeroValue",
      "signature": "float10 GetZeroValue(float10 * __return_storage_ptr__)",
      "calling_convention": "__stdcall",
      "comment": "Returns a zero value as an extended precision floating point number.\n\nAlgorithm:\n1. Discard any existing floating point stack value with FSTP\n2. Load 0.0 onto the FPU stack with FLDZ\n3. Return the value in the FPU accumulator\n\nReturns:\nfloat10 - Always returns 0.0\n\nNotes:\nThis is a minimal stub function that returns a constant zero value. It uses\nthe extended precision floating point format and __stdcall calling convention.",
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
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "038f21ccadf05fbd1bec4c0181e46e90"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_58c3c7e175be": {
      "addresses": {
        "LoD/PD2": "0x6F9BC1D6"
      },
      "rvas": {
        "LoD/PD2": "0xC1D6"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "InitializeThresholdValue",
      "signature": "void InitializeThresholdValue(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes a threshold value for floating-point comparison operations.\n\nAlgorithm:\n1. Pop and discard two floating-point values from the FPU stack (FSTP ST0)\n2. Load the extended precision threshold value from global data at 0x6f9c5ba0\n3. Check if the initialization flag at [EBP - 0x90] is less than 1\n4. If flag is uninitialized (< 1), set it to 1 to prevent re-initialization\n5. Return the loaded threshold value in ST0 (extended precision)\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nExtended precision floating-point threshold value in ST0\nUsed for numerical comparisons in damage calculations, spell effects, or type classification\n\nSpecial Cases:\nMagic Numbers Reference:\n- 0x6f9c5ba0: Global threshold value storage location\n- 0x90: Stack offset to initialization flag (144 bytes)\n- 0x01: Initialization flag value (prevents re-initialization)\n\nError Handling:\nNo explicit error handling - relies on FPU stack management and global data integrity\n\nStructure Layout:\nStack Frame Layout:\nOffset   Size  Field Name       Type    Description\n-0x90    1     InitFlag         byte    Initialization status flag (0=uninitialized, 1=initialized)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:58c3c7e175be8c196c57976e375f315f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "58c3c7e175be8c196c57976e375f315f",
        "CFG": "82ab21280f7756b94aebf888fcf167cf",
        "PRO": "b92f53eeaeabab194d9e5084e2cb23a3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "58c3c7e175be8c196c57976e375f315f"
      }
    },
    "D2sound_MNE_3c4be6dbcf12": {
      "addresses": {
        "LoD/PD2": "0x6F9BC1E9"
      },
      "rvas": {
        "LoD/PD2": "0xC1E9"
      },
      "sizes": {
        "LoD/PD2": 10
      },
      "name": "SetActiveFlag",
      "signature": "void SetActiveFlag(void)",
      "calling_convention": "__stdcall",
      "comment": "Sets an active/enabled flag to 1 at a caller's stack location.\n\nAlgorithm:\n1. Write byte value 0x1 to stack offset -0x90 relative to EBP\n2. Return to caller\n\nParameters:\nUses implicit caller's stack frame via EBP register.\nSets flag at EBP-0x90 (144 bytes from EBP).\n\nReturns:\nvoid - no return value.\n\nSpecial Cases:\n- Flag location is at fixed negative offset from EBP\n- The OR CL,CL instruction after the write is unused/dead code\n- Function uses caller's stack frame directly via EBP",
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
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3c4be6dbcf1260e7f12c4f60862ff7d6"
      }
    },
    "D2sound_MNE_d63502919c4c": {
      "addresses": {
        "LoD/PD2": "0x6F9BC200"
      },
      "rvas": {
        "LoD/PD2": "0xC200"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "SetupFloatingPointExceptionHandler",
      "signature": "float10 SetupFloatingPointExceptionHandler(float10 * __return_storage_ptr__, uint inputValue_eax, int errorCode, ushort errorFlags, uint stackParam1, void * exceptionContext, void * exceptionHandler, uint recoveryOption, void * callbackPointer)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: float10 SetupFloatingPointExceptionHandler(float10 * __return_storage_ptr__, uint inputValue_eax, int errorCode, ushort errorFlags, uint stackParam1, void * exceptionContext, void * exceptionHandler, uint recoveryOption, void * callbackPointer)",
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
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d63502919c4c985cfbdccf3184dd15d0"
      },
      "param_counts": {
        "LoD/PD2": 9
      }
    },
    "D2sound_MNE_9215dd175454": {
      "addresses": {
        "LoD/PD2": "0x6F9BC217"
      },
      "rvas": {
        "LoD/PD2": "0xC217"
      },
      "sizes": {
        "LoD/PD2": 60
      },
      "name": "__startOneArgErrorHandling",
      "signature": "float10 __startOneArgErrorHandling(float10 * __return_storage_ptr__, uint dwErrorCode, int nErrorType, ushort wStatusFlags, uint dwReserved1, uint dwReserved2, uint dwReserved3)",
      "calling_convention": "__fastcall",
      "comment": "Handles floating point error conditions for single-argument mathematical functions\n\nAlgorithm:\n1. Store incoming floating point value from ST(0) register as double precision\n2. Copy error parameters to local stack variables for function call\n3. Call HandleFloatingPointException with error type and status flags by reference\n4. Return original floating point value converted back to extended precision\n\nParameters:\n- param_1 (undefined4): Error code identifier for the specific math function\n- param_2 (int): Error type classification (domain, range, overflow, etc.)\n- param_3 (ushort): Floating point control word status flags (by reference)\n- param_4 (undefined4): Reserved parameter for future use\n- param_5 (undefined4): Reserved parameter for future use  \n- param_6 (undefined4): Reserved parameter for future use\nIMPLICIT in_ST0 (float10): Original mathematical function input value\n\nReturns:\n- Extended precision floating point value preserving original input\n- Status flags may be modified through param_3 reference\n\nSpecial Cases:\n- Function preserves original mathematical value regardless of error state\n- Error handling delegates to HandleFloatingPointException for processing\n- Reserved parameters allow for future API extension without signature changes\n\nError Handling:\n- All error processing delegated to HandleFloatingPointException\n- Function serves as wrapper to preserve value while handling error state\n- Control word status updated through reference parameter",
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
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9215dd17545429f5a2114f3f9c06e96c"
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "D2sound_MNE_3f015c1c75c5": {
      "addresses": {
        "LoD/PD2": "0x6F9BC260"
      },
      "rvas": {
        "LoD/PD2": "0xC260"
      },
      "sizes": {
        "LoD/PD2": 21
      },
      "name": "Pow2",
      "signature": "float10 Pow2(float10 * __return_storage_ptr__, float10 exponent)",
      "calling_convention": "__stdcall",
      "comment": "Computes 2 raised to the power of the input value (2^x).\n\nAlgorithm:\n1. Load input value from ST0 floating-point register\n2. Round input to nearest integer using FRNDINT\n3. Subtract rounded value from original to get fractional part: frac = x - round(x)\n4. Negate the fractional part: -frac\n5. Compute 2^(-frac) - 1 using F2XM1 (computes 2^x - 1 for x in [-1, 1])\n6. Add 1 to get 2^(-frac)\n7. Scale result by 2^round(x) using FSCALE to get final result\n8. Return result as 80-bit extended precision floating-point value\n\nParameters:\nexponent: The exponent value (x) for which to compute 2^x. Input is in ST0 register.\n\nReturns:\nfloat10: The result of 2^exponent as an 80-bit extended precision floating-point value.\n\nSpecial Cases:\n- This function uses the x87 FPU (x87 floating-point unit)\n- Uses F2XM1 which is accurate for inputs in range [-1, 1], so the function splits exponent into integer and fractional parts\n- The result is returned on the FPU stack (ST0)\n- Calling convention is __stdcall (callee cleans stack)\n\nAlgorithm Notes:\nThe computation uses the mathematical identity: 2^x = 2^(integer_part) * 2^(fractional_part)\nThis separates the problem into scaling by a power of 2 (fast FSCALE) and computing 2^frac where frac is in [-1,1]",
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
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3f015c1c75c5efb05d68ef52e0407e8b"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_2499e8fc5969": {
      "addresses": {
        "LoD/PD2": "0x6F9BC275"
      },
      "rvas": {
        "LoD/PD2": "0xC275"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "SetFPUControlWord",
      "signature": "void SetFPUControlWord(uint controlWord)",
      "calling_convention": "__stdcall",
      "comment": "Sets the x87 FPU control word with specific precision and rounding mode.\n\nThis utility function modifies the x87 floating-point unit (FPU) control word to ensure consistent floating-point behavior across different platforms. It extracts the rounding mode bits (0x300) from the input parameter and combines them with the precision bits (0x7f) before loading into the FPU control register.\n\nAlgorithm:\n1. Load control word parameter from stack at [ESP + 4]\n2. Extract rounding mode by masking with 0x300\n3. Combine extracted bits with precision bits (0x7f) using OR operation\n4. Store result in temporary stack location at [ESP + 6]\n5. Load FPU control register (FLDCW) from the temporary location\n6. Return to caller\n\nParameters:\ncontrolWord (unsigned int): Input control word containing rounding mode and other FPU bits\n\nReturns:\nvoid (no return value; modifies FPU state)\n\nSpecial Cases:\n- The function expects the caller to preserve stack alignment\n- Only the rounding mode (0x300) and precision bits (0x7f) are meaningful\n- This is typically called when entering numerical computation code paths\n- The FLDCW instruction loads the control word and takes effect immediately\n\nFPU Control Word Bit Layout:\nBits 0-5: Precision Control (0x7f mask used here for full precision)\nBits 6-7: Rounding Mode (masked with 0x300)\nBits 8-9: Infinity Control / Reserved\nBits 10-15: Exception Masks",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2499e8fc59692f6e5479749bdf8573b2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2499e8fc59692f6e5479749bdf8573b2",
        "CFG": null,
        "PRO": "6ac2b36b650e9421f95685b6edc12d6e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2499e8fc59692f6e5479749bdf8573b2"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_7e73328c30de": {
      "addresses": {
        "LoD/PD2": "0x6F9BC2A5"
      },
      "rvas": {
        "LoD/PD2": "0xC2A5"
      },
      "sizes": {
        "LoD/PD2": 67
      },
      "name": "__fload_withFB",
      "signature": "uint __fload_withFB(double * pDoubleUnused, double * pDoubleValue)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: uint __fload_withFB(double * pDoubleUnused, double * pDoubleValue)",
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
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7e73328c30de0e16ec37226d5c0fbaeb"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_118a84069540": {
      "addresses": {
        "LoD/PD2": "0x6F9BC2FE"
      },
      "rvas": {
        "LoD/PD2": "0xC2FE"
      },
      "sizes": {
        "LoD/PD2": 13
      },
      "name": "RestoreFpuControlWord",
      "signature": "void RestoreFpuControlWord(void)",
      "calling_convention": "__stdcall",
      "comment": "Restores the x86 FPU (Floating Point Unit) control word from the stack.\n\nAlgorithm:\n1. Check if the value at ESP (top of stack) is 0x27f (default FPU control word)\n2. If not equal, load the value at ESP into the FPU control word register via FLDCW\n3. If equal (already correct), skip the FLDCW instruction\n4. Pop EDX from stack to clean up\n5. Return to caller\n\nThis function is used to restore FPU state after mathematical operations that may have modified the control word. The value 0x27f represents the default FPU control word setting (PC bits for precision control, exception masks). This is called from mathematical computation functions to ensure consistent FPU state.\n\nParameters:\nNone - relies on stack-based parameter (control word value at ESP)\n\nReturns:\nvoid - modifies FPU control word register as side effect\n\nSpecial Cases:\n- If control word already equals 0x27f, FLDCW is skipped (optimization)\n- Uses __stdcall convention - callee cleans stack via RET\n- Sensitive to precise stack alignment at entry\n\nNote: Function uses 1 stack-allocated temporary variable optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:118a84069540ef5bdaff27e56dcaadec",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "118a84069540ef5bdaff27e56dcaadec",
        "CFG": "7750d3e200f3a3c6416ddf41088bb841",
        "PRO": "8cb32a0d56a2452e759161b6ffdb7e9f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "118a84069540ef5bdaff27e56dcaadec"
      }
    },
    "D2sound_MNE_0c71b5715e2e": {
      "addresses": {
        "LoD/PD2": "0x6F9BC349"
      },
      "rvas": {
        "LoD/PD2": "0xC349"
      },
      "sizes": {
        "LoD/PD2": 163
      },
      "name": "MathLibGammaErrorHandler",
      "signature": "void MathLibGammaErrorHandler(float10 * pValue, int nErrorCode, uint dwParam3, uint dwParam4, uint dwParam5, uint dwParam6, uint dwParam7)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: void MathLibGammaErrorHandler(float10 * pValue, int nErrorCode, uint dwParam3, uint dwParam4, uint dwParam5, uint dwParam6, uint dwParam7)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0c71b5715e2e7c5f22ef70735f27ff6f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0c71b5715e2e7c5f22ef70735f27ff6f",
        "CFG": "1d927b07221b2d93b8f37eb335ea758e",
        "PRO": "456d89e7bb0dbf9148c82d622f3167e8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0c71b5715e2e7c5f22ef70735f27ff6f"
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "D2sound_MNE_a73632a203a9": {
      "addresses": {
        "LoD/PD2": "0x6F9BC3EC"
      },
      "rvas": {
        "LoD/PD2": "0xC3EC"
      },
      "sizes": {
        "LoD/PD2": 110
      },
      "name": "__d_inttype",
      "signature": "int __d_inttype(double dValue)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: int __d_inttype(double dValue)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a73632a203a909b26ae754b1694e766c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a73632a203a909b26ae754b1694e766c",
        "CFG": "2a243539dd196277feb3e0d2576d58d9",
        "PRO": "95b801d8d6037d2c6a83a97f076feca4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a73632a203a909b26ae754b1694e766c"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_953b88fcc929": {
      "addresses": {
        "LoD/PD2": "0x6F9BC45A"
      },
      "rvas": {
        "LoD/PD2": "0xC45A"
      },
      "sizes": {
        "LoD/PD2": 354
      },
      "name": "__powhlp",
      "signature": "int __powhlp(int nHighWord, int nLowWord, double flExponent, double * pflResult)",
      "calling_convention": "__cdecl",
      "comment": "Handles special cases for floating point power operations\n\nAlgorithm:\n1. Combine high and low word parameters into 64-bit base value\n2. Get absolute value of base for comparisons\n3. Check for infinity exponent cases (0x7ff00000)\n4. Handle negative infinity exponent cases  \n5. Check for infinity base cases (0x7ff00000 or -0x100000)\n6. Call __d_inttype to determine if exponent is integer\n7. Apply special case rules based on base and exponent values\n8. Store final result in output parameter\n9. Return status code (0 = error, 1 = success with adjustment)\n\nParameters:\n- nHighWord: High 32 bits of 64-bit base value\n- nLowWord: Low 32 bits of 64-bit base value  \n- flExponent: Double precision exponent value\n- pflResult: Pointer to store computed result\n\nReturns:\n- 0: Normal computation (no adjustment needed)\n- 1: Special case handled with adjustment\n\nSpecial Cases:\n- Infinity exponent (0x7ff00000): Returns 0.0 or infinity based on base\n- Negative infinity exponent: Returns 0.0 for large base, infinity for small base\n- Infinity base: Returns NaN for invalid combinations\n- Zero base with negative exponent: Returns infinity\n- Negative base with non-integer exponent: Returns NaN\n\nMagic Numbers Reference:\n- 0x7ff00000: IEEE 754 positive infinity bit pattern\n- -0x100000: IEEE 754 negative infinity bit pattern  \n- _DAT_6f9c0988: Zero constant (0.0)\n- _DAT_6f9c0990: One constant (1.0)\n- _DAT_6f9c5c08: Positive infinity constant\n- _DAT_6f9c5c10: Negative infinity constant\n- _DAT_6f9c5c28: NaN constant",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:953b88fcc92998ca7186d4cbec68693d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "953b88fcc92998ca7186d4cbec68693d",
        "CFG": "363c3b3e5522660d364c8efb5c45b90a",
        "PRO": "1cd40860b5085be3a8f29d67a357b9c4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "953b88fcc92998ca7186d4cbec68693d"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_6fccd9d03ed4": {
      "addresses": {
        "LoD/PD2": "0x6F9BC5BC"
      },
      "rvas": {
        "LoD/PD2": "0xC5BC"
      },
      "sizes": {
        "LoD/PD2": 50
      },
      "name": "__ZeroTail",
      "signature": "int __ZeroTail(uint * pBuffer, int nBitPosition)",
      "calling_convention": "__cdecl",
      "comment": "Tests whether all bits from a specified bit position to the end of a 96-bit (3 dword) buffer are zero.\n\nAlgorithm:\n1. Calculate starting dword index by dividing bit position by 32 (0x20)\n2. Create bitmask to isolate bits from start position to end of current dword  \n3. Check if any bits are set in the masked portion of current dword\n4. If bits are set, return 0 (not all zero)\n5. Move to next dword and check all 32 bits\n6. Repeat until reaching end of 3-dword buffer (index > 2)\n7. If no set bits found in any dword, return 1 (all zero)\n\nParameters:\npBuffer - Pointer to 3-dword (12-byte) buffer representing 96-bit value\nnBitPosition - Starting bit position to check from (0-95)\n\nReturns:\n1 if all bits from nBitPosition to end of buffer are zero\n0 if any bit from nBitPosition to end is set\n\nSpecial Cases:\nIf nBitPosition >= 96, behavior undefined (no bounds checking)\nFunction always checks exactly 3 dwords (indices 0, 1, 2)\n\nMagic Numbers Reference:\n0x20 (32) - Bits per dword, used for index calculation\n0x1fU (31) - Maximum bit offset within dword for masking\n2 - Maximum dword index (3 dwords total: indices 0, 1, 2)\n\nNote: Function uses 2 stack-allocated temporary variables optimized away by decompiler:\nuVar1 (dwBitmask): Current dword value after masking\niVar2 (nDwordIndex): Current dword index being processed",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6fccd9d03ed4f3aec03022e6df14f4f5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6fccd9d03ed4f3aec03022e6df14f4f5",
        "CFG": "cb8eff8eb27b04d335095ce75c22ce5f",
        "PRO": "217443a6ab0b2833f2937bf021aaf5cd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6fccd9d03ed4f3aec03022e6df14f4f5"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_28413b8bd9dd": {
      "addresses": {
        "LoD/PD2": "0x6F9BC5EE"
      },
      "rvas": {
        "LoD/PD2": "0xC5EE"
      },
      "sizes": {
        "LoD/PD2": 77
      },
      "name": "__IncMan",
      "signature": "void __IncMan(uint * pBitArray, int nBitIndex)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void __IncMan(uint * pBitArray, int nBitIndex)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:28413b8bd9ddfb3032353a0938531af3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "28413b8bd9ddfb3032353a0938531af3",
        "CFG": "6b04914845343aef842ac72ada5146ad",
        "PRO": "ec80bbce0ebae89ca3c161c42bfaf671"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "28413b8bd9ddfb3032353a0938531af3"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_d1605fa863a6": {
      "addresses": {
        "LoD/PD2": "0x6F9BC63B"
      },
      "rvas": {
        "LoD/PD2": "0xC63B"
      },
      "sizes": {
        "LoD/PD2": 114
      },
      "name": "__RoundMan",
      "signature": "uint __RoundMan(uint * pMantissa, int nBitPosition)",
      "calling_convention": "__cdecl",
      "comment": "Rounds floating-point mantissa at specified bit position using round-to-even.\n\nAlgorithm:\n1. Calculate word index (bit_position / 32) and bit offset within word\n2. Check if rounding bit is set and all trailing bits are zero\n3. If rounding conditions met, increment mantissa at position-1\n4. Clear all bits at and after the rounding position\n5. Zero out any complete words beyond the rounding position\n6. Return carry-out from increment operation\n\nParameters:\npMantissa: Pointer to 96-bit mantissa as array of 3 uint32 words\nnBitPosition: Bit position where rounding occurs (0-95)\n\nReturns:\n0: No carry-out from rounding operation\n1: Carry-out occurred, exponent should be incremented\n\nSpecial Cases:\nMagic number 0x20 (32): Bits per word in mantissa representation\nMagic number 0x1f (31): Mask for bit position within word  \nMagic number 3: Total words in 96-bit mantissa\n\nError Handling:\nNo validation - assumes valid bit position and mantissa pointer\nRelies on __ZeroTail and __IncMan for trailing bit analysis and increment",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d1605fa863a6daa5441d188cba14b16b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d1605fa863a6daa5441d188cba14b16b",
        "CFG": "97543a482edce26b5d1274d6a4ca10c7",
        "PRO": "7365ce6234d1c82258fcb77a49f826af"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d1605fa863a6daa5441d188cba14b16b"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_549d5b8046a6": {
      "addresses": {
        "LoD/PD2": "0x6F9BC6AD"
      },
      "rvas": {
        "LoD/PD2": "0xC6AD"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "__CopyMan",
      "signature": "void __CopyMan(uint * param_1, uint * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void __CopyMan(uint * param_1, uint * param_2)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:549d5b8046a6f807c0249d1d16a7d887",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "549d5b8046a6f807c0249d1d16a7d887",
        "CFG": "f09da8ab2298e4bafedfaee404f68269",
        "PRO": "e28c28e73495db16cbdecab1ac63d34c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "549d5b8046a6f807c0249d1d16a7d887"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_4325b0f74a7a": {
      "addresses": {
        "LoD/PD2": "0x6F9BC6C8"
      },
      "rvas": {
        "LoD/PD2": "0xC6C8"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "__IsZeroMan",
      "signature": "uint __IsZeroMan(uint * pManData)",
      "calling_convention": "__cdecl",
      "comment": "Checks if a floating-point mantissa structure is all zeros\n\nAlgorithm:\n1. Initialize loop index to 0\n2. For each of 3 DWORD elements in mantissa array:\n   a. Check if current element is non-zero\n   b. If non-zero found, return 0 (false)\n   c. Increment index to next element\n3. If all elements are zero, return 1 (true)\n\nParameters:\n  pManData (uint *): Pointer to 3-element mantissa array (12 bytes total)\n\nReturns:\n  1: All mantissa elements are zero (number is zero)\n  0: At least one mantissa element is non-zero\n\nSpecial Cases:\n  - Processes exactly 3 DWORD elements (0x0, 0x4, 0x8 offsets)\n  - Used in floating-point zero detection routines\n\nMagic Numbers Reference:\n  0x3: Number of DWORD elements in mantissa structure\n  0x4: Size of each DWORD element in bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4325b0f74a7ab70f3912235413ec786a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4325b0f74a7ab70f3912235413ec786a",
        "CFG": "722628398da33b1109acda7d875be5d4",
        "PRO": "a04f218dc6e4eddbc8409f96e66483a5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4325b0f74a7ab70f3912235413ec786a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_2c7cab825b88": {
      "addresses": {
        "LoD/PD2": "0x6F9BC6E1"
      },
      "rvas": {
        "LoD/PD2": "0xC6E1"
      },
      "sizes": {
        "LoD/PD2": 123
      },
      "name": "__ShrMan",
      "signature": "void __ShrMan(uint * pdwMantissa, int nShiftCount)",
      "calling_convention": "__cdecl",
      "comment": "Performs right bit shift on a 96-bit mantissa represented as a 3-element uint array\n\nAlgorithm:\n\n1. Extract bit-level shift amount (nShiftCount % 32) into byBitShift\n2. Initialize element index counter (nElementIndex) and carry bits accumulator (dwCarryBits)  \n3. Process each of the 3 mantissa elements from low to high order:\n   a. Load current element value into dwCurrentElement\n   b. Shift element right by byBitShift bits and OR with carry from previous element\n   c. Calculate new carry bits from shifted-out portion of current element\n   d. Store result back to mantissa array and increment to next element\n4. Calculate word-level shift offset (2 - nShiftCount / 32)\n5. Initialize pdwSourcePtr to mantissa element at calculated offset  \n6. Process elements from high to low order (index 2 down to 0):\n   a. If current index is below word shift boundary, zero the element\n   b. Otherwise copy from source pointer to maintain shifted data alignment\n   c. Decrement both element index and source pointer\n\nParameters:\n\npdwMantissa - Pointer to 3-element uint array representing 96-bit mantissa\nnShiftCount - Number of bits to shift right (0-95 range typical)\n\nReturns:\n\nvoid - Mantissa array is modified in place\n\nSpecial Cases:\n\n- nShiftCount >= 96: Results in mantissa being zeroed (shift beyond precision)\n- nShiftCount == 0: No operation performed, mantissa unchanged\n- Word-aligned shifts (multiples of 32): Only step 4-6 executed, no bit-level processing\n\nMagic Numbers Reference:\n\n0x20 (32 decimal) - Bits per uint element, used for modulo and division operations\n0x1f (31 decimal) - Bit mask for extracting shift amounts within 32-bit boundary  \n3 - Number of elements in mantissa array (96 bits / 32 bits per element)\n2 - Highest element index in 3-element array (zero-based indexing)\n\nError Handling:\n\nNo explicit validation - assumes valid mantissa pointer and reasonable shift count\nCaller responsible for ensuring pdwMantissa points to valid 3-element array\nNegative shift counts treated as large positive values due to unsigned arithmetic\n\nNote: Local variables local_8, uVar1, iVar2, bVar3, puVar4 could not be renamed due to connection issues but correspond to dwCarryBits, dwCurrentElement, nElementIndex, byBitShift, pdwSourcePtr respectively.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2c7cab825b88bfd42a85feb377dd1d15",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2c7cab825b88bfd42a85feb377dd1d15",
        "CFG": "349c77f53c00e5d2b17a0ac8dc3f06b3",
        "PRO": "aae200d257dfcc5dba17b6b52c6da243"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2c7cab825b88bfd42a85feb377dd1d15"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_7eeb91add89e": {
      "addresses": {
        "LoD/PD2": "0x6F9BC75C"
      },
      "rvas": {
        "LoD/PD2": "0xC75C"
      },
      "sizes": {
        "LoD/PD2": 344
      },
      "name": "__ld12cvt",
      "signature": "undefined4 __ld12cvt(ushort * param_1, uint * param_2, int * param_3)",
      "calling_convention": "__cdecl",
      "comment": "Convert 12-byte extended precision floating point to formatted output\n\nAlgorithm:\n1. Extract exponent from word 5 (bits 0-14) and sign bit (bit 15)\n2. Load 64-bit mantissa from words 1-4 into local buffer\n3. Calculate biased exponent by subtracting bias (0x3fff)\n4. Check for zero value using __IsZeroMan helper\n5. If non-zero, copy mantissa to working buffer using __CopyMan\n6. Perform rounding using __RoundMan with specified precision\n7. Adjust exponent if rounding caused overflow\n8. Check exponent bounds against format limits (min/max exponent)\n9. Handle underflow by zeroing mantissa\n10. Handle overflow by setting infinity representation (0x80000000)\n11. For normal range, apply precision shift using __ShrMan\n12. Combine sign, exponent, and mantissa into final format\n13. Store result based on output format (32-bit or 64-bit)\n\nParameters:\npwMantissa - Pointer to 12-byte extended precision input (6 words)\npdwResult - Pointer to output buffer for converted result  \npnFormat - Pointer to format specification array with 6 elements:\n  [0] Max exponent for overflow detection\n  [1] Normal range upper bound\n  [2] Precision bits for rounding\n  [3] Final shift amount \n  [4] Output format (0x20=32-bit, 0x40=64-bit)\n  [5] Exponent offset for result\n\nReturns:\n0 - Zero result\n1 - Overflow/infinity result  \n2 - Normal finite result\n\nSpecial Cases:\nZero input (exponent 0x0000) produces zero output\nMaximum exponent (0x7fff) indicates infinity or NaN\nUnderflow (exponent too small) produces zero\nOverflow (exponent too large) produces infinity (0x80000000)\n\nMagic Numbers Reference:\n0x3fff - Exponent bias for extended precision format\n0x7fff - Exponent mask (excludes sign bit)\n0x8000 - Sign bit mask in exponent word\n0x80000000 - Infinity representation in mantissa\n0x7fffffff - Mantissa mask (excludes implicit leading bit)\n0x20 - 32-bit output format code\n0x40 - 64-bit output format code\n\nExtended Precision Format:\nWord 0: Low 16 bits of mantissa\nWord 1: Next 16 bits of mantissa  \nWord 2: Next 16 bits of mantissa\nWord 3: High 16 bits of mantissa\nWord 4: (Unused alignment)\nWord 5: Sign bit (15) + 15-bit biased exponent (14-0)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7eeb91add89e62104683a18ab6e9d675",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7eeb91add89e62104683a18ab6e9d675",
        "CFG": "442586d9f6169fcc4a7c39483eabd545",
        "PRO": "ee24a9f04c93ba392409927f8f51060b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7eeb91add89e62104683a18ab6e9d675"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_09d6403e834e": {
      "addresses": {
        "LoD/PD2": "0x6F9BC8B4"
      },
      "rvas": {
        "LoD/PD2": "0xC8B4"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "FID_conflict:__ld12tod",
      "signature": "INTRNCVT_STATUS FID_conflict:__ld12tod(_LDBL12 * _Ifp, _CRT_DOUBLE * _D)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Multiple Matches With Different Base Names\n __ld12tod\n __ld12tof\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:09d6403e834e217532debf7a54bafa14",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "09d6403e834e217532debf7a54bafa14",
        "CFG": null,
        "PRO": "81d5ba5a009abbe91f9495cf2d526c51"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "09d6403e834e217532debf7a54bafa14"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_ADDR_6F9BC8CA": {
      "addresses": {
        "LoD/PD2": "0x6F9BC8CA"
      },
      "rvas": {
        "LoD/PD2": "0xC8CA"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "FID_conflict:__ld12tod",
      "signature": "INTRNCVT_STATUS FID_conflict:__ld12tod(_LDBL12 * _Ifp, _CRT_DOUBLE * _D)",
      "calling_convention": "__cdecl",
      "comment": "Convert 12-byte long double format to standard double format.\n\nAlgorithm:\n1. Validate input parameters _Ifp (source 12-byte long double) and _D (destination double)\n2. Call __ld12cvt core conversion function with parameters:\n   - (ushort *)_Ifp: Source 12-byte long double cast to ushort array\n   - (uint *)_D: Destination double cast to uint array  \n   - (int *)&DAT_6f9c5bd0: Conversion control/format descriptor table\n3. Return conversion status from __ld12cvt\n\nParameters:\n- _Ifp (_LDBL12 *): Pointer to source 12-byte long double format\n- _D (_CRT_DOUBLE *): Pointer to destination standard double format\n\nReturns:\n- INTRNCVT_STATUS: Conversion status (SUCCESS=0, various error codes for overflow/underflow/invalid)\n\nSpecial Cases:\n- Function is simple wrapper around __ld12cvt core implementation\n- Uses shared conversion descriptor table at DAT_6f9c5bd0\n- Part of Visual Studio 2003 CRT math library (multiple base names __ld12tod/__ld12tof)\n\nMagic Numbers Reference:\n- DAT_6f9c5bd0: Conversion format descriptor table for double precision target",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:09d6403e834e217532debf7a54bafa14",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "09d6403e834e217532debf7a54bafa14",
        "CFG": null,
        "PRO": "143ba4873a2092ec93df008aa9663d4b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "09d6403e834e217532debf7a54bafa14"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_d0108701376b": {
      "addresses": {
        "LoD/PD2": "0x6F9BC8E0"
      },
      "rvas": {
        "LoD/PD2": "0xC8E0"
      },
      "sizes": {
        "LoD/PD2": 69
      },
      "name": "ConvertStringToExtendedDouble",
      "signature": "void ConvertStringToExtendedDouble(_CRT_DOUBLE * pOutDouble, byte * pNumberString)",
      "calling_convention": "__cdecl",
      "comment": "Parse a decimal string and convert to extended double precision format.\n\nAlgorithm:\n1. Load and XOR global stack cookie with EBP for validation\n2. Call ParseDecimalString to convert input byte string to 80-bit long double format\n3. Call FID_conflict___ld12tod to convert 80-bit long double to 64-bit double format\n4. Verify stack integrity by XORing stack cookie with current EBP\n5. Call stack validation function FUN_6f9b47e5\n6. Return with cleanup\n\nParameters:\n  pOutDouble: Pointer to _CRT_DOUBLE structure to receive converted value\n  pNumberString: Pointer to null-terminated decimal string to parse (e.g., \"3.14159\")\n\nReturns:\n  void - Output written to pOutDouble parameter\n\nSpecial Cases:\n  Stack Cookie Validation: Uses global DAT_6f9c56c0 as canary to detect stack corruption\n  Zero Initialization: All temporary stack buffers initialized to zero before use\n  Precision: Intermediate 80-bit long double provides extended precision before final conversion",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d0108701376b16ac6499325944a4e45e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d0108701376b16ac6499325944a4e45e",
        "CFG": null,
        "PRO": "a2d093ef31cc49add33192fa15612d47"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d0108701376b16ac6499325944a4e45e"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_ADDR_6F9BC925": {
      "addresses": {
        "LoD/PD2": "0x6F9BC925"
      },
      "rvas": {
        "LoD/PD2": "0xC925"
      },
      "sizes": {
        "LoD/PD2": 69
      },
      "name": "ConvertStringToDouble",
      "signature": "void ConvertStringToDouble(_CRT_DOUBLE * pDoubleOut, byte * pDecimalString)",
      "calling_convention": "__cdecl",
      "comment": "Converts a decimal string representation to a double-precision floating point value with stack buffer overflow protection.\n\nAlgorithm:\n1. Load global stack canary value from DAT_6f9c56c0 and XOR with stack frame pointer to create a per-call canary\n2. Store the canary in stack slot [EBP-4] for verification at function exit\n3. Call ParseDecimalString to parse the input decimal string (pDecimalString) into long double format (longDoubleValue) and extract exponent (decimalExponent)\n4. Call __ld12tod to convert the 12-byte long double value to 8-byte double-precision format, storing result at pDoubleOut\n5. Verify stack canary by XORing stored canary with current stack frame pointer - if mismatch detected, jump to error handler\n6. Call FUN_6f9b47e5 with XORed canary value for cleanup/verification\n7. Return to caller\n\nParameters:\n- pDoubleOut (_CRT_DOUBLE *): Output parameter, pointer to CRT_DOUBLE where converted value is stored\n- pDecimalString (byte *): Input parameter, pointer to null-terminated decimal string to parse (e.g., \"3.14159\")\n\nReturns:\n- void: Function returns no value; result is stored via pDoubleOut pointer\n\nSpecial Cases:\n- Stack canary mismatch indicates buffer overflow attempt; calls error handler (FUN_6f9b47e5)\n- Handles extreme exponents through ParseDecimalString delegation\n- Requires global canary seed at DAT_6f9c56c0 to be initialized",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d0108701376b16ac6499325944a4e45e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d0108701376b16ac6499325944a4e45e",
        "CFG": null,
        "PRO": "a2d093ef31cc49add33192fa15612d47"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d0108701376b16ac6499325944a4e45e"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_f7937fb06735": {
      "addresses": {
        "LoD/PD2": "0x6F9BC96A"
      },
      "rvas": {
        "LoD/PD2": "0xC96A"
      },
      "sizes": {
        "LoD/PD2": 119
      },
      "name": "__fptostr",
      "signature": "errno_t __fptostr(char * pszBuffer, size_t cbBufferSize, STRFLT * pStrFlt, int nUnused)",
      "calling_convention": "__cdecl",
      "comment": "Converts floating-point number to string representation with specified buffer size\n\nAlgorithm:\n1. Initialize output buffer with '0' as first character and position pointer after it\n2. Extract digits string pointer from STRFLT structure at offset 0xc (pStrFlt[3].sign)\n3. Copy digits from STRFLT to buffer, padding with '0' if source runs out of digits\n4. Null-terminate the digit string in buffer\n5. Perform rounding if next digit > '4': increment previous digits, handling carry propagation\n6. If result starts with '1', increment exponent field in STRFLT structure (offset 4)\n7. Otherwise, shift digits left to remove leading '0' using memmove\n8. Return pointer to result string\n\nParameters:\npszBuffer (char*): Output buffer to store string representation\ncbBufferSize (size_t): Size of output buffer in bytes\npStrFlt (STRFLT*): Pointer to floating-point structure containing digits and exponent\nnUnused (int): Unused parameter, likely for API compatibility\n\nReturns:\nerrno_t: Pointer to result string cast as errno_t (non-standard return usage)\n\nSpecial Cases:\n- If buffer size <= 0, only null terminator is written\n- Digits exhausted from source: padded with '0' characters  \n- Rounding carries through all '9' digits: converts to '1' with exponent increment\n- Leading digit becomes '1': exponent incremented, digits kept as-is\n- Leading digit remains '0': digits shifted left to remove leading zero\n\nStructure Layout:\nSTRFLT structure (inferred from usage):\nOffset  Size  Field Name    Type     Description\n0x00    4     field_0x0     uint     Unknown field\n0x04    4     exponent      int      Exponent value, incremented when leading digit becomes '1'  \n0x08    4     field_0x8     uint     Unknown field\n0x0c    4     pDigits       char*    Pointer to digits string\n\nMagic Numbers:\n0x0c (12): Offset to digits pointer in STRFLT structure\n0x04 (4): Offset to exponent field in STRFLT structure\n'4': Rounding threshold - digits > '4' cause rounding up\n'9': Carry propagation check - '9' digits become '0' with carry forward\n'0': Default padding character when source digits exhausted\n'1': Leading digit that triggers exponent increment",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f7937fb067350d139a4f89ae55a00917",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f7937fb067350d139a4f89ae55a00917",
        "CFG": "d07cb40aeb07237476d52676c927435a",
        "PRO": "865b14b419b1a6f9a5981b0a9ec610d4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f7937fb067350d139a4f89ae55a00917"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_019950436ea0": {
      "addresses": {
        "LoD/PD2": "0x6F9BC9E1"
      },
      "rvas": {
        "LoD/PD2": "0xC9E1"
      },
      "sizes": {
        "LoD/PD2": 186
      },
      "name": "___dtold",
      "signature": "void ___dtold(uint * pLongDouble, uint * pDouble)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void ___dtold(uint *pLongDouble, uint *pDouble)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:019950436ea0c15cb62fdba8ce181372",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "019950436ea0c15cb62fdba8ce181372",
        "CFG": "fc5d450afd52ad404d439019afee5207",
        "PRO": "5d2b83b0034359c3b23c6dba310d5a9e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "019950436ea0c15cb62fdba8ce181372"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_91e85de7f1df": {
      "addresses": {
        "LoD/PD2": "0x6F9BCA9B"
      },
      "rvas": {
        "LoD/PD2": "0xCA9B"
      },
      "sizes": {
        "LoD/PD2": 120
      },
      "name": "ConvertDoubleForStringFormat",
      "signature": "void ConvertDoubleForStringFormat(_CRT_DOUBLE crtDouble, uint precision, int * pOutputArray, uint * pFormatArray)",
      "calling_convention": "__cdecl",
      "comment": "Converts a CRT double-precision floating-point number to a formatted string representation.\n\nThis function is part of the CRT string formatting pipeline. It takes a floating-point value and\nconverts it to an intermediate string format suitable for further processing by __fptostr and\nrelated formatting functions.\n\nAlgorithm:\n1. Initialize security cookie with XOR of global security value and stack frame pointer\n2. Convert _CRT_DOUBLE parameter to native double using ___dtold()\n3. Call ConvertDoubleToString to generate string with precision 0x11 (17 decimal places)\n4. Extract conversion results: sign byte, decimal position, and digit count\n5. Store outputs: output[0]=sign, output[1]=decimal, output[2]=digit count, output[3]=format ptr\n6. Call CopyStringWithAlignment to process format array output\n7. Verify security cookie via XOR and restore stack frame\n\nParameters:\n  crtDouble     - _CRT_DOUBLE: Input floating-point value in CRT internal format\n  precision     - uint: Precision/flag parameter (used as base for output array)\n  pOutputArray  - int *: Output array [0]=sign, [1]=decimal, [2]=digit count, [3]=format ptr\n  pFormatArray  - uint *: Output format array (6 uint elements)\n\nReturns:\n  void: Results stored in pOutputArray and pFormatArray\n\nSpecial Cases:\n  Sign byte is 0x2d ('-') for negative, else positive\n  ConvertDoubleToString always uses 17 decimal digits for double precision\n  Security cookie prevents stack buffer overflow attacks\n\nMagic Numbers Reference:\n  0x11 (17 decimal) - Standard double precision digit count\n  0x2d (45 decimal) - ASCII minus sign character\n  0x8 - Offset for digit count in output array\n  0x4 - Offset for decimal position in output array\n  0xc - Offset for format pointer in output array\n\nStructure Layout (Local Variables):\n  Offset  Size    Field Name           Type         Description\n  -0x4    4       securityCookie       uint         XOR security cookie\n  -0x10   10      doubleBuf            _LDBL12      Double conversion buffer\n  -0x2a   1       signByte             byte         Sign character\n  -0x2c   2       decimalPosition      short        Decimal point position\n  -0x28   24      strfltArray          uint[6]      Format output array\n  -0x34   4       local_34             uint         Additional buffer space",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:91e85de7f1df15bac4c74b0caf518a31",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "91e85de7f1df15bac4c74b0caf518a31",
        "CFG": null,
        "PRO": "0deb23a0825f9d852d60b8316eebe252"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "91e85de7f1df15bac4c74b0caf518a31"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_4ccc97743d98": {
      "addresses": {
        "LoD/PD2": "0x6F9BCB1C"
      },
      "rvas": {
        "LoD/PD2": "0xCB1C"
      },
      "sizes": {
        "LoD/PD2": 146
      },
      "name": "__abstract_cw",
      "signature": "uint __abstract_cw(void)",
      "calling_convention": "__stdcall",
      "comment": "Convert x87 FPU control word to abstract control word format\n\nAlgorithm:\n1. Initialize abstract control word to 0\n2. Map exception mask bits from FPU format to abstract format\n   - Invalid operation (bit 0 \u2192 bit 4): 0x01 \u2192 0x10\n   - Denormal operand (bit 1 \u2192 bit 19): 0x02 \u2192 0x80000  \n   - Divide by zero (bit 2 \u2192 bit 3): 0x04 \u2192 0x08\n   - Overflow (bit 3 \u2192 bit 2): 0x08 \u2192 0x04\n   - Underflow (bit 4 \u2192 bit 1): 0x10 \u2192 0x02\n   - Precision (bit 5 \u2192 bit 0): 0x20 \u2192 0x01\n3. Map precision control bits (bits 8-9 \u2192 bits 8-9):\n   - 24-bit (0x000 \u2192 0x20000): Single precision default\n   - 53-bit (0x200 \u2192 0x10000): Double precision  \n   - 64-bit (0x300 \u2192 0x00000): Extended precision (no flag)\n4. Map rounding control bits (bits 10-11 \u2192 bits 8-9):\n   - Round to nearest (0x000 \u2192 no bits): Default rounding\n   - Round down (0x400 \u2192 0x100): Toward negative infinity\n   - Round up (0x800 \u2192 0x200): Toward positive infinity  \n   - Round toward zero (0xC00 \u2192 0x300): Truncation\n5. Map infinity control bit (bit 12 \u2192 bit 18): 0x1000 \u2192 0x40000\n\nParameters:\nIMPLICIT BX - x87 FPU control word (16-bit value)\n\nReturns:\nuint - Abstract control word with remapped bit fields\n\nMagic Numbers Reference:\n0x01 - Invalid operation mask in FPU format\n0x02 - Denormal operand mask in FPU format  \n0x04 - Divide by zero mask in FPU format\n0x08 - Overflow mask in FPU format\n0x10 - Underflow mask in FPU format\n0x20 - Precision mask in FPU format\n0x300 - Precision control field mask (bits 8-9)\n0x200 - 53-bit precision control value\n0xC00 - Rounding control field mask (bits 10-11)\n0x400 - Round down control value\n0x800 - Round up control value\n0xC00 - Round toward zero control value\n0x1000 - Infinity control bit (bit 12)\n0x10000 - Double precision flag in abstract format\n0x20000 - Single precision flag in abstract format\n0x40000 - Infinity control flag in abstract format\n0x80000 - Denormal exception flag in abstract format",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4ccc97743d9837257b044f8cb70aafb7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4ccc97743d9837257b044f8cb70aafb7",
        "CFG": "30497491f77bd5f594f7bc3b4d751710",
        "PRO": "d7747158697a2b9b9c62ab34cb2090d5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4ccc97743d9837257b044f8cb70aafb7"
      }
    },
    "D2sound_MNE_573ef52db1c0": {
      "addresses": {
        "LoD/PD2": "0x6F9BCBAE"
      },
      "rvas": {
        "LoD/PD2": "0xCBAE"
      },
      "sizes": {
        "LoD/PD2": 142
      },
      "name": "__hw_cw",
      "signature": "uint __hw_cw(void)",
      "calling_convention": "__stdcall",
      "comment": "Convert hardware floating-point control word format to standard format.\n\nAlgorithm:\n1. Extract exception mask bits from hardware format and remap to standard positions\n2. Convert precision control bits (0x300 mask) to standard format \n3. Convert rounding control bits (0x30000 mask) to standard format\n4. Set infinity control bit (0x40000) if present in hardware format\n5. Return converted control word in standard format\n\nParameters:\nIMPLICIT dwHwControlWord (EBX) - Hardware control word with vendor-specific bit layout\n\nReturns:\nuint - Converted control word in standard C runtime format\n  0x00 - Success with converted control word\n  Bit layout: Exception masks (0x3F), Precision (0x300), Rounding (0xC00), Infinity (0x1000)\n\nMagic Numbers Reference:\n0x01 - Invalid operation exception mask (hardware bit 0)\n0x02 - Denormalized exception mask (hardware bit 1) \n0x04 - Zero divide exception mask (hardware bit 2)\n0x08 - Overflow exception mask (hardware bit 3)\n0x10 - Underflow exception mask (hardware bit 4)\n0x20 - Precision exception mask (hardware bit 5)\n0x80000 - Denormalized exception mask (hardware bit 19)\n0x100 - Single precision (hardware format)\n0x200 - Double precision (hardware format)\n0x300 - Extended precision (hardware format)\n0x10000 - Round down (hardware format)\n0x20000 - Round up (hardware format)\n0x30000 - Round to zero (hardware format)\n0x40000 - Infinity control (hardware format)\n\nBit Mapping:\nHardware Bit \u2192 Standard Bit\n0x01 \u2192 0x20 (Invalid operation)\n0x02 \u2192 0x10 (Zero divide)\n0x04 \u2192 0x08 (Overflow)\n0x08 \u2192 0x04 (Underflow)\n0x10 \u2192 0x01 (Precision)\n0x80000 \u2192 0x02 (Denormalized)\n0x100 \u2192 0x400 (Single precision)\n0x200 \u2192 0x800 (Double precision)  \n0x300 \u2192 0xC00 (Extended precision)\n0x00 \u2192 0x300 (Default precision when none set)\n0x10000 \u2192 0x200 (Round down)\n0x00 \u2192 0x300 (Default rounding when none set)\n0x40000 \u2192 0x1000 (Infinity control)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:573ef52db1c0502425f5c4477c52e1c6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "573ef52db1c0502425f5c4477c52e1c6",
        "CFG": "5e9cf973cf6c6a6c6fd62abfd520d057",
        "PRO": "c929b45524c8dcacc1c64778a74bb7de"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "573ef52db1c0502425f5c4477c52e1c6"
      }
    },
    "D2sound_MNE_d0e2b07b7895": {
      "addresses": {
        "LoD/PD2": "0x6F9BCC3C"
      },
      "rvas": {
        "LoD/PD2": "0xCC3C"
      },
      "sizes": {
        "LoD/PD2": 50
      },
      "name": "__control87",
      "signature": "uint __control87(uint _NewValue, uint _Mask)",
      "calling_convention": "__cdecl",
      "comment": "Modify floating-point control word with selective bit masking.\n\nAlgorithm:\n1. Get current abstract control word state via __abstract_cw()\n2. Save current FPU control word to local stack storage (FSTCW)\n3. Apply hardware control word changes via __hw_cw()\n4. Compute new control word: (current & ~mask) | (newvalue & mask)\n5. Restore FPU control word from stack storage (FLDCW)\n6. Return the computed control word result\n\nParameters:\n- _NewValue (uint): New control word bits to apply where mask bits are set\n- _Mask (uint): Bitmask specifying which control word bits to modify\n\nReturns:\n- uint: Resulting control word after applying masked changes\n- Returns combination of preserved original bits and new masked bits\n\nVariables:\n- uVar1 (dwCurrentControl): Current abstract control word returned by __abstract_cw()\n- local_8 (wControlWord): Stack storage for FPU control word (FSTCW/FLDCW operations)\n\nSpecial Cases:\n- If _Mask is 0x00000000, no changes applied, returns current control word\n- If _Mask is 0xFFFFFFFF, completely replaces control word with _NewValue\n- Hardware control word changes affect actual FPU state\n- Abstract control word represents software-level control state\n\nMagic Numbers Reference:\n- Control word bits follow x87 FPU specification\n- Common masks: 0x0F3F (precision/rounding), 0x003F (exception masks)\n- Rounding modes: 0x0000 (nearest), 0x0400 (down), 0x0800 (up), 0x0C00 (truncate)\n\nError Handling:\n- No explicit error checking performed\n- Invalid control word values passed through to hardware\n- Relies on FPU hardware to handle invalid bit combinations\n- Function assumes valid FPU state exists\n\nNote: Function uses assembly-only variable local_8 for FPU control word storage that was optimized away in decompiled view.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d0e2b07b7895a0cd732f2691caec5399",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d0e2b07b7895a0cd732f2691caec5399",
        "CFG": null,
        "PRO": "6c88070a9d1b3bf10cd919663a9c03e2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d0e2b07b7895a0cd732f2691caec5399"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_03d2d9a1894b": {
      "addresses": {
        "LoD/PD2": "0x6F9BCC6E"
      },
      "rvas": {
        "LoD/PD2": "0xCC6E"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "__controlfp",
      "signature": "uint __controlfp(uint _NewValue, uint _Mask)",
      "calling_convention": "__cdecl",
      "comment": "Wrapper function to control floating-point processor behavior with legacy compatibility.\n\nAlgorithm:\n1. Accept new control value and mask parameters\n2. Apply compatibility mask (0xfff7ffff) to remove unsupported bits\n3. Call __control87 with filtered mask to set processor control word\n4. Return the previous control word value\n\nParameters:\n_NewValue (uint): New floating-point control word value to set\n_Mask (uint): Mask specifying which control bits to modify\n\nReturns:\nuint: Previous floating-point control word value before modification\nZero: If control operation fails or processor doesn't support floating-point\n\nSpecial Cases:\nCompatibility mask 0xfff7ffff removes bit 19 (0x00080000) for legacy compatibility\nThis ensures compatibility with older floating-point control implementations\n\nMagic Numbers Reference:\n0xfff7ffff: Compatibility mask removing bit 19 for legacy support\n  Decimal: 4294836223\n  Binary: 11111111111101111111111111111111\n  Purpose: Filters out modern control bits not supported by legacy implementations",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:03d2d9a1894bad6481c3d75928ae7b95",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "03d2d9a1894bad6481c3d75928ae7b95",
        "CFG": null,
        "PRO": "1d8ceb55870a92a5d13ad99654078b9d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "03d2d9a1894bad6481c3d75928ae7b95"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_STR_370b8cbe1369": {
      "addresses": {
        "LoD/PD2": "0x6F9BCC84"
      },
      "rvas": {
        "LoD/PD2": "0xCC84"
      },
      "sizes": {
        "LoD/PD2": 631
      },
      "name": "InvokeFloatingPointMath",
      "signature": "void InvokeFloatingPointMath(double * pOperand1, double * pOperand2, double * pResult, int functionCode)",
      "calling_convention": "__cdecl",
      "comment": "Dispatches to appropriate floating-point math function based on opcode.\n\nAlgorithm:\n1. Initialize stack canary for buffer overflow protection\n2. Load function code parameter and compare against 0xa1 (161 decimal)\n3. If code <= 0xa1: dispatch to functions 0x2-0x1d (add, subtract, multiply, divide, exponential, logarithm variants)\n4. If code > 0xa1: dispatch to functions 0xa2-0x3ef (extended math operations)\n5. For each matched code, determine operation type and mode flag:\n   - Mode 1: Single parameter operation (e.g., absolute value)\n   - Mode 2: Two parameter operation with validation\n   - Mode 3: Special operation (e.g., floor)\n   - Mode 4: Extended operation with return value check\n6. Load three double-precision parameters from stack (operand1, operand2, result)\n7. Call selected math function via function pointer at [0x6f9c5c00]\n8. Test return value: if zero (failure), get thread errno and set EINVAL (0x22) or EDOM (0x21)\n9. Store result value in output parameter\n10. Verify stack canary before returning\n\nFunction codes dispatch table (selected):\n- 0x2: Subtract operation\n- 0x3: Multiply operation\n- 0x8: Logarithm base 10\n- 0x9: Natural logarithm\n- 0xe/0xf: Power operation\n- 0x18-0x1d: Extended operations\n- 0xa1: Single parameter operation\n- 0xa2-0x3ef: Extended math operations\n\nParameters:\n- pOperand1 (double*): First operand or special value input\n- pOperand2 (double*): Second operand (may be unused for single-param ops)\n- pResult (double*): Output buffer for result value\n- functionCode (int): Opcode selecting which math function to execute\n\nReturns:\n- void (result written to pResult parameter)\n- On error: errno set to EINVAL (invalid argument) or EDOM (domain error)\n\nError codes:\n- EINVAL (0x22): Invalid parameter or unsupported function code\n- EDOM (0x21): Math domain error (e.g., sqrt of negative, log of zero)\n\nSpecial cases:\n- Code 0x1a returns constant 1.0 (2^0) without function call\n- Code 0x1b uses FLD1 instruction to load 1.0 constant\n- Stack canary XOR check prevents buffer overflow exploitation\n- All FPU operations use stack-based parameter passing",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:370b8cbe13698caeaaee92ddff8255c1",
      "indexes": {
        "EXP": null,
        "STR": "370b8cbe13698caeaaee92ddff8255c1",
        "API": null,
        "MNE": "d52f75ee99221e82332ba1e2c1d2bafa",
        "CFG": "ca4b3470541a7f1b4af2350254cd4523",
        "PRO": "5f747f85b3a5188536b2daa855966508"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d52f75ee99221e82332ba1e2c1d2bafa"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2sound_MNE_8193641d08c8": {
      "addresses": {
        "LoD/PD2": "0x6F9BCEFB"
      },
      "rvas": {
        "LoD/PD2": "0xCEFB"
      },
      "sizes": {
        "LoD/PD2": 252
      },
      "name": "HandleFloatingPointException",
      "signature": "void HandleFloatingPointException(int exceptionCode, int * pExceptionStatus, ushort * pExceptionInfo)",
      "calling_convention": "__cdecl",
      "comment": "Handles C++ floating-point runtime exceptions with exception type routing and FP state management.\n\nALGORITHM:\n1. Load and validate status value from pExceptionStatus[0] (range 1-8)\n2. Route to appropriate handler mode based on status value:\n   - Status 1 or 5: Set handler mode to 8\n   - Status 2: Set handler mode to 4\n   - Status 3: Set handler mode to 0x11\n   - Status 4: Set handler mode to 0x12\n   - Status 6: Reset pExceptionStatus[0] to 1 and continue\n   - Status 7: Set pExceptionStatus[0] to 1\n   - Status 8: Set handler mode to 0x10\n   - Other: Continue without handler mode\n3. Pop handler mode into EBX and call __handle_exc with exception context\n4. If handler succeeds, route based on exception code (0x10, 0x16, 0x1d):\n   - If matched: Set FP control bits 0-1 to 3\n   - If not matched: Clear FP control bit 0\n5. Call __raise_exc with exception parameters and FP state\n6. Call InitializeFloatingPointMode if status != 8 and global flag not set\n7. Set thread error code with current status value\n8. Verify stack guard before cleanup and return\n\nPARAMETERS:\n  exceptionCode (int): Exception code type (checked for 0x10, 0x16, 0x1d)\n  pExceptionStatus (int *): Pointer to status/mode value (values 1-8)\n  pExceptionInfo (ushort *): Pointer to exception information\n\nRETURNS:\n  void - Exception handled, FP state initialized if needed\n\nSPECIAL CASES:\n  - Stack guard verification for buffer overflow protection\n  - FP mode bits modified based on exception code\n  - Status 6: Special handling resets to 1 before processing\n  - Global flag check controls FP initialization\n  - Status values 1-8 map to handler modes 0x4-0x12",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8193641d08c8ae704d69d5b8c671a293",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8193641d08c8ae704d69d5b8c671a293",
        "CFG": "68ba03bdb68dfed29f9a239223d5f39b",
        "PRO": "58a0a97d65f99e60005970b0d73b1e03"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8193641d08c8ae704d69d5b8c671a293"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_5b53deeaee2f": {
      "addresses": {
        "LoD/PD2": "0x6F9BCFF7"
      },
      "rvas": {
        "LoD/PD2": "0xCFF7"
      },
      "sizes": {
        "LoD/PD2": 17
      },
      "name": "__frnd",
      "signature": "float10 __frnd(double param_1)",
      "calling_convention": "__cdecl",
      "comment": "Round double-precision floating-point value to integer using x87 FRNDINT instruction.\n\nAlgorithm:\n\n1. Load double-precision parameter onto x87 FPU stack\n2. Execute FRNDINT instruction to round according to current rounding mode  \n3. Store rounded result as 80-bit extended precision value\n4. Return extended precision result\n\nParameters:\n\nparam_1 (double): Double-precision floating-point value to round\n\nReturns:\n\nfloat10: Extended precision (80-bit) rounded value\n- Rounding behavior depends on x87 control word rounding mode:\n  - 0x00: Round to nearest even (default)\n  - 0x01: Round down (toward negative infinity)\n  - 0x02: Round up (toward positive infinity) \n  - 0x03: Round toward zero (truncate)\n\nSpecial Cases:\n\n- Input \u00b1infinity returns \u00b1infinity unchanged\n- Input NaN returns NaN unchanged\n- Input values already integers return unchanged\n- Rounding mode controlled by x87 FPU control word bits RC[1:0]",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5b53deeaee2f2e36d1b6e935bca6b0ee",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5b53deeaee2f2e36d1b6e935bca6b0ee",
        "CFG": null,
        "PRO": "ad394f0243f0259f439ca5dfcaed752f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5b53deeaee2f2e36d1b6e935bca6b0ee"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_524fd89ddf8c": {
      "addresses": {
        "LoD/PD2": "0x6F9BD008"
      },
      "rvas": {
        "LoD/PD2": "0xD008"
      },
      "sizes": {
        "LoD/PD2": 156
      },
      "name": "__fpclass",
      "signature": "int __fpclass(double _X)",
      "calling_convention": "__cdecl",
      "comment": "Classifies IEEE 754 double-precision floating point values into standard categories.\n\nAlgorithm:\n1. Extract exponent bits (_X._6_2_ & 0x7ff0) and check for special values (infinity/NaN)\n2. If exponent is 0x7ff0 (all bits set), call __sptype to determine special type\n3. Map __sptype results: 1 \u2192 0x200 (quiet NaN), 2 \u2192 4 (signaling NaN), 3 \u2192 2 (infinity), other \u2192 1 (invalid)\n4. Check for denormal numbers: exponent is 0 but mantissa is non-zero\n5. Return classification based on sign bit and value characteristics\n6. Handle zero values by comparing with global constant _DAT_6f9c0988\n7. Return normal number classification based on sign bit\n\nParameters:\n- _X (double): IEEE 754 double-precision value to classify\n\nReturns:\n- 0x200: Quiet NaN\n- 0x100: Positive normal number  \n- 0x080: Positive denormal number\n- 0x040: Positive zero\n- 0x008: Negative normal number\n- 0x010: Negative denormal number  \n- 0x020: Negative zero\n- 4: Signaling NaN\n- 2: Infinity (positive or negative)\n- 1: Invalid/undefined classification\n\nSpecial Cases:\n- Uses bit manipulation to extract IEEE 754 components\n- Handles both positive and negative zero detection\n- Leverages __sptype helper for NaN/infinity classification\n\nMagic Numbers Reference:\n- 0x7ff0: IEEE 754 exponent mask for double precision\n- 0x7ff0000000000000: Full exponent field mask  \n- 0x8000000000000000: Sign bit mask\n- 0xfffff00000000: Mantissa high bits mask\n- 0x200: Quiet NaN classification code\n- 0x100: Positive normal classification base\n- 0x080: Positive denormal classification base  \n- 0x040: Positive zero classification base\n\nNote: Function uses 1 stack-allocated temporary variable optimized away by decompiler.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:524fd89ddf8cd302152cccf17782ec81",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "524fd89ddf8cd302152cccf17782ec81",
        "CFG": "65e7da282a57368285623946497912d5",
        "PRO": "b05dea8c225bd5ec0b6e686bb0d96923"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "524fd89ddf8cd302152cccf17782ec81"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_c2d88561bc66": {
      "addresses": {
        "LoD/PD2": "0x6F9BD0A4"
      },
      "rvas": {
        "LoD/PD2": "0xD0A4"
      },
      "sizes": {
        "LoD/PD2": 42
      },
      "name": "__set_exp",
      "signature": "float10 __set_exp(undefined8 param_1, short param_2)",
      "calling_convention": "__cdecl",
      "comment": "IEEE 754 double-precision floating-point exponent manipulation function\n\nAlgorithm:\n1. Extract mantissa bits from input double-precision value (param_1)\n2. Add bias adjustment (param_2) to IEEE 754 double-precision bias (0x3fe = 1022)\n3. Shift adjusted exponent to proper bit position (bits 52-62 in double format)\n4. Combine with sign bit and mantissa fraction from original value\n5. Construct new double-precision value with modified exponent\n6. Return result as extended precision float10\n\nParameters:\n- param_1 (undefined8 \u2192 double): Source double-precision floating-point value containing mantissa and original exponent\n- param_2 (short): Exponent bias adjustment value to be added to current exponent\n\nReturns:\n- float10: Extended precision floating-point result with adjusted exponent\n- Uses IEEE 754 double-precision intermediate representation before conversion\n\nSpecial Cases:\n- 0x3fe: IEEE 754 double-precision exponent bias (1023 - 1 = 1022)\n- 0x10: Left shift by 4 bits to position exponent in bits 4-14 of high word\n- 0x800f: Mask preserving sign bit (0x8000) and lower mantissa bits (0x000f)\n- CONCAT26: Ghidra operator combining 2-byte and 6-byte values into 8-byte result\n\nMagic Numbers Reference:\n- 0x3fe (1022): IEEE 754 double-precision exponent bias minus 1\n- 0x10 (16): Bit shift multiplier to position exponent field  \n- 0x800f: Bit mask for sign + lower mantissa preservation\n- _6_2_: Byte slice operator accessing bytes 6-7 of 8-byte double\n\nError Handling:\n- No explicit overflow/underflow checking\n- Relies on IEEE 754 standard behavior for extreme exponent values\n- Invalid inputs may produce infinity, NaN, or denormal results\n\nIEEE 754 Double-Precision Bit Layout (64-bit):\nOffset  Size  Field Name    Type    Description\n0-5     6     Mantissa_Lo   int6    Lower 48 bits of mantissa fraction\n6-7     2     Exp_Mantissa  short   Upper 4 mantissa bits + 11 exponent bits + 1 sign bit\n        Bit   Field         Mask    Purpose\n        63    Sign          0x8000  Sign bit (0=positive, 1=negative)\n        52-62 Exponent      0x7ff0  11-bit biased exponent (bias=1023)\n        0-51  Mantissa      0x000f  52-bit mantissa fraction (implicit leading 1)\n\nAlgorithm Step Implementation:\nStep 1-2: param_2 + 0x3fe (add bias adjustment to 1022)\nStep 3: * 0x10 (shift to exponent bit position)  \nStep 4: | param_1._6_2_ & 0x800f (combine with sign + lower mantissa)\nStep 5: CONCAT26(..., (int6)param_1) (rebuild 64-bit double)\nStep 6: return (float10)local_c (convert to extended precision)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c2d88561bc66a9a3fa3664be1df6f9e8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c2d88561bc66a9a3fa3664be1df6f9e8",
        "CFG": null,
        "PRO": "a9df541ebd1c78a9489ce2fd30a9b726"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c2d88561bc66a9a3fa3664be1df6f9e8"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_2ec5ac5ebb61": {
      "addresses": {
        "LoD/PD2": "0x6F9BD0CE"
      },
      "rvas": {
        "LoD/PD2": "0xD0CE"
      },
      "sizes": {
        "LoD/PD2": 91
      },
      "name": "__sptype",
      "signature": "int __sptype(int nMantissaLow, uint dwExponentHigh)",
      "calling_convention": "__cdecl",
      "comment": "Classifies IEEE 754 double-precision floating-point special values\n\nAlgorithm:\n1. Check if dwExponentHigh equals 0x7ff00000 (positive infinity pattern)\n   - If nMantissaLow is zero, return 1 (positive infinity)\n2. Check if dwExponentHigh equals 0xfff00000 (negative infinity pattern) \n   - If nMantissaLow is zero, return 2 (negative infinity)\n3. Extract upper 13 bits of dwExponentHigh and test for NaN pattern\n   - If (dwExponentHigh._2_2_ & 0x7ff8) equals 0x7ff8, return 3 (NaN)\n4. Check for general infinity pattern with non-zero mantissa\n   - If upper bits match 0x7ff0 but mantissa parts are non-zero, return 4 (infinity with mantissa)\n5. If no special patterns match, return 0 (normal number)\n\nParameters:\nnMantissaLow (int): Lower 32-bit mantissa portion of IEEE 754 double\ndwExponentHigh (uint): Upper 32-bit portion containing sign, exponent, and upper mantissa bits\n\nReturns:\n0: Normal finite number or zero\n1: Positive infinity (+INF)\n2: Negative infinity (-INF) \n3: Not a Number (NaN)\n4: Infinity with non-zero mantissa bits\n\nSpecial Cases:\n- Function processes split IEEE 754 double as two 32-bit integers\n- Uses bit masking to extract exponent and mantissa components\n- Pattern 0x7ff00000 identifies positive infinity when mantissa is zero\n- Pattern 0xfff00000 identifies negative infinity when mantissa is zero\n- Mask 0x7ff8 on upper 16 bits detects NaN values\n- Mask 0x7ff0 on upper 16 bits detects infinity patterns\n\nMagic Numbers Reference:\n0x7ff00000: Positive infinity bit pattern in upper 32 bits\n0xfff00000: Negative infinity bit pattern in upper 32 bits  \n0x7ff8: Mask for NaN detection on upper 13 bits\n0x7ff0: Mask for infinity detection on upper 12 bits\n0x7ffff: Mask for upper mantissa bits (19 bits)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2ec5ac5ebb611e5364351abf011810d6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2ec5ac5ebb611e5364351abf011810d6",
        "CFG": "cca987bf92bb6ff6c3156fd073775652",
        "PRO": "614e71bfd9f37d6578ef0d371da967f9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2ec5ac5ebb611e5364351abf011810d6"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_9e04031ea01b": {
      "addresses": {
        "LoD/PD2": "0x6F9BD129"
      },
      "rvas": {
        "LoD/PD2": "0xD129"
      },
      "sizes": {
        "LoD/PD2": 188
      },
      "name": "__decomp",
      "signature": "float10 __decomp(uint param_1, uint param_2, int * param_3)",
      "calling_convention": "__cdecl",
      "comment": "Decomposes a double-precision floating-point number into mantissa and exponent components.\n\nAlgorithm:\n1. Check for special case where input equals _DAT_6f9c0988 (returns zero mantissa/exponent)\n2. Handle denormalized numbers (exponent field is zero but mantissa non-zero)\n3. Normalize denormalized values by shifting left until bit 4 of byte 2 is set\n4. Set sign bit if original value was negative\n5. Call __set_exp to construct normalized floating-point value with zero exponent\n6. Calculate and store exponent value in output parameter\n7. Return normalized mantissa as float10\n\nParameters:\ndwMantissaLow - Low 32 bits of double-precision input value\ndwMantissaHigh - High 32 bits of double-precision input value  \npnExponent - Pointer to integer where exponent will be stored\n\nReturns:\nfloat10 normalized mantissa value (exponent removed)\n\nSpecial Cases:\n- Input equals _DAT_6f9c0988: Returns 0.0 with exponent 0\n- Denormalized numbers: Normalized before decomposition\n- Normal numbers: Exponent extracted and mantissa normalized\n\nMagic Numbers:\n0x7ff00000 - IEEE 754 exponent mask for double precision\n0xfffff - IEEE 754 mantissa mask for high word  \n0x80000000 - Sign bit mask for 32-bit value\n0x10 - Normalization check bit (bit 4 of mantissa high byte)\n0x3fe - IEEE 754 exponent bias adjustment (1023 - 1)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9e04031ea01b653d189e39211f9b145c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9e04031ea01b653d189e39211f9b145c",
        "CFG": "e79118e273ac7d5c9c6df16f78e099a8",
        "PRO": "03dbab0725c0461c6cba45e54ad6929f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9e04031ea01b653d189e39211f9b145c"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_c4400c8562aa": {
      "addresses": {
        "LoD/PD2": "0x6F9BD1E5"
      },
      "rvas": {
        "LoD/PD2": "0xD1E5"
      },
      "sizes": {
        "LoD/PD2": 33
      },
      "name": "___addl",
      "signature": "uint ___addl(uint dwAddend1, uint dwAddend2, uint * pdwResult)",
      "calling_convention": "__cdecl",
      "comment": "Performs unsigned 32-bit addition with overflow detection.\n\nAlgorithm:\n1. Add the two unsigned 32-bit operands (dwAddend1 + dwAddend2)\n2. Check for overflow by comparing result against both operands\n3. Set carry flag to 1 if overflow occurred, 0 if no overflow\n4. Store the sum result in the output pointer\n5. Return the carry flag\n\nParameters:\ndwAddend1 - First unsigned 32-bit operand for addition\ndwAddend2 - Second unsigned 32-bit operand for addition  \npdwResult - Pointer to store the 32-bit sum result\n\nReturns:\n0 - No overflow occurred, result is valid\n1 - Overflow occurred, result wrapped around\n\nSpecial Cases:\n- Overflow detection uses condition: (result < dwAddend1) || (result < dwAddend2)\n- This is a standard library function for checked arithmetic operations\n- Visual Studio 2003 Release runtime library implementation\n\nMagic Numbers Reference:\n0x0 - No overflow/carry flag clear\n0x1 - Overflow detected/carry flag set\n\nError Handling:\n- No explicit error handling - assumes valid input pointers\n- Overflow is detected and reported via return value\n- Result pointer must be valid (no NULL check performed)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c4400c8562aa84099781d0cf50c17c5c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c4400c8562aa84099781d0cf50c17c5c",
        "CFG": "5ac69ddc4dc620d0fa43b9c6ebcc7e34",
        "PRO": "4788371aeb00092042a82d0f103cc412"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c4400c8562aa84099781d0cf50c17c5c"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_8d620fa28637": {
      "addresses": {
        "LoD/PD2": "0x6F9BD206"
      },
      "rvas": {
        "LoD/PD2": "0xD206"
      },
      "sizes": {
        "LoD/PD2": 94
      },
      "name": "___add_12",
      "signature": "void ___add_12(uint * pdwFirst, uint * pdwSecond)",
      "calling_convention": "__cdecl",
      "comment": "Performs 96-bit addition of two unsigned integers with carry propagation\n\nAlgorithm:\n1. Add LSB (Least Significant) 32-bit words using ___addl with carry detection\n2. If carry from step 1, propagate carry to middle word by adding 1\n3. If carry from step 2, propagate carry to MSB word by adding 1  \n4. Add middle 32-bit words using ___addl with carry detection\n5. If carry from step 4, propagate carry to MSB word by adding 1\n6. Add MSB (Most Significant) 32-bit words using ___addl (no carry handling needed)\n\nParameters:\n  pdwFirst  - uint * - Pointer to first 96-bit number (3 consecutive uint values), modified in-place\n  pdwSecond - uint * - Pointer to second 96-bit number (3 consecutive uint values), read-only\n\nReturns:\n  void - Result stored in pdwFirst array, overwrites original first operand\n\nSpecial Cases:\n  Overflow from MSB addition is ignored (no carry beyond 96 bits)\n  Both arrays must contain exactly 3 consecutive uint values (12 bytes total)\n\nStructure Layout:\n  Offset  Size  Field Name    Type   Description\n  0x00    4     dwLSB        uint   Least Significant 32-bit word\n  0x04    4     dwMiddle     uint   Middle 32-bit word  \n  0x08    4     dwMSB        uint   Most Significant 32-bit word",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8d620fa2863768144d8aebe01f0829de",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8d620fa2863768144d8aebe01f0829de",
        "CFG": "8de88aa5a2ff6c2a27fe35242cac67b4",
        "PRO": "592cde8777105acd14104e1a687e5fa8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8d620fa2863768144d8aebe01f0829de"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_ecf23adbf69d": {
      "addresses": {
        "LoD/PD2": "0x6F9BD264"
      },
      "rvas": {
        "LoD/PD2": "0xD264"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "___shl_12",
      "signature": "void ___shl_12(uint * pdwNumber96)",
      "calling_convention": "__cdecl",
      "comment": "Visual Studio 2003 runtime library function performing 12-bit left shift on 96-bit number.\n\nAlgorithm:\n1. Load lower 32 bits (pdwNumber96[0]) and middle 32 bits (pdwNumber96[1]) into temporary variables\n2. Shift lower 32 bits left by 1 bit, store back to pdwNumber96[0]\n3. Shift middle 32 bits left by 1 bit, OR with overflow from lower 32 bits (bit 31), store to pdwNumber96[1]\n4. Shift upper 32 bits (pdwNumber96[2]) left by 1 bit, OR with overflow from middle 32 bits (bit 31), store to pdwNumber96[2]\n5. Return (void)\n\nParameters:\npdwNumber96 (uint *): Pointer to 96-bit number stored as array of 3 consecutive uint values\n                      [0] = Lower 32 bits (bits 0-31)\n                      [1] = Middle 32 bits (bits 32-63) \n                      [2] = Upper 32 bits (bits 64-95)\n\nReturns:\nvoid - Function modifies the 96-bit number in-place\n\nSpecial Cases:\n- No bounds checking performed on pointer parameter\n- Assumes pdwNumber96 points to valid array of at least 3 uint elements\n- Bit overflow from upper 32 bits is lost (bits above 95 discarded)\n- Function performs exactly 12 iterations of 1-bit left shift when called 12 times\n\nMagic Numbers Reference:\n0x1f (31 decimal): Bit mask for extracting bit 31 (highest bit in 32-bit uint)\n                   Used to capture overflow bit from lower/middle words\n\nError Handling:\n- No error checking for NULL pointer\n- No validation of memory access bounds\n- Caller responsible for ensuring valid 96-bit number buffer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ecf23adbf69da5c45f5232ddf63ff9c3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ecf23adbf69da5c45f5232ddf63ff9c3",
        "CFG": null,
        "PRO": "636133735ea2668356c76a7d7c718ca0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ecf23adbf69da5c45f5232ddf63ff9c3"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_df39be31c90d": {
      "addresses": {
        "LoD/PD2": "0x6F9BD292"
      },
      "rvas": {
        "LoD/PD2": "0xD292"
      },
      "sizes": {
        "LoD/PD2": 45
      },
      "name": "___shr_12",
      "signature": "void ___shr_12(uint * pdwNumber)",
      "calling_convention": "__cdecl",
      "comment": "Performs single-bit right shift operation on 96-bit (3-DWORD) multi-precision number\n\nAlgorithm:\n1. Store middle word (pdwNumber[1]) in temporary variable\n2. Shift middle word right by 1 bit, fill high bit with low bit from high word\n3. Shift high word (pdwNumber[2]) right by 1 bit\n4. Shift low word (pdwNumber[0]) right by 1 bit, fill high bit with low bit from middle word\n\nParameters:\npdwNumber - Pointer to 3-element DWORD array representing 96-bit number\n          - [0] = Low word (bits 0-31)\n          - [1] = Middle word (bits 32-63) \n          - [2] = High word (bits 64-95)\n\nReturns:\nvoid - Result stored in-place in pdwNumber array\n\nSpecial Cases:\nOperates on big-endian word order for multi-precision arithmetic\n\nMagic Numbers Reference:\n0x1f (31 decimal) - Bit shift count to move bit 0 to bit 31 position",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:df39be31c90d40388c4132cbde70d848",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "df39be31c90d40388c4132cbde70d848",
        "CFG": null,
        "PRO": "23addef651b78e84b59c048c86318797"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "df39be31c90d40388c4132cbde70d848"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_6dd9e098c401": {
      "addresses": {
        "LoD/PD2": "0x6F9BD2BF"
      },
      "rvas": {
        "LoD/PD2": "0xD2BF"
      },
      "sizes": {
        "LoD/PD2": 232
      },
      "name": "ConvertSignificandToMantissa",
      "signature": "void ConvertSignificandToMantissa(char * significandDigits, int digitCount, uint * pMantissa12)",
      "calling_convention": "__cdecl",
      "comment": "Converts a string of decimal digits to normalized binary mantissa with exponent.\n\nThis function implements a decimal significand to binary mantissa conversion using\niterative multiplication by 10 (implemented as SHL\u00d74 + ADD). The resulting 96-bit\nmantissa is normalized so the high bit of the upper 32-bit word (bits 95-64) is set,\nand the exponent is adjusted accordingly to maintain the value.\n\nAlgorithm:\n1. Initialize the 96-bit mantissa [12 bytes / 3 dwords] to zero at [EBX+0], [EBX+4], [EBX+8]\n2. If digitCount is 0, skip to normalization phase\n3. For each decimal digit in the string:\n   - Shift mantissa left by 4 bits (SHL_12 called 3 times = multiply by 2^4 = 16)\n   - Load next digit character (0-9) as a value\n   - Shift mantissa left by 1 more bit (total 5 bits = multiply by 32)\n   - Add the digit value to the mantissa\n   - Move to next character in input string\n4. After all digits processed, normalize the mantissa:\n   - If [EBX+8] (high word) is zero, perform 16-bit rotation of all three words\n     Extract high 16 bits of [EBX+4] \u2192 [EBX+8], shift remaining words down\n     Repeat until [EBX+8] is non-zero, decrement exponent by 16 for each rotation\n5. Final alignment: shift mantissa left until bit 15 of [EBX+8] is set (0x8000)\n   Decrement the exponent value by 1 for each single-bit shift\n6. Store the final exponent value at offset +10 in the mantissa structure\n\nParameters:\n- significandDigits (char*): Pointer to first digit character (0-9 ASCII values)\n- digitCount (int): Number of digits to process (e.g., 25 for normalized form)\n- pMantissa12 (uint*): Pointer to 12-byte output structure with three 32-bit words\n\nReturns:\n- No return value; result stored at *pMantissa12\n\nSpecial Cases:\n- digitCount = 0: Mantissa set to zero, exponent set to 0x404e (initial default)\n- All digits are zero: Result is 0, exponent remains 0x404e\n- Mantissa overflow: Normalized to 96-bit representation with exponent adjustment\n- Final normalization ensures [EBX+8] has bit 15 set for consistent representation\n\nStructure Layout:\nOffset  Size  Field Name        Type      Description\n------  ----  ---------------   --------  ------------------------------------\n+0      4     mantissaLow       uint      Bits 31-0 of 96-bit mantissa\n+4      4     mantissaMid       uint      Bits 63-32 of 96-bit mantissa\n+8      4     mantissaHigh      uint      Bits 95-64 of 96-bit mantissa\n+10     2     exponent          ushort    16-bit signed exponent value\n\nNote: Function uses 1 stack-allocated temporary variable (local_18) optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6dd9e098c401c5314529c240c6cfca58",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6dd9e098c401c5314529c240c6cfca58",
        "CFG": "722ed1e82370bd3730433905371ea209",
        "PRO": "f3f02189f026b250f7c2eeea015b9547"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6dd9e098c401c5314529c240c6cfca58"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_51067a812fad": {
      "addresses": {
        "LoD/PD2": "0x6F9BD3A7"
      },
      "rvas": {
        "LoD/PD2": "0xD3A7"
      },
      "sizes": {
        "LoD/PD2": 1039
      },
      "name": "ParseDecimalString",
      "signature": "void ParseDecimalString(_LDBL12 * pDecimalOutput, int * pEndPos, byte * pInputString, int precisionAddend, int integerExponent, int fractionalExponent, int allowExponent)",
      "calling_convention": "__cdecl",
      "comment": "Parses a decimal string into internal long double representation.\n\nThis function implements a state-machine-based decimal number parser that handles:\n- Optional whitespace before the number\n- Optional sign (+/-)\n- Integer and fractional parts separated by decimal point  \n- Scientific notation with exponent (e/E followed by optional +/- and digits)\n- Precision adjustment and exponent scaling for context-specific formatting\n\nThe function uses state machine states 0-11 to track parsing progress, building\na 23-digit significand array and calculating the effective exponent. The parsed\nresult is stored as a 12-byte _LDBL12 structure containing sign, mantissa, and\nexponent fields.\n\nAlgorithm:\n1. Initialize parse state, significand array, and exponent tracking variables\n2. Skip leading whitespace (space 0x20, tab 0x09, newline 0x0A, carriage return 0x0D)\n3. Parse optional sign (+/- characters) and set sign multiplier (0 for + or 0x8000 for -)\n4. Execute state machine to parse digits before decimal point (state 3)\n5. When decimal point found, enter fractional parsing (state 4) \n6. Handle exponent notation (e/E) by reading exponent digits (state 9)\n7. Validate significand and call ConvertSignificandToMantissa to normalize mantissa\n8. Calculate final exponent by combining parsed exponent with adjustment parameters\n9. Call ModularExponentiate to scale mantissa by 10^exponent \n10. Store result: sign bits in upper word, mantissa in middle words, exponent in lower word\n\nParameters:\n- pDecimalOutput (_LDBL12*): Output buffer for parsed decimal value\n- pEndPos (int*): Output pointer to position after last parsed character  \n- pInputString (byte*): Input string to parse\n- precisionAddend (int): Additional precision bits to apply (typically 0)\n- integerExponent (int): Exponent adjustment for integer part (typically 0)\n- fractionalExponent (int): Exponent adjustment for fractional part (typically 0) \n- allowExponent (int): If non-zero, allow e/E notation; if zero, stop at exponent\n\nReturns:\n- No return value; result stored in *pDecimalOutput\n- *pEndPos updated to point after last parsed character\n\nSpecial Cases:\n- Empty or non-numeric input: returns all zeros\n- Significand exceeds 25 digits: only first 25 stored, additional digits affect exponent\n- Exponent exceeds 5185 (0x1451): clamped to 5185 \n- Exponent below -5186: clamped to -5186\n- Multiple leading zeros: skipped in fractional part to maintain precision\n\nMagic Numbers Reference:\n- 0x20: Space character \n- 0x09: Tab character\n- 0x0A: Line feed character  \n- 0x0D: Carriage return character\n- 0x2B: Plus sign character (+)\n- 0x2D: Minus sign character (-)\n- 0x30: Zero character ('0')\n- 0x8000: Sign bit mask for negative numbers\n- 0x1451: Maximum exponent value (5185 decimal)\n- 0x1450: Exponent limit check (5184 decimal)\n- -0x1451: Minimum exponent value (-5185 decimal)\n- 0x19: Maximum significand digits (25 decimal)\n- 0x18: Significand overflow threshold (24 decimal)\n\nState Machine:\n- State 0: Initial parsing, expecting sign or digit\n- State 1: Found leading zero, checking for more digits\n- State 2: Found sign, expecting digit or decimal\n- State 3: Parsing integer digits before decimal point\n- State 4: Parsing fractional digits after decimal point  \n- State 5: Found decimal point without preceding digits\n- State 6: Found exponent indicator (e/E)\n- State 7: Expecting exponent digits after sign\n- State 8: Parsing leading zeros in exponent\n- State 9: Parsing exponent digits\n- State 10: Exponent parsing complete\n- State 11: Found exponent sign, need exponent digits",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:51067a812fadc7d24e800d427a3a129f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "51067a812fadc7d24e800d427a3a129f",
        "CFG": "3ef5ce516ea11458619b625f0d5cf9a8",
        "PRO": "f1b6c4b656c56680d445da3c5e3dcccd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "51067a812fadc7d24e800d427a3a129f"
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "D2sound_STR_caf0293062c4": {
      "addresses": {
        "LoD/PD2": "0x6F9BD7E7"
      },
      "rvas": {
        "LoD/PD2": "0xD7E7"
      },
      "sizes": {
        "LoD/PD2": 668
      },
      "name": "ConvertDoubleToString",
      "signature": "int ConvertDoubleToString(uint mantissaLow, uint mantissaHigh, ushort exponentWithSign, int precision, byte adjustFlags, short * outputBuffer)",
      "calling_convention": "__cdecl",
      "comment": "Converts a 96-bit long double floating-point number to a decimal string representation.\n   \nAlgorithm:\n1. Extract and validate sign bit (bit 15 of exponent) for +/- indicator\n2. Check for zero: if exponent and mantissa are both zero, output \"0\" and return\n3. Check for special floating-point values with exponent=0x7fff (infinity/NaN)\n4. For normal numbers, compute effective binary exponent from normalized form\n5. Use modular exponentiation to convert mantissa digits to decimal\n6. Generate decimal digits up to specified precision with proper rounding\n7. Apply rounding rule: if next digit >= 5, increment last digit and propagate carries\n8. Strip trailing zeros if no rounding needed, then update exponent and digit count\n9. Return to caller with exponent in EAX, string written to output buffer\n   \nOutput Buffer Structure (short array):\n- [0] = signed exponent value (-32768 to 32767)\n- [1] = sign character: '+' (0x20) or '-' (0x2d)\n- [2] = first digit or status code (0x30-0x39 for digits, special for exceptions)\n- [3] = digit count or status flag\n- [4+] = null-terminated ASCII digit string ('0'-'9')\n   \nParameters:\n- mantissaLow: Lower 32 bits of 64-bit binary mantissa\n- mantissaHigh: Upper 32 bits of 64-bit binary mantissa\n- exponentWithSign: 16-bit field with sign (bit 15) and biased exponent (bits 0-14)\n- precision: Maximum number of decimal digits to generate (0-21, auto-clamped to 21)\n- adjustFlags: Control flags; bit 0 set adjusts exponent when set\n- outputBuffer: Pointer to short array for output (minimum 15 bytes for normal numbers)\n   \nReturns:\n- EAX: Decimal exponent value written to outputBuffer[0]\n   \nSpecial Cases:\n- Zero: All-zero mantissa outputs \"0.0\" with exponent 0\n- Positive infinity (0x7fff, 0x80000000, 0x0): Outputs \"INF\"\n- Negative infinity (0xffff, 0x80000000, 0x0): Outputs \"-INF\"\n- Quiet NaN (0x7fff, mantissa_high=0xc0000000 or 0x40000000): Outputs \"QNAN\" or \"IND\"\n- Signaling NaN: Outputs \"SNAN\"\n- Negative zero: Treated as zero with '-' sign\n\nNote: Function uses 1 stack-allocated temporary variable optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:caf0293062c4e4caabf207f9f9a0ab4c",
      "indexes": {
        "EXP": null,
        "STR": "caf0293062c4e4caabf207f9f9a0ab4c",
        "API": null,
        "MNE": "0388957b0fc3482b6c2688de750f3211",
        "CFG": "231080f647c368f267ab09a722998c2d",
        "PRO": "bb6ad5a9cc343c0507e3a029e38be7ea"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0388957b0fc3482b6c2688de750f3211"
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "D2sound_ADDR_6F9BDA83": {
      "addresses": {
        "LoD/PD2": "0x6F9BDA83"
      },
      "rvas": {
        "LoD/PD2": "0xDA83"
      },
      "sizes": {
        "LoD/PD2": 3
      },
      "name": "InitializeFloatingPointMode",
      "signature": "int InitializeFloatingPointMode(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes floating-point control mode and returns success status.\n\nThis function is called during floating-point environment setup and error handling\nto initialize the floating-point control state. It returns 0 to indicate successful\ninitialization.\n\nAlgorithm:\n1. Clear EAX register (XOR EAX, EAX) to set return value to 0\n2. Return from function with success status\n\nReturns:\nint - 0 on successful initialization, used as status code by caller\n\nContext:\nCalled from FUN_6f9bcefb during error handling when floating-point state needs\nto be checked or initialized before further floating-point operations.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:acbc2c857bf1a8401ca8fe5de1c0ec70",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "acbc2c857bf1a8401ca8fe5de1c0ec70",
        "CFG": null,
        "PRO": "7206840be1be8fa373a01e5868c0863f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "acbc2c857bf1a8401ca8fe5de1c0ec70"
      }
    },
    "D2sound_MNE_2dfd4c619a53": {
      "addresses": {
        "LoD/PD2": "0x6F9BDA86"
      },
      "rvas": {
        "LoD/PD2": "0xDA86"
      },
      "sizes": {
        "LoD/PD2": 677
      },
      "name": "__raise_exc",
      "signature": "void __raise_exc(uint * pExceptionRecord, uint * pdwFpuStatusWord, uint dwExceptionFlags, int nThreadId, double * pdFpuRegisterLow, double * pdFpuRegisterHigh)",
      "calling_convention": "__cdecl",
      "comment": "Converts FPU exception flags into Windows structured exception and raises it\n\nAlgorithm:\n1. Initialize exception record array elements to zero (indices 1-3)\n2. Process FPU exception flags to Windows exception codes:\n   - 0x10 (underflow) -> STATUS_FLOAT_UNDERFLOW (0xC000008F)\n   - 0x02 (denormal) -> STATUS_FLOAT_INVALID_OPERATION (0xC0000093)\n   - 0x01 (invalid) -> STATUS_FLOAT_INVALID_OPERATION (0xC0000091) \n   - 0x04 (overflow) -> STATUS_FLOAT_OVERFLOW (0xC000008E)\n   - 0x08 (divide by zero) -> STATUS_FLOAT_DIVIDE_BY_ZERO (0xC0000090)\n3. Map FPU status word bits to exception context with bit position translation\n4. Get current FPU status using __statfp() and map additional status flags\n5. Process FPU control word precision and rounding mode settings\n6. Encode thread ID into exception record with 5-bit left shift\n7. Set floating point context flags for low and high register portions\n8. Copy FPU register values to exception record at offsets 4 and 0x14\n9. Clear FPU status and raise Windows structured exception via RaiseException\n10. After exception handling, restore FPU status word from exception context\n11. Restore FPU control word precision and rounding settings\n12. Copy modified FPU register values back to output parameters\n\nParameters:\npExceptionRecord: Pointer to EXCEPTION_RECORD structure array for Windows SEH\npdwFpuStatusWord: Pointer to FPU status word (16-bit value in DWORD)\ndwExceptionFlags: FPU exception mask with standard x87 exception bits\nnThreadId: Thread identifier to encode in exception context\npdFpuRegisterLow: Pointer to low portion of FPU register value\npdFpuRegisterHigh: Pointer to high portion of FPU register value\n\nReturns:\nvoid - Function returns only after exception is handled\n\nSpecial Cases:\n- Multiple exception flags can be set simultaneously\n- Thread ID is limited to 13 bits due to 5-bit shift encoding\n- FPU registers are saved and restored across exception handling\n- Control word settings affect precision and rounding behavior\n\nMagic Numbers Reference:\n0x10: FPU underflow exception flag\n0x02: FPU denormal operand exception flag  \n0x01: FPU invalid operation exception flag\n0x04: FPU overflow exception flag\n0x08: FPU divide by zero exception flag\n0xC000008F: STATUS_FLOAT_UNDERFLOW Windows exception code\n0xC0000093: STATUS_FLOAT_INVALID_OPERATION Windows exception code\n0xC0000091: STATUS_FLOAT_INVALID_OPERATION Windows exception code\n0xC000008E: STATUS_FLOAT_OVERFLOW Windows exception code\n0xC0000090: STATUS_FLOAT_DIVIDE_BY_ZERO Windows exception code\n0xC00: FPU precision control mask (bits 8-9)\n0x300: FPU rounding control mask (bits 8-9)\n0x1FFE0: Thread ID encoding mask (bits 5-17)\n\nException Record Structure Layout:\nOffset | Size | Field Name | Type | Description\n0x00   | 4    | ExceptionCode | DWORD | Windows exception code\n0x04   | 4    | ExceptionFlags | DWORD | Exception context flags  \n0x08   | 4    | ExceptionRecord | DWORD | Nested exception pointer\n0x0C   | 4    | ExceptionAddress | DWORD | Faulting instruction address\n0x10   | 8    | FpuRegisterLow | double | Low FPU register value\n0x50   | 8    | FpuRegisterHigh | double | High FPU register value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2dfd4c619a532db9b09184566755e39d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2dfd4c619a532db9b09184566755e39d",
        "CFG": "77fdd9a1bb838a20e4385f5adcb4eb4b",
        "PRO": "11274a8dcbbf42a927f9736d216d5dd8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2dfd4c619a532db9b09184566755e39d"
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "D2sound_MNE_bd26660a5c3b": {
      "addresses": {
        "LoD/PD2": "0x6F9BDD2B"
      },
      "rvas": {
        "LoD/PD2": "0xDD2B"
      },
      "sizes": {
        "LoD/PD2": 548
      },
      "name": "__handle_exc",
      "signature": "bool __handle_exc(uint dwExceptionFlags, double * pdValue, uint dwControlWord)",
      "calling_convention": "__cdecl",
      "comment": "Processes floating-point unit (FPU) exceptions and adjusts values based on exception flags and control word settings.\n\nAlgorithm:\n1. Extract active exception flags from parameter 1 (mask with 0x1f)\n2. Check for divide-by-zero exception (flag 0x08 set and control word bit 0x01 enabled)\n   - Call HandleFPUExceptionFlags(1) and clear flag 0x08 from active flags\n3. Check for invalid operation exception (flag 0x04 set and control word bit 0x04 enabled)  \n   - Call HandleFPUExceptionFlags(4) and clear flag 0x04 from active flags\n4. Check for inexact result exception (flag 0x01 set and control word bit 0x08 enabled)\n   - Call HandleFPUExceptionFlags(8) to signal exception\n   - Apply rounding mode based on control word bits 0x0C00:\n     * 0x000: Round to nearest (positive or negative infinity based on sign)\n     * 0x400: Round toward positive infinity  \n     * 0x800: Round toward negative infinity\n     * 0xC00: Round toward positive infinity (same as 0x400)\n   - Set output value to appropriate infinity constant and clear flag 0x01\n5. Check for denormalized operand exception (flag 0x02 set and control word bit 0x10 enabled)\n   - Decompose floating-point value using __decomp to get mantissa and exponent\n   - Adjust exponent by subtracting 0x600 (1536 decimal) for normalization\n   - If exponent below -0x432 (-1074), multiply by zero constant and set underflow flag\n   - Otherwise normalize mantissa by setting implicit bit 0x10000000000000\n   - If exponent below -0x3FD (-1021), perform gradual underflow:\n     * Right-shift mantissa while tracking lost bits for rounding\n     * Set rounding flag if any bits lost during shifting\n   - Restore original sign if input was negative\n   - Store normalized result back to parameter 2 pointer\n   - Call HandleFPUExceptionFlags(0x10) if rounding occurred, clear flag 0x02\n6. Check for underflow exception (flag 0x10 set and control word bit 0x20 enabled)\n   - Call HandleFPUExceptionFlags(0x20) and clear flag 0x10 from active flags\n7. Return true if all exception flags have been processed (remaining flags == 0)\n\nParameters:\ndwExceptionFlags (param_1): FPU status register exception flags (bits 0-4)\n  - Bit 0x01: Inexact result (IE)\n  - Bit 0x02: Denormalized operand (DE)  \n  - Bit 0x04: Invalid operation (IE)\n  - Bit 0x08: Divide by zero (ZE)\n  - Bit 0x10: Numeric underflow (UE)\npdValue (param_2): Pointer to double-precision floating-point value to be adjusted\ndwControlWord (param_3): FPU control word with exception masks and rounding mode\n  - Bits 0x01, 0x04, 0x08, 0x10, 0x20: Exception enable masks  \n  - Bits 0x0C00: Rounding control (0x000=nearest, 0x400=+inf, 0x800=-inf, 0xC00=zero)\n\nReturns:\ntrue: All exception flags were successfully processed and cleared\nfalse: One or more exception flags remain unprocessed\n\nSpecial Cases:\n- Global constants _DAT_6f9c0988 (zero), _DAT_6f9c5c08 (positive infinity), _DAT_6f9c5c18 (negative infinity)\n- Gradual underflow implements IEEE 754 denormalized number handling\n- Rounding mode 0xC00 treated same as 0x400 (toward positive infinity)\n\nMagic Numbers Reference:\n0x1F - Exception flags mask (bits 0-4)\n0x600 - Exponent bias adjustment (1536 decimal)\n0x432 - Minimum normal exponent threshold (1074 decimal) \n0x3FD - Gradual underflow threshold (1021 decimal)\n0x10000000000000 - IEEE 754 double mantissa implicit bit\n0x0C00 - Rounding mode field mask in control word",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bd26660a5c3bb450be04aed223c70830",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bd26660a5c3bb450be04aed223c70830",
        "CFG": "01a003f325b3ae724802a4081f0dcedd",
        "PRO": "4bec92df8ddf778f0a31570481018d91"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bd26660a5c3bb450be04aed223c70830"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2sound_MNE_292f205a8ae5": {
      "addresses": {
        "LoD/PD2": "0x6F9BDF4F"
      },
      "rvas": {
        "LoD/PD2": "0xDF4F"
      },
      "sizes": {
        "LoD/PD2": 40
      },
      "name": "SetThreadErrorCode",
      "signature": "void SetThreadErrorCode(int nErrorCode)",
      "calling_convention": "__cdecl",
      "comment": "Sets the thread-local error code based on exception type.\n\nAlgorithm:\n1. Load the error code parameter from the stack\n2. Compare error code against 1 (floating-point domain error)\n   - If equal, jump to handle domain error case\n3. Check if error code is <= 0 (invalid codes)\n   - If yes, return immediately with no action\n4. Compare error code against 3 (maximum valid code)\n   - If greater, return immediately (out of range)\n5. Call GetThreadErrnoPointer() to get thread-local errno pointer\n6. Store 0x22 (ERANGE) to errno for codes 2-3\n7. Return to caller\n\nParameters:\n- nErrorCode (int): Exception/error type code from floating-point operations\n  Valid range: 1-3, where 1=EDOM, 2-3=ERANGE\n\nReturns:\n- void: No return value, sets errno via thread-local storage\n\nSpecial Cases:\n- Error codes <= 0: Treated as invalid, function returns with no action\n- Error codes > 3: Treated as out-of-range, function returns with no action\n- Code 1: Sets errno to 0x21 (decimal 33, EDOM - domain error)\n- Codes 2-3: Set errno to 0x22 (decimal 34, ERANGE - range error)\n- Thread-local errno accessed via GetThreadErrnoPointer()\n\nMagic Numbers Reference:\n- 0x21 (33): EDOM - Mathematical argument out of domain\n- 0x22 (34): ERANGE - Mathematical result not representable",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:292f205a8ae52b2efacb41fa43053bdd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "292f205a8ae52b2efacb41fa43053bdd",
        "CFG": "9f0e6dcc6217912767c0e6d0aa226117",
        "PRO": "578823ea30c16b638421af32d6eb9ab3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "292f205a8ae52b2efacb41fa43053bdd"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_58d1fb148bc6": {
      "addresses": {
        "LoD/PD2": "0x6F9BDF77"
      },
      "rvas": {
        "LoD/PD2": "0xDF77"
      },
      "sizes": {
        "LoD/PD2": 11
      },
      "name": "__statfp",
      "signature": "int __statfp(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the current floating-point unit (FPU) status word.\n\nAlgorithm:\n1. Store FPU status word from status register to memory (FSTSW instruction)\n2. Sign-extend the stored status word from 16-bit to 32-bit (MOVSX instruction)\n3. Return the extended status word as integer result\n\nParameters:\nNone\n\nReturns:\nint - Current FPU status word containing exception flags, condition code bits, and stack pointer\n\nSpecial Cases:\nThe function directly accesses the FPU status register through assembly instructions.\nThis is a low-level hardware interface function for floating-point error handling.\n\nNote: Function uses 1 stack-allocated temporary variable (local_4) optimized away by decompiler.\nThe variable serves as intermediate storage for the FSTSW instruction result before sign-extension.\n\nMagic Numbers Reference:\nStatus word bits follow IEEE 754 standard:\n- Bits 0-5: Exception flags (invalid operation, denormalized operand, divide-by-zero, overflow, underflow, precision)\n- Bits 8-10: Condition code bits C0, C2, C3\n- Bits 11-13: Stack pointer (top of FPU stack)\n- Bit 15: Busy flag (FPU operation in progress)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:58d1fb148bc62cfcf756bcba05f86ccf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "58d1fb148bc62cfcf756bcba05f86ccf",
        "CFG": null,
        "PRO": "198ed6423479e7e841c8d783de210331"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "58d1fb148bc62cfcf756bcba05f86ccf"
      }
    },
    "D2sound_MNE_42778b58dd0d": {
      "addresses": {
        "LoD/PD2": "0x6F9BDF82"
      },
      "rvas": {
        "LoD/PD2": "0xDF82"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "__clrfp",
      "signature": "int __clrfp(void)",
      "calling_convention": "__stdcall",
      "comment": "Clear floating-point status register and return previous status word.\n\nAlgorithm:\n1. Save current FPU status word to stack using FNSTSW instruction\n2. Clear FPU exception flags using FNCLEX instruction  \n3. Load saved status word from stack and sign-extend to int\n4. Return previous status word as integer\n\nParameters:\nNone\n\nReturns:\nint - Previous FPU status word value before clearing flags\n     - Bits contain floating-point exception and condition flags\n     - Return value preserves all status information from before clear operation\n\nSpecial Cases:\nFPU Status Word Bits (16-bit value returned as int):\n- Bit 0 (0x0001): Invalid operation exception flag\n- Bit 1 (0x0002): Denormalized operand exception flag  \n- Bit 2 (0x0004): Zero divide exception flag\n- Bit 3 (0x0008): Overflow exception flag\n- Bit 4 (0x0010): Underflow exception flag\n- Bit 5 (0x0020): Precision exception flag\n- Bit 6 (0x0040): Stack fault flag\n- Bit 7 (0x0080): Error summary status\n- Bits 8-10: Top of stack pointer (ST0-ST7)\n- Bits 11-13: Condition code bits C0-C2\n- Bit 14 (0x4000): Condition code bit C3\n- Bit 15 (0x8000): FPU busy flag\n\nError Handling:\nNo error conditions - function always succeeds and clears FPU flags",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:42778b58dd0d14715b1955d2e17baad3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "42778b58dd0d14715b1955d2e17baad3",
        "CFG": null,
        "PRO": "79fce4ef20d93f024d9b1d693ae98a5e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "42778b58dd0d14715b1955d2e17baad3"
      }
    },
    "D2sound_MNE_80c2e5debd16": {
      "addresses": {
        "LoD/PD2": "0x6F9BDF8E"
      },
      "rvas": {
        "LoD/PD2": "0xDF8E"
      },
      "sizes": {
        "LoD/PD2": 36
      },
      "name": "__ctrlfp",
      "signature": "int __ctrlfp(void)",
      "calling_convention": "__stdcall",
      "comment": "Controls floating-point unit precision and rounding modes.\n\nAlgorithm:\n1. Load current FPU control word into local storage\n2. Return current control word value as integer\n\nParameters:\nNone\n\nReturns:\nCurrent FPU control word as integer value\n\nSpecial Cases:\nThis is a standard library function wrapper around FPU control word access.\nThe function reads but does not modify the FPU control word.\n\nMagic Numbers Reference:\nFPU control word contains precision control (bits 8-9) and rounding mode (bits 10-11).",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:80c2e5debd168e4e0485e934e71a955d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "80c2e5debd168e4e0485e934e71a955d",
        "CFG": null,
        "PRO": "ea5c247f03dba2e563587ca1c755f21e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "80c2e5debd168e4e0485e934e71a955d"
      }
    },
    "D2sound_MNE_ea28d68d4b7c": {
      "addresses": {
        "LoD/PD2": "0x6F9BDFB2"
      },
      "rvas": {
        "LoD/PD2": "0xDFB2"
      },
      "sizes": {
        "LoD/PD2": 86
      },
      "name": "HandleFPUExceptionFlags",
      "signature": "void HandleFPUExceptionFlags(byte fpuFlagsMask)",
      "calling_convention": "__stdcall",
      "comment": "Handles floating-point unit (FPU) exception flags during exception processing.\n\nThis function processes a flags byte that controls which FPU operations are executed.\nEach bit in the input parameter corresponds to a specific FPU operation:\n- Bit 0 (0x01): Convert double at 0x6f9c5d20 to integer and store in stack\n- Bit 3 (0x08): Load and store double at 0x6f9c5d20, then save FPU status to AX\n- Bit 4 (0x10): Load and store double at 0x6f9c5d2c to stack\n- Bit 2 (0x04): Execute FPU division: FLDZ; FLD1; FDIVRP (0/1 = 0)\n- Bit 5 (0x20): Load PI constant and store to stack\n\nAlgorithm:\n1. Push ECX twice to set up stack space (8 bytes total)\n2. Load parameter flags byte into CL register\n3. Test bit 0 (0x01): if clear, skip to flag_bit_3_check\n4. Load extended double from memory address 0x6f9c5d20\n5. Convert to integer and store on stack at [ESP+0xc]\n6. Wait for FPU operation completion\n7. Test bit 3 (0x08): if clear, skip to flag_bit_4_check\n8. Load FPU status word into AX register\n9. Load extended double from memory address 0x6f9c5d20\n10. Store as double-precision on stack [ESP]\n11. Wait and reload FPU status word\n12. Test bit 4 (0x10): if clear, skip to flag_bit_2_check\n13. Load extended double from memory address 0x6f9c5d2c\n14. Store as double-precision on stack [ESP]\n15. Wait for FPU operation completion\n16. Test bit 2 (0x04): if clear, skip to flag_bit_5_check\n17. Execute FPU division sequence: load zero, load one, divide and pop\n18. Store result and wait\n19. Test bit 5 (0x20): if clear, skip to epilogue\n20. Load PI constant (FLDPI) and store to stack [ESP]\n21. Wait for FPU operation completion\n22. Pop ECX twice (stack cleanup)\n23. Return to caller\n\nParameters:\nfpuFlagsMask (byte) - Bit flags controlling which FPU operations execute:\n  - 0x01: Convert/store double from 0x6f9c5d20\n  - 0x04: Execute FPU division (0/1)\n  - 0x08: Load/store double from 0x6f9c5d20 and get FPU status\n  - 0x10: Load/store double from 0x6f9c5d2c\n  - 0x20: Load and store PI constant\n\nReturns:\nvoid - No return value. FPU operations modify the FPU stack and memory at [ESP].\n\nSpecial Cases:\n- Multiple bits can be set simultaneously, enabling multiple operations\n- All FPU operations are synchronized with WAIT instruction\n- Memory addresses 0x6f9c5d20 and 0x6f9c5d2c are accessed without null checks\n- FPU status word (AX) is overwritten during bit 3 operation\n- Stack operations use ESP+0xc offset for bit 0 operation (caller parameter access)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ea28d68d4b7ce7d535c6ca874aba9cdf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ea28d68d4b7ce7d535c6ca874aba9cdf",
        "CFG": "7502e22954c3d2f1a19df576ed7ccc51",
        "PRO": "9ecec5cf4c4f38ad1a2615a7166f24cc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ea28d68d4b7ce7d535c6ca874aba9cdf"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2sound_MNE_e57f9b957e5f": {
      "addresses": {
        "LoD/PD2": "0x6F9BE008"
      },
      "rvas": {
        "LoD/PD2": "0xE008"
      },
      "sizes": {
        "LoD/PD2": 566
      },
      "name": "AccumulateMultiplicationResult",
      "signature": "void AccumulateMultiplicationResult(int * pAccumulator, int * pMultiplier)",
      "calling_convention": "__cdecl",
      "comment": "Accumulates multiplication result using digit-by-digit addition with normalization.\n\nAlgorithm:\n1. Initialize local buffers and extract exponent fields from both operands\n   - Get multiplier exponent at offset +0xa, mask to 15 bits (max magnitude)\n   - Get accumulator exponent at offset +0xa, mask to 15 bits\n   - Extract sign difference from bit 0x8000 of both exponent fields\n2. Validate input ranges: ensure both exponents < 0x7fff and sum < 0xbffe\n3. Handle zero-value cases:\n   - If sum < 0x3fc0 (too small), zero out result and return\n   - If accumulator is zero, increment sum exponent; validate multiplier not all zeros\n   - If multiplier is zero, increment sum exponent; validate accumulator not all zeros\n4. Perform 5x5 digit-by-digit multiplication:\n   - For each row (0-4) and column (0-4): load ushort, multiply, add to local buffer with carry\n   - Calls ___addl() to perform addition with carry propagation at each (row, col)\n5. Adjust exponent by adding 0xc002 (base adjustment for 5-digit precision):\n   - If exponent <= 0: shift right by magnitude, set carry bit if result odd\n   - If exponent > 0: shift left by magnitude until bit 0x80 detected\n6. Round result by checking if combined value >= 0x8000:\n   - If true and all subsequent digits are 0xff...: increment higher digits\n   - Handle all-zeros case (increment exponent)\n7. Validate result exponent <= 0x7ffe; if overflow, set sign-adjusted overflow value\n8. Write normalized result to accumulator: exponent at +0xa, 12-byte mantissa at +0x0 to +0x8\n9. Call stack canary verification function VerifyStackCanary()\n\nParameters:\npAccumulator: Pointer to 12-byte large number for accumulating results (exponent at +0xa)\npMultiplier: Pointer to 12-byte large number to multiply and add (exponent at +0xa)\n\nReturns:\nNone (void function, modifies pAccumulator in place)\n\nSpecial Cases:\n- Zero operands: Increment exponent and set result accordingly\n- Underflow (exponent < 0x3fc0): Results in zero value\n- Overflow (exponent > 0x7ffe): Results in sign-adjusted maximum value (0x7fff8000)\n- Rounding: 0x18000 mask indicates need to round up combined values\n\nStructure Layout:\nLarge numbers stored as [dword lower][dword middle][dword upper][ushort exponent]\n\nNote: Function uses 2 stack-allocated temporary variables (local_c, local_10) optimized away by decompiler",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e57f9b957e5ffdb4b85cc387a6cef2b2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e57f9b957e5ffdb4b85cc387a6cef2b2",
        "CFG": "f7ce5b6b8fca87572460b08b83d6e995",
        "PRO": "f25d4b9f3905f403a4f0f3f36506a848"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e57f9b957e5ffdb4b85cc387a6cef2b2"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2sound_MNE_6cc300b1da5e": {
      "addresses": {
        "LoD/PD2": "0x6F9BE23E"
      },
      "rvas": {
        "LoD/PD2": "0xE23E"
      },
      "sizes": {
        "LoD/PD2": 142
      },
      "name": "ModularExponentiate",
      "signature": "void ModularExponentiate(int * pResult, uint exponent, int flags)",
      "calling_convention": "__cdecl",
      "comment": "Modular exponentiation using tabulated binary method with sign handling.\n\nAlgorithm:\n1. Load and verify stack canary value for security check\n2. Initialize table base pointer based on exponent sign (positive vs negative)\n3. If exponent is negative, negate it and switch to alternate lookup table\n4. Initialize result buffer to zero if flags parameter is zero\n5. Loop while exponent != 0:\n   a. Divide exponent by 8 (right shift 3), extract remainder (0-7)\n   b. Advance table pointer by fixed stride (0x54 bytes per iteration)\n   c. If remainder != 0:\n      - Compute offset into current table entry using remainder\n      - Check sign flag at table entry (0x8000 bit in word)\n      - If sign flag set, copy entry to local buffer (12 bytes)\n      - Otherwise use table entry directly\n      - Call accumulator function with result buffer and table data\n6. Verify and restore stack canary value\n7. Call stack guard verification function before return\n\nParameters:\n- pResult: Pointer to result buffer for accumulating multiplication results\n- exponent: The exponent value (can be negative, will be negated for calculation)\n- flags: Control flags (0 = initialize result buffer, non-zero = preserve existing)\n\nReturns:\nNone (void function, modifies pResult buffer in place)\n\nSpecial Cases:\n- Zero exponent: Skips all processing, just initializes/verifies buffer\n- Negative exponent: Negates value and uses alternate precomputed table\n- Table sign flag (0x8000): Indicates special handling required for table entry",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6cc300b1da5eeec1802d54785701cebf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6cc300b1da5eeec1802d54785701cebf",
        "CFG": "a9a3f776447da6b72fc11c4aab1f0885",
        "PRO": "b8d3f5fb333344c51f5ead0fa838674b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6cc300b1da5eeec1802d54785701cebf"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    }
  }
};

if (typeof FUNCTION_DATA === 'undefined') FUNCTION_DATA = {};
FUNCTION_DATA['D2sound.dll'] = FUNCTIONS_D2sound_dll;
