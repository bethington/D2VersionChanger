// Auto-generated from function_registry_v2.json
// Generated: 2025-12-16T20:37:06.337995
// Functions for binkw32.dll
// Versions: LoD/PD2

var FUNCTIONS_binkw32_dll = {
  "versions": [
    "LoD/PD2"
  ],
  "functions": {
    "binkw32_MNE_ccf71b7c6bd6": {
      "addresses": {
        "LoD/PD2": "0x03821000"
      },
      "rvas": {
        "LoD/PD2": "0x1000"
      },
      "sizes": {
        "LoD/PD2": 65
      },
      "name": "radmalloc",
      "signature": "int radmalloc(uint param_1)",
      "calling_convention": "__stdcall",
      "comment": "__stdcall radmalloc,4",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ccf71b7c6bd67f4220ac02d284da0560",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ccf71b7c6bd67f4220ac02d284da0560",
        "CFG": "8cc6ad9b5e9270959ff0e809933480e7",
        "PRO": "6794e00ecab07d376a641171904c0877"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ccf71b7c6bd67f4220ac02d284da0560"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_ce7b7bb0113f": {
      "addresses": {
        "LoD/PD2": "0x03821050"
      },
      "rvas": {
        "LoD/PD2": "0x1050"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "radfree",
      "signature": "undefined radfree(int param_1)",
      "calling_convention": "__stdcall",
      "comment": "__stdcall radfree,4",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ce7b7bb0113fd49b4bbcff6f485c13e8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ce7b7bb0113fd49b4bbcff6f485c13e8",
        "CFG": "c28d843778d6313eca5e15ea77ffbb3e",
        "PRO": "62e81e4974f36d793731d84b609054f2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ce7b7bb0113fd49b4bbcff6f485c13e8"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_STR_c0ad15467707": {
      "addresses": {
        "LoD/PD2": "0x03821070"
      },
      "rvas": {
        "LoD/PD2": "0x1070"
      },
      "sizes": {
        "LoD/PD2": 210
      },
      "name": "ValidateDLLLocation",
      "signature": "int ValidateDLLLocation(HMODULE hModule, int nReason)",
      "calling_convention": "__stdcall",
      "comment": "Validates that the DLL is installed in the Windows or System directory.\n\nAlgorithm:\n1. Check if nReason equals DLL_PROCESS_ATTACH (1); return 1 if not\n2. Store hModule in global variable at 0x385caa0\n3. Call GetModuleFileNameA to retrieve full module path\n4. Calculate string length using REPNE SCASB instruction\n5. Scan backward from end of path to locate separator (\\ or :)\n6. Null-terminate path at separator to isolate directory portion\n7. Call GetWindowsDirectoryA to retrieve Windows directory path\n8. Perform case-insensitive comparison of module directory with Windows directory\n9. If not in Windows directory, call GetSystemDirectoryA\n10. Perform case-insensitive comparison of module directory with System directory\n11. If not in either directory, display error message and return 0\n12. If found in either directory, return 1 (failure - DLL in wrong location)\n\nParameters:\nhModule (HMODULE) - Handle to the module instance\nnReason (int) - Reason for DLL notification (1=DLL_PROCESS_ATTACH)\n\nReturns:\nint - 1 if validation fails or nReason != 1, 0 if DLL in correct location\n\nSpecial Cases:\n- Early return with value 1 if nReason != DLL_PROCESS_ATTACH\n- Uses string parsing to extract directory from full module path\n- Compares directories case-insensitively using __strcmpi\n- Displays messagebox with error text if DLL location invalid\n\nMagic Numbers:\n0x7f - Maximum path buffer size (127 characters)\n0x385caa0 - Global variable storing module handle\n0x10 - MessageBoxA style flag (MB_ICONHAND)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:c0ad15467707cfe32300724cf778aa20",
      "indexes": {
        "EXP": null,
        "STR": "c0ad15467707cfe32300724cf778aa20",
        "API": null,
        "MNE": "8a158e28828156dcb58ea62c4cc81c4f",
        "CFG": "f641a76fc092a259b0952767ed53bb71",
        "PRO": "48652219fb5ceef43a9902f66a3963ce"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8a158e28828156dcb58ea62c4cc81c4f"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_8941e8b912ae": {
      "addresses": {
        "LoD/PD2": "0x03821150"
      },
      "rvas": {
        "LoD/PD2": "0x1150"
      },
      "sizes": {
        "LoD/PD2": 187
      },
      "name": "InitializeBinkFile",
      "signature": "int InitializeBinkFile(BinkFile * pBinkFile, LPCSTR pFilePath, uint dwFlags)",
      "calling_convention": "__stdcall",
      "comment": "Initializes a Bink file structure for reading or memory-based access.\n\nThis function initializes the Bink file handler structure with either a file handle (if reading from disk)\nor memory pointer (if using memory-based playback). It sets up function pointers for I/O operations and\nvalidates file access. If the file cannot be opened, it returns failure.\n\nAlgorithm:\n1. Clear the first 50 DWORDs of the Bink file structure\n2. Check if the MEMORY_MODE flag (0x800000) is set in dwFlags\n3. If not memory mode: attempt to open file with read-only access\n   - If first open fails, retry with read-write access\n   - If both fail, return failure (0)\n4. If memory mode: use pFilePath as a raw memory pointer and set memory flag\n5. Set up six function pointers in the structure for I/O callbacks\n6. Return success (1)\n\nParameters:\n- pBinkFile: Pointer to BinkFile structure (104 bytes) to initialize\n- pFilePath: Filename string (disk mode) or memory pointer (memory mode)\n- dwFlags: Bit flags controlling initialization behavior (0x800000 = MEMORY_MODE)\n\nReturns:\n- 1 if initialization succeeded\n- 0 if file open failed in disk mode\n\nSpecial Cases:\n- MEMORY_MODE (0x800000): Uses pFilePath as a raw memory pointer\n- File open retry: Attempts read-only first, then read-write if that fails\n- File flags: Uses 0x80000000 (GENERIC_READ) and 0x8000080 (sequential access)\n- Function pointers for ReadProc, WriteProc, GetInfoProc, SetInfoProc, CloseProc, SetSoundProc\n\nStructure Layout (BinkFile - 104 bytes):\n| Offset | Size | Field Name        | Type     | Description                      |\n|--------|------|-------------------|----------|----------------------------------|\n| 0x00   | 4    | ReadProc          | pointer  | Read callback function           |\n| 0x04   | 4    | WriteProc         | pointer  | Write callback function          |\n| 0x08   | 4    | GetInfoProc       | pointer  | Get info callback function       |\n| 0x0C   | 4    | SetInfoProc       | pointer  | Set info callback function       |\n| 0x10   | 4    | CloseProc         | pointer  | Close callback function          |\n| 0x14   | 4    | SetSoundProc      | pointer  | Set sound callback function      |\n| 0x18   | 48   | reserved          | dword[12]| Reserved space (12 DWORDs)       |\n| 0x48   | 4    | hFile             | dword    | File handle or memory pointer    |\n| 0x4C   | 8    | reserved          | dword[2] | Reserved space                   |\n| 0x54   | 4    | reserved          | dword    | Reserved space                   |\n| 0x58   | 4    | reserved          | dword    | Reserved space                   |\n| 0x5C   | 4    | reserved          | dword    | Reserved space                   |\n| 0x60   | 4    | bIsMemory         | dword    | Flag: 1 if memory mode, 0 disk   |\n| 0x64   | 4    | fileOffset        | dword    | Current file pointer position    |",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8941e8b912ae2ef8e03da6f313394db0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8941e8b912ae2ef8e03da6f313394db0",
        "CFG": "475c0c4b0ae1fd09c8f312cdf6dbcc7a",
        "PRO": "9917dffabd88c4e4ae91db0a91066bce"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8941e8b912ae2ef8e03da6f313394db0"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_70e19c34028b": {
      "addresses": {
        "LoD/PD2": "0x03821210"
      },
      "rvas": {
        "LoD/PD2": "0x1210"
      },
      "sizes": {
        "LoD/PD2": 167
      },
      "name": "ReadFileWithLocking",
      "signature": "DWORD ReadFileWithLocking(BinkFile * pFileContext, int filePosition, LPVOID pBuffer, DWORD bytesToRead)",
      "calling_convention": "__stdcall",
      "comment": "Reads data from a Bink file with thread-safe reference counting and file seeking.\n\nAlgorithm:\n1. Increment reference count using atomic lock at offset +0x5c in BinkFile structure\n2. Wait until memory-based I/O completes by polling reserved9 field and calling _BinkService_4\n3. If file position differs from reserved12, seek file pointer to new position using SetFilePointer\n4. Call ReadFile Windows API to read bytesToRead from file into pBuffer\n5. Update current file position in reserved12 by adding bytes read from stack offset +0x4\n6. Store position in reserved13 and calculate available bytes: reserved8 - reserved12\n7. Clamp available bytes to reserved8 maximum using conditional move\n8. Decrement reference count using atomic lock\n9. Return bytes read (stored in EAX from stack parameter)\n\nParameters:\n  pFileContext: BinkFile * - Pointer to Bink file context structure with I/O handlers and file state\n  filePosition: int - Target file position to seek to, or -1 to skip seeking\n  pBuffer: LPVOID - Buffer to receive file data\n  bytesToRead: DWORD - Number of bytes to read from file\n\nReturns:\n  DWORD - Number of bytes read from file\n\nSpecial Cases:\n  - If filePosition equals 0xffffffff, skip SetFilePointer call\n  - If reserved9 is non-zero (memory I/O busy), loop calling Sleep and _BinkService_4\n  - reserved8 is max readable bytes; clamp calculated available bytes to this limit\n  - Uses locked increment/decrement for thread-safe reference counting at offset +0x5c\n\nStructure Layout:\n  Offset | Size | Field Name    | Purpose\n  -------|------|---------------|------------------------------------------\n    0x48 |   4  | hFile         | File handle for ReadFile/SetFilePointer\n    0x4c |   4  | reserved12    | Current file position (relative to start)\n    0x50 |   4  | reserved13    | Last known file position\n    0x5c |   4  | reserved16    | Reference count (atomic locked)\n    0x60 |   4  | reserved9     | Memory I/O busy flag\n    0x74 |   4  | SetInfoProc   | Pointer to seek function (used indirectly)\n    0x78 |   4  | CloseProc     | Pointer used for available bytes calculation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:70e19c34028b2fb63cd0f4868863792f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "70e19c34028b2fb63cd0f4868863792f",
        "CFG": "3c2c2a488caa49d997b99da92039569f",
        "PRO": "4579dbd1be34c135b618b15641603643"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "70e19c34028b2fb63cd0f4868863792f"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkService@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_API_65b17a4bc5f4": {
      "addresses": {
        "LoD/PD2": "0x038212C0"
      },
      "rvas": {
        "LoD/PD2": "0x12C0"
      },
      "sizes": {
        "LoD/PD2": 699
      },
      "name": "ReadFileWithBufferManagement",
      "signature": "DWORD ReadFileWithBufferManagement(int pFileContext, undefined4 unused1, uint seekPosition, undefined4 * pOutputBuffer, DWORD readSize)",
      "calling_convention": "__stdcall",
      "comment": "Reads file data into circular buffer with thread synchronization and speed limiting.\n\nAlgorithm:\n1. If seekPosition != -1 and differs from current buffer position, seek to new position:\n   - Increment refcount at [pFileContext+0x5c] using atomic INC.LOCK\n   - Wait for threads to complete (poll [pFileContext+0x60])\n   - If seek is within buffered range [0x50,0x4c], advance pointers\n   - Otherwise seek file to [0x74]+seekPosition and reset buffer state\n2. Copy buffered data to output: read from [pFileContext+0x54] into pOutputBuffer\n   - Check if data wraps around buffer end at [pFileContext+0x68]\n   - Use REP MOVSD for DWORD copies, REP MOVSB for remainder bytes\n   - Update [0x54]=buffer read pointer, [0x44]=pending bytes, [0x58]=consumed\n3. If more data needed (readSize > 0):\n   - Call ReadFile on handle [pFileContext+0x48] with bytesReadFromFile output\n   - Update counters: [0x4c]=file position, [0x50]=current, [0x20]=total read\n   - If speed limit set at [0x7c], sleep to throttle: sleep_ms = (bytes_read*1000)/limit\n   - Update timings: [0x28]+=elapsed, [0x2c]+=total\n4. Update predictive read buffer space at [0x40] based on available data\n5. Release refcount at [0x5c] if acquired, then return elapsedTime in EAX\n\nParameters:\n  pFileContext: Pointer to file I/O context structure with embedded circular buffer\n  unused1: Unused parameter (reserved)\n  seekPosition: File position to seek to (-1 means no seek, use buffered data)\n  pOutputBuffer: Pointer to output buffer for read data\n  readSize: Number of bytes to read into pOutputBuffer\n\nReturns:\n  EAX: Elapsed time in milliseconds since function start, plus accumulated [pFileContext+0x2c]\n\nSpecial Cases:\n  - Refcount [0x5c] prevents concurrent file operations during seek\n  - Magic 0x1000 threshold at [0x40] marks buffer low-water mark\n  - Buffer wraps at [0x68]; write pointer [0x54] resets at [0x64]\n  - Speed limiting: actual delay = (readSize*1000) / [0x7c] milliseconds\n  - Thread-safe: uses atomic INC/DEC on refcount for synchronization",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:65b17a4bc5f409d069066c5aababb779",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "65b17a4bc5f409d069066c5aababb779",
        "MNE": "fbd16f78809eb1e67dde550b7e2fcb7e",
        "CFG": "191f77019e84df1cff29622c5f75f5a6",
        "PRO": "25926f17c86edf710ca7563c809c015a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fbd16f78809eb1e67dde550b7e2fcb7e"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkService@4",
          "_BinkService@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_0b5d66b3662b": {
      "addresses": {
        "LoD/PD2": "0x03821580"
      },
      "rvas": {
        "LoD/PD2": "0x1580"
      },
      "sizes": {
        "LoD/PD2": 85
      },
      "name": "WaitForBinkFileAccess",
      "signature": "uint WaitForBinkFileAccess(BinkFile * pBinkFile, uint dwOffset)",
      "calling_convention": "__stdcall",
      "comment": "Manages concurrent access to Bink file by incrementing a reference counter, waiting for exclusive access, then decrementing the counter. Returns page-aligned offset.\n\nAlgorithm:\n1. Increment reference counter at offset +0x5c (atomic LOCK operation)\n2. Load wait flag from offset +0x60 into register\n3. While wait flag is non-zero:\n   - Call Sleep(0) to yield processor\n   - Call BinkService function via function pointer at offset +0x18\n   - Reload wait flag from offset +0x60\n4. Decrement reference counter at offset +0x5c (atomic LOCK operation)\n5. Round up dwOffset to nearest 0x1000 byte boundary (page size)\n6. Return page-aligned offset\n\nParameters:\n- pBinkFile: Pointer to BinkFile structure containing access control fields\n- dwOffset: File offset or size value to be page-aligned\n\nReturns:\n- Page-aligned offset: (dwOffset + 0xFFF) & 0xFFFFF000\n\nSpecial Cases:\n- The reference counter acts as a lock for concurrent file access\n- Wait flag at offset +0x60 indicates when file is busy\n- Sleep(0) and BinkService calls implement a spin-wait loop yielding to other threads\n- Return value rounds up to nearest 4KB page boundary (typical for file operations)\n- LOCK prefix ensures atomic increment/decrement on multiprocessor systems",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0b5d66b3662b4610e5335569925079fb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0b5d66b3662b4610e5335569925079fb",
        "CFG": "ca13b0936d7d2a42bfa9fd47b995589c",
        "PRO": "a90d819a6ae1fb410ac90d35417230bb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0b5d66b3662b4610e5335569925079fb"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkService@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_b44c1e185c2c": {
      "addresses": {
        "LoD/PD2": "0x038215E0"
      },
      "rvas": {
        "LoD/PD2": "0x15E0"
      },
      "sizes": {
        "LoD/PD2": 121
      },
      "name": "InitializeBinkFile",
      "signature": "void InitializeBinkFile(BinkFile * pBinkFile, uint baseAddress, uint pageSize, undefined4 param4, undefined4 param5)",
      "calling_convention": "__stdcall",
      "comment": "Initializes and configures a Bink video file structure with memory layout and initialization flags.\n\nAlgorithm:\n1. Increment reference counter at offset +0x5c using atomic LOCK operation\n2. Wait loop: repeatedly call Sleep(0) and _BinkService_4 while counter at offset +0x60 is non-zero\n3. Align pageSize to 4KB boundary (mask with 0xfffff000)\n4. Store baseAddress at offsets +0x64, +0x54, +0x6c\n5. Store (baseAddress + alignedSize) at offset +0x68\n6. Store alignedSize at offsets +0x38, +0x58\n7. Clear initialization flag at offset +0x44\n8. Store param4 and param5 at offsets +0x78, +0x7c\n9. Decrement reference counter at offset +0x5c using atomic LOCK operation\n\nParameters:\n  pBinkFile: Pointer to BinkFile structure to initialize (104 bytes)\n  baseAddress: Base memory address for the Bink file buffer\n  pageSize: Total size of memory region (will be page-aligned)\n  param4: Additional configuration parameter (stored at offset +0x78)\n  param5: Additional configuration parameter (stored at offset +0x7c)\n\nReturns:\n  void - Function performs in-place initialization of BinkFile structure\n\nSpecial Cases:\n  - Uses atomic LOCK operations for thread-safe reference counting\n  - Page alignment mask (0xfffff000) aligns pageSize to 4KB boundaries\n  - Wait loop allows other threads to access Bink service during initialization\n  - Multiple fields store similar values suggesting redundant bookkeeping\n\nStructure Layout (BinkFile offsets):\n  Offset | Size | Field Name       | Type   | Description\n  -------|------|------------------|--------|----------------------------------------\n    0x00 |    4 | ReadProc         | ptr    | Read callback function\n    0x04 |    4 | WriteProc        | ptr    | Write callback function\n    0x08 |    4 | GetInfoProc      | ptr    | Get info callback function\n    0x0c |    4 | SetInfoProc      | ptr    | Set info callback function\n    0x10 |    4 | CloseProc        | ptr    | Close callback function\n    0x14 |    4 | SetSoundProc     | ptr    | Set sound callback function\n    0x18 |    4 | Reserved         | ptr    | (Points to Sleep function ptr at 0x038430d0)\n    0x5c |    1 | RefCount         | byte   | Reference counter (atomic operations)\n    0x60 |    4 | WaitFlag         | dword  | Wait condition flag\n    0x64 |    4 | BaseAddr1        | dword  | Base address copy 1\n    0x54 |    4 | BaseAddr2        | dword  | Base address copy 2\n    0x6c |    4 | BaseAddr3        | dword  | Base address copy 3\n    0x68 |    4 | EndAddr          | dword  | End address (baseAddr + size)\n    0x38 |    4 | AlignedSize1     | dword  | Aligned size copy 1\n    0x58 |    4 | AlignedSize2     | dword  | Aligned size copy 2\n    0x44 |    4 | InitFlag         | dword  | Initialization flag (zeroed)\n    0x78 |    4 | Config1          | dword  | Configuration parameter 1\n    0x7c |    4 | Config2          | dword  | Configuration parameter 2",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b44c1e185c2c0726e0d35b2a2760d526",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b44c1e185c2c0726e0d35b2a2760d526",
        "CFG": "214332a222f1a5a253220cd69ccebffe",
        "PRO": "5e5983c62b5d4103b1195b0a4dcdc59e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b44c1e185c2c0726e0d35b2a2760d526"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkService@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_02a4d84f0677": {
      "addresses": {
        "LoD/PD2": "0x03821660"
      },
      "rvas": {
        "LoD/PD2": "0x1660"
      },
      "sizes": {
        "LoD/PD2": 87
      },
      "name": "BinkServiceCleanup",
      "signature": "void BinkServiceCleanup(int * pBinkContext)",
      "calling_convention": "__stdcall",
      "comment": "Manages Bink service cleanup with reference counting and resource release.\n\nAlgorithm:\n1. Acquire reference count lock and increment counter at offset 0x5c\n2. Load service status flag from offset 0x60 (non-zero means service active)\n3. Loop while service status is non-zero: call Sleep(0) to yield, then call _BinkService_4 with context pointer from offset 0x18, reload status\n4. Exit loop when service status becomes zero\n5. Check cleanup flag at offset 0x70 (zero means should close handle)\n6. If flag is zero, close handle from offset 0x48 via CloseHandle API\n7. Acquire reference count lock again and decrement counter at offset 0x5c\n8. Return to caller\n\nParameters:\n- pBinkContext: int * - Pointer to Bink service context structure containing service state and handles\n\nReturns:\n- void - No return value\n\nSpecial Cases:\n- Uses LOCK/UNLOCK macros for thread-safe reference counting at offset 0x5c\n- Polling loop with Sleep(0) ensures cooperative waiting without busy-waiting\n- Conditional CloseHandle is guarded by flag at offset 0x70 to prevent double-close\n- Cleanup flag at 0x70 can be pre-set to skip handle closure if needed\n\nStructure Layout (context offsets):\nOffset | Size | Field Name    | Type      | Description\n-------|------|---------------|-----------|------------------------\n 0x18  |  4   | servicePtr    | int*      | Pointer passed to _BinkService_4\n 0x48  |  4   | handleToClose | HANDLE    | Windows handle closed if flag=0\n 0x5c  |  1   | refCount      | byte      | Reference counter (LOCK protected)\n 0x60  |  4   | serviceStatus | int       | Status flag (non-zero=active)\n 0x70  |  4   | closeFlag     | int       | Control flag (0=close handle)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:02a4d84f0677d99c67e86a8e3a1e4a0f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "02a4d84f0677d99c67e86a8e3a1e4a0f",
        "CFG": "08d8b4f09c7ccfc6dedc603174452543",
        "PRO": "24e881c66cbfac424d938e1764f6493b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "02a4d84f0677d99c67e86a8e3a1e4a0f"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkService@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_bb60d25eda88": {
      "addresses": {
        "LoD/PD2": "0x038216C0"
      },
      "rvas": {
        "LoD/PD2": "0x16C0"
      },
      "sizes": {
        "LoD/PD2": 410
      },
      "name": "ReadFileWithSyncAndThrottle",
      "signature": "uint ReadFileWithSyncAndThrottle(int * pFileIOState)",
      "calling_convention": "__stdcall",
      "comment": "Synchronously reads file data with thread coordination and rate throttling.\n\nThis function is part of a multi-threaded file I/O system. It coordinates read\noperations using atomic increment/decrement operations on two synchronization\ncounters, ensuring only one thread reads at a time. It also implements optional\nrate limiting by delaying between reads based on a throughput target.\n\nAlgorithm:\n1. Atomically increment both sync counters (offset +0x60 and +0x5c)\n2. Check if both counters equal 1 (indicating this is the only active reader)\n3. If not the only reader, set error flag and return 0xffffffff\n4. If the only reader, check buffer capacity (offset +0x58) and available space\n5. If insufficient buffer space, copy current to previous offset (+0x40 from +0x44)\n6. Otherwise, call timeGetTime() to record start time\n7. Set read-in-progress flag (offset +0x1c = 1)\n8. Call ReadFile() to read 0x1000 (4096) bytes from file handle (offset +0x48)\n9. Clear read-in-progress flag (offset +0x1c = 0)\n10. Update total bytes read counter (offset +0x20)\n11. Update current file position counter (offset +0x4c)\n12. Update write buffer position pointer (offset +0x6c), wrap if needed\n13. Decrement remaining buffer size (offset +0x58)\n14. Increment bytes processed counter (offset +0x44)\n15. Update max offset reached (offset +0x3c) if applicable\n16. If throttling enabled (offset +0x7c != 0), calculate delay needed to match throughput\n17. Sleep in a loop until elapsed time reaches target delay\n18. Record elapsed time and add to total time counter (offset +0x28)\n19. If no state change (offset +0x24), add to idle time (offset +0x30), else add to busy time (offset +0x34)\n20. Atomically decrement both sync counters\n21. If this thread wasn't the only reader, sleep(0) to yield CPU\n22. Return bytes read or 0xffffffff on error\n\nParameters:\n  pFileIOState: Pointer to file I/O state structure with the following offsets:\n    +0x1c: read-in-progress flag (set to 1 during ReadFile call)\n    +0x20: total bytes successfully read counter\n    +0x24: state flag (0 when idle)\n    +0x28: total elapsed time for all reads (milliseconds)\n    +0x30: accumulated idle read time (milliseconds)\n    +0x34: accumulated busy read time (milliseconds)\n    +0x3c: maximum offset reached during reads\n    +0x40: previous offset value (copy destination)\n    +0x44: total bytes processed counter\n    +0x48: file handle for ReadFile()\n    +0x4c: current file position counter\n    +0x58: remaining buffer size counter\n    +0x5c: sync counter 2 (incremented at start, decremented at end)\n    +0x60: sync counter 1 (incremented at start, decremented at end)\n    +0x64: wrap-around buffer base address\n    +0x68: wrap-around buffer end address\n    +0x6c: current write position in buffer\n    +0x78: current read position counter\n    +0x7c: throttle throughput limit (bytes per second, 0 = no throttle)\n\nReturns:\n  uint: Number of bytes read from file, or 0xffffffff if synchronization failed\n        (another thread was already reading when this function tried to read)\n\nSpecial Cases:\n  - Throttling: If offset +0x7c is non-zero, the function calculates how many\n    milliseconds a 0x1000-byte read should take at the specified throughput\n    (bytes per second), then sleeps to enforce that rate limit\n  - Wrap-around buffer: Offset +0x6c is a position pointer that wraps around\n    between +0x64 and +0x68, resetting to +0x64 when it exceeds +0x68\n  - Synchronization: Two independent counters prevent concurrent reads. Both\n    must equal 1 for the read to proceed. If not, returns error immediately",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bb60d25eda889adae0739398f3eb5ece",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bb60d25eda889adae0739398f3eb5ece",
        "CFG": "7d211539dae80d28a7ea6f9850cdc7fb",
        "PRO": "5ca8448311cf83f64a4cd318d83a3c03"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bb60d25eda889adae0739398f3eb5ece"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_f5ca552f677d": {
      "addresses": {
        "LoD/PD2": "0x03821860"
      },
      "rvas": {
        "LoD/PD2": "0x1860"
      },
      "sizes": {
        "LoD/PD2": 955
      },
      "name": "DCT_Forward8x8",
      "signature": "void DCT_Forward8x8(uchar * pOutputBuffer, int nStride, short * pInputData, int * pDCTCoefficients)",
      "calling_convention": "__cdecl",
      "comment": "Forward 8-point DCT (Discrete Cosine Transform) with fixed-point arithmetic.\n\nAlgorithm:\n1. Phase 1 (Columns): For each of 8 input columns, check if even components are all zero\n2. If all zeros: compute simple DC component (input[0] * coeff[0] >> 11)\n3. If non-zero: perform full 8-point DCT on both even and odd components with butterfly operations\n4. Store 8 intermediate results in local output array (local_100)\n5. Phase 2 (Rows): Process 8x8 block row-wise from intermediate results\n6. Apply DCT butterfly operations and fixed-point scaling\n7. Output 8 normalized byte values per row with rounding (0x7f offset, right shift 8)\n\nParameters:\n- pOutputBuffer: Output byte buffer pointer for DCT coefficients\n- nStride: Row stride/pitch in output buffer\n- pInputData: Array of 8 signed short input values (16-bit samples)\n- pDCTCoefficients: Pre-computed fixed-point cosine coefficient table with scale factor 11\n\nReturns: void (results written to pOutputBuffer)\n\nSpecial Cases:\n- Magic constant 0xb50 (2896 in decimal): Fixed-point scaled cosine(pi/8)\n- Magic constant 0xec8 (3784 in decimal): Fixed-point scaled cosine(3*pi/8)\n- Magic constant 0x14e8 (5352 in decimal): Fixed-point scaled cosine(pi/4)\n- Magic constant 0x8a9 (2217 in decimal): Fixed-point scaled cosine(pi/16)\n- All DCT computations use >> 0xb (right shift 11 bits) for fixed-point normalization\n- Output rounding: (value + 0x7f) >> 8 converts fixed-point to 8-bit unsigned byte",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f5ca552f677d9d85d47471669a71b39b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f5ca552f677d9d85d47471669a71b39b",
        "CFG": "6cc6399cc0ad2eaa3646b7e25e576b8a",
        "PRO": "55ee6e8ec8917f1b0c0cca18e8e57baa"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f5ca552f677d9d85d47471669a71b39b"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_c1c99cf2421b": {
      "addresses": {
        "LoD/PD2": "0x03821C20"
      },
      "rvas": {
        "LoD/PD2": "0x1C20"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "ApplyDCTTransformBlock",
      "signature": "void ApplyDCTTransformBlock(uchar * pSourceBuffer, int nStride, short * pDCTCoefficients, int nBlockIndex)",
      "calling_convention": "__stdcall",
      "comment": "Applies 8x8 block Discrete Cosine Transform (DCT) to video/image plane data.\n\nAlgorithm:\n1. Retrieve stride value from ESP+0x10 and shift left by 8 bits\n2. Add 0x38431dc base address to compute output buffer pointer\n3. Load source buffer pointer, stride, and coefficient pointers from stack\n4. Push calculated output buffer pointer and parameters onto stack\n5. Call DCT_Forward8x8 to perform forward DCT transformation\n6. Clean up stack by adding 0x10 to ESP\n7. Return to caller with __stdcall convention (EDX:EAX preserved)\n\nParameters:\n- pSourceBuffer: Pointer to 8x8 source pixel block\n- nStride: Byte stride between rows in source buffer\n- pDCTCoefficients: Pointer to short array for output coefficients\n- nBlockIndex: Block index used to calculate output buffer offset (multiplied by 0x100)\n\nReturns:\n- void: DCT coefficients written to memory location computed from base 0x38431dc + (nBlockIndex << 8)\n\nSpecial Cases:\n- Output buffer calculated as: (&DAT_038431dc) + (nBlockIndex * 0x100)\n- This allows each block to have a 256-byte (0x100) output buffer allocation\n- DCT coefficients stored in short (2-byte) integer format\n- Function is wrapper for actual DCT implementation in DCT_Forward8x8",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c1c99cf2421bbca4d93b6ed9360dc2ea",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c1c99cf2421bbca4d93b6ed9360dc2ea",
        "CFG": null,
        "PRO": "912c17003ec1e8560f7b788a74738fe3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c1c99cf2421bbca4d93b6ed9360dc2ea"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_ADDR_03821C50": {
      "addresses": {
        "LoD/PD2": "0x03821C50"
      },
      "rvas": {
        "LoD/PD2": "0x1C50"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "ApplyDCTTransformBlock",
      "signature": "void ApplyDCTTransformBlock(uchar * pSourceBuffer, int nStride, short * pDCTCoefficients, int nBlockIndex)",
      "calling_convention": "__stdcall",
      "comment": "Applies 8x8 block Discrete Cosine Transform (DCT) to video/image plane data.\n\nAlgorithm:\n1. Retrieve block index from stack at ESP+0x10\n2. Shift block index left by 8 bits (multiply by 0x100)\n3. Add base address 0x38431dc to compute output buffer offset\n4. Load all parameters from stack (source buffer, stride, coefficients)\n5. Push calculated output buffer pointer as 4th parameter\n6. Call DCT_Forward8x8 function with all parameters\n7. Clean stack (add 0x10 to ESP) and return to caller\n\nParameters:\n- pSourceBuffer (ESP+0x4): Pointer to 8x8 source pixel block to be transformed\n- nStride (ESP+0x8): Byte stride between rows in source buffer\n- pDCTCoefficients (ESP+0xc): Pointer to short array for output DCT coefficients\n- nBlockIndex (ESP+0x10): Block index used to calculate output buffer offset\n\nReturns:\n- void: DCT coefficients written to memory location computed from base 0x38431dc + (nBlockIndex * 0x100)\n\nSpecial Cases:\n- Output buffer is allocated dynamically at address: (&DAT_038431dc) + (nBlockIndex * 0x100)\n- Each block gets exactly 0x100 (256) bytes for output coefficients\n- Supports multiple sequential blocks by incrementing block index\n- DCT output stored as short integers (2-byte format)\n- Function acts as dispatcher/wrapper for DCT_Forward8x8 implementation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c1c99cf2421bbca4d93b6ed9360dc2ea",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c1c99cf2421bbca4d93b6ed9360dc2ea",
        "CFG": null,
        "PRO": "912c17003ec1e8560f7b788a74738fe3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c1c99cf2421bbca4d93b6ed9360dc2ea"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_739481209f0d": {
      "addresses": {
        "LoD/PD2": "0x03821C80"
      },
      "rvas": {
        "LoD/PD2": "0x1C80"
      },
      "sizes": {
        "LoD/PD2": 1121
      },
      "name": "ProcessDCTBlock",
      "signature": "void ProcessDCTBlock(int blockDataPtr, int stride, short * quantTable, int * dctCoefficients)",
      "calling_convention": "__cdecl",
      "comment": "ProcessDCTBlock - Applies inverse DCT transform and quantization to 8x8 DCT coefficient block\n\nAlgorithm:\n1. Initialize loop counters for 8 columns and 8 rows\n2. For each of 8 columns, check if all quantized coefficients are zero\n3. If all zero: fill 8 output values with simple scaled first coefficient (coeff[0]*quant[0]>>11)\n4. If non-zero: perform full 1D inverse DCT on column using 8-point algorithm with magic constants:\n   - Multiply each coefficient by corresponding quantization value\n   - Apply fixed-point arithmetic with 11-bit right shifts (precision scaling)\n   - Compute intermediate sums and differences to build output values\n5. Store 8 output values to column output buffer (4-byte stride)\n6. Move to next column (stride += 4, quantTable += 1)\n7. For each of 8 row groups, apply second transform stage:\n   - Load 8 pre-transformed column values from previously computed buffer\n   - Apply second 1D inverse DCT stage with clipping and packing\n   - Convert 16 intermediate values to 8-bit pixels with rounding (+0x7f before >>8)\n   - Pack 4 adjacent pixels into 32-bit word (replicate to fill all 32 bits for color)\n   - Store packed pixels to output block at stride intervals\n\nParameters:\nblockDataPtr - Base address of output image/block data buffer (receives transformed pixels)\nstride - Row stride in bytes between consecutive output rows (typically 256 for 8x8 block stride)\nquantTable - Pointer to 8-element quantization table (short values, one per row/column)\ndctCoefficients - Pointer to 64-element DCT coefficient array [0..63] arranged as 8 rows\n\nReturns:\nvoid - Output written directly to blockDataPtr at stride intervals\n\nSpecial Cases:\n- All-zero DC coefficient: fills column with constant value (zero DCT bypass)\n- Fixed-point precision: all intermediate multiplies use 11-bit right shift (1/(2^11) = 1/2048 scale)\n- Pixel clipping: output values are clipped to [0,255] range via rounding (add 0x7f) and byte extraction\n- 32-bit pixel packing: result replicated across 32 bits ([R,G,B,A] identical - monochrome or palette mode)\n\nStructure Layout:\nQuantization Table (8 shorts):\nOffset  Size  Field       Type    Description\n0       2     q[0]        short   DC coefficient quantizer\n2       2     q[1]        short   AC coefficient quantizer for row 1\n4       2     q[2]        short   AC coefficient quantizer for row 2\n...\n14      2     q[7]        short   AC coefficient quantizer for row 7\n\nDCT Coefficient Array (64 ints):\nOffset  Size  Field       Type    Description\n0       4     coeff[0]    int     DC coefficient\n4       4     coeff[1]    int     AC coefficient (1,0)\n...\n252     4     coeff[63]   int     AC coefficient (7,7)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:739481209f0d2341ed11618a070c0e2e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "739481209f0d2341ed11618a070c0e2e",
        "CFG": "ec6e997f33c72bf964ac0f1c9aa25cd7",
        "PRO": "136da23c181ec3ab3efd35d44e1a4fdc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "739481209f0d2341ed11618a070c0e2e"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_949a12f407cd": {
      "addresses": {
        "LoD/PD2": "0x038220F0"
      },
      "rvas": {
        "LoD/PD2": "0x20F0"
      },
      "sizes": {
        "LoD/PD2": 1046
      },
      "name": "IDCTProcess8x8Block",
      "signature": "void IDCTProcess8x8Block(int outputRowPtr, int outputStride, short * pQuantTablePtr, int tableIndex, int outputBasePtr)",
      "calling_convention": "__stdcall",
      "comment": "Performs 8x8 Inverse Discrete Cosine Transform (IDCT) on quantized frequency coefficients.\n\nThis function implements a separable 2D IDCT in two passes: first horizontally across all 8 coefficients per row, then vertically down each column. Uses fixed-point arithmetic with 11-bit fractional precision and applies output level shifting (adding 128 and right-shifting 8 bits) before storing results as unsigned bytes.\n\nAlgorithm:\n1. Initialize output array with 8 rows x 8 columns in stack buffer\n2. First pass: For each of 8 input coefficient rows, perform 1D IDCT\n   - If all non-DC coefficients are zero, fill all 8 output values with DC coefficient\n   - Otherwise, compute 8-point IDCT using cosine basis functions (stored at quantization table)\n   - Apply fixed-point scaling (right-shift by 11 bits)\n3. Second pass: For each of 8 output columns, perform 1D IDCT on row results\n   - Compute 8-point IDCT of column data\n   - Apply scaling, add offset (0x7f = 127), right-shift 8 bits\n   - Add previous pixel value from destination buffer (reconstruction)\n   - Clamp to byte range and write to output scanline\n\nParameters:\n  outputRowPtr: Starting address of current output row in destination buffer\n  outputStride: Bytes between consecutive output rows (pitch)\n  pQuantTable: Pointer to 8-element quantization table (cosine coefficients)\n  tableIndex: Index into global quantization table array (offset 0x38451dc)\n  outputBasePtr: Base address of output buffer (used for previous pixel values during reconstruction)\n\nReturns: void (modifies output buffer in-place)\n\nStructure Layout - Quantization Table (8 DWORDs):\n  Offset  Size  Field Name           Type    Description\n  0x00    4     cos_0_0              dword   DC component constant\n  0x04    4     cos_1_0              dword   1D IDCT basis coefficient\n  0x08    4     cos_2_0              dword   2D IDCT basis coefficient\n  0x0C    4     cos_3_0              dword   IDCT basis coefficient for 3\n  0x10    4     cos_4_0              dword   IDCT basis coefficient for 4\n  0x14    4     cos_5_0              dword   IDCT basis coefficient for 5\n  0x18    4     cos_6_0              dword   IDCT basis coefficient for 6\n  0x1C    4     cos_7_0              dword   IDCT basis coefficient for 7",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:949a12f407cde85adcd110a6d2c8a5f2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "949a12f407cde85adcd110a6d2c8a5f2",
        "CFG": "f457eff5dbde5cc2305d55b5bed28ded",
        "PRO": "364571e63c0b42ac03e1f41176278560"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "949a12f407cde85adcd110a6d2c8a5f2"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_7a890653f212": {
      "addresses": {
        "LoD/PD2": "0x03822510"
      },
      "rvas": {
        "LoD/PD2": "0x2510"
      },
      "sizes": {
        "LoD/PD2": 189
      },
      "name": "_ExpandBundleSizes@8",
      "signature": "undefined _ExpandBundleSizes@8(uint * param_1, uint param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7a890653f21270c876da2530f1ef2d3f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7a890653f21270c876da2530f1ef2d3f",
        "CFG": null,
        "PRO": "4e76c81470e2988ecc180e10cfbc4c5c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7a890653f21270c876da2530f1ef2d3f"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_eb628dcd1979": {
      "addresses": {
        "LoD/PD2": "0x038225D0"
      },
      "rvas": {
        "LoD/PD2": "0x25D0"
      },
      "sizes": {
        "LoD/PD2": 62
      },
      "name": "CalculateAssetBufferSize",
      "signature": "uint CalculateAssetBufferSize(int baseOffset, uint width, uint height, int depth)",
      "calling_convention": "__cdecl",
      "comment": "Calculates aligned buffer size for game asset storage.\\n\\nAlgorithm:\\n1. Clamp height parameter to minimum 8 bits\\n2. Clamp height parameter to maximum 16 bits if above 15\\n3. Shift width right by 3 bits (divide by 8)\\n4. Calculate primary buffer size: (width >> 3) * height * depth >> 3\\n5. Calculate base offset contribution: (baseOffset * height) >> 3\\n6. Add both components and constant offset of 3\\n7. Apply 4-byte alignment mask (0xfffffffc)\\n8. Return aligned size\\n\\nParameters:\\n- baseOffset: Base memory offset for calculation (typically 0x200)\\n- width: Image/texture width in pixels\\n- height: Image/texture height in pixels (clamped to 8-16 range)\\n- depth: Bit depth or multiplier factor\\n\\nReturns:\\n- uint: Aligned buffer size in bytes, rounded down to 4-byte boundary\\n\\nSpecial Cases:\\n- Height values < 9 are set to 8\\n- Height values 9-15 are set to 16\\n- Height values >= 16 remain unchanged\\n- Final result is aligned to 4-byte boundary via AND 0xfffffffc\\n\\nStructure Layout:\\nThe function processes data with these stride patterns:\\n- Byte stride: 8 (division by 8 via SHR)\\n- Alignment: 4-byte boundary\\n- Used in ExpandBundleSizes for game asset buffers",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:eb628dcd19798960da45ec68c6e0c23f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "eb628dcd19798960da45ec68c6e0c23f",
        "CFG": "9f1e400507e0bab22bb89a5ad7e2b31b",
        "PRO": "5b45d71d48c825abf1275e223f921683"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "eb628dcd19798960da45ec68c6e0c23f"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_67b04c28fb1d": {
      "addresses": {
        "LoD/PD2": "0x03822610"
      },
      "rvas": {
        "LoD/PD2": "0x2610"
      },
      "sizes": {
        "LoD/PD2": 5514
      },
      "name": "_ExpandPlane@44",
      "signature": "uint * _ExpandPlane@44(uint * param_1, uint * param_2, uint param_3, uint param_4, uint param_5, uint * param_6, undefined4 param_7, int param_8, uint param_9, undefined4 * param_10, uint param_11)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:67b04c28fb1d13a20830188d10278eff",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "67b04c28fb1d13a20830188d10278eff",
        "CFG": "b6de094d92e1deecea4b76620b4bcb0b",
        "PRO": "4ed31ddeefe8731151d7fb9ded6db19d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "67b04c28fb1d13a20830188d10278eff"
      },
      "param_counts": {
        "LoD/PD2": 11
      }
    },
    "binkw32_MNE_623afa8601b5": {
      "addresses": {
        "LoD/PD2": "0x03823BE0"
      },
      "rvas": {
        "LoD/PD2": "0x3BE0"
      },
      "sizes": {
        "LoD/PD2": 168
      },
      "name": "ExpandPlaneCell",
      "signature": "void ExpandPlaneCell(uint cellMask, uint * pCellData, int offsetBase, uint bitOffset, int dimension, int stride, int initializeParams)",
      "calling_convention": "__cdecl",
      "comment": "Initializes a plane cell expansion record with calculated power value and configuration.\n\nAlgorithm:\n1. Calculate cell index: offsetBase + (bitOffset >> 3) * stride - 1\n2. Determine power value based on cell index ranges using lookup table or comparisons:\n   - If index < 0x81: lookup byte from DAT_0384800f + index\n   - If index < 0x200: power = 9 or 10 based on index < 0x100\n   - If index < 0x400: power = 11 or 12 based on index < 0x200\n   - If index < 0x1000: power = 13 or 14 based on index < 0x1000\n   - If index >= 0x1000: power = 15 or 16 based on index < 0x4000\n3. Initialize pCellData structure fields:\n   - [0] = 0 (offset 0x0)\n   - [1] = 0 (offset 0x4)\n   - [2] = dimension (offset 0x8)\n   - [10] = powerValue (offset 0x28)\n4. If initializeParams != 0:\n   - [11] = cellMask (offset 0x2c)\n   - [3] = 1 << (dimension - 1) (offset 0xc, bitmask)\n   Else:\n   - [3] = 0 (offset 0xc, no bitmask)\n   - [11] = cellMask (offset 0x2c)\n\nParameters:\n- cellMask: Mask or identifier for the plane cell\n- pCellData: Pointer to expansion record structure (12+ dwords)\n- offsetBase: Base offset for index calculation\n- bitOffset: Bit offset, divided by 8 for byte offset calculation\n- dimension: Size/power dimension value (typically 8-16)\n- stride: Multiplier for offset calculation\n- initializeParams: Flag controlling bitmask initialization (0=conditional, non-zero=always)\n\nReturns:\nvoid (initializes structure in-place via pCellData pointer)\n\nStructure Layout:\nOffset  Size  Field Name          Type   Description\n0x0     4     padding0            dword  Always 0\n0x4     4     padding1            dword  Always 0\n0x8     4     dimension           dword  Size/dimension value from parameter\n0xc     4     bitmask             dword  1 << (dimension-1) or 0 based on initializeParams\n0x10    32    reserved0           bytes  Unused expansion data\n0x28    4     powerValue          dword  Calculated power/shift value (9-16)\n0x2c    4     cellMask            dword  Cell mask/identifier from parameter",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:623afa8601b5f4e2ac2f66474834215c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "623afa8601b5f4e2ac2f66474834215c",
        "CFG": "99da5d1d8dd85d80961dc92b0df1e605",
        "PRO": "d6e9ccfe2a0e1ee0f6544b1d0fcc0d37"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "623afa8601b5f4e2ac2f66474834215c"
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "binkw32_MNE_7402afe48fd7": {
      "addresses": {
        "LoD/PD2": "0x03823C90"
      },
      "rvas": {
        "LoD/PD2": "0x3C90"
      },
      "sizes": {
        "LoD/PD2": 30
      },
      "name": "DecodeBitstreamData",
      "signature": "void DecodeBitstreamData(int pSourceData, int * pBitstreamReader)",
      "calling_convention": "__cdecl",
      "comment": "Decodes data from a bitstream reader into a destination structure.\n\nThis is a wrapper function that calls the core bitstream decoder with properly\noffset pointers to different parts of a data structure. The function extracts\nspecific field offsets from the base source address and passes them to the\nbitstream decoding engine.\n\nAlgorithm:\n1. Extract pointer to output table at offset +0x24 from source data\n2. Extract pointer to length/count data at offset +0x20 from source data\n3. Extract pointer to alphabet/symbol table at offset +0x10 from source data\n4. Call the bitstream decoder with the bitstream reader and extracted pointers\n\nParameters:\n- pSourceData (int): Base address of source data structure containing compressed data\n- pBitstreamReader (int*): Pointer to bitstream reader state, contains:\n  - [0]: Current pointer into input stream (advances during decoding)\n  - [1]: Word buffer with current bits being processed\n  - [2]: Partial bits from current word (right-shifted value)\n  - [3]: Bit position counter (0-31)\n\nReturns:\n- void: The bitstream reader is updated in-place with new position and state\n\nStructure Offsets (pSourceData):\n- +0x10: Pointer to alphabet/symbol lookup table\n- +0x20: Pointer to symbol counts/frequencies\n- +0x24: Pointer to output/destination table\n\nSpecial Cases:\n- The bitstream reader must be initialized before calling\n- The output destinations must be properly allocated\n- Bit positions use 31-0 (MSB to LSB) convention",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7402afe48fd7d64081795b95537a3127",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7402afe48fd7d64081795b95537a3127",
        "CFG": null,
        "PRO": "b4b69e6f9be303b5b22f85032ea32d1f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7402afe48fd7d64081795b95537a3127"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_2dea06d4d687": {
      "addresses": {
        "LoD/PD2": "0x03823CB0"
      },
      "rvas": {
        "LoD/PD2": "0x3CB0"
      },
      "sizes": {
        "LoD/PD2": 1137
      },
      "name": "DecodeHuffmanTree",
      "signature": "void DecodeHuffmanTree(int * pBitstreamReader, undefined4 * pOutputTable, uint * pSymbolCounts, undefined1 * pAlphabetTable)",
      "calling_convention": "__cdecl",
      "comment": "Decodes a Huffman tree from a bitstream and builds a symbol lookup table.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2dea06d4d687b9f440221e864c9a45ba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2dea06d4d687b9f440221e864c9a45ba",
        "CFG": "74a3da7a40b59a6a457ab45cdd33965d",
        "PRO": "bfdd83aa11e64245295e1fe5b9cfe896"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2dea06d4d687b9f440221e864c9a45ba"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_9190a8f0423f": {
      "addresses": {
        "LoD/PD2": "0x03824130"
      },
      "rvas": {
        "LoD/PD2": "0x4130"
      },
      "sizes": {
        "LoD/PD2": 177
      },
      "name": "DecodeBitStreamBytes",
      "signature": "void DecodeBitStreamBytes(BitStreamDecoder * pDecoder, byte * pOutput, byte * pZeroBytes, byte * pOneBytes, int zeroCount)",
      "calling_convention": "__cdecl",
      "comment": "Decodes a bitstream into output bytes using two input byte streams.\n\nAlgorithm:\n1. Initialize oneCount to match zeroCount (tracks remaining bytes from each stream)\n2. Main decode loop:\n   a. Check if bit buffer needs refill (bitsRemaining == 0)\n   b. If refill needed: load next 32-bit value from source, shift right 1, set bitsRemaining to 31\n   c. If refill not needed: shift current buffer right 1, decrement bitsRemaining\n   d. Extract LSB from the shifted value (bit value before shift = original LSB)\n   e. If bit is 0: copy from pZeroBytes, decrement zeroCount\n   f. If bit is 1: copy from pOneBytes, decrement oneCount\n   g. Advance output pointer\n   h. Continue until zeroCount reaches 0 (all zero bits processed)\n3. If oneCount still has remaining bytes: copy directly from pOneBytes\n4. Exit if both streams exhausted\n\nParameters:\npDecoder (BitStreamDecoder*) - Pointer to bitstream decoder state containing:\n  - pDataSource: pointer to 32-bit word buffer (incremented when refilled)\n  - bitsRemaining: count of bits left in current buffer value\nzeroCount (int) - Number of bytes to read from pZeroBytes stream\npOutput (byte*) - Output buffer for decoded bytes\npZeroBytes (byte*) - Input stream of bytes for bits=0\npOneBytes (byte*) - Input stream of bytes for bits=1\n\nReturns:\nvoid\n\nSpecial Cases:\n- Processes one bit at a time from 32-bit words in source buffer\n- Stops decoding when zeroCount reaches 0\n- Copies remaining oneBytes directly without further bit processing\n- Buffer refill loads 32 bits but uses only 31 bits per load cycle\n\nStructure Layout:\nBitStreamDecoder at decoder offset:\nOffset  Size  Field Name       Type     Description\n0x00    0x04  pDataSource      pointer  Pointer to next 32-bit word in source buffer\n0x08    0x04  bitBuffer        uint     Current buffer value being consumed bit-by-bit\n0x0C    0x04  bitsRemaining    int      Number of valid bits remaining in bitBuffer (0-31)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9190a8f0423f5acc2bb744a488828fbe",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9190a8f0423f5acc2bb744a488828fbe",
        "CFG": "9a72b0c192370ccb948ef9235f58c4d1",
        "PRO": "a386898ce9dd2428c236b7933e0a06e5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9190a8f0423f5acc2bb744a488828fbe"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_14974876f08f": {
      "addresses": {
        "LoD/PD2": "0x038241F0"
      },
      "rvas": {
        "LoD/PD2": "0x41F0"
      },
      "sizes": {
        "LoD/PD2": 93
      },
      "name": "DecodeHuffmanAlphabets",
      "signature": "void DecodeHuffmanAlphabets(void * pDecoderContext, BitStreamDecoder * pBitStream, uchar * pAlphabetBuffer)",
      "calling_convention": "__cdecl",
      "comment": "Decodes 16 Huffman alphabets from a compressed bit stream and stores them in a buffer.\n\nAlgorithm:\n1. Initialize output table pointer to buffer offset 0x140 (Huffman code tables)\n2. Initialize alphabet table pointer to buffer start (alphabet data)\n3. Loop 16 times:\n   a. Call DecodeHuffmanTree to decode one alphabet's Huffman codes\n   b. Advance output table pointer by 4 bytes (1 dword)\n   c. Advance alphabet table pointer by 16 bytes (0x10)\n   d. Decrement loop counter\n4. After main loop, decode final Huffman tree from decoder context\n5. Zero out completion flag at buffer offset 0x180\n\nParameters:\npDecoderContext: Decoder context structure containing auxiliary Huffman tree info at offsets 0x10 (alphabet data), 0x20 (code pointer), and 0x24 (code table)\npBitStream: Bit stream decoder for reading compressed data\npAlphabetBuffer: 384-byte buffer for storing 16 alphabets (0x140 bytes for codes) + completion flag\n\nReturns:\nNone (void function)\n\nSpecial Cases:\n- Alphabet loop processes exactly 16 fixed alphabets\n- Final Huffman tree is decoded from context-specific offsets rather than iterative pattern\n- Completion flag at offset 0x180 is zeroed as 4-byte value (undefined4)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:14974876f08ffa831008244a8c8d48c9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "14974876f08ffa831008244a8c8d48c9",
        "CFG": "d69bc82e329d76c21526cdfbd9e8cc3d",
        "PRO": "0ff171db1d83b8c977a80293e0b1e922"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "14974876f08ffa831008244a8c8d48c9"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_e0b7a148de08": {
      "addresses": {
        "LoD/PD2": "0x03824250"
      },
      "rvas": {
        "LoD/PD2": "0x4250"
      },
      "sizes": {
        "LoD/PD2": 671
      },
      "name": "ExpandBitstreamLiteral",
      "signature": "void ExpandBitstreamLiteral(int * pExpansionState, int * pInputStream)",
      "calling_convention": "__cdecl",
      "comment": "Expands a bitstream into uncompressed data using literal byte encoding.\n\nAlgorithm:\n1. Validate that input and output buffers are in sync (param_1[0] == param_1[1])\n2. Load initial bitstream position: word pointer, bit offset, remaining bits\n3. Extract and decode the first data block size using variable-length bitfield extraction\n4. If size is zero, output padding and return\n5. If size is non-zero, decode and output literals or back-references:\n   - Check if next bit flag (LSB of decoded value) indicates literal or copy\n   - For literals (flag=0): Decode symbol from lookup table, output bytes to buffer\n   - For copies (flag=1): Decode literal chunk, replicate pattern in output buffer\n6. Continue decoding until output buffer is filled\n7. Update bitstream state with final position and remaining bits\n\nParameters:\npExpansionState (int *): Expansion state block\n  Offset +0x00: Current input pointer (synchronized with +0x04)\n  Offset +0x04: Input end marker (synchronized with +0x00)\n  Offset +0x20: Unused\n  Offset +0x24: Uncompressed output data pointer\n  Offset +0x28: Compressed input data word pointer\n  Offset +0x2c: Output buffer write pointer\n\npInputStream (int *): Bitstream decoder state\n  Offset +0x00: Data source word pointer (word-aligned)\n  Offset +0x04: Not used in this context\n  Offset +0x08: Bitfield value\n  Offset +0x0c: Remaining bits in bitfield\n\nReturns:\nvoid - Updates pExpansionState and pInputStream with final decoder state\n\nSpecial Cases:\n- Zero-length output block: Advances pointer by 4 bytes and returns\n- Cross-word boundary reads: Combines bits from consecutive words\n- Literal chunk flag (LSB): Determines output strategy\n- Symbol lookup via offset +0x24 table for code-length decoding",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e0b7a148de08163aa410dc31152a2532",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e0b7a148de08163aa410dc31152a2532",
        "CFG": "69650437e974d15647c5ae1e7b6c05ac",
        "PRO": "3d7da7797c030259f08d7eba5f463007"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e0b7a148de08163aa410dc31152a2532"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_06e714ce5919": {
      "addresses": {
        "LoD/PD2": "0x038247E0"
      },
      "rvas": {
        "LoD/PD2": "0x47E0"
      },
      "sizes": {
        "LoD/PD2": 732
      },
      "name": "DecodePlaneData",
      "signature": "void DecodePlaneData(int * pBufferState, BitStreamDecoder * pBitStream, int pGameState)",
      "calling_convention": "__cdecl",
      "comment": "Decodes Huffman-compressed plane data from a bit stream.\n\nThis function decompresses plane data using two-stage Huffman decoding with\nliteral and distance codes. It processes compressed bit data sequentially,\ndecoding run-length encoded segments and filling output buffers.\n\nAlgorithm:\n1. Validate buffer state sanity check (first[0] == first[1])\n2. Initialize bit stream extraction from data source\n3. Extract initial bit code and determine literal/copy operation\n4. Loop through each pixel to decode:\n   a. Decode primary huffman code (length table at pGameState+0x100)\n   b. Decode secondary huffman code (literal distance tables)\n   c. Extract literal bits or backward copy distance\n   d. Store combined literal-distance pair as output byte\n5. Fill remaining buffer with repeated pattern if needed\n6. Update bit stream state and buffer positions\n\nParameters:\n- pBufferState: Pointer to buffer management state [offset 0x2c=buffer start,\n  0x30=buffer end, 0x28=bit width, 0x2b=output buffer base, 0x20-24=flags]\n- pBitStream: Pointer to bit stream decoder with source, buffer, bit count\n- pGameState: Game state context with huffman table offsets (+0x100, +0x140, +0x180)\n\nReturns:\n- void; modifies pBufferState and pBitStream in-place\n\nSpecial Cases:\n- If pixelsDecoded==0: no decoding occurs, buffer unchanged\n- If pixelsDecoded<-0x16: fills remaining buffer with repeated pattern\n- Handles bit boundary crossings when bits span multiple DWORDs",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:06e714ce5919b22cb5e48dcfdb7a6503",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "06e714ce5919b22cb5e48dcfdb7a6503",
        "CFG": "dd3685d1a245a42f1ad16e6e6658afc7",
        "PRO": "5c126b0a3303b9d27cf287f3752cc615"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "06e714ce5919b22cb5e48dcfdb7a6503"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_4fd2aec4b210": {
      "addresses": {
        "LoD/PD2": "0x03824AC0"
      },
      "rvas": {
        "LoD/PD2": "0x4AC0"
      },
      "sizes": {
        "LoD/PD2": 510
      },
      "name": "DecompressBitstream",
      "signature": "void DecompressBitstream(int * pStateIn, int * pStateOut)",
      "calling_convention": "__cdecl",
      "comment": "Decompresses a bitstream using Huffman-style table lookup.\n\nAlgorithm:\n1. Verify state validity by checking if input min==max\n2. Extract bit stream parameters from state structure\n3. Read and mask initial value from bit stream\n4. If output count zero, initialize output buffer, else process bits\n5. For even-bit: loop through decode table, lookup nibbles, advance\n6. For odd-bit: extract 4 bits, fill repeat pattern throughout output\n7. Restore bit stream state to output structure\n\nParameters:\n- pStateIn: Pointer to input state [min_offset, max_offset, ...]\n- pStateOut: Pointer to decompression state [word_ptr, -, bitbuf, bits_left, ...]\n\nReturns:\n- void (output written to buffer specified in pStateOut)\n\nSpecial Cases:\n- Zero output: Sets output buffer min=max, advances max by 4\n- Bit boundaries: Handles word boundary crossings during reads\n- Fill patterns: Detects odd LSB and expands 4-bit pattern",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4fd2aec4b21046bea8d79c8ef86e684c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4fd2aec4b21046bea8d79c8ef86e684c",
        "CFG": "a305d90eb9f6c64572135e4dfac9363d",
        "PRO": "2234a1da0aaf1d2b54e8ad87e76d676f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4fd2aec4b21046bea8d79c8ef86e684c"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_e69065048e9a": {
      "addresses": {
        "LoD/PD2": "0x03824CC0"
      },
      "rvas": {
        "LoD/PD2": "0x4CC0"
      },
      "sizes": {
        "LoD/PD2": 491
      },
      "name": "DecodeHuffmanSymbols",
      "signature": "void DecodeHuffmanSymbols(int * pDecodeContext, BitStreamDecoder * pBitStream)",
      "calling_convention": "__cdecl",
      "comment": "Decodes Huffman-encoded symbol pairs from a bitstream and writes decoded bytes to output buffer.\\\"}}]",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e69065048e9aee8805e8c120c828f6b0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e69065048e9aee8805e8c120c828f6b0",
        "CFG": "3eb597ca82d9d96318a0a97e56a7a23e",
        "PRO": "e99d8f1f02e921d93584d751baefed57"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e69065048e9aee8805e8c120c828f6b0"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_84ef8a248f89": {
      "addresses": {
        "LoD/PD2": "0x03824EB0"
      },
      "rvas": {
        "LoD/PD2": "0x4EB0"
      },
      "sizes": {
        "LoD/PD2": 599
      },
      "name": "DecodeHuffmanPlane",
      "signature": "void DecodeHuffmanPlane(HuffmanState * pHuffmanState, CompressionState * pCompressionState)",
      "calling_convention": "__cdecl",
      "comment": "Decodes a plane of Huffman-encoded data from a compressed bit stream.\n\nAlgorithm:\n1. Validate that input Huffman state min/max values match (line 0x3824eba)\n2. Extract initial bit window from source (lines 0x3824ec3-0x3824f2f)\n3. If no bits extracted, mark output buffer range and return (lines 0x3824f35-0x038250e9)\n4. For each output byte to decode:\n   a. Check if current symbol is odd/even (line 0x3824f6b)\n   b. If even: Use table lookup with 8-bit prefix to decode byte\n   c. If odd: Use 4-bit prefix to decode literal value, then fill output with pattern\n5. Update bit position and fetch next word when needed\n6. Write decoded bytes to output buffer at specified stride\n7. Update compression state with consumed bits position\n\nParameters:\npHuffmanState: Pointer to Huffman decode state containing bit window buffer, \n              table pointers, and bit position tracking (48 bytes)\npCompressionState: Pointer to bit stream state tracking current word pointer, \n                  consumed bits, bit buffer, and available bits (16 bytes)\n\nReturns: void (modifies output buffer ranges in pHuffmanState)\n\nSpecial Cases:\n- Empty plane: Advances output by 4 bytes when no bits available\n- Byte boundary crossing: Loads next word from source when bits depleted\n- Literal fill: When symbol is odd, fills output pattern with 1/2/4-byte copies\n- Bit width 0: Fast path skips table lookup for single-bit symbols\n- Register reuse: EDI tracks output byte count, regenerated from word when needed",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:84ef8a248f891afc5fc0a161769e08c4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "84ef8a248f891afc5fc0a161769e08c4",
        "CFG": "7a884a56c92f906859b44d439ed7682f",
        "PRO": "20302f4d51abc3b562e1fc765fc8fe06"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "84ef8a248f891afc5fc0a161769e08c4"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_ae27250c0070": {
      "addresses": {
        "LoD/PD2": "0x03825110"
      },
      "rvas": {
        "LoD/PD2": "0x5110"
      },
      "sizes": {
        "LoD/PD2": 805
      },
      "name": "DecodeBitstreamSymbol",
      "signature": "void DecodeBitstreamSymbol(short * pOutputBuffer, BitStreamDecoder * pBitstream)",
      "calling_convention": "__cdecl",
      "comment": "Decodes variable-length encoded symbols from a bitstream into an output buffer.\n\nAlgorithm:\n1. Validate input and output buffer pointers are valid and consistent\n2. Extract initial field width from bitstream state (parameter at offset +0x28)\n3. Extract field value using specified bit width from current bitstream position\n4. If field is zero, output special marker and return with buffer initialization\n5. If extended mode enabled: extract additional bits for sign handling\n6. For each symbol iteration:\n   - Extract 4-bit control code from bitstream\n   - If zero: fill output with repeated decoded value\n   - If non-zero: extract variable-length encoded bits and decode\n7. Apply sign correction and accumulate values to decoded symbol\n8. Store decoded values to output buffer with proper pointer advancement\n9. Update bitstream pointer and position counters before return\n\nParameters:\n- pOutputBuffer: Pointer to output array for decoded short values\n- pBitstream: Pointer to BitStreamDecoder structure (12 bytes)\n  - +0x0: pDataSource - Current position in compressed data\n  - +0x4: bitBuffer - 32-bit accumulator for bit extraction\n  - +0x8: bitsRemaining - Number of valid bits in buffer\n\nReturns:\n- void (updates bitstream state and output buffer in-place)\n\nSpecial Cases:\n- Zero field value triggers early return with buffer initialization\n- Extended mode (pOutputBuffer[3] != 0) uses 33-bit field width (0x21)\n- Negative field values trigger sign extension and value negation\n- Zero bit count refills bitstream from next source dword\n- Multiple symbol decode paths handle different control codes\n- Bit position wraps and refills from next source dword at boundaries",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ae27250c0070ffb873a0b864b76271aa",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ae27250c0070ffb873a0b864b76271aa",
        "CFG": "e9c3a82d42e8255973e2c79ce08c39ef",
        "PRO": "14a3409b9826c1f19a28f450574d16a9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ae27250c0070ffb873a0b864b76271aa"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_API_070a9c48e7b4": {
      "addresses": {
        "LoD/PD2": "0x03825440"
      },
      "rvas": {
        "LoD/PD2": "0x5440"
      },
      "sizes": {
        "LoD/PD2": 368
      },
      "name": "_ExpandBink@56",
      "signature": "undefined _ExpandBink@56(uint * param_1, uint * param_2, uint * param_3, uint * param_4, int param_5, int param_6, int param_7, uint param_8, uint param_9, uint * param_10, undefined4 param_11, undefined4 * param_12, uint param_13, uint param_14)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:070a9c48e7b420f8e579d5fcb772d391",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "070a9c48e7b420f8e579d5fcb772d391",
        "MNE": "1b461d798425509cecc8809d0678be7a",
        "CFG": "4b2c885de0683f18c63b0a7a3519bb1b",
        "PRO": "9ea5af00da8e8f8446c2b857dbce46db"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "1b461d798425509cecc8809d0678be7a"
      },
      "api_calls": {
        "LoD/PD2": [
          "_ExpandPlane@44",
          "_ExpandPlane@44",
          "_ExpandPlane@44",
          "_ExpandPlane@44"
        ]
      },
      "param_counts": {
        "LoD/PD2": 14
      }
    },
    "binkw32_MNE_9b926041d7cd": {
      "addresses": {
        "LoD/PD2": "0x038255B0"
      },
      "rvas": {
        "LoD/PD2": "0x55B0"
      },
      "sizes": {
        "LoD/PD2": 78
      },
      "name": "_BinkBufferSetDirectDraw@8",
      "signature": "undefined4 _BinkBufferSetDirectDraw@8(int param_1, int param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9b926041d7cdcd37a78048a3908ae189",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9b926041d7cdcd37a78048a3908ae189",
        "CFG": "59fda47cda35dae8080ac5e7e31b8139",
        "PRO": "da20f26a9a119390d2620f21f953bb8c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9b926041d7cdcd37a78048a3908ae189"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_b1984582b121": {
      "addresses": {
        "LoD/PD2": "0x03825600"
      },
      "rvas": {
        "LoD/PD2": "0x5600"
      },
      "sizes": {
        "LoD/PD2": 486
      },
      "name": "InitializeDisplayCapabilities",
      "signature": "void InitializeDisplayCapabilities(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes display and graphics device capabilities for Bink video playback.\n\nAlgorithm:\n1. Initialize 79-element capabilities buffer with zeros and size marker (0x13c)\n2. Call DirectDraw virtual method at offset 0x2c to query device capabilities\n3. Parse capability flags from buffer[1] and set corresponding bits in global DAT_0384f144:\n   - Bit 0x800000 -> 0xc0000000\n   - Bit 0x1000000 -> 0x80000000\n   - Bit 0x80000 -> 0x30000000\n   - Bit 0x100000 -> 0x20000000\n   - Bit 0x2000000 -> 0xc000000\n   - Bit 0x4000000 -> 0x8000000\n   - Bit 0x200000 -> 0x3000000\n   - Bit 0x400000 -> 0x2000000\n4. Parse buffer[1] upper byte (AH) flags and set bits in global DAT_0384f148:\n   - Bit 0x4000 -> 0xc0000000\n   - Bit 0x8000 -> 0x80000000\n   - Bit 0x400 -> 0x30000000\n   - Bit 0x800 -> 0x20000000\n   - Bit 0x10000 -> 0xc000000\n   - Bit 0x20000 -> 0x8000000\n   - Bit 0x1000 -> 0x3000000\n   - Bit 0x2000 -> 0x2000000\n5. Initialize 8-element metrics buffer with zeros\n6. Call second virtual method at offset 0x54 to query additional metrics\n7. Extract pixel format data from metrics buffer and shift right by 3 bits, store in DAT_0384f138\n8. Call GetSystemMetrics(0) for screen width, store in DAT_0384f014\n9. Call GetSystemMetrics(1) for screen height, store in DAT_0384f010\n10. Get device context for null window\n11. Query device capabilities with GetDeviceCaps(hdc, 0xe) for horizontal resolution\n12. Query device capabilities with GetDeviceCaps(hdc, 0xc) for vertical resolution\n13. Multiply horizontal*vertical and store in DAT_0384f00c\n14. Release device context\n15. If color depth is 8-bit, set DAT_0384f018 to 0xfd and return\n16. Otherwise, call FUN_038257f0 twice with different parameters and sum results\n17. Store sum in DAT_0384f018\n\nReturns:\nvoid - Updates global display capability state variables\n\nSpecial Cases:\n- 8-bit color depth (DAT_0384f00c == 8) requires special handling with fixed palette value\n- Device capability flags are mapped from DirectDraw format to internal representation\n- Unaffected registers EBX and ESI are preserved throughout execution",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b1984582b1216fb7cd1ad1549ffa41c6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b1984582b1216fb7cd1ad1549ffa41c6",
        "CFG": "8e9ab774104400fef7eefd54616caaf8",
        "PRO": "b39dfc10b80388501346a68ac2cf54d3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b1984582b1216fb7cd1ad1549ffa41c6"
      }
    },
    "binkw32_MNE_8d037910f675": {
      "addresses": {
        "LoD/PD2": "0x038257F0"
      },
      "rvas": {
        "LoD/PD2": "0x57F0"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "FilterBitsByMask",
      "signature": "uint FilterBitsByMask(uint sourceBits, uint maskBits)",
      "calling_convention": "__cdecl",
      "comment": "Filters bits from source parameter using mask parameter.\\n\\nAlgorithm:\\n1. Initialize result (EAX) to zero and set bit counters to 1\\n2. Loop 32 times (for each bit position):\\n   a. Check if current bit is set in maskBits\\n   b. If set, check if corresponding bit in sourceBits is set\\n   c. If both are set, add current bit to result\\n   d. Shift source bit counter left by 1\\n   e. Shift mask bit counter left by 1\\n   f. Decrement loop counter\\n3. Return accumulated result bits\\n\\nParameters:\\nsourceBits (uint): Source bit pattern to filter\\nmaskBits (uint): Mask pattern indicating which bits to check\\n\\nReturns:\\nuint: Filtered result containing only bits set in both sourceBits and maskBits\\n\\nSpecial Cases:\\n- Iterates exactly 32 times, processing all 32 bits\\n- Magic number 0x20 (32 decimal) sets bit iteration count\\n- Result accumulates via OR operations with shifted bit values\\n- Used for filtering display capability flags in graphics initialization\\n\\nStructure Layout:\\nNo structure access - operates on raw 32-bit bit patterns",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8d037910f675db1b341455807d56a33e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8d037910f675db1b341455807d56a33e",
        "CFG": "aeffd579fa895787f9ca9e48433de620",
        "PRO": "cb86acbaf99dac3c51cb3271895e8e14"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8d037910f675db1b341455807d56a33e"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_STR_7942da5e7922": {
      "addresses": {
        "LoD/PD2": "0x038258A0"
      },
      "rvas": {
        "LoD/PD2": "0x58A0"
      },
      "sizes": {
        "LoD/PD2": 801
      },
      "name": "_BinkIsSoftwareCursor@8",
      "signature": "uint _BinkIsSoftwareCursor@8(HCURSOR param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:7942da5e7922bc3effd8893ee77266e8",
      "indexes": {
        "EXP": null,
        "STR": "7942da5e7922bc3effd8893ee77266e8",
        "API": null,
        "MNE": "a303d3997501b7b17458422718b5241d",
        "CFG": "5e517dd0aeff4d498e74bb1c0eec8eaa",
        "PRO": "7660228653f386edda993b4aa5654a75"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a303d3997501b7b17458422718b5241d"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_5273b47c7bff": {
      "addresses": {
        "LoD/PD2": "0x03825BD0"
      },
      "rvas": {
        "LoD/PD2": "0x5BD0"
      },
      "sizes": {
        "LoD/PD2": 174
      },
      "name": "_BinkCheckCursor@20",
      "signature": "int _BinkCheckCursor@20(HWND param_1, int param_2, int param_3, int param_4, int param_5)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5273b47c7bff4b543c31331d1d2faf1f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5273b47c7bff4b543c31331d1d2faf1f",
        "CFG": "f21fdeff545ddbe0443e0b148078084a",
        "PRO": "ac20e03bb00ed271f9397b75e8d23d29"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5273b47c7bff4b543c31331d1d2faf1f"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_99a9ecebfd6d": {
      "addresses": {
        "LoD/PD2": "0x03825C80"
      },
      "rvas": {
        "LoD/PD2": "0x5C80"
      },
      "sizes": {
        "LoD/PD2": 34
      },
      "name": "_BinkRestoreCursor@4",
      "signature": "undefined _BinkRestoreCursor@4(int param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:99a9ecebfd6d0b64f3d9054ca75ff273",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "99a9ecebfd6d0b64f3d9054ca75ff273",
        "CFG": "7cb574b35dda7037811ad1bca9b700a0",
        "PRO": "d7dc4e0086b2dd72f2535b645d3ffc2e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "99a9ecebfd6d0b64f3d9054ca75ff273"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_c317bcdd0a17": {
      "addresses": {
        "LoD/PD2": "0x03825CB0"
      },
      "rvas": {
        "LoD/PD2": "0x5CB0"
      },
      "sizes": {
        "LoD/PD2": 32
      },
      "name": "_BinkBufferSetResolution@12",
      "signature": "undefined _BinkBufferSetResolution@12(undefined4 param_1, undefined4 param_2, undefined4 param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c317bcdd0a1727fec1a7cacd7d0f50fc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c317bcdd0a1727fec1a7cacd7d0f50fc",
        "CFG": null,
        "PRO": "ed43bd10a6108c31b53e3d4253e1f6be"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c317bcdd0a1727fec1a7cacd7d0f50fc"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_3ccc82b1da50": {
      "addresses": {
        "LoD/PD2": "0x03825CD0"
      },
      "rvas": {
        "LoD/PD2": "0x5CD0"
      },
      "sizes": {
        "LoD/PD2": 170
      },
      "name": "_BinkBufferCheckWinPos@12",
      "signature": "undefined _BinkBufferCheckWinPos@12(int * param_1, int * param_2, int * param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3ccc82b1da50b1f334d3687367fef8f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3ccc82b1da50b1f334d3687367fef8f7",
        "CFG": "56a9270b549732b122e9b7de5469bc93",
        "PRO": "046dc639cefaa62982dbf1c7227122c1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3ccc82b1da50b1f334d3687367fef8f7"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_c40040f787cb": {
      "addresses": {
        "LoD/PD2": "0x03825D80"
      },
      "rvas": {
        "LoD/PD2": "0x5D80"
      },
      "sizes": {
        "LoD/PD2": 118
      },
      "name": "_BinkBufferSetOffset@12",
      "signature": "undefined4 _BinkBufferSetOffset@12(int * param_1, int param_2, int param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c40040f787cbbcc5e7ed1ba48d32d893",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c40040f787cbbcc5e7ed1ba48d32d893",
        "CFG": "78789e0509aad56bc67016dcf4bf9b69",
        "PRO": "2e65823b3c6f48c5edb92c2b5eb284bd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c40040f787cbbcc5e7ed1ba48d32d893"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_e46b8cd4e365": {
      "addresses": {
        "LoD/PD2": "0x03825E00"
      },
      "rvas": {
        "LoD/PD2": "0x5E00"
      },
      "sizes": {
        "LoD/PD2": 360
      },
      "name": "UpdateRenderSurfaceWithClipping",
      "signature": "void UpdateRenderSurfaceWithClipping(int * pRenderSurface, int nUpdateMode)",
      "calling_convention": "__cdecl",
      "comment": "Updates render surface with viewport clipping and mode adjustment\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e46b8cd4e3654510815acfb607ea499e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e46b8cd4e3654510815acfb607ea499e",
        "CFG": "a4ac809d04d1bc6ef1c54e7d0d97435d",
        "PRO": "3e3fcf60e7cbfce8f5b99c952b423a80"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e46b8cd4e3654510815acfb607ea499e"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_STR_7ae0a63442fd": {
      "addresses": {
        "LoD/PD2": "0x03825F70"
      },
      "rvas": {
        "LoD/PD2": "0x5F70"
      },
      "sizes": {
        "LoD/PD2": 1960
      },
      "name": "_BinkBufferOpen@16",
      "signature": "uint * _BinkBufferOpen@16(HWND param_1, uint param_2, uint param_3, uint param_4)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:7ae0a63442fda68f53885cdca4c21121",
      "indexes": {
        "EXP": null,
        "STR": "7ae0a63442fda68f53885cdca4c21121",
        "API": "e9927986064a7244e11e92f3b98c00ba",
        "MNE": "34f6e5ceb0b7c0aa5b0ba959e3e93149",
        "CFG": "77d4e2fd461a0e3bec2e851d748ad985",
        "PRO": "14b5df030de8f43c9583c1c5837559f7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "34f6e5ceb0b7c0aa5b0ba959e3e93149"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkDDSurfaceType@4",
          "_BinkDDSurfaceType@4",
          "_BinkDDSurfaceType@4",
          "_BinkDDSurfaceType@4",
          "_BinkIsSoftwareCursor@8",
          "_BinkDDSurfaceType@4",
          "_BinkDDSurfaceType@4",
          "_BinkDDSurfaceType@4",
          "_radmalloc@4",
          "_radfree@4",
          "...+3 more"
        ]
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_9dbe11483c0e": {
      "addresses": {
        "LoD/PD2": "0x03826740"
      },
      "rvas": {
        "LoD/PD2": "0x6740"
      },
      "sizes": {
        "LoD/PD2": 305
      },
      "name": "InitializeGraphicsDisplay",
      "signature": "void InitializeGraphicsDisplay(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes graphics display capabilities for video rendering.\n\nAlgorithm:\n1. Check if initialization already in progress (DAT_0384f120)\n2. Initialize DirectDraw surface if not yet done (DAT_0384f140)\n3. Validate surface is ready (capability count >= 0x20)\n4. Call surface capability enumeration callback (DAT_0384f13c)\n5. Check context flags and validate required surface parameters\n6. Calculate method parameter flags based on context state\n7. Call surface capability query method at offset +0x50\n8. If successful, optionally call surface parameter update at offset +0x54\n9. Clear internal buffer array (27 dwords starting at offset 0)\n10. Initialize buffer structure (0x6c bytes) with method parameters\n11. Call surface initialization method at offset +0x18\n12. If successful, call display capabilities initialization\n13. On error, call surface cleanup method at offset +0x8\n14. Increment initialization counter on successful completion\n\nParameters:\nNone - function operates on global graphics state variables\n\nReturns:\nvoid - no return value\n\nSpecial Cases:\n- DAT_0384f120 is an initialization guard/counter (early exit if != 0)\n- DAT_0384f140 tracks capability count from DirectDraw enumeration\n- contextFlags (iStack_4) determines which method parameters to use\n- methodParams array stores: [buffer_size=0x6c, param_flags, reserved]\n- Virtual method offsets: +0x8 cleanup, +0x10 query, +0x18 init, +0x50 capability, +0x54 update\n\nStructure Layout:\nGraphics surface object (DAT_0384f124) uses virtual method dispatch:\nOffset   Size   Method Name                  Description\n0x00     4      vtable pointer              Pointer to virtual method table\n0x08     4      cleanup                     Release surface resources\n0x10     4      query_capability            Query capability flags\n0x18     4      initialize                  Initialize graphics surface\n0x50     4      check_capability            Validate capability state\n0x54     4      update_parameters           Update surface parameters",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9dbe11483c0e42ddf5d87ee4d23fa5ba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9dbe11483c0e42ddf5d87ee4d23fa5ba",
        "CFG": "1396f07c9721d75e35b10c38e6b3602e",
        "PRO": "818e0223fa5c45002640a4b85908830c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9dbe11483c0e42ddf5d87ee4d23fa5ba"
      }
    },
    "binkw32_STR_60b786edb4e1": {
      "addresses": {
        "LoD/PD2": "0x03826880"
      },
      "rvas": {
        "LoD/PD2": "0x6880"
      },
      "sizes": {
        "LoD/PD2": 92
      },
      "name": "InitializeDirectDrawLibrary",
      "signature": "void InitializeDirectDrawLibrary(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize DirectDraw library and retrieve DirectDrawCreate function pointer.\n\nALGORITHM\n1. Save current error mode using SetErrorMode(0x8000) - SEM_FAILCRITICALERRORS flag\n2. Load DDRAW.DLL library using LoadLibraryA\n3. Restore previous error mode by calling SetErrorMode with saved value\n4. Validate loaded module handle - check if >= 0x20 (sentinel for valid HMODULE)\n5. If valid: Get DirectDrawCreate function pointer via GetProcAddress\n6. If function pointer obtained: Return successfully (function_pointer != 0x0)\n7. If function pointer is NULL: Free library and set sentinel value 0x1\n8. Store sentinel value 0x1 at 0x0384f140 to indicate initialization failure\n\nPARAMETERS\nNone\n\nRETURNS\nvoid - No return value. Stores results in global variables:\n  DAT_0384f140: HMODULE to loaded DDRAW.DLL (or sentinel 0x1 if failed)\n  DAT_0384f13c: FARPROC to DirectDrawCreate function (or 0x0 if failed)\n\nSPECIAL CASES\n- Magic constant 0x8000: SEM_FAILCRITICALERRORS - prevents critical error dialogs\n- Magic constant 0x20: Sentinel value to distinguish valid HMODULE from NULL\n- Magic constant 0x1: Sentinel indicating initialization failure\n- DDRAW.DLL name stored at 0x03847b30\n- DirectDrawCreate string name stored at 0x03847b1c\n- SetErrorMode, LoadLibraryA, GetProcAddress, FreeLibrary are imported Windows APIs\n- Called from InitializeGraphicsDisplay at 0x0382675a",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:60b786edb4e14e02992e95a5d91b9455",
      "indexes": {
        "EXP": null,
        "STR": "60b786edb4e14e02992e95a5d91b9455",
        "API": null,
        "MNE": "9530209639a085768537dbf85108ca35",
        "CFG": "8f87c31656cb4d867ca492e31cb2d365",
        "PRO": "c535d27e15fa1ca427c2cab3cae93bcc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9530209639a085768537dbf85108ca35"
      }
    },
    "binkw32_MNE_8646e65f8660": {
      "addresses": {
        "LoD/PD2": "0x038268E0"
      },
      "rvas": {
        "LoD/PD2": "0x68E0"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "DecrementBinkBufferRefCount",
      "signature": "void DecrementBinkBufferRefCount(void)",
      "calling_convention": "__stdcall",
      "comment": "Decrements the Bink buffer reference counter and releases graphics resources.\\n\\nAlgorithm:\\n1. Load reference counter from DAT_0384f120 and decrement it\\n2. If reference counter is not zero, jump to function exit\\n3. If reference counter is zero:\\n   a. Call virtual method at offset +0x8 from DAT_0384f128 (cleanup callback)\\n   b. Call virtual method at offset +0x8 from DAT_0384f124 (cleanup callback)\\n4. Clear DAT_0384f124 and DAT_0384f128 to NULL\\n5. Return to caller\\n\\nParameters:\\nNone - This is a cleanup function called during Bink buffer destruction with no parameters.\\n\\nReturns:\\nvoid - No return value\\n\\nSpecial Cases:\\n- When reference count is decremented to zero, virtual methods are invoked on global buffer objects\\n  to perform cleanup (e.g., releasing DirectDraw surfaces, graphics resources)\\n- The global pointers are set to NULL after cleanup to prevent double-deletion\\n- Only executed once per resource lifecycle when the last reference is released\\n\\nStructure Layout:\\nBoth DAT_0384f128 and DAT_0384f124 are objects with virtual method tables:\\nOffset  Size  Field Type  Description\\n------  ----  -----------  ----------------------------\\n0x0     4     void*       Pointer to virtual method table (vftable)\\n0x8     4     function*   Cleanup method pointer\\n\\nThe function extracts the vftable pointer (offset 0), then calls the method at offset +0x8.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8646e65f86602832ca832a9077dd6dc8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8646e65f86602832ca832a9077dd6dc8",
        "CFG": "373ab06ce4995b11aa294c119b308ebf",
        "PRO": "9ae8734658c70d042163597d4048c519"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8646e65f86602832ca832a9077dd6dc8"
      }
    },
    "binkw32_MNE_286ffbb1c957": {
      "addresses": {
        "LoD/PD2": "0x03826910"
      },
      "rvas": {
        "LoD/PD2": "0x6910"
      },
      "sizes": {
        "LoD/PD2": 346
      },
      "name": "InitializeDisplayMetrics",
      "signature": "int InitializeDisplayMetrics(HWND hWindow, int displayMode)",
      "calling_convention": "__cdecl",
      "comment": "Initializes display metrics and optionally changes display mode.\\n\\nAttempts to set one of two display resolutions (1920x1200 or 1536x1152) based on configuration globals, then queries and caches system metrics including screen dimensions and DPI values. This function appears to be part of initialization for a graphics subsystem with fallback resolution support.\\n\\nAlgorithm:\\n1. Check if already initialized (DAT_0384f120 != 0) - return early if so\\n2. If displayMode != 0 and all config globals are valid:\\n   a. Attempt first display mode (1920x1200) via ChangeDisplaySettingsA with CDS_FULLSCREEN\\n   b. If fails, attempt second mode (1536x1152) with same parameters\\n   c. Mark success flag if either mode change succeeds (return == 0)\\n3. Clear global display configuration variables (targetWidth, targetHeight, colorDepth)\\n4. Query system metrics: GetSystemMetrics(0) for screen width, GetSystemMetrics(1) for height\\n5. Get device context and query DPI: GetDeviceCaps(hdc, LOGPIXELSX) and GetDeviceCaps(hdc, LOGPIXELSY)\\n6. Calculate total bytes: horizontalDpi * verticalDpi / 8 with proper signed rounding\\n7. Store result and increment initialization counter\\n8. Return 1 (success)\\n\\nParameters:\\n  hWindow (HWND) - Window handle for GetDC device context queries, used to obtain device metrics\\n  displayMode (int) - Mode indicator; non-zero triggers optional display resolution change attempt\\n\\nReturns:\\n  int - Always returns 1 (success) after metrics collection\\n\\nSpecial Cases:\\n  - If DAT_0384f120 != 0, function returns immediately (already initialized)\\n  - Display mode change failures do not prevent metrics collection (function continues)\\n  - Uses signed division with 7-bit AND mask for proper rounding before right-shift by 3\\n  - Magic number 0x94 is sizeof(DEVMODEA) structure field\\n  - Magic numbers 0x1c0000 and 0x180000 represent pixel resolutions (1920x1200 and 1536x1152)\\n\\nData References:\\n  DAT_0384f120 - Initialization complete flag\\n  DAT_0384f12c - Target display width from config\\n  DAT_0384f130 - Target display height from config\\n  DAT_0384f134 - Target color depth from config\\n  DAT_0384f014 - Cached screen width in pixels\\n  DAT_0384f010 - Cached screen height in pixels\\n  DAT_0384f00c - Cached DPI product (width * height)\\n  DAT_0384f138 - Cached bytes per pixel calculation\\n  DAT_0384f14c - Display mode success flag\\n  DAT_0384f150 - Initialization counter\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:286ffbb1c957324283eefc5784bd7a18",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "286ffbb1c957324283eefc5784bd7a18",
        "CFG": "ef6b559f818d68391151c9c48a9482dc",
        "PRO": "b10535ee983cd575b8e68ebf6e1451e0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "286ffbb1c957324283eefc5784bd7a18"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_abb7627d3872": {
      "addresses": {
        "LoD/PD2": "0x03826A70"
      },
      "rvas": {
        "LoD/PD2": "0x6A70"
      },
      "sizes": {
        "LoD/PD2": 38
      },
      "name": "DecrementDisplaySettingRefCount",
      "signature": "void DecrementDisplaySettingRefCount(void)",
      "calling_convention": "__stdcall",
      "comment": "Decrements the display settings reference counter and restores default display settings when counter reaches zero.\n\nAlgorithm:\n1. Decrement the global reference counter (DAT_0384f150)\n2. If counter is not zero, return immediately (other references still active)\n3. If counter is zero and the reset flag (DAT_0384f14c) is set:\n   a. Clear the reset flag\n   b. Call ChangeDisplaySettingsA with NULL and CDS_RESET (0x4) to restore default display settings\n4. Return to caller\n\nReturns:\nvoid - No return value\n\nPurpose:\nThis function manages display device context restoration for the Bink video playback library. It maintains a reference counter that tracks how many display-related operations are active. When all operations complete (counter reaches zero), it restores the original display settings using the Windows ChangeDisplaySettingsA API. This prevents display corruption when switching between Bink video playback and other video modes.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:abb7627d3872c2d00a8002ae54abcc62",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "abb7627d3872c2d00a8002ae54abcc62",
        "CFG": "90d60dbdb3100bc570ed25ac0c839313",
        "PRO": "b0ac7848f969db07e06a5c6ce8a63f2c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "abb7627d3872c2d00a8002ae54abcc62"
      }
    },
    "binkw32_MNE_df772668f478": {
      "addresses": {
        "LoD/PD2": "0x03826AA0"
      },
      "rvas": {
        "LoD/PD2": "0x6AA0"
      },
      "sizes": {
        "LoD/PD2": 227
      },
      "name": "InitializeBinkBuffer",
      "signature": "uint InitializeBinkBuffer(BinkFile * pBinkFile, uint width, uint height)",
      "calling_convention": "__cdecl",
      "comment": "Initializes a Bink video buffer with specified dimensions for video playback.\n\nAlgorithm:\n1. Validate input by checking global Bink system initialization status (DAT_0384f124)\n2. Initialize local buffer configuration structure by clearing 27 DWORDs (0x6c bytes)\n3. Configure buffer parameters: store width (param_2) and height (param_3) in local structure\n4. Set buffer format constants: 0x6c for width encoding, 0x1007 for height encoding\n5. Set buffer mode flags to 0x4080 and pixel configuration to 0x20 and 0x4\n6. Call global Bink initialization callback via virtual function at offset +0x18\n7. Return failure (0) immediately if initialization callback returns non-zero error\n8. Call buffer open/create callback via virtual function at offset +0x64 with config\n9. Return failure (0) if buffer open callback returns non-zero error; cleanup via offset +0x8\n10. Call FUN_03826b90 helper function to finalize buffer configuration data\n11. Call buffer setup method via virtual function at offset +0x80 to apply configuration\n12. Return success code 0x20 indicating buffer initialization complete\n\nParameters:\n  pBinkFile - Pointer to BinkFile structure containing vtable callbacks (104 bytes)\n  width - Requested buffer width in pixels (stored at offset +0x14 in config)\n  height - Requested buffer height in pixels (stored at offset +0x18 in config)\n\nReturns:\n  0x20 (32) indicating successful buffer initialization and readiness\n  0 (zero) indicating initialization failure at either vtable callback stage\n\nSpecial Cases:\n  - Uses fixed configuration values: 0x6c (width marker), 0x1007 (height marker)\n  - Buffer mode flags 0x4080 indicate color/compression mode settings\n  - Cleanup only performed if open callback fails; init failure skips cleanup\n  - Relies on global Bink system being pre-initialized before this call\n  - Configuration is done via local stack structure passed to helper function",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:df772668f4787d715c93166d2a6804d1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "df772668f4787d715c93166d2a6804d1",
        "CFG": "a69d5482d3c4cb1f553fa82757dac7ff",
        "PRO": "bc813ebc77b0d5f789264b5855195133"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "df772668f4787d715c93166d2a6804d1"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_faf5bb396f76": {
      "addresses": {
        "LoD/PD2": "0x03826B90"
      },
      "rvas": {
        "LoD/PD2": "0x6B90"
      },
      "sizes": {
        "LoD/PD2": 454
      },
      "name": "ClearBinkBuffer",
      "signature": "void ClearBinkBuffer(void * pBufferData, uint colorFormat, uint pitch, uint width, uint height)",
      "calling_convention": "__cdecl",
      "comment": "Initializes a Bink video frame buffer by filling it with zeros or format-specific patterns.\\n\\nAlgorithm:\\n1. Extract pixel format from low 4 bits of colorFormat parameter (0, 1-6, 8, 9, or 10)\\n2. For formats 0 and 1-6 (standard RGB/8-bit formats):\\n   - Calculate row byte count: width * scale factor (1 or determined by DAT_0384f138)\\n   - Fill each row with zeros using REP STOSD for dwords and REP STOSB for remainder\\n   - Advance buffer pointer by pitch for next row\\n   - Repeat for height rows\\n3. For format 8 (8-bit alpha channel):\\n   - Fill each row with 0x80008000 (alpha=128, mostly transparent)\\n   - Fill remainder bytes with 0x8000\\n   - Advance by pitch for height rows\\n4. For format 9 (16-bit chroma format):\\n   - Fill with 0x800080 (Y=128, chroma=128)\\n   - Fill remainder with 0x80\\n   - Advance by pitch for height rows\\n5. For format 10 (YUV 4:2:0 planar):\\n   - First fill full height luma plane with 0x10101010 (Y=16, black)\\n   - Then fill chroma planes (half height) with 0x80808080 (Cb=Cr=128, neutral)\\n   - Each plane row advances by pitch/2\\n\\nParameters:\\n  pBufferData: Pointer to video frame buffer (first plane for planar formats)\\n  colorFormat: Pixel format specifier (low 4 bits determine type: 0/1-6=RGB, 8=Alpha, 9=Chroma, 10=YUV420)\\n  pitch: Bytes per row in each plane (stride)\\n  width: Pixel width of the frame\\n  height: Pixel height of the frame (full height for luma, half for chroma in YUV420)\\n\\nReturns:\\n  void - Buffer is modified in-place\\n\\nSpecial Cases:\\n  - Formats 0 and 1-6 are treated identically (both clear to zeros)\\n  - YUV420 format (10) uses half-height for chroma planes with width/2 pitch\\n  - Alpha=128 (0x80) represents full transparency in format 8\\n  - Chroma=128 (0x80) represents neutral color in format 9",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:faf5bb396f76b407fd98719b3b34ce15",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "faf5bb396f76b407fd98719b3b34ce15",
        "CFG": "b0373c928dbbca10ee1e4a199fbe7fb7",
        "PRO": "0f3746fb55e597abe90fc385f606d74b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "faf5bb396f76b407fd98719b3b34ce15"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_125118f786fd": {
      "addresses": {
        "LoD/PD2": "0x03826D80"
      },
      "rvas": {
        "LoD/PD2": "0x6D80"
      },
      "sizes": {
        "LoD/PD2": 255
      },
      "name": "InitializeBinkVideoBuffer",
      "signature": "BinkFile * InitializeBinkVideoBuffer(uint codecFormat, uint width, uint height)",
      "calling_convention": "__cdecl",
      "comment": "Initializes a Bink video buffer with a specified codec format, width, and height.\n\nAlgorithm:\n1. Clear 27 quadwords of local buffer space (27*4 = 108 bytes)\n2. Calculate output flags based on codec format (0x800-0x3800 range with 0x40 bit)\n3. Set up codec default flags (0x6C and 0x7 for resolution/color depth)\n4. If codec format > 16, override with flags 0x1007 and set codec version fields\n5. Initialize Bink codec system via global interface at [0x0384f124]\n6. Check if initialization failed (return 0 on failure)\n7. Open codec with buffer dimensions via interface offset 0x64\n8. Check if codec open failed, cleanup and return 0 if error\n9. Call ClearBinkBuffer to initialize buffer contents\n10. Register buffer with codec system at offset 0x80\n11. Return initialized codec flags\n\nParameters:\n- codecFormat (uint): Codec fourCC identifier or version (0=default, 1=alt1, >16 enhanced)\n- width (uint): Buffer width in pixels\n- height (uint): Buffer height in pixels\n\nReturns:\n- BinkFile*: Pointer to initialized codec interface on success, NULL on failure\n\nSpecial Cases:\n- Format values > 16 enable 0x1007 flags and additional codec features\n- Global codec system at 0x0384f124 must be initialized first\n- Codec cleanup via interface method at offset +0x8 on error\n- Returns NULL (0) on codec initialization or opening failure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:125118f786fd1c6dc08dec1e9cc3f598",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "125118f786fd1c6dc08dec1e9cc3f598",
        "CFG": "74c9721c48af8c6d40023ee593e51e52",
        "PRO": "f5f6eef471c2e4f00609d31a5cd6739b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "125118f786fd1c6dc08dec1e9cc3f598"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_c5ea813d5c3f": {
      "addresses": {
        "LoD/PD2": "0x03826E80"
      },
      "rvas": {
        "LoD/PD2": "0x6E80"
      },
      "sizes": {
        "LoD/PD2": 257
      },
      "name": "DetectDeviceContextColorFormat",
      "signature": "char DetectDeviceContextColorFormat(HDC hdc, uint * pColorMasks)",
      "calling_convention": "__cdecl",
      "comment": "Detects the color format of a device context by creating a test bitmap and analyzing its pixel format.\n\nAlgorithm:\n1. Load global color depth value and check if <= 2 bits (palettized/monochrome)\n2. If color depth <= 2: Return RGB888 format with 0xFF0000/0xFF00/0xFF masks\n3. Initialize BITMAPINFO structure by clearing 266 DWORD entries\n4. Create 1x1 compatible bitmap with CreateCompatibleBitmap()\n5. Call GetDIBits() twice to force pixel format detection in the BITMAPINFO structure\n6. Delete the test bitmap with DeleteObject()\n7. Check if compression type is BI_BITFIELDS (0x3) - required for non-standard RGB formats\n8. If BI_BITFIELDS and first color mask is 0xF800: Return RGB565 format (return value 4)\n9. Otherwise: Return default RGB555 format with 0x7C00/0x3E0/0x1F masks (return value 3)\n\nParameters:\n- hdc: Device context to analyze for color format support\n- pColorMasks: Pointer to array of 3 DWORDs receiving [red_mask, green_mask, blue_mask]\n\nReturns:\n- char: Format identifier - 1/2 for RGB888 (based on color depth != 3), 3 for RGB555 (default), 4 for RGB565\n\nStructure Layout:\nThe BITMAPINFO structure (1064 bytes on stack) contains:\n- Offset 0x00 (biSize): Set to 0x28 (40 bytes for BITMAPINFOHEADER)\n- Offset 0x04 (biWidth/biHeight/biPlanes/biBitCount): Filled by GetDIBits()\n- Offset 0x10 (biCompression): 0x3 (BI_BITFIELDS) for RGB565/555 formats\n- Offset 0x14+: Color masks populated by GetDIBits() during format detection",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c5ea813d5c3f8da4e4d3367fba747141",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c5ea813d5c3f8da4e4d3367fba747141",
        "CFG": "623be3cb097db681b60f8163df44d258",
        "PRO": "79521cab5adcdfd77a4f22b1b0e17c4d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c5ea813d5c3f8da4e4d3367fba747141"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_API_7ea41d38c3be": {
      "addresses": {
        "LoD/PD2": "0x03826F90"
      },
      "rvas": {
        "LoD/PD2": "0x6F90"
      },
      "sizes": {
        "LoD/PD2": 174
      },
      "name": "_BinkBufferClose@4",
      "signature": "undefined _BinkBufferClose@4(int * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:7ea41d38c3be5dbcf086509c906678ea",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "7ea41d38c3be5dbcf086509c906678ea",
        "MNE": "e0b9a405a9d25d7e0de5fcd64576c951",
        "CFG": "48fb537a52b8e67306ca41f7784e5633",
        "PRO": "11d07ac556097f9fad31fa6b51a25243"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e0b9a405a9d25d7e0de5fcd64576c951"
      },
      "api_calls": {
        "LoD/PD2": [
          "_radfree@4",
          "_radfree@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_API_9887be655cf0": {
      "addresses": {
        "LoD/PD2": "0x03827040"
      },
      "rvas": {
        "LoD/PD2": "0x7040"
      },
      "sizes": {
        "LoD/PD2": 304
      },
      "name": "_BinkBufferLock@4",
      "signature": "undefined4 _BinkBufferLock@4(int * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:9887be655cf0ff15792804a06d265415",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "9887be655cf0ff15792804a06d265415",
        "MNE": "21005134343d54da28a8166b388f2921",
        "CFG": "1d3f4c3e8d569fdf49ee3db24bc3009a",
        "PRO": "cc179bf40862fe5554c887a37070dbb4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "21005134343d54da28a8166b388f2921"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkCheckCursor@20",
          "_BinkRestoreCursor@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_ecef6e0b2795": {
      "addresses": {
        "LoD/PD2": "0x03827170"
      },
      "rvas": {
        "LoD/PD2": "0x7170"
      },
      "sizes": {
        "LoD/PD2": 103
      },
      "name": "_BinkBufferUnlock@4",
      "signature": "undefined4 _BinkBufferUnlock@4(int * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ecef6e0b279551dbbcf95cc18e5c85a1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ecef6e0b279551dbbcf95cc18e5c85a1",
        "CFG": "cb0ff409c6c417241ca55c6e4c444bac",
        "PRO": "8324a4b6421804d6e2db35b23f3825eb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ecef6e0b279551dbbcf95cc18e5c85a1"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkRestoreCursor@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_3f1f35b24251": {
      "addresses": {
        "LoD/PD2": "0x038271E0"
      },
      "rvas": {
        "LoD/PD2": "0x71E0"
      },
      "sizes": {
        "LoD/PD2": 892
      },
      "name": "_BinkBufferBlit@12",
      "signature": "undefined _BinkBufferBlit@12(uint * param_1, int param_2, uint param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3f1f35b242519577ce4e15a92fcf599d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3f1f35b242519577ce4e15a92fcf599d",
        "CFG": "25b12c037008ce74e860020335ed040b",
        "PRO": "35660c5064f2d3c597f075897c0a1d0d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3f1f35b242519577ce4e15a92fcf599d"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_35f2f3033ded": {
      "addresses": {
        "LoD/PD2": "0x03827560"
      },
      "rvas": {
        "LoD/PD2": "0x7560"
      },
      "sizes": {
        "LoD/PD2": 268
      },
      "name": "_BinkBufferSetScale@12",
      "signature": "bool _BinkBufferSetScale@12(uint * param_1, uint param_2, uint param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:35f2f3033ded8cf8e3da0f673cf18137",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "35f2f3033ded8cf8e3da0f673cf18137",
        "CFG": "7d2305e036591e793dcefee8a9e3e4ed",
        "PRO": "b1066d20272dbe76a036c9f3d51d1638"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "35f2f3033ded8cf8e3da0f673cf18137"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_f5b0d4999cef": {
      "addresses": {
        "LoD/PD2": "0x03827670"
      },
      "rvas": {
        "LoD/PD2": "0x7670"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "_BinkBufferSetHWND@8",
      "signature": "undefined4 _BinkBufferSetHWND@8(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f5b0d4999cef381bea9a054131983f79",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f5b0d4999cef381bea9a054131983f79",
        "CFG": null,
        "PRO": "86ffe9e76e720076fa0a9a543035b74c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f5b0d4999cef381bea9a054131983f79"
      }
    },
    "binkw32_STR_b6d60490f87d": {
      "addresses": {
        "LoD/PD2": "0x03827680"
      },
      "rvas": {
        "LoD/PD2": "0x7680"
      },
      "sizes": {
        "LoD/PD2": 339
      },
      "name": "_BinkBufferGetDescription@4",
      "signature": "undefined4 * _BinkBufferGetDescription@4(int param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:b6d60490f87d2a5083c8d0e46c6e8e49",
      "indexes": {
        "EXP": null,
        "STR": "b6d60490f87d2a5083c8d0e46c6e8e49",
        "API": null,
        "MNE": "96cc9aefc1f81e382ad7e74816c06f8d",
        "CFG": "e9e3238573fb8758cb6dacb6540ea203",
        "PRO": "e269f50f7a4ab75a284cf6739f69fc24"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "96cc9aefc1f81e382ad7e74816c06f8d"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_7b4de9f0cf35": {
      "addresses": {
        "LoD/PD2": "0x03827800"
      },
      "rvas": {
        "LoD/PD2": "0x7800"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "_BinkBufferGetError@0",
      "signature": "undefined4 * _BinkBufferGetError@0(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "d16ac494b9b96b2951092563cd8d4040"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "binkw32_API_7f9bbd97ca85": {
      "addresses": {
        "LoD/PD2": "0x03827810"
      },
      "rvas": {
        "LoD/PD2": "0x7810"
      },
      "sizes": {
        "LoD/PD2": 68
      },
      "name": "_BinkBufferClear@8",
      "signature": "undefined4 _BinkBufferClear@8(uint * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:7f9bbd97ca85ff583a3f664734814d7d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "7f9bbd97ca85ff583a3f664734814d7d",
        "MNE": "a2e98173ea0fa30efee842e6d4858d83",
        "CFG": "d01e5563fdbdd888c84d483857608197",
        "PRO": "02f93fae42b03fd546077fbbca3f1f68"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a2e98173ea0fa30efee842e6d4858d83"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkBufferLock@4",
          "_BinkBufferUnlock@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_130e7ed55ea4": {
      "addresses": {
        "LoD/PD2": "0x03827860"
      },
      "rvas": {
        "LoD/PD2": "0x7860"
      },
      "sizes": {
        "LoD/PD2": 303
      },
      "name": "_BinkDDSurfaceType@4",
      "signature": "undefined4 _BinkDDSurfaceType@4(int * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:130e7ed55ea40ac920c81c59ca0445bf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "130e7ed55ea40ac920c81c59ca0445bf",
        "CFG": "7ccaf72ab6a00908b4fc1bafcb79ee76",
        "PRO": "d07cdbd9723f92257a889186a065bafa"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "130e7ed55ea40ac920c81c59ca0445bf"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_2e320bf81519": {
      "addresses": {
        "LoD/PD2": "0x03827990"
      },
      "rvas": {
        "LoD/PD2": "0x7990"
      },
      "sizes": {
        "LoD/PD2": 84
      },
      "name": "RecordBinkAllocation",
      "signature": "void RecordBinkAllocation(dword allocationSize, int unused)",
      "calling_convention": "__stdcall",
      "comment": "Records a memory allocation request for later commitment to the Bink memory pool.\n\nAlgorithm:\n1. Align the requested size to 16-byte boundary (round up to multiple of 16)\n2. Calculate the memory offset increment based on current pool position and aligned size\n3. Update the global allocation pointer with the calculated increment\n4. Store the allocation size in the allocation size tracking array at current index\n5. Store the original allocation request in the allocation request tracking array at current index\n6. Increment the allocation index counter for next allocation\n\nParameters:\n- allocationSize: Size in bytes to allocate (will be aligned to 16-byte boundary)\n- unused: Parameter present for compatibility, unused in this function\n\nReturns:\n- void: No return value; results are stored in global allocation tracking arrays\n\nSpecial Cases:\n- Input size is rounded up to nearest 16-byte boundary (offset 0xa-0xd add 0xF then mask with 0xFFFFFFF0)\n- Allocation tracking uses bit-shift operations for efficiency (SHR by 5 = divide by 32)\n- Supports up to 32 concurrent allocations before wraparound (AND with 0x1F after increment)\n\nStructure Layout:\nGlobal allocation pool state maintained in BSS segment:\n- 0x0384f668: Current allocation pool offset/pointer (dword)\n- 0x0384f66c: Current allocation index counter (dword, 0-31 range due to 5-bit mask)\n- 0x0384f164: Array of allocation sizes [index*4] (dword array, up to 32 entries)\n- 0x0384f364: Array of allocation requests [index*4] (dword array, up to 32 entries)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2e320bf81519acea38e6c31a9369e455",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2e320bf81519acea38e6c31a9369e455",
        "CFG": null,
        "PRO": "c1209678b27e2a424c8b88709fd14908"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2e320bf81519acea38e6c31a9369e455"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_61ec8fae9fdc": {
      "addresses": {
        "LoD/PD2": "0x038279F0"
      },
      "rvas": {
        "LoD/PD2": "0x79F0"
      },
      "sizes": {
        "LoD/PD2": 117
      },
      "name": "InitializeBinkMemoryBuffers",
      "signature": "void InitializeBinkMemoryBuffers(int basePointer, int bufferSize)",
      "calling_convention": "__stdcall",
      "comment": "Initializes Bink video memory buffers with 16-byte alignment\n\nAlgorithm:\n1. Calculate 16-byte aligned buffer size from input using (bufferSize + 0xF) & 0xFFFFFFF0\n2. Update total allocation counter at basePointer+0x234 by adding global header size and aligned size\n3. Allocate memory via radmalloc with header size and aligned buffer size\n4. If allocation succeeds, initialize array of buffer pointers by:\n   - Setting first pointer to allocation end (allocated + alignedSize)\n   - Iterating through buffer descriptor array (DAT_0384f164) and chaining pointers\n   - Each pointer points to the end of its respective buffer region\n5. Clear global counters (DAT_0384f668 and DAT_0384f66c) to reset state\n\nParameters:\n- basePointer: Base address of allocation context structure\n- bufferSize: Requested buffer size (will be aligned to 16-byte boundary)\n\nReturns:\n- void (modifies memory via side effects)\n\nSpecial Cases:\n- 16-byte alignment: (bufferSize + 0xF) & 0xFFFFFFF0 ensures proper alignment\n- Memory allocation may fail if radmalloc returns NULL\n- Allocation counter at basePointer+0x234 tracks cumulative allocations\n- Global DAT_0384f668 holds header size (reset to 0 after use)\n- Global DAT_0384f66c holds number of buffer regions (reset to 0 after initialization)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:61ec8fae9fdcc46d6b969bf474620d41",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "61ec8fae9fdcc46d6b969bf474620d41",
        "CFG": "29d1b72a82f1b0dbac02e80eac7d3bb3",
        "PRO": "07db882c0300e099fb2003a85ff09960"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "61ec8fae9fdcc46d6b969bf474620d41"
      },
      "api_calls": {
        "LoD/PD2": [
          "_radmalloc@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_15cee1312777": {
      "addresses": {
        "LoD/PD2": "0x03827A70"
      },
      "rvas": {
        "LoD/PD2": "0x7A70"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "_BinkSetError@4",
      "signature": "undefined _BinkSetError@4(char * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:15cee131277731f5e0a95b64c1426a2e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "15cee131277731f5e0a95b64c1426a2e",
        "CFG": null,
        "PRO": "63639c8fbd0979c26ae2c7987109d363"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "15cee131277731f5e0a95b64c1426a2e"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_ADDR_03827AA0": {
      "addresses": {
        "LoD/PD2": "0x03827AA0"
      },
      "rvas": {
        "LoD/PD2": "0x7AA0"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "_BinkGetError@0",
      "signature": "undefined4 * _BinkGetError@0(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "38ac63cccb56e39f021198f8646bf50f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "binkw32_MNE_bf26ed235a61": {
      "addresses": {
        "LoD/PD2": "0x03827AB0"
      },
      "rvas": {
        "LoD/PD2": "0x7AB0"
      },
      "sizes": {
        "LoD/PD2": 74
      },
      "name": "_BinkSetSoundSystem@8",
      "signature": "bool _BinkSetSoundSystem@8(undefined * param_1, undefined4 param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bf26ed235a61e8de1341117d5e0162b9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bf26ed235a61e8de1341117d5e0162b9",
        "CFG": "ddc31928774f965d54ee468a9096d228",
        "PRO": "12c65cb6acb1f788702801732fb630ee"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bf26ed235a61e8de1341117d5e0162b9"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_6c6168eac6c7": {
      "addresses": {
        "LoD/PD2": "0x03827B00"
      },
      "rvas": {
        "LoD/PD2": "0x7B00"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "_BinkSetFrameRate@8",
      "signature": "undefined _BinkSetFrameRate@8(undefined4 param_1, undefined4 param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6c6168eac6c7759f12c8ffc4e8b125b9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6c6168eac6c7759f12c8ffc4e8b125b9",
        "CFG": null,
        "PRO": "a055e00af2361ee5d187f7c04a335d89"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6c6168eac6c7759f12c8ffc4e8b125b9"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_0f26f5ebbb65": {
      "addresses": {
        "LoD/PD2": "0x03827B20"
      },
      "rvas": {
        "LoD/PD2": "0x7B20"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "_BinkSetIOSize@4",
      "signature": "undefined _BinkSetIOSize@4(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0f26f5ebbb6562741331dd6e6bdd0342",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0f26f5ebbb6562741331dd6e6bdd0342",
        "CFG": null,
        "PRO": "d1c4e91458b43294493df53b1ba4fa13"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0f26f5ebbb6562741331dd6e6bdd0342"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_ADDR_03827B30": {
      "addresses": {
        "LoD/PD2": "0x03827B30"
      },
      "rvas": {
        "LoD/PD2": "0x7B30"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "_BinkSetSimulate@4",
      "signature": "undefined _BinkSetSimulate@4(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0f26f5ebbb6562741331dd6e6bdd0342",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0f26f5ebbb6562741331dd6e6bdd0342",
        "CFG": null,
        "PRO": "c1e62e8527cbb760328e0c7c04db6170"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0f26f5ebbb6562741331dd6e6bdd0342"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_ADDR_03827B40": {
      "addresses": {
        "LoD/PD2": "0x03827B40"
      },
      "rvas": {
        "LoD/PD2": "0x7B40"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "_BinkSetSoundTrack@4",
      "signature": "undefined _BinkSetSoundTrack@4(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0f26f5ebbb6562741331dd6e6bdd0342",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0f26f5ebbb6562741331dd6e6bdd0342",
        "CFG": null,
        "PRO": "5c1d539cc0f07c1a9d071e5b1bfe927d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0f26f5ebbb6562741331dd6e6bdd0342"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_STR_006319909ada": {
      "addresses": {
        "LoD/PD2": "0x03827B50"
      },
      "rvas": {
        "LoD/PD2": "0x7B50"
      },
      "sizes": {
        "LoD/PD2": 1775
      },
      "name": "_BinkOpen@8",
      "signature": "int * _BinkOpen@8(int * param_1, uint param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:006319909adad92336fed515e047f38e",
      "indexes": {
        "EXP": null,
        "STR": "006319909adad92336fed515e047f38e",
        "API": "70c287284d4d9602d23b9ac832be7172",
        "MNE": "9949f33e28435d2f3cd2e5a9bf170681",
        "CFG": "95d14828d626134188340e0df2dd5a1e",
        "PRO": "f1a4646b67b2741f0bc19f17f5d702b6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9949f33e28435d2f3cd2e5a9bf170681"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkSetError@4",
          "_BinkSetError@4",
          "_BinkSetError@4",
          "_ExpandBundleSizes@8"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_STR_9b54e721e121": {
      "addresses": {
        "LoD/PD2": "0x0382823F"
      },
      "rvas": {
        "LoD/PD2": "0x823F"
      },
      "sizes": {
        "LoD/PD2": 1122
      },
      "name": "InitializeBinkPlayback",
      "signature": "BinkFile * InitializeBinkPlayback(uint maxWidth, uint maxHeight)",
      "calling_convention": "__fastcall",
      "comment": "Initializes and prepares a Bink video file for playback with audio/video decoding.\n\nAlgorithm:\n1. Calculate aspect ratio from maxWidth and maxHeight parameters\n2. Check if 0x2000 flag is set in video configuration; if not, set compression flag\n3. If flag unset: initialize primary memory buffers with default configuration\n4. If flag set: allocate secondary memory buffers with calculated size\n5. Configure framerate (either 2000ms default or custom from video properties)\n6. Call ProcessBinkVideoFrame to initialize decoder state\n7. Get current timestamp via timeGetTime for frame timing\n8. If memory allocation succeeded, scan audio stream for available tracks\n9. Search through track array to find current frame's audio index\n10. If audio track found with valid codec: allocate audio buffer and configure playback\n11. Create worker thread for continuous video frame processing if conditions met\n12. Return BinkFile pointer or NULL on failure\n\nParameters:\n  maxWidth   : uint - Maximum video frame width in pixels\n  maxHeight  : uint - Maximum video frame height in pixels\n\nReturns:\n  BinkFile * - Pointer to initialized BinkFile structure on success\n             - NULL pointer if initialization or thread creation fails\n\nSpecial Cases:\n  * If allocation fails at offset +0x108, returns NULL and logs \"Out of memory\" error\n  * Frame index search returns -1 if no matching track found\n  * Custom framerate calculation: (frameTime * customRate) / (2000 / frameRate)\n  * Audio buffer size calculation: (sampleRate * channels * 256) / 1000\n  * Thread only created if no memory flag 0x8000000 OR audio track is valid",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:9b54e721e12190afbf3c23c3fb64cf58",
      "indexes": {
        "EXP": null,
        "STR": "9b54e721e12190afbf3c23c3fb64cf58",
        "API": "d04d75323fd5cd8bdc81e0ab5da30c2e",
        "MNE": "242ca02abdecdce7a2a08f04da7e34d4",
        "CFG": "e853d95f7990eb96e0540c062176ae54",
        "PRO": "593454c9fb0e4425265599a7b9b6e8f0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "242ca02abdecdce7a2a08f04da7e34d4"
      },
      "api_calls": {
        "LoD/PD2": [
          "_radfree@4",
          "_BinkSetError@4",
          "_radmalloc@4",
          "_BinkClose@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_API_0096a9bfa1cc": {
      "addresses": {
        "LoD/PD2": "0x038286B0"
      },
      "rvas": {
        "LoD/PD2": "0x86B0"
      },
      "sizes": {
        "LoD/PD2": 185
      },
      "name": "ProcessBinkVideoFrame",
      "signature": "void ProcessBinkVideoFrame(void * pBinkHandle, uint frameIndex)",
      "calling_convention": "__cdecl",
      "comment": "Processes a Bink video frame with optional sound and frame offset callbacks.\n\nAlgorithm:\n1. Decrement frameIndex if non-zero to convert 1-based to 0-based indexing\n2. Call pre-processing callback FUN_03828770 if callback pointer (offset +0x1e8) is set\n3. Copy previous frame state: offset +0x10 = offset +0xc (frame progress tracking)\n4. If processing first frame (frameIndex == 0): toggle Bink sound on/off, clear audio flag\n5. Choose processing path based on callback mode flag (offset +0x108):\n   - If mode == 0: Call frame callback (offset +0x114) with frame offset data\n   - If mode != 0: Calculate and store frame offset using base table offset\n6. Call post-processing callback FUN_03828770 if callback pointer (offset +0x1e8) is set\n7. Increment and store next frame index (offset +0xc = frameIndex + 1)\n\nParameters:\npBinkHandle : void * - Bink handle/context structure containing playback state, callbacks, and frame tables\nframeIndex : uint - Frame index to process (1-based; 0 is special case for sound initialization)\n\nReturns:\nvoid - No return value; modifies Bink playback state in-place\n\nSpecial Cases:\n- frameIndex=0 is treated as first frame: triggers sound reset and audio flag clear\n- Magic number 0xfffffffe masks bit 0 (parity/LSB flag) from frame offset values\n- Frame offset calculation uses stride of 4 bytes (dword table entries)\n- Callback at offset +0x114 receives 5 parameters: context ptr, frame index, masked offset, stored offset, size\n\nMemory Layout (Bink Handle Offsets):\nOffset | Size | Field | Type | Description\n-------|------|-------|------|-------------\n0x0c   | 4    | CurrentFrameState | uint | Frame progress/state tracking\n0x10   | 4    | PreviousFrameState | uint | Prior frame state\n0x104  | 4    | StoredFrameOffset | uint | Frame offset for callbacks\n0x108  | 4    | FrameMode | int | Processing mode: 0=callback, else=offset\n0x10c  | 4    | FrameTablePtr | uint* | Pointer to frame offset table\n0x110  | 4    | CallbackContext | void | Start of callback context data\n0x114  | 4    | FrameCallback | func* | Function pointer for frame processing\n0x1e8  | 4    | PreProcessCallback | int | Pre/post processing callback (-1=disabled)\n0x20c  | 4    | AudioFlag | uint | Audio processing flag (set=enabled, clear=disabled)\n0x22c  | 4    | SoundEnabled | int | Sound output enable flag (0=disabled, else=enabled)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:0096a9bfa1ccec82c4941cbf55142d7c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "0096a9bfa1ccec82c4941cbf55142d7c",
        "MNE": "5b0f449f369105e479fccbee12de942d",
        "CFG": "663aa8489587b8064a31bfbcedfe7b3a",
        "PRO": "f687c39185d4023c5f79f1a124702955"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5b0f449f369105e479fccbee12de942d"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkSetSoundOnOff@8",
          "_BinkSetSoundOnOff@8"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_8ba509241f4f": {
      "addresses": {
        "LoD/PD2": "0x03828770"
      },
      "rvas": {
        "LoD/PD2": "0x8770"
      },
      "sizes": {
        "LoD/PD2": 558
      },
      "name": "ProcessBinkFrameBuffer",
      "signature": "void ProcessBinkFrameBuffer(int * hBink)",
      "calling_convention": "__stdcall",
      "comment": "Processes Bink video frame with reference counting, buffer management, and frame callbacks.\\n\\nAlgorithm:\\n1. Acquire reference via atomic increment on offset +0x29c\\n2. If reference count becomes 1, proceed with frame processing\\n3. Call initialization callback at offset +0x2a4 if present\\n4. Check buffer availability and deinterlace flags\\n5. Update deinterlace threshold counter if conditions met\\n6. Read frame data chunk via callback at offset +0x2a8\\n7. Calculate copy size based on buffer capacity and frame data size\\n8. Copy source buffer data to output buffer (handles gap cases)\\n9. Call post-processing callback at offset +0x2ac with frame size\\n10. Continue reading frames in loop until callback returns 0\\n11. Release reference via atomic decrement on offset +0x29c\\n\\nParameters:\\npBinkHandle : int * - Bink internal handle structure containing:\\n  - Offset +0x284: Write position in output buffer\\n  - Offset +0x288: Output buffer end address\\n  - Offset +0x290: Write pointer/position\\n  - Offset +0x29c: Reference count for threading\\n  - Offset +0x2a0: Deinterlace mode flag (0=disabled, else=enabled)\\n  - Offset +0x2a4: Init callback function pointer\\n  - Offset +0x2a8: Read frame data callback function pointer\\n  - Offset +0x2ac: Post-process callback function pointer\\n  - Offset +0x2c8: Deinterlace flag for current frame\\n  - Offset +0x298: Remaining data size to read\\n  - Offset +0x2c4: Max buffer size\\n  - Offset +0x368: Deinterlace threshold counter\\n  - Offset +0x36c: Deinterlace threshold value\\n  - Offset +0x374: Last deinterlace position\\n\\nReturns:\\nvoid - No return value; modifies buffer state in-place\\n\\nSpecial Cases:\\n- Reference count 1 check prevents reentrant processing\\n- Atomic increment/decrement operations ensure thread safety\\n- Deinterlace: threshold of 0x2ee added to position when conditions met\\n- Memory copy uses dword loops for efficiency when available\\n- Gap handling: if write position < source end, copies gap then primary data",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8ba509241f4faa2cef023d14fc340a90",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8ba509241f4faa2cef023d14fc340a90",
        "CFG": "f1998d4791e6e0733fee14d197c5000f",
        "PRO": "d509d34bd5ad929698ffe49e069f8b8d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8ba509241f4faa2cef023d14fc340a90"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_9a541bcc903f": {
      "addresses": {
        "LoD/PD2": "0x038289A0"
      },
      "rvas": {
        "LoD/PD2": "0x89A0"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "Convert16BitSamplesToUnsigned8Bit",
      "signature": "void Convert16BitSamplesToUnsigned8Bit(char * pDestBuffer, undefined2 * pSourceSamples, uint sampleCount)",
      "calling_convention": "__cdecl",
      "comment": "Converts packed 16-bit audio samples to 8-bit unsigned PCM format.\n\nAlgorithm:\n1. Calculate loop count by right-shifting sampleCount by 1 (divide by 2)\n2. Jump to cleanup if no iterations needed (loopCounter == 0)\n3. For each iteration:\n   - Load 16-bit word from source buffer (ECX)\n   - Advance source pointer by 2 bytes\n   - Extract high byte via SAR EDX, 0x8\n   - Apply bias offset 0x80 (convert signed to unsigned)\n   - Store 8-bit result to destination buffer\n   - Increment destination pointer\n   - Decrement loop counter and continue\n4. Restore ESI and return\n\nParameters:\n- pDestBuffer (EAX): char* pointing to output buffer for 8-bit samples\n- pSourceSamples (ECX): undefined2* (uint16*) pointing to packed 16-bit samples\n- sampleCount (ESI): uint total number of 16-bit samples to convert\n\nReturns:\n- void\n\nSpecial Cases:\n- If sampleCount is 0, function returns immediately without processing\n- Right-shift by 1 truncates odd sample counts (processes even number of samples)\n- High byte extraction via SAR assumes big-endian or specific packing format\n- Offset 0x80 converts from signed (-128 to 127) to unsigned (0 to 255)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9a541bcc903ff4ee859ac8534df3ddeb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9a541bcc903ff4ee859ac8534df3ddeb",
        "CFG": "3faa1a24a3d4c996032f03064ca761f6",
        "PRO": "8faf15f2547cd16a3e97bff58dd31528"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9a541bcc903ff4ee859ac8534df3ddeb"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_7ad93d1a555b": {
      "addresses": {
        "LoD/PD2": "0x038289D0"
      },
      "rvas": {
        "LoD/PD2": "0x89D0"
      },
      "sizes": {
        "LoD/PD2": 143
      },
      "name": "FillBufferWithZeros",
      "signature": "void FillBufferWithZeros(int pBufferState)",
      "calling_convention": "__cdecl",
      "comment": "Fills a circular/ring buffer with zeros, managing wrap-around when write pointer exceeds buffer boundaries.\\n\\nAlgorithm:\\n1. Check if current position (offset 0x298) is less than capacity (offset 0x370)\\n2. Calculate remaining size needed: capacity - current position\\n3. Get buffer end pointer from offset 0x284\\n4. Calculate new write position: current pointer (0x290) - remaining size\\n5. If new position wraps before buffer end:\\n   a. Calculate wrap-around portion size\\n   b. Fill from buffer end pointer with zeros (DWORD-aligned then remaining bytes)\\n   c. Fill from buffer start with remaining data\\n6. Fill remaining buffer area with zeros (DWORD-aligned then remaining bytes)\\n7. Update current position by adding remaining size\\n\\nParameters:\\npBufferState (int): Pointer to buffer state structure containing:\\n  - offset 0x280: Buffer base pointer\\n  - offset 0x284: Buffer end pointer\\n  - offset 0x290: Current write pointer\\n  - offset 0x298: Current position counter\\n  - offset 0x370: Buffer capacity\\n\\nReturns:\\nvoid - No return value\\n\\nSpecial Cases:\\n- Uses REP STOSD/STOSB for efficient zero-filling with DWORD alignment\\n- Handles circular buffer wrap-around when position exceeds end\\n- Processes remaining bytes after DWORD-aligned fill operations",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7ad93d1a555bb9d08862b095b2fc464c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7ad93d1a555bb9d08862b095b2fc464c",
        "CFG": "e6d4cfc732ebcb5ddd2e9b3cce6f93b9",
        "PRO": "dbb846f726ed4e0d260927213b10d464"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7ad93d1a555bb9d08862b095b2fc464c"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_6980d730e4de": {
      "addresses": {
        "LoD/PD2": "0x03828A60"
      },
      "rvas": {
        "LoD/PD2": "0x8A60"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "ComputeArrayElementDifferences",
      "signature": "uint ComputeArrayElementDifferences(uint arraySize, int * pArrayValues, uint strideOffset, int * pMaxDiffIndex)",
      "calling_convention": "__cdecl",
      "comment": "Computes maximum difference between strided array elements and weighted average.\n\nAlgorithm:\n1. Initialize maxDifference to 0 and maxDiffElementIndex to 0\n2. If arraySize > strideOffset, iterate through array comparing differences:\n   - Calculate difference between pArrayValues[i+strideOffset] and pArrayValues[i]\n   - Track maximum difference and index of maximum\n3. If maxDifference is 0, compute weighted average:\n   - Calculate (pArrayValues[arraySize] - pArrayValues[0]) * strideOffset / arraySize\n4. Return maxDifference (or weighted average if no differences found)\n5. Write maxDiffElementIndex to *pMaxDiffIndex\n\nParameters:\n  arraySize: Total number of elements in array\n  pArrayValues: Pointer to array of signed integers\n  strideOffset: Offset/stride between element comparisons\n  pMaxDiffIndex: Output pointer to store index of max difference element\n\nReturns:\n  Maximum difference found between strided elements, or weighted average if max is 0\n\nSpecial Cases:\n  - If arraySize <= strideOffset, skips loop and computes weighted average\n  - Magic value 0 indicates no significant differences, triggers fallback calculation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6980d730e4de9a5b6aaea3e0ef269ee0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6980d730e4de9a5b6aaea3e0ef269ee0",
        "CFG": "ad859d86f55ca2cb4c494a69c35e689c",
        "PRO": "ae6443e0c6df33d2bd18fe3ed3cdf726"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6980d730e4de9a5b6aaea3e0ef269ee0"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_ccce9ff8629e": {
      "addresses": {
        "LoD/PD2": "0x03828AD0"
      },
      "rvas": {
        "LoD/PD2": "0x8AD0"
      },
      "sizes": {
        "LoD/PD2": 172
      },
      "name": "ProcessBinkVideoPlayback",
      "signature": "void ProcessBinkVideoPlayback(void * pBinkPlayer)",
      "calling_convention": "__stdcall",
      "comment": "Processes Bink video playback in a continuous loop\\n\\nAlgorithm:\\n1. Check if player status (offset +0x250) is 1 (READY). If not, set to 2 (DONE) and return\\n2. Initialize nextFrameTime to 0\\n3. Start main playback loop:\\n   a. Check render flag at offset +0x20 for bit 0x8000000 (if set, skip processing)\\n   b. Check validity flag at offset +0x108 (if non-zero, skip frame processing)\\n   c. Call frame processor function pointer at offset +0x120 with buffer at offset +0x110\\n   d. Calculate frame rate ratio: ((offset +0x154+1) * 100) / (offset +0x150+1)\\n   e. If ratio > 50%, sleep 5ms; otherwise sleep 10ms\\n   f. Get current time from timeGetTime()\\n   g. If time > nextFrameTime and offset +0x1e8 != -1, call ProcessBinkFrameBuffer\\n   h. Check if status changed; if not 1, set to 2 and exit\\n   i. Repeat loop\\n\\nParameters:\\n  pBinkPlayer: Pointer to Bink player structure containing:\\n    - Offset +0x20: Render flags (bit 0x8000000 = skip rendering)\\n    - Offset +0x108: Validity flag (0 = valid, non-zero = invalid)\\n    - Offset +0x110: Frame buffer start\\n    - Offset +0x120: Function pointer to frame processor\\n    - Offset +0x150: Numerator value for frame rate calculation\\n    - Offset +0x154: Denominator value for frame rate calculation\\n    - Offset +0x1e8: Frame index (-1 = invalid)\\n    - Offset +0x250: Player state (1=READY, 2=DONE)\\n\\nReturns:\\n  void\\n\\nSpecial Cases:\\n  - Magic numbers: 0x32 (50 decimal, frame rate threshold), 0xa (10ms default sleep)\\n  - Frame rate is calculated as a percentage; >50% triggers 5ms sleep, <=50% uses 10ms\\n  - Loop continues indefinitely until status changes from READY to DONE\\n  - ProcessBinkFrameBuffer is only called when enough time has elapsed and frame is valid",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ccce9ff8629e688eacc62c769377bdf3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ccce9ff8629e688eacc62c769377bdf3",
        "CFG": "d5601f252609504190ed90b23cb32f9e",
        "PRO": "f9790682257180ec93880de333a135c1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ccce9ff8629e688eacc62c769377bdf3"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_API_0d5624e07cf0": {
      "addresses": {
        "LoD/PD2": "0x03828B80"
      },
      "rvas": {
        "LoD/PD2": "0x8B80"
      },
      "sizes": {
        "LoD/PD2": 1600
      },
      "name": "_BinkCopyToBuffer@28",
      "signature": "undefined4 _BinkCopyToBuffer@28(int * param_1, uint param_2, uint param_3, int param_4, uint param_5, uint param_6, uint param_7)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:0d5624e07cf093ff43c3a6c62d4c3b55",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "0d5624e07cf093ff43c3a6c62d4c3b55",
        "MNE": "8eed9034e584c58152b45874152708b1",
        "CFG": "e67e2ba0656f198f5e6c3506d1f2a42c",
        "PRO": "0fb37b2725ad2a7f95fbd91d45986cbf"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8eed9034e584c58152b45874152708b1"
      },
      "api_calls": {
        "LoD/PD2": [
          "_YUV_init@4",
          "_BinkPause@8",
          "_BinkPause@8",
          "_YUV_blit_32bpp@48",
          "_YUV_blit_24bpp@48",
          "_YUV_blit_16bpp@48",
          "_YUV_blit_UYVY@48",
          "_YUV_blit_YUY2@48",
          "_YUV_blit_32bpp_mask@48",
          "_YUV_blit_24bpp_mask@48",
          "...+4 more"
        ]
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "binkw32_MNE_4c594ffa40cc": {
      "addresses": {
        "LoD/PD2": "0x03829210"
      },
      "rvas": {
        "LoD/PD2": "0x9210"
      },
      "sizes": {
        "LoD/PD2": 42
      },
      "name": "InitializeBinkTiming",
      "signature": "void InitializeBinkTiming(void * pBinkHandle)",
      "calling_convention": "__cdecl",
      "comment": "Initializes Bink video playback timing on first call.\n\nAlgorithm:\n1. Check if timing has been initialized (offset +0x20c non-zero)\n2. If not initialized, call timeGetTime() to get current system time\n3. Store the current time at offset +0x20c in the Bink handle\n4. Read frame count from offset +0x1fc, decrement by 1\n5. Store decremented frame count at offset +0x210\n6. Return to caller\n\nParameters:\n- pBinkHandle (void*): Pointer to Bink playback context structure\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- Function is idempotent: subsequent calls skip initialization if offset +0x20c is non-zero\n- Frame count is decremented from initial value (typically 0)\n- Used by Bink API wrapper functions (_BinkDoFrame, _BinkWait, _BinkCopyToBuffer)\n\nStructure Layout:\nOffset  Size  Field Name        Type        Description\n0x1fc   4     frame_count       uint        Initial frame count value\n0x20c   4     start_time_ms     uint        System time from timeGetTime() when playback started\n0x210   4     current_frame     uint        Current frame number (decremented each call)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4c594ffa40cc6011fbd055a26c7a7a9c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4c594ffa40cc6011fbd055a26c7a7a9c",
        "CFG": "bc042e4f56c5c862716dd36277cac9ef",
        "PRO": "d5422ce8f943c3d30f2d46592bb199ae"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4c594ffa40cc6011fbd055a26c7a7a9c"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_828ddfda5cf6": {
      "addresses": {
        "LoD/PD2": "0x03829240"
      },
      "rvas": {
        "LoD/PD2": "0x9240"
      },
      "sizes": {
        "LoD/PD2": 1243
      },
      "name": "_BinkDoFrame@4",
      "signature": "undefined4 _BinkDoFrame@4(int * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:828ddfda5cf60ee581badbb279450a28",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "828ddfda5cf60ee581badbb279450a28",
        "CFG": "26c298de73630e3611820f5a2aabb4a7",
        "PRO": "c7aace89c1f080073f9cf247ca92d833"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "828ddfda5cf60ee581badbb279450a28"
      },
      "api_calls": {
        "LoD/PD2": [
          "_ExpandBink@56"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_9911d36575de": {
      "addresses": {
        "LoD/PD2": "0x03829720"
      },
      "rvas": {
        "LoD/PD2": "0x9720"
      },
      "sizes": {
        "LoD/PD2": 77
      },
      "name": "_BinkNextFrame@4",
      "signature": "undefined _BinkNextFrame@4(int * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9911d36575de29f20d789acc2c19c5d5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9911d36575de29f20d789acc2c19c5d5",
        "CFG": "71e03f35ef22feb1ba4d33deb41cb9e0",
        "PRO": "658d6958999c0dce4d6844cc8641455d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9911d36575de29f20d789acc2c19c5d5"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_a8c7f43cc1a5": {
      "addresses": {
        "LoD/PD2": "0x03829770"
      },
      "rvas": {
        "LoD/PD2": "0x9770"
      },
      "sizes": {
        "LoD/PD2": 37
      },
      "name": "UpdateBinkFrameTiming",
      "signature": "void UpdateBinkFrameTiming(int * pBinkHandle, DWORD currentTime)",
      "calling_convention": "__cdecl",
      "comment": "Updates Bink video frame timing information by accumulating frame delays.\n\nAlgorithm:\n1. Check if a previous frame timestamp is stored at offset +0x208\n2. If found, calculate the time delta (current - previous timestamp)\n3. Accumulate the delta into the frame adjustment counter at offset +0x240\n4. Clear the previous timestamp at offset +0x208 to zero\n5. Return without modification if no previous timestamp exists\n\nParameters:\npBinkHandle [int*]: Pointer to Bink file/state structure\ncurrentTime [DWORD]: Current system time in milliseconds from timeGetTime()\n\nReturns:\nvoid - Function modifies structure in place\n\nSpecial Cases:\n- If offset +0x208 is zero, no adjustment is made (first frame or reset)\n- Offset +0x240 accumulates all frame timing adjustments\n- The function handles timing synchronization for frame playback\n- Used by BinkWait and BinkNextFrame for frame timing coordination\n\nStructure Layout:\nOffset | Size | Field Name      | Type  | Description\n-------|------|-----------------|-------|------------------\n 0x208 |   4  | lastTimestamp   | DWORD | Previous frame timestamp\n 0x240 |   4  | timingAdjustment| DWORD | Accumulated frame delay adjustment",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a8c7f43cc1a5ca6057d221f2392511d8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a8c7f43cc1a5ca6057d221f2392511d8",
        "CFG": "dc31fd8ae2ce6da459435b7f021fe995",
        "PRO": "d8efdb342cf5d9a5148d1f3e79a05dcd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a8c7f43cc1a5ca6057d221f2392511d8"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_2cb7d265593b": {
      "addresses": {
        "LoD/PD2": "0x038297A0"
      },
      "rvas": {
        "LoD/PD2": "0x97A0"
      },
      "sizes": {
        "LoD/PD2": 209
      },
      "name": "_BinkGetKeyFrame@12",
      "signature": "uint _BinkGetKeyFrame@12(int param_1, uint param_2, uint param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2cb7d265593b6b868b6ca3a78e9b29d7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2cb7d265593b6b868b6ca3a78e9b29d7",
        "CFG": "8395f00fb8dca3d19e6a735b1f35d9c7",
        "PRO": "72a948b62cd39ce47fd399770a908bf9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2cb7d265593b6b868b6ca3a78e9b29d7"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_API_ec39d932b8fd": {
      "addresses": {
        "LoD/PD2": "0x03829880"
      },
      "rvas": {
        "LoD/PD2": "0x9880"
      },
      "sizes": {
        "LoD/PD2": 189
      },
      "name": "_BinkGoto@12",
      "signature": "undefined _BinkGoto@12(int * param_1, uint param_2, byte param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:ec39d932b8fdd46cdf66e0b6a315ef79",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "ec39d932b8fdd46cdf66e0b6a315ef79",
        "MNE": "72bb3023b5ef1797716aa30825bc7079",
        "CFG": "17f8376618709a6e13b6463b98009a5f",
        "PRO": "19afb8a02d63608342e5ce7cc8f4a733"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "72bb3023b5ef1797716aa30825bc7079"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkGetKeyFrame@12",
          "_BinkPause@8",
          "_BinkDoFrame@4",
          "_BinkNextFrame@4",
          "_BinkDoFrame@4",
          "_BinkNextFrame@4",
          "_BinkPause@8"
        ]
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_API_0aacbb0223ce": {
      "addresses": {
        "LoD/PD2": "0x03829940"
      },
      "rvas": {
        "LoD/PD2": "0x9940"
      },
      "sizes": {
        "LoD/PD2": 205
      },
      "name": "_BinkClose@4",
      "signature": "undefined _BinkClose@4(int * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:0aacbb0223ce77d67e426a1fa0addad9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "0aacbb0223ce77d67e426a1fa0addad9",
        "MNE": "d93ddd2689b7904ae5b60a7c2f81d7d7",
        "CFG": "fcda30d22389bad49144e13092711d40",
        "PRO": "821835b13ddd0636c9921e0385cf38b1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d93ddd2689b7904ae5b60a7c2f81d7d7"
      },
      "api_calls": {
        "LoD/PD2": [
          "_BinkPause@8",
          "_radfree@4",
          "_radfree@4",
          "_radfree@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_baf7485d9fbb": {
      "addresses": {
        "LoD/PD2": "0x03829A10"
      },
      "rvas": {
        "LoD/PD2": "0x9A10"
      },
      "sizes": {
        "LoD/PD2": 344
      },
      "name": "_BinkWait@4",
      "signature": "uint _BinkWait@4(int * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:baf7485d9fbb8902d593b1851d7fdc18",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "baf7485d9fbb8902d593b1851d7fdc18",
        "CFG": "637ce8076bc4c8adc4fb3ba50e9b73b8",
        "PRO": "10e907120144a212d58219f04899d312"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "baf7485d9fbb8902d593b1851d7fdc18"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_a5662b9be757": {
      "addresses": {
        "LoD/PD2": "0x03829B70"
      },
      "rvas": {
        "LoD/PD2": "0x9B70"
      },
      "sizes": {
        "LoD/PD2": 98
      },
      "name": "UpdateRealtimeMetrics",
      "signature": "void UpdateRealtimeMetrics(void * pContext, uint timestamp)",
      "calling_convention": "__cdecl",
      "comment": "Updates realtime metrics tracking for Bink video playback timing.\n\nAlgorithm:\n1. Check if offset 0x218 contains a pending start time (non-zero value)\n2. If pending, calculate elapsed time: current timestamp - pending start time\n3. Clear the pending start time at offset 0x218\n4. If calculated elapsed time exceeds max time (offset 0x21c):\n   - Save previous max to previous max slot (offset 0x224)\n   - Set new max time to calculated elapsed time\n   - Save associated data values from offset 0x220 and 0xc to offsets 0x228 and 0x220\n   - Return early\n5. Otherwise, if calculated elapsed time exceeds secondary threshold (offset 0x224):\n   - Update secondary max to calculated elapsed time\n   - Update associated data at offset 0x228 from offset 0xc\n\nParameters:\n- pContext: void * - Pointer to context structure containing timing data\n- timestamp: uint - Current timestamp value in milliseconds\n\nReturns:\n- void\n\nSpecial Cases:\n- Function only processes if offset 0x218 is non-zero (has pending start time)\n- Tracks both maximum and secondary maximum elapsed times\n- Clears pending start time immediately after calculating elapsed time\n- Preserves associated metadata values alongside timing measurements",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a5662b9be7573145add48449989b505f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a5662b9be7573145add48449989b505f",
        "CFG": "473d086ee94878b8f6ec467e2de64aec",
        "PRO": "776b79b836ccdccc0aedbd4d4c6a70c7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a5662b9be7573145add48449989b505f"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_03eb0f650679": {
      "addresses": {
        "LoD/PD2": "0x03829BE0"
      },
      "rvas": {
        "LoD/PD2": "0x9BE0"
      },
      "sizes": {
        "LoD/PD2": 133
      },
      "name": "_BinkPause@8",
      "signature": "int _BinkPause@8(int * param_1, int param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:03eb0f650679304c0b14b943b0e85b26",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "03eb0f650679304c0b14b943b0e85b26",
        "CFG": "e0b55856203a0ea509c868c075a69d8e",
        "PRO": "f67c661d6323541884aa145a8a4df243"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "03eb0f650679304c0b14b943b0e85b26"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_74fe75352684": {
      "addresses": {
        "LoD/PD2": "0x03829C70"
      },
      "rvas": {
        "LoD/PD2": "0x9C70"
      },
      "sizes": {
        "LoD/PD2": 430
      },
      "name": "_BinkGetSummary@8",
      "signature": "undefined _BinkGetSummary@8(undefined4 * param_1, undefined4 * param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:74fe75352684d4f6556e8b894e057e9d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "74fe75352684d4f6556e8b894e057e9d",
        "CFG": "41dc7fc5c9dabdfa01f5e854eaaaa0ee",
        "PRO": "ec4d7cc68b3efa95a2e3c1fae3be6e16"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "74fe75352684d4f6556e8b894e057e9d"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_671864590936": {
      "addresses": {
        "LoD/PD2": "0x03829E20"
      },
      "rvas": {
        "LoD/PD2": "0x9E20"
      },
      "sizes": {
        "LoD/PD2": 301
      },
      "name": "_BinkGetRealtime@12",
      "signature": "undefined _BinkGetRealtime@12(int param_1, undefined4 * param_2, uint param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:671864590936673a7354683953b975ca",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "671864590936673a7354683953b975ca",
        "CFG": "9e38f54eb90ee713dc939c4cd421835b",
        "PRO": "a9c6341a6a9793f629349c484c1c04b0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "671864590936673a7354683953b975ca"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_ba21fdd131c0": {
      "addresses": {
        "LoD/PD2": "0x03829F50"
      },
      "rvas": {
        "LoD/PD2": "0x9F50"
      },
      "sizes": {
        "LoD/PD2": 882
      },
      "name": "_BinkGetRects@8",
      "signature": "uint _BinkGetRects@8(uint * param_1, uint param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ba21fdd131c02a68df11256a5a4c5252",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ba21fdd131c02a68df11256a5a4c5252",
        "CFG": "24cce061d242445b922ba57b4178acf1",
        "PRO": "2e1eeefa93bc2767efe91596f2faa625"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ba21fdd131c02a68df11256a5a4c5252"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_b321489c43a1": {
      "addresses": {
        "LoD/PD2": "0x0382A2D0"
      },
      "rvas": {
        "LoD/PD2": "0xA2D0"
      },
      "sizes": {
        "LoD/PD2": 348
      },
      "name": "FindLargestNonZeroRect",
      "signature": "int FindLargestNonZeroRect(int * pOutRect, int stride, int height, int * pInRect)",
      "calling_convention": "__cdecl",
      "comment": "Finds the largest non-zero rectangular region in a 2D array by scanning from edges.\n\nAlgorithm:\n1. Convert input rectangle coordinates from pixel to tile units (divide by 16)\n2. Scan from top edge downward to find first non-zero row\n3. Scan from bottom edge upward to find last non-zero row\n4. Scan from left edge rightward to find first non-zero column\n5. Scan from right edge leftward to find last non-zero column\n6. Return 1 if non-zero region found, 0 if entire array is zero\n\nParameters:\n- pOutRect (int*): Output rectangle with fields [x, y, width, height] as tile coordinates\n- stride (int): Number of bytes between array rows\n- height (int): Number of rows in the array\n- pInRect (int*): Input rectangle with fields [x_pixels, y_pixels, width_pixels, height_pixels]\n\nReturns:\n- 1 if non-zero region was found and pOutRect updated\n- 0 if entire array contains only zero bytes\n\nSpecial Cases:\n- Input coordinates use pixel units (16 pixels = 1 tile)\n- Scan operations use tile-based arithmetic (division by 16)\n- Output uses both pixel and tile units simultaneously in structure fields\n- Empty array (all zeros) returns 0 without modifying pOutRect",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b321489c43a17c8bc653c7614c1dc777",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b321489c43a17c8bc653c7614c1dc777",
        "CFG": "a0691b32944850c009606c768252d880",
        "PRO": "23f49d372e0695e0c1d8f1994380f243"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b321489c43a17c8bc653c7614c1dc777"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_8afa61c73dfd": {
      "addresses": {
        "LoD/PD2": "0x0382A430"
      },
      "rvas": {
        "LoD/PD2": "0xA430"
      },
      "sizes": {
        "LoD/PD2": 420
      },
      "name": "FindOptimalRectangleSplit",
      "signature": "int FindOptimalRectangleSplit(int * pLeftRect, int * pRightRect, int * pSourceRect, int nParam4, int nParam5)",
      "calling_convention": "__cdecl",
      "comment": "FindOptimalRectangleSplit - Finds the best way to split a rectangle into two parts based on non-zero regions\n\nAlgorithm:\n1. Check if source rectangle width >= 0x20 (32 pixels)\n   - If width is large enough, attempt horizontal split\n   - Calculate aligned half-width (half + 15) & 0xFFFFFFF0\n   - Find largest non-zero rect in left half\n   - Find largest non-zero rect in right half\n   - Calculate horizontal split score: source_area - left_area - right_area\n2. Check if source rectangle height >= 0x20 (32 pixels)\n   - If height is large enough, attempt vertical split\n   - Calculate aligned half-height (half + 15) & 0xFFFFFFF0\n   - Find largest non-zero rect in top half\n   - Find largest non-zero rect in bottom half\n   - Calculate vertical split score: source_area - top_area - bottom_area\n3. Compare split scores and return the maximum\n   - If vertical split score > horizontal score, update output rects and return vertical score\n   - Otherwise return horizontal score\n\nParameters:\npLeftRect (or pTopRect): Pointer to 4-element int array [x, y, width, height] for left/top rectangle result\npRightRect (or pBottomRect): Pointer to 4-element int array [x, y, width, height] for right/bottom rectangle result\npSourceRect: Pointer to 4-element int array [x, y, width, height] defining source rectangle bounds\nnParam4: Video width in pixels (used by FindLargestNonZeroRect)\nnParam5: Video height in pixels (used by FindLargestNonZeroRect)\n\nReturns:\nInteger representing the area difference for the best split found\n- Horizontal split: source_area - (left_rect_area + right_rect_area)\n- Vertical split: source_area - (top_rect_area + bottom_rect_area)\n- Returns 0 if both width and height < 0x20 (no split possible)\n\nSpecial Cases:\n- Minimum dimension: Both width and height must be >= 0x20 (32 pixels) to attempt split\n- Alignment: Split positions are aligned to 16-byte boundaries for video optimization\n- Rectangle format: Each rect is [x, y, width, height] with area = width * height\n- No valid split: If both splits fail (width < 32 AND height < 32), returns 0",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8afa61c73dfdfb6b182e4cae2c97a28d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8afa61c73dfdfb6b182e4cae2c97a28d",
        "CFG": "b29679b569548e8f213e34d2fa57f945",
        "PRO": "0a310b734bb095fac0531154ab631b08"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8afa61c73dfdfb6b182e4cae2c97a28d"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_02f60b998423": {
      "addresses": {
        "LoD/PD2": "0x0382A5E0"
      },
      "rvas": {
        "LoD/PD2": "0xA5E0"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "_BinkService@4",
      "signature": "undefined _BinkService@4(int * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:02f60b998423d792b7f03ffb0e2dbed3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "02f60b998423d792b7f03ffb0e2dbed3",
        "CFG": "b70e7b162a9ff701225259b587af782d",
        "PRO": "40d982bbe7b681b825a61646608b141e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "02f60b998423d792b7f03ffb0e2dbed3"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_27d9eae3fe39": {
      "addresses": {
        "LoD/PD2": "0x0382A600"
      },
      "rvas": {
        "LoD/PD2": "0xA600"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "_BinkSetVolume@8",
      "signature": "undefined _BinkSetVolume@8(int param_1, undefined4 param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:27d9eae3fe39b46611cc1e4571db6907",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "27d9eae3fe39b46611cc1e4571db6907",
        "CFG": "2bea3eb19dd06b49df098eed6ded289c",
        "PRO": "1b552ecc44522cc0012633c7ddf6eb43"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "27d9eae3fe39b46611cc1e4571db6907"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_ADDR_0382A630": {
      "addresses": {
        "LoD/PD2": "0x0382A630"
      },
      "rvas": {
        "LoD/PD2": "0xA630"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "_BinkSetPan@8",
      "signature": "undefined _BinkSetPan@8(int param_1, undefined4 param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:27d9eae3fe39b46611cc1e4571db6907",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "27d9eae3fe39b46611cc1e4571db6907",
        "CFG": "2bea3eb19dd06b49df098eed6ded289c",
        "PRO": "1b552ecc44522cc0012633c7ddf6eb43"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "27d9eae3fe39b46611cc1e4571db6907"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_ADDR_0382A660": {
      "addresses": {
        "LoD/PD2": "0x0382A660"
      },
      "rvas": {
        "LoD/PD2": "0xA660"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "_BinkLogoAddress@0",
      "signature": "undefined * _BinkLogoAddress@0(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "994fa0387d62a90cf97efee68752d22d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "binkw32_MNE_a7220ac22854": {
      "addresses": {
        "LoD/PD2": "0x0382A670"
      },
      "rvas": {
        "LoD/PD2": "0xA670"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "_BinkGetTrackType@8",
      "signature": "undefined4 _BinkGetTrackType@8(int param_1, int param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a7220ac2285460f515b72dab5562d1b6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a7220ac2285460f515b72dab5562d1b6",
        "CFG": "e4d929dcade813bcfed0f23f20c25712",
        "PRO": "ea219bdd55ab593fa4c5bb6064239c2d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a7220ac2285460f515b72dab5562d1b6"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_ADDR_0382A690": {
      "addresses": {
        "LoD/PD2": "0x0382A690"
      },
      "rvas": {
        "LoD/PD2": "0xA690"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "_BinkGetTrackMaxSize@8",
      "signature": "undefined4 _BinkGetTrackMaxSize@8(int param_1, int param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a7220ac2285460f515b72dab5562d1b6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a7220ac2285460f515b72dab5562d1b6",
        "CFG": "e4d929dcade813bcfed0f23f20c25712",
        "PRO": "6e04976b4f73f3a28790c4c6fcb305fe"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a7220ac2285460f515b72dab5562d1b6"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_ADDR_0382A6B0": {
      "addresses": {
        "LoD/PD2": "0x0382A6B0"
      },
      "rvas": {
        "LoD/PD2": "0xA6B0"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "_BinkGetTrackID@8",
      "signature": "undefined4 _BinkGetTrackID@8(int param_1, int param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a7220ac2285460f515b72dab5562d1b6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a7220ac2285460f515b72dab5562d1b6",
        "CFG": "e4d929dcade813bcfed0f23f20c25712",
        "PRO": "350be01073b3f87f16ab9e27fff06ce0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a7220ac2285460f515b72dab5562d1b6"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_a12c2c16e653": {
      "addresses": {
        "LoD/PD2": "0x0382A6D0"
      },
      "rvas": {
        "LoD/PD2": "0xA6D0"
      },
      "sizes": {
        "LoD/PD2": 213
      },
      "name": "_BinkOpenTrack@8",
      "signature": "uint * _BinkOpenTrack@8(uint param_1, uint param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a12c2c16e6534ee1fb1913cb480c01a8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a12c2c16e6534ee1fb1913cb480c01a8",
        "CFG": "e2002b5bdbe94d35105e723f2367ff33",
        "PRO": "2beea65a0d0709ca9662b5e043af34b8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a12c2c16e6534ee1fb1913cb480c01a8"
      },
      "api_calls": {
        "LoD/PD2": [
          "_radmalloc@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_de598d52c061": {
      "addresses": {
        "LoD/PD2": "0x0382A7B0"
      },
      "rvas": {
        "LoD/PD2": "0xA7B0"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "_BinkCloseTrack@4",
      "signature": "undefined _BinkCloseTrack@4(int param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:de598d52c0612751d3d66fac812e7e95",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "de598d52c0612751d3d66fac812e7e95",
        "CFG": "4583fb81bcbb65d398ef64df6f5a37f7",
        "PRO": "bac16610341554761324ca18a1ba5a3f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "de598d52c0612751d3d66fac812e7e95"
      },
      "api_calls": {
        "LoD/PD2": [
          "_radfree@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_3fc74eacdf99": {
      "addresses": {
        "LoD/PD2": "0x0382A7E0"
      },
      "rvas": {
        "LoD/PD2": "0xA7E0"
      },
      "sizes": {
        "LoD/PD2": 280
      },
      "name": "_BinkGetTrackData@8",
      "signature": "char * _BinkGetTrackData@8(int param_1, char * param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3fc74eacdf995fcb13a48e5d23da57bb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3fc74eacdf995fcb13a48e5d23da57bb",
        "CFG": "c4ef4f4c69ee189e061fdfcf4aa08a56",
        "PRO": "cc852635856803ae62cf652f13d9ca93"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3fc74eacdf995fcb13a48e5d23da57bb"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_d93979ee5098": {
      "addresses": {
        "LoD/PD2": "0x0382A900"
      },
      "rvas": {
        "LoD/PD2": "0xA900"
      },
      "sizes": {
        "LoD/PD2": 21
      },
      "name": "_BinkSetVideoOnOff@8",
      "signature": "undefined _BinkSetVideoOnOff@8(int param_1, undefined4 param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d93979ee509812b79548e80a1d5ed0c9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d93979ee509812b79548e80a1d5ed0c9",
        "CFG": "185a13320262684e11525fe4d9449cba",
        "PRO": "3f60cd43786502744e9c652616842db4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d93979ee509812b79548e80a1d5ed0c9"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_4ebb33337bd8": {
      "addresses": {
        "LoD/PD2": "0x0382A920"
      },
      "rvas": {
        "LoD/PD2": "0xA920"
      },
      "sizes": {
        "LoD/PD2": 342
      },
      "name": "_BinkSetSoundOnOff@8",
      "signature": "int _BinkSetSoundOnOff@8(int param_1, undefined4 param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4ebb33337bd8444af3fc770818752cc7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4ebb33337bd8444af3fc770818752cc7",
        "CFG": "b7c67ba43236be10d5c4da9e4f92c77b",
        "PRO": "15a96686c98e858f5dd689248c48890d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4ebb33337bd8444af3fc770818752cc7"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_API_2a813995b144": {
      "addresses": {
        "LoD/PD2": "0x0382AA80"
      },
      "rvas": {
        "LoD/PD2": "0xAA80"
      },
      "sizes": {
        "LoD/PD2": 81
      },
      "name": "CreateThreadWithPackedParameters",
      "signature": "undefined4 * CreateThreadWithPackedParameters(undefined4 param1, undefined4 param2, undefined4 param3)",
      "calling_convention": "__stdcall",
      "comment": "Wraps multiple parameters in allocated buffer and creates thread to process them.\\nAllocates 20-byte parameter structure containing three input values plus thread handle and exit code return location. Safely handles allocation failure and thread creation failure with appropriate cleanup.\\\"",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:2a813995b1441f088cdfb419380fb2ad",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "2a813995b1441f088cdfb419380fb2ad",
        "MNE": "e60cdc166688190c40d25749a944e762",
        "CFG": "a5a0331dc24c0c358b55661d564e7637",
        "PRO": "8c5f8dffe43a7478b225620bc2f54ab2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e60cdc166688190c40d25749a944e762"
      },
      "api_calls": {
        "LoD/PD2": [
          "_radmalloc@4",
          "_radfree@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_02819bb1b587": {
      "addresses": {
        "LoD/PD2": "0x0382AAE0"
      },
      "rvas": {
        "LoD/PD2": "0xAAE0"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "InvokeCallbackPacket",
      "signature": "uint InvokeCallbackPacket(CallbackPacket * pPacket)",
      "calling_convention": "__stdcall",
      "comment": "Invokes a callback function with parameters from a packet structure.\\n\\nAlgorithm:\\n1. Load the callback packet pointer from the stack parameter\\n2. Extract the function pointer from offset 0 of the packet\\n3. Check if the function pointer is non-null\\n4. If valid, extract param1 (offset 4) and param2 (offset 8) from the packet\\n5. Call the callback function with both parameters\\n6. Return status code 0 (success)\\n\\nParameters:\\n  pPacket (CallbackPacket*): Pointer to callback packet containing function pointer and two DWORD parameters\\n\\nReturns:\\n  0: Always returns 0 (success status code)\\n\\nStructure Layout:\\n  Offset  Size  Field Name    Type      Description\\n  0x0     0x4   pFunction     pointer   Function pointer to invoke\\n  0x4     0x4   param1        DWORD     First parameter to callback\\n  0x8     0x4   param2        DWORD     Second parameter to callback\\n  Total: 0xC (12 bytes)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:02819bb1b587ed4caef76373a64224b6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "02819bb1b587ed4caef76373a64224b6",
        "CFG": "4acc71aeabdee03873d6f4cf1d84c281",
        "PRO": "df0515a4481223ff02d7ca5ed81f5fdc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "02819bb1b587ed4caef76373a64224b6"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_7f662ad0ee6f": {
      "addresses": {
        "LoD/PD2": "0x0382AB00"
      },
      "rvas": {
        "LoD/PD2": "0xAB00"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "CleanupBinkHandle",
      "signature": "void CleanupBinkHandle(void * pBinkHandle)",
      "calling_convention": "__stdcall",
      "comment": "Cleans up and frees a Bink video handle structure.\n\nAlgorithm:\n1. Check if pBinkHandle is not NULL\n2. Extract HANDLE from offset +0xc within the structure\n3. Call CloseHandle to release the Windows handle resource\n4. Call radfree to deallocate the Bink structure itself\n5. Return to caller\n\nParameters:\n  pBinkHandle: Pointer to Bink handle structure containing HANDLE at offset +0xc.\n              If NULL, function returns immediately without action.\n\nReturns:\n  void\n\nSpecial Cases:\n  - If pBinkHandle is NULL, no cleanup occurs (safe no-op)\n  - The HANDLE at offset +0xc must be a valid Windows handle or NULL\n  - Must be called before memory containing pBinkHandle is freed\n\nStructure Layout:\n  Offset | Size | Field Name     | Type   | Description\n  -------|------|----------------|--------|------------------\n  +0x0c  | 0x4  | hEvent/Handle  | HANDLE | Windows handle to be closed",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7f662ad0ee6f8dabb307791a233ec837",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7f662ad0ee6f8dabb307791a233ec837",
        "CFG": "e4d929dcade813bcfed0f23f20c25712",
        "PRO": "73eec923ea90dddcdf5671f96b32d4bc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7f662ad0ee6f8dabb307791a233ec837"
      },
      "api_calls": {
        "LoD/PD2": [
          "_radfree@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_60a3cff6f83a": {
      "addresses": {
        "LoD/PD2": "0x0382AB20"
      },
      "rvas": {
        "LoD/PD2": "0xAB20"
      },
      "sizes": {
        "LoD/PD2": 1613
      },
      "name": "_YUV_init@4",
      "signature": "undefined _YUV_init@4(int param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:60a3cff6f83a208b2ba23755bfe502a1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "60a3cff6f83a208b2ba23755bfe502a1",
        "CFG": "29a739e94f64e8f8826907da580e4fc2",
        "PRO": "c8afdb1fe11bf33044066f591b8cbd5a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "60a3cff6f83a208b2ba23755bfe502a1"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_548267d6275b": {
      "addresses": {
        "LoD/PD2": "0x0382B180"
      },
      "rvas": {
        "LoD/PD2": "0xB180"
      },
      "sizes": {
        "LoD/PD2": 88
      },
      "name": "GetTimestampAndInitializeYUV",
      "signature": "ulonglong GetTimestampAndInitializeYUV(void)",
      "calling_convention": "__stdcall",
      "comment": "Read CPU timestamp counter and initialize YUV codec marker.\n\nAlgorithm:\n1. Setup structured exception handling (SEH) frame with handlers at 0x3847cd8 and 0x383ced0\n2. Save current FS:[0x0] pointer for exception chain restoration\n3. Initialize completion flag (0x0385c80c) to -1 before operation\n4. Execute RDTSC instruction to read CPU cycle counter\n5. Set completion flag (0x0385c80c) to 1 to indicate successful initialization\n6. Execute SEH cleanup: restore FS:[0x0] from saved pointer\n7. Return 64-bit timestamp from EDX:EAX\n\nParameters:\nNone - This is a void function with no parameters\n\nReturns:\nunsigned long long - 64-bit CPU timestamp counter from RDTSC instruction\n  Value represents processor cycle count since last reset\n  Can be used for precise timing measurements (typically nanosecond-scale)\n\nSpecial Cases:\n- SEH handlers at 0x3847cd8 and 0x383ced0 provide exception protection\n- Exception filter set to 0 or -1 depending on context\n- Completion flag (0x0385c80c) acts as initialization status marker\n- Used in YUV video codec initialization (_YUV_init caller)\n- Returns TSC value regardless of SEH exceptions\n\nStructure Layout:\nStack frame (negative offsets from EBP):\n  Offset  Size  Field Name          Type        Description\n  -0x04   4     exception_filter    dword       Exception disposition code\n  -0x08   4     seh_frame           pointer     SEH frame pointer (saved ESP)\n  -0x10   4     saved_fs_ptr        pointer     Saved FS:[0x0] for restoration\n  -0x18   4     esp_save            pointer     Stack frame reference",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:548267d6275b00d05d07d52d34b221dc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "548267d6275b00d05d07d52d34b221dc",
        "CFG": "a86bf6f0193967be873d7ae76cd141bb",
        "PRO": "08e24923f3c70cb01e13fa71a6379b82"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "548267d6275b00d05d07d52d34b221dc"
      }
    },
    "binkw32_MNE_bb371b5dcf86": {
      "addresses": {
        "LoD/PD2": "0x0382B240"
      },
      "rvas": {
        "LoD/PD2": "0xB240"
      },
      "sizes": {
        "LoD/PD2": 134
      },
      "name": "ProcessLookupTablePair",
      "signature": "int ProcessLookupTablePair(int iterationCount, int resultOffset)",
      "calling_convention": "__cdecl",
      "comment": "Processes parallel lookup table transformations for two data streams.\n\nAlgorithm:\n1. Load iteration count from iterationCount parameter into register EDX\n2. Loop iterationCount times:\n   a. Read index byte from source pointer at 0x038532e8, increment pointer\n   b. Look up value in table at 0x385674c using index as 4-byte offset multiplier\n   c. Write looked-up value to both destination and destination+4 at 0x038532e0\n   d. Read second index byte from source pointer at 0x038532ec, increment pointer\n   e. Look up value in second table entry using same table base\n   f. Write looked-up value to both destination and destination+4 at 0x038532e4\n   g. Advance both destination pointers by 8 bytes (2 dwords)\n   h. Decrement loop counter and jump to loop_start_table_lookup if not zero\n3. Return sum of iterationCount + resultOffset\n\nParameters:\n  iterationCount : int - Number of iterations to perform\n  resultOffset : int - Offset value to add to return result\n\nReturns:\n  int - Sum of iterationCount + resultOffset\n\nSpecial Cases:\n  - Loop counter is decremented with DEC instruction; JNZ at 0x0382b2ba continues while non-zero\n  - Lookup table at 0x0385674c contains 4-byte entries indexed by byte values (0-255)\n  - Two parallel data streams processed simultaneously (pointers at 0x038532e0 and 0x038532e4)\n  - Source index pointers at 0x038532e8 and 0x038532ec advance independently\n  - Each destination write is duplicated to adjacent memory location (offset +4)\n  - EDI register fixed to 8 (0x8) as stride value for pointer advancement\n\nStructure Layout:\n  Global State Pointers:\n  Offset | Size | Name              | Type     | Description\n  -------|------|-------------------|----------|------------------------------------------\n  0x38532e0 | 4  | destPtr1          | void*    | First destination pointer (advanced by 8)\n  0x38532e4 | 4  | destPtr2          | void*    | Second destination pointer (advanced by 8)\n  0x38532e8 | 4  | srcIndexPtr1      | byte*    | First source index pointer (incremented by 1)\n  0x38532ec | 4  | srcIndexPtr2      | byte*    | Second source index pointer (incremented by 1)\n  0x385674c | 1024 | lookupTable      | uint[256] | 256-entry lookup table with 4-byte values",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bb371b5dcf86ffac445d42186118143d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bb371b5dcf86ffac445d42186118143d",
        "CFG": "ac9aad99255a025ce7e86ca738667c82",
        "PRO": "b95ef7378b970a6c4af27b17122f72d9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bb371b5dcf86ffac445d42186118143d"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_512206a0524f": {
      "addresses": {
        "LoD/PD2": "0x0382BEA0"
      },
      "rvas": {
        "LoD/PD2": "0xBEA0"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "_YUV_blit_32bpp@48",
      "signature": "undefined _YUV_blit_32bpp@48(uint param_1, uint param_2, int param_3, uint param_4, uint param_5, uint param_6, uint param_7, uint param_8, uint param_9, uint param_10, uint param_11, uint param_12)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:512206a0524f73d7cb6b767324468599",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "512206a0524f73d7cb6b767324468599",
        "CFG": null,
        "PRO": "4aa7612d48544b1683e2715d82b72345"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "512206a0524f73d7cb6b767324468599"
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "binkw32_MNE_a8b1898d0a64": {
      "addresses": {
        "LoD/PD2": "0x0382BEF0"
      },
      "rvas": {
        "LoD/PD2": "0xBEF0"
      },
      "sizes": {
        "LoD/PD2": 962
      },
      "name": "YuvBlitHelper",
      "signature": "void YuvBlitHelper(uint srcX, uint srcY, int srcPitch, uint destPitch, uint uvBaseOffset, uint uvHeight, uint destHeight, uint destWidth, uint srcWidth, uint uvPitch, uint srcLineSkip, uint formatFlags, int * pFormatType)",
      "calling_convention": "__cdecl",
      "comment": "YUV format blitting helper for pixel data conversion and rendering\\n\\nAlgorithm:\\n1. Load format flags and validate/adjust YUV format scaling (0x60000000: 4:2:0 half-height)\\n2. Read format type from pFormatType (2=2-byte aligned, 3=4-byte aligned)\\n3. Align source X/Y coordinates based on format requirements (subtract 3/6/9 pixels as needed)\\n4. Calculate base source buffer offset: srcX + (srcPitch * srcY) + (formatType * srcY)\\n5. Apply double-width format adjustments for formats 0x20000000 and 0x50000000\\n6. Call FUN_0382c2d0 for format-specific conversion setup\\n7. Calculate destination buffer offsets for luma and chroma planes\\n8. Compute UV plane offsets based on height/width and format flags (0x10000)\\n9. Process optional first row if height is odd using callback DAT_03858f7c\\n10. Calculate pitch alignment requirements (0-3 bytes) and chroma component masks\\n11. Update palette pointer DAT_03851ab4 if enabled\\n12. Main loop: iterate through remaining rows calling FUN_0382d000 to fetch pixels\\n13. Process fetched pixels through color conversion functions (DAT_03856340, DAT_03856b5c)\\n14. Advance all buffer pointers by calculated pitches after each iteration\\n15. Process final row if height boundaries don't match\\n16. Call FUN_0382c2c0 cleanup callback if DAT_0384f680 enabled and flag 0x40000 clear\\n\\nParameters:\\nsrcX: Source X coordinate (byte offset, may be misaligned)\\nsrcY: Source Y coordinate (row index in source image)\\nsrcPitch: Bytes per row in source image buffer\\ndestPitch: Bytes per row in destination image buffer\\nuvBaseOffset: Starting byte offset for UV chroma data\\nuvHeight: Height of UV plane (may be 1:1 or 1:2 vs luma)\\ndestHeight: Height of destination image in pixels\\ndestWidth: Width of destination image in pixels\\nsrcWidth: Width of source image in pixels\\nuvPitch: Bytes per row in UV chroma buffer\\nsrcLineSkip: Additional row skip in source (for interlacing)\\nformatFlags: Bit flags controlling format type and mode\\n  Bits 28-30: Format selector (0x60000000=4:2:0, 0x20000000/0x50000000=double-width)\\n  Bit 16: UV plane layout selector (0=Y then UV, 1=interleaved)\\n  Bit 18: Flag 0x40000 suppresses final callback when set\\npFormatType: Pointer to format type code (2 or 3 for alignment, modified during execution)\\n\\nReturns:\\n(void) - Updates global buffer offsets (DAT_038532e0, DAT_038532e4, etc.) and calls\\nrendering callbacks through function pointers\\n\\nSpecial Cases:\\n- Format type 2 (2-byte aligned): Adjusts X to 4-byte boundary if (X & 3) == 2\\n- Format type 3 (4-byte aligned): Tests X+1, X-2, X-1 modulo 4, adjusting Y and subtracting 3/6/9\\n- 4:2:0 format: Halves srcWidth, destHeight, adjusts vertical sampling\\n- Odd height: First row processed separately via callback, increment row counter\\n- Global data modified: DAT_038532e0, DAT_038532e4, DAT_038532e8, DAT_038532ec, DAT_038532f0, DAT_038532f4",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a8b1898d0a64cb0315f8c47c3af5498b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a8b1898d0a64cb0315f8c47c3af5498b",
        "CFG": "976c8d2932b9b87dabcefc705c348065",
        "PRO": "53a2ac81bb5385be0ace5cdcab5f718e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a8b1898d0a64cb0315f8c47c3af5498b"
      },
      "param_counts": {
        "LoD/PD2": 13
      }
    },
    "binkw32_MNE_d4cb972de0ac": {
      "addresses": {
        "LoD/PD2": "0x0382C2C0"
      },
      "rvas": {
        "LoD/PD2": "0xC2C0"
      },
      "sizes": {
        "LoD/PD2": 3
      },
      "name": "ClearMMXState",
      "signature": "void ClearMMXState(void)",
      "calling_convention": "__stdcall",
      "comment": "Clear MMX state after YUV color conversion operations\n\nAlgorithm:\n1. Execute EMMS instruction to clear all MMX registers and floating-point state\n\nReturns:\nvoid - Clears processor MMX state, enabling safe return to C code\n\nSpecial Cases:\n- Called as cleanup callback from YuvBlitHelper and FUN_03830ab0 when DAT_0384f680 != 0\n- Only invoked if 0x40000 format flag is NOT set in formatFlags parameter\n- CRITICAL: MMX state must be cleared before switching back to floating-point or general-purpose code\n- Execution of EMMS is required after MMX operations (e.g., PADDB, PADDW, PMULHW) to avoid FPU conflicts\n\nStructure Layout:\nNo parameters or local variables - pure register operation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d4cb972de0acf295942e7ba45ebb29f6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d4cb972de0acf295942e7ba45ebb29f6",
        "CFG": null,
        "PRO": "7e9a5b205daa1bf0dc51b4f20f91c62e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d4cb972de0acf295942e7ba45ebb29f6"
      }
    },
    "binkw32_MNE_95962302f71f": {
      "addresses": {
        "LoD/PD2": "0x0382C2D0"
      },
      "rvas": {
        "LoD/PD2": "0xC2D0"
      },
      "sizes": {
        "LoD/PD2": 2013
      },
      "name": "ConfigureYuvBlitParameters",
      "signature": "void ConfigureYuvBlitParameters(uint blitFlags, int * pPitchOrStride, int width, int height, int * pSurfaceFormat, int * pOutputOffset)",
      "calling_convention": "__cdecl",
      "comment": "Configures YUV blit parameters and manages color palette initialization.\n\nAlgorithm:\n1. Initialize frame counter to 0\n2. Store input pitch/stride value in global\n3. Check high bit flag (0x10000) to determine palette initialization path\n4. If high bit set: initialize mode to 1 and copy 8 palette lookup tables (0x100 dwords each) from source to destination buffers\n5. If high bit clear: check if mode was already initialized; if not, initialize to 0 and copy single palette table (0x800 dwords)\n6. Check surface flag (0x40000) to determine alternate rendering path\n7. Extract color mode from bits [30:28] to determine blit operation type\n8. For color mode 0x10000000 or 0x40000000: calculate buffer sizes, call helper, update pitch, calculate output offset\n9. For color mode 0x30000000 or 0x50000000: calculate negative buffer offset using doubled pitch\n10. For other modes: calculate buffer offset based on pitch and width\n11. Check alternate format flag (0x20000) to select between two different field offset sets\n12. Load color table field offsets and dimension parameters from structure\n13. Validate min <= max for selected dimensions\n14. Store final shift bit value in global (1 << max_dimension)\n15. Store mask value (shift - 1) in global\n\nParameters:\n- blitFlags (uint): Bit flags controlling rendering mode (bits 16-30)\n- pPitchOrStride (int*): Pointer to pitch/stride value, will be doubled\n- width (int): Surface width in pixels\n- height (int): Surface height in pixels\n- pSurfaceFormat (int*): Pointer to surface format structure with color tables\n- pOutputOffset (int*): Pointer to output buffer offset (calculated and stored)\n\nReturns: void\n\nSpecial Cases:\n- Magic value 0x100: Palette table copy count (256 dwords per table)\n- Magic value 0x800: Full palette size when clearing mode\n- Multiple conditional paths based on bit flags create distinct code paths\n- Palette initialization only occurs if mode state changes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:95962302f71f14243137ff3100c3ee5f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "95962302f71f14243137ff3100c3ee5f",
        "CFG": "c9a456ba29e8cd7f5e8a64a2cf75660f",
        "PRO": "9ae0f00e37471092998bc8058765c552"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "95962302f71f14243137ff3100c3ee5f"
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "binkw32_API_320a44a3b803": {
      "addresses": {
        "LoD/PD2": "0x0382CAB0"
      },
      "rvas": {
        "LoD/PD2": "0xCAB0"
      },
      "sizes": {
        "LoD/PD2": 93
      },
      "name": "AllocateYuvBuffer",
      "signature": "void AllocateYuvBuffer(int requiredSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates or reuses a YUV buffer with size constraints.\n\nAlgorithm:\n1. Align required size to 32-byte boundary: (requiredSize + 0x1F) & 0xFFFFFFE0\n2. Calculate total allocation size as 2x aligned size (for Y and UV planes)\n3. Check if current buffer is large enough (DAT_0385c810 >= allocSize)\n4. If insufficient: free existing buffer (DAT_0385c814), allocate new buffer via radmalloc\n5. Update buffer capacity (DAT_0385c810), buffer pointer (DAT_0385c814)\n6. Set split point to buffer start + aligned size (DAT_0385c818)\n\nParameters:\nrequiredSize (int): Requested size in bytes for Y plane\n\nReturns:\nvoid - Updates global buffer pointers and state\n\nGlobal Variables:\nDAT_0385c810 (DWORD): Current allocated buffer size\nDAT_0385c814 (void*): Pointer to allocated buffer memory\nDAT_0385c818 (void*): Pointer to UV plane (buffer + alignedSize)\n\nSpecial Cases:\n- Size is aligned to 32-byte boundary for cache efficiency\n- Allocation size is 2x aligned size (Y plane + UV plane)\n- Existing buffer is freed only if insufficient for new size\n- 0x1F mask value = 31, used with +0x1F for 32-byte alignment",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:320a44a3b8034bd3b246893d2e30bc9d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "320a44a3b8034bd3b246893d2e30bc9d",
        "MNE": "470a4fa36be53ee478bf1f3a6d746fe2",
        "CFG": "2905a5f71956f3ea8f8249f7e990e9c6",
        "PRO": "774eef3a2193c12c7a5331bb63fb31ca"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "470a4fa36be53ee478bf1f3a6d746fe2"
      },
      "api_calls": {
        "LoD/PD2": [
          "_radfree@4",
          "_radmalloc@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_2e8babe0f59f": {
      "addresses": {
        "LoD/PD2": "0x0382CB10"
      },
      "rvas": {
        "LoD/PD2": "0xCB10"
      },
      "sizes": {
        "LoD/PD2": 145
      },
      "name": "ComputeDimensionShift",
      "signature": "void ComputeDimensionShift(uint * pDimensionValue, int dimensionHeight)",
      "calling_convention": "__cdecl",
      "comment": "Validates and computes rendering dimension shift values for YUV blit operations.\\n\\nAlgorithm:\\n1. Check if rendering mode is enabled (DAT_0385c80c == 1)\\n2. Load dimension value from pointer parameter\\n3. Validate dimension is odd (bit 0 set) AND not exceeds 0x2000\\n4. If validation fails: set error handlers and store error code (0x82)\\n5. If validation passes: compute new dimension as (value + height*4)\\n6. Check bit 1 of computed dimension to select handler pair\\n7. If bit 1 set: use alternate rendering handlers (0x382cd10, 0x382cdd0)\\n8. If bit 1 clear: use normal rendering handlers (0x382cbb0, 0x382cc60)\\n9. If mode disabled: use fallback rendering handlers (0x382ce90, 0x382cfc0)\\n\\nParameters:\\n- pDimensionValue (uint*): Pointer to dimension value, will be updated with computed shift\\n- dimensionHeight (int): Height value used to compute dimension shift (multiplied by 4)\\n\\nReturns: void\\n\\nSpecial Cases:\\n- Magic value 0x82: Error code stored when validation fails\\n- Magic value 0x2000: Maximum valid dimension threshold\\n- Bit operations: bit 0 (odd check), bit 1 (handler selection)\\n- Global state: DAT_0385c80c enables/disables mode, affects handler initialization",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2e8babe0f59f307a579e33f2393270b9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2e8babe0f59f307a579e33f2393270b9",
        "CFG": "26548ac02979c119983816c26e2f0026",
        "PRO": "9485001954d74355f246a39258d54566"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2e8babe0f59f307a579e33f2393270b9"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_66278f4839da": {
      "addresses": {
        "LoD/PD2": "0x0382CE90"
      },
      "rvas": {
        "LoD/PD2": "0xCE90"
      },
      "sizes": {
        "LoD/PD2": 64
      },
      "name": "MeasureCallbackExecutionTime",
      "signature": "void MeasureCallbackExecutionTime(void * pCallbackContext)",
      "calling_convention": "__stdcall",
      "comment": "Measures the execution time of a callback function using RDTSC.\n\nAlgorithm:\n1. Allocate local variables for timer values on the stack\n2. Capture initial RDTSC value (high-resolution timestamp)\n3. Call registered callback function with provided context parameter\n4. Capture final RDTSC value\n5. Calculate elapsed clock cycles (final - initial)\n6. Pass elapsed time to FUN_0382ced0 for processing/logging\n\nParameters:\n- pCallbackContext (void*): Opaque context pointer passed to callback function\n\nReturns:\n- void: No return value; timing is passed to FUN_0382ced0\n\nSpecial Cases:\n- RDTSC values are 64-bit but only low 32-bits are used for difference\n- Callback function pointer is stored at constant address 0x03856b50\n- Caller cleans stack (stdcall convention)\n\nTiming Analysis:\n- Uses RDTSC for high-precision CPU cycle counting\n- Measures only callback execution; function overhead not included\n- Useful for profiling performance-critical callback functions",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:66278f4839da28ded1eaf5e21045b2e5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "66278f4839da28ded1eaf5e21045b2e5",
        "CFG": null,
        "PRO": "8c738c6cf4769bab23cdde57147be240"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "66278f4839da28ded1eaf5e21045b2e5"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_bd480b198928": {
      "addresses": {
        "LoD/PD2": "0x0382CED0"
      },
      "rvas": {
        "LoD/PD2": "0xCED0"
      },
      "sizes": {
        "LoD/PD2": 230
      },
      "name": "ProcessElapsedCycles",
      "signature": "void ProcessElapsedCycles(uint elapsedCycles)",
      "calling_convention": "__cdecl",
      "comment": "Processes elapsed CPU cycles from RDTSC timing measurements.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bd480b198928a9bc8a7b26d75a6b65d7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bd480b198928a9bc8a7b26d75a6b65d7",
        "CFG": "eec9cbedd5ea7f97847323d74f1b9dd7",
        "PRO": "ac0728b2619e1468f756d5aa95ebc08f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bd480b198928a9bc8a7b26d75a6b65d7"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_ADDR_0382CFC0": {
      "addresses": {
        "LoD/PD2": "0x0382CFC0"
      },
      "rvas": {
        "LoD/PD2": "0xCFC0"
      },
      "sizes": {
        "LoD/PD2": 64
      },
      "name": "MeasureCallbackExecutionTime",
      "signature": "void MeasureCallbackExecutionTime(void * pCallbackContext)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void MeasureCallbackExecutionTime(void *pCallbackContext)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:66278f4839da28ded1eaf5e21045b2e5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "66278f4839da28ded1eaf5e21045b2e5",
        "CFG": null,
        "PRO": "8c738c6cf4769bab23cdde57147be240"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "66278f4839da28ded1eaf5e21045b2e5"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_d4c428924d7f": {
      "addresses": {
        "LoD/PD2": "0x0382D000"
      },
      "rvas": {
        "LoD/PD2": "0xD000"
      },
      "sizes": {
        "LoD/PD2": 77
      },
      "name": "GetYuvBlitTimestamp",
      "signature": "ulonglong GetYuvBlitTimestamp(uint param1, uint param2, int lastFrameNumber, int currentFrameNumber)",
      "calling_convention": "__fastcall",
      "comment": "YUV Blit Timestamp Synchronization Function\\n\\nAlgorithm:\\n1. Load current timing flags from global timing state\\n2. Check if frame skipping is disabled and frame numbers differ\\n3. If enabled, verify timing flag bit 0 is clear (not already executing)\\n4. If clear, set flag bit 2 and read CPU timestamp counter for timing sync\\n5. Check if flag bit 1 is set (frame skip indicator)\\n6. Return either current or last frame number based on synchronization status\\n\\nParameters:\\nparam1: First ESD/timing value (passed in ECX via __fastcall)\\nparam2: Second ESD/timing value (passed in EDX via __fastcall)\\nlastFrameNumber: Previous frame number for video frame tracking (stack param)\\ncurrentFrameNumber: Current frame number being processed (stack param)\\n\\nReturns:\\n64-bit value combining timing state: upper 32 bits contain updated param2, lower 32 bits contain frame number selector\\n\\nSpecial Cases:\\n- Global DAT_03856348 controls frame skip behavior when set to non-zero\\n- DAT_0385c80c flag (1 = enabled) gates timing update logic\\n- Timing flags stored at DAT_03851ab4: bit 0 = timing active, bit 1 = frame skip, bit 2 = timestamp captured\\n- CPU timestamp stored in DAT_03856b4c for synchronization\\n- Function returns last frame number when flag bit 1 is set, current frame otherwise",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d4c428924d7fef684ebc213f4fc0eed1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d4c428924d7fef684ebc213f4fc0eed1",
        "CFG": "67b598c16f9fc8abdd20beaf44e45be0",
        "PRO": "4d53901063ca37b765b99d85c6382342"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d4c428924d7fef684ebc213f4fc0eed1"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_f1b0856acf5d": {
      "addresses": {
        "LoD/PD2": "0x0382D050"
      },
      "rvas": {
        "LoD/PD2": "0xD050"
      },
      "sizes": {
        "LoD/PD2": 167
      },
      "name": "UpdateFrameRateFromTiming",
      "signature": "void UpdateFrameRateFromTiming(void)",
      "calling_convention": "__stdcall",
      "comment": "Adjusts frame rate timing level based on elapsed CPU cycles and configuration flags.\n\nAlgorithm:\n1. Load configuration flags from global state (bits 0-15 contain flags and level, bits 8-15 contain threshold)\n2. Check if timing measurement is enabled (bit 2 set = 0x4)\n3. If timing disabled, exit immediately\n4. Read CPU timestamp counter (RDTSC) to get current cycle count\n5. Calculate elapsed cycles by subtracting previous timestamp from current\n6. Store elapsed cycles back to timing storage location\n7. Check if level mode adjustment is enabled (bit 1 set = 0x2)\n8. If level mode disabled, encode elapsed time into upper byte and update config flags with bit 1 set\n9. If level mode enabled, extract current level from bits 3-7 (5-bit field)\n10. Extract threshold value from bits 8-15 and compare with elapsed cycles\n11. If elapsed > threshold (underperforming): decrement level by 1 (clamped at 0)\n12. If elapsed <= threshold (performing well): increment level by 1 (clamped at 31)\n13. Encode new level back into bits 3-7 of config flags\n14. Write updated config to global state\n\nParameters:\nNone. Uses global state:\n- DAT_03851ab4: Pointer to config flags (bits: 0=unknown, 1=level_mode, 2=timing_enabled, 3-7=level, 8-15=threshold)\n- DAT_03856b4c: Storage for elapsed CPU cycles\n\nReturns:\nvoid. Updates global config state based on timing measurements.\n\nSpecial Cases:\n- Level 0: Represents idle/slowest frame rate; cannot be decremented further\n- Level 31 (0x1F): Represents maximum frame rate; when exceeded, resets config to 1\n- Level transitions: Adjusted by \u00b11 based on performance relative to threshold\n- Bit packing: Config uses 16-bit value with multiple fields; bit masking used to preserve other flags\n- Threshold encoding: High byte contains performance threshold value; low byte contains level/flag bits",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f1b0856acf5d358573d7e9dbd470c8df",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f1b0856acf5d358573d7e9dbd470c8df",
        "CFG": "3ba11ddfead1377e35d1cda9c88fdc26",
        "PRO": "24946692be46a95caeed242c940336ea"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f1b0856acf5d358573d7e9dbd470c8df"
      }
    },
    "binkw32_MNE_5045c13907c1": {
      "addresses": {
        "LoD/PD2": "0x0382D2A0"
      },
      "rvas": {
        "LoD/PD2": "0xD2A0"
      },
      "sizes": {
        "LoD/PD2": 150
      },
      "name": "ProcessTableDataWithDualStreams",
      "signature": "int ProcessTableDataWithDualStreams(int iterationCount, int offset)",
      "calling_convention": "__cdecl",
      "comment": "Processes table data through dual parallel streams with lookup table transformation.\n\nAlgorithm:\n1. Initialize loop counter from iterationCount parameter\n2. Loop for iterationCount iterations:\n   a. Read byte from first source pointer (DAT_038532e8)\n   b. Increment first source pointer\n   c. Look up value in table at 0x385674c using byte as index\n   d. Transform by duplicating to low and high bytes (value | (value << 8))\n   e. Write transformed 4-byte value to first output pointer (DAT_038532e0)\n   f. Write low word (first 2 bytes) to offset +4 in output buffer\n   g. Read byte from second source pointer (DAT_038532ec)\n   h. Increment second source pointer\n   i. Look up and transform using same table\n   j. Write to second output pointer (DAT_038532e4) with offset +4 write\n   k. Advance both output pointers by 6 bytes\n   l. Decrement loop counter\n3. Return sum of input parameters (iterationCount + offset)\n\nParameters:\n  iterationCount (int): Number of iterations to process in main loop\n  offset (int): Value added to return value; semantic purpose varies by caller\n\nReturns:\n  int: Sum of input parameters (iterationCount + offset)\n\nSpecial Cases:\n  - Magic value 6: Stride/step size for advancing output pointers between iterations\n  - Dual processing: Two independent data streams processed in parallel within same loop\n  - Table lookup: Uses byte index into global table at 0x385674c (256-byte lookup table)\n  - Byte duplication: Transforms single byte to 16-bit pattern for extended data width",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5045c13907c17820d5a96145cb44c188",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5045c13907c17820d5a96145cb44c188",
        "CFG": "79a7345a55f92761cfc038fd48ef9eda",
        "PRO": "d3b7c4f05c8574ae41caef7e2c1744ed"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5045c13907c17820d5a96145cb44c188"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_26dd36043da0": {
      "addresses": {
        "LoD/PD2": "0x0382D4E0"
      },
      "rvas": {
        "LoD/PD2": "0xD4E0"
      },
      "sizes": {
        "LoD/PD2": 138
      },
      "name": "ProcessDualLookupTableEntries",
      "signature": "int ProcessDualLookupTableEntries(int entryCount, int offsetValue)",
      "calling_convention": "__cdecl",
      "comment": "Processes entries from dual lookup tables using index sequences.\n\nAlgorithm:\n1. Initialize loop counter from entryCount parameter\n2. Load first index byte from global source pointer (0x038532e8)\n3. Increment source pointer and look up value in table at 0x385674c\n4. Write 2-byte word and low byte to first output buffer (0x038532e0)\n5. Load second index byte from global source pointer (0x038532ec)\n6. Increment source pointer and look up value in table at 0x385674c\n7. Write 2-byte word and low byte to second output buffer (0x038532e4)\n8. Advance both output pointers by 3 bytes (stride)\n9. Decrement counter and repeat until all entries processed\n10. Return sum of entryCount and offsetValue parameters\n\nParameters:\nentryCount (int): Number of entries to process from index sequences\noffsetValue (int): Offset value added to return result\n\nReturns:\nint: Sum of entryCount and offsetValue (entryCount + offsetValue)\n\nSpecial Cases:\n- Uses global state pointers for index and output buffer management\n- Table lookup at 0x385674c indexed by byte * 4 (word stride)\n- Each output entry is 3 bytes with word at offset 0 and byte at offset 2\n- If entryCount is 0, loop does not execute and returns offsetValue\n\nStructure Layout:\nOutput Buffer Entry (3 bytes):\n  Offset  Size  Field       Type      Description\n  0x00    2     word_value  word      Lookup table word value\n  0x02    1     byte_value  byte      Low byte of lookup value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:26dd36043da0cff4c91026ae63a6efc0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "26dd36043da0cff4c91026ae63a6efc0",
        "CFG": "47d49df4522ed740497b07eab08cf39b",
        "PRO": "73bfb064b99333b6e06581a3c8bb8165"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "26dd36043da0cff4c91026ae63a6efc0"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_ADDR_0382E1D0": {
      "addresses": {
        "LoD/PD2": "0x0382E1D0"
      },
      "rvas": {
        "LoD/PD2": "0xE1D0"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "_YUV_blit_24bpp@48",
      "signature": "undefined _YUV_blit_24bpp@48(uint param_1, uint param_2, int param_3, uint param_4, uint param_5, uint param_6, uint param_7, uint param_8, uint param_9, uint param_10, uint param_11, uint param_12)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:512206a0524f73d7cb6b767324468599",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "512206a0524f73d7cb6b767324468599",
        "CFG": null,
        "PRO": "eb5f6ebd5d95d77cc7748b54b0bc6484"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "512206a0524f73d7cb6b767324468599"
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "binkw32_MNE_0e65e1fb8532": {
      "addresses": {
        "LoD/PD2": "0x0382E370"
      },
      "rvas": {
        "LoD/PD2": "0xE370"
      },
      "sizes": {
        "LoD/PD2": 140
      },
      "name": "TransformAndCopyLookupTable",
      "signature": "int TransformAndCopyLookupTable(int itemCount, int sumValue)",
      "calling_convention": "__cdecl",
      "comment": "Transform and copy data from lookup table to output buffers\nReads indices from two global source pointers, uses them to look up word values in a lookup table, and writes the results to two global output buffers. Each iteration processes indices for two parallel data streams.\n\nAlgorithm:\n1. Initialize loop counter from itemCount parameter\n2. Loop for itemCount iterations:\n   a. Read index from first source pointer (DAT_038532e8), increment source pointer\n   b. Look up word value at offset [DAT_0385634c + index]\n   c. Write lookup value to first output buffer (DAT_038532e0)\n   d. Write same value to offset +2 in first output buffer\n   e. Read index from second source pointer (DAT_038532ec), increment source pointer\n   f. Look up word value at offset [DAT_0385634c + index]\n   g. Write lookup value to second output buffer (DAT_038532e4)\n   h. Write same value to offset +2 in second output buffer\n   i. Advance first output buffer pointer by 4 bytes\n   j. Advance second output buffer pointer by 4 bytes\n   k. Decrement loop counter, continue if not zero\n3. Return sum of itemCount and sumValue parameters\n\nParameters:\n- itemCount (int): Number of transformation iterations to perform\n- sumValue (int): Value to add to itemCount for return value\n\nReturns:\n- int: Sum of itemCount + sumValue (represents total items processed plus additional offset)\n\nSpecial Cases:\n- itemCount=0 would result in no loop iterations, returning sumValue unchanged\n- Lookup table is accessed with 4-byte stride (index*4) to retrieve word values\n- Both output streams write duplicate values at consecutive offsets (offset 0 and offset +2)\n- Global pointers are modified during execution; function has side effects on global state\n\nGlobal Data References:\n- DAT_038532e8: Source pointer for first index stream (incremented per iteration)\n- DAT_038532ec: Source pointer for second index stream (incremented per iteration)  \n- DAT_038532e0: Output pointer for first data stream (incremented 4 bytes per iteration)\n- DAT_038532e4: Output pointer for second data stream (incremented 4 bytes per iteration)\n- DAT_0385634c: Lookup table base address (word values indexed by byte offsets)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0e65e1fb8532f9049d3b376601889169",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0e65e1fb8532f9049d3b376601889169",
        "CFG": "1ec639e3efbd134193ea8af7eddac8d0",
        "PRO": "075503457a49d513409619cf73033b45"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0e65e1fb8532f9049d3b376601889169"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_91a5e847d365": {
      "addresses": {
        "LoD/PD2": "0x0382E590"
      },
      "rvas": {
        "LoD/PD2": "0xE590"
      },
      "sizes": {
        "LoD/PD2": 114
      },
      "name": "CopyInterleavedTableEntries",
      "signature": "int CopyInterleavedTableEntries(int count, int additionalValue)",
      "calling_convention": "__cdecl",
      "comment": "Copies interleaved entries from a lookup table to two separate output buffers.\n\nAlgorithm:\n1. Initialize loop counter with parameter count\n2. Loop for count iterations:\n   a. Read byte index from source pointer at DAT_038532e8\n   b. Increment source pointer at DAT_038532e8\n   c. Lookup word value at DAT_0385634c[index*4]\n   d. Write word value to destination at DAT_038532e0\n   e. Increment destination pointer at DAT_038532e0\n   f. Repeat (a-e) for second table using DAT_038532ec source and DAT_038532e4 destination\n   g. Increment both destinations by 2 (EDI register)\n   h. Decrement loop counter\n3. Return: count + additionalValue\n\nParameters:\n  count (ESI): Number of iterations to perform\n  additionalValue (stack): Value to add to count for return\n\nReturns:\n  int: count + additionalValue\n\nSpecial Cases:\n- Accesses global state pointers for dual-channel table reading\n- Performs table lookup with index*4 stride (dword-sized entries)\n- Reads 16-bit values (word) from table\n- Writes 16-bit values to two separate destinations in lockstep",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:91a5e847d365e396cb4038029fe26f37",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "91a5e847d365e396cb4038029fe26f37",
        "CFG": "a99ce5cedb9ebbfcbc1dfb8ad73c4156",
        "PRO": "af495b37950e6b85679f6c2b971738da"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "91a5e847d365e396cb4038029fe26f37"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_ADDR_0382EF60": {
      "addresses": {
        "LoD/PD2": "0x0382EF60"
      },
      "rvas": {
        "LoD/PD2": "0xEF60"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "_YUV_blit_16bpp@48",
      "signature": "undefined _YUV_blit_16bpp@48(uint param_1, uint param_2, int param_3, uint param_4, uint param_5, uint param_6, uint param_7, uint param_8, uint param_9, uint param_10, uint param_11, uint param_12)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:512206a0524f73d7cb6b767324468599",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "512206a0524f73d7cb6b767324468599",
        "CFG": null,
        "PRO": "b5c3a1381e50335b52b6bd74760d3531"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "512206a0524f73d7cb6b767324468599"
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "binkw32_MNE_e8938b232dc4": {
      "addresses": {
        "LoD/PD2": "0x0382F1D0"
      },
      "rvas": {
        "LoD/PD2": "0xF1D0"
      },
      "sizes": {
        "LoD/PD2": 205
      },
      "name": "ExpandByteToWidthWithAlpha",
      "signature": "int ExpandByteToWidthWithAlpha(int byteCount, int addValue)",
      "calling_convention": "__cdecl",
      "comment": "Expands single bytes into duplicated 16-bit values with alpha channel mask.\n\nAlgorithm:\n1. Initialize loop counter from byteCount, decrement by 2 each iteration\n2. For each iteration, process two pairs of byte values:\n   - Load byte from source pointer at DAT_038532e8\n   - Duplicate to form (byte << 16) | byte pattern\n   - Apply alpha mask 0x80008000 via OR operation\n   - Write expanded value to output buffer at DAT_038532e0\n   - Increment source and output pointers by 2\n3. Repeat steps for second pair using DAT_038532ec and DAT_038532e4\n4. Advance both output buffer pointers by 8 bytes (2 dwords per iteration)\n5. Continue loop while remainingCount > 0\n6. Return sum of input parameters (byteCount + addValue)\n\nParameters:\n  byteCount: Number of bytes to process (decremented by 2 per iteration)\n  addValue: Value added to byteCount for return value calculation\n\nReturns:\n  int: Sum of byteCount and addValue\n\nSpecial Cases:\n  - Magic value 0x80008000: Alpha channel mask (high bit set in each 16-bit half)\n  - Byte duplication: Each byte source is duplicated within 16-bit field\n  - Two parallel streams: Processes two independent byte sequences simultaneously\n  - Source/destination via globals: Uses global pointers DAT_038532e8, DAT_038532e0, DAT_038532ec, DAT_038532e4",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e8938b232dc428549f2aa90498091d98",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e8938b232dc428549f2aa90498091d98",
        "CFG": "a993af83fa4236bf6762e2f9d6102cc5",
        "PRO": "36296e117c5233a3a2aa23797e07fd91"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e8938b232dc428549f2aa90498091d98"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_dcbfd1c41ddd": {
      "addresses": {
        "LoD/PD2": "0x0382F560"
      },
      "rvas": {
        "LoD/PD2": "0xF560"
      },
      "sizes": {
        "LoD/PD2": 307
      },
      "name": "ProcessDualPixelBuffer",
      "signature": "int ProcessDualPixelBuffer(int pixelCount, int resultOffset)",
      "calling_convention": "__cdecl",
      "comment": "Processes dual pixel buffers with color blending and dual output\\nThis function performs synchronized pixel processing on two separate source buffers,\\napplying color blending operations and writing results to both primary and secondary\\noutput buffers. Used for advanced image rendering with dual-buffer synchronization.\\n\\nAlgorithm:\\n1. Initialize loop counter by subtracting 2 from pixelCount\\n2. Load one byte from each of three source pointers (src0, src1, src2)\\n3. Combine source bytes into 32-bit pixel value via bit-shifting and ORing\\n4. Calculate color blend mask using (pixel & 0xff00ff) << 8\\n5. Generate blended color from secondary source with mask application\\n6. Write combined pixel value to primary output buffer at current offset\\n7. Write blended color to primary output buffer + 4 bytes\\n8. Write same values to secondary output buffer using DAT_0385331c base pointer\\n9. Load and process secondary source bytes with similar blending logic\\n10. Increment all source pointers by 2 (process 2 bytes per iteration)\\n11. Increment output pointers by 8 (process 8 bytes per iteration)\\n12. Decrement loop counter by 2 and continue if counter > 0\\n13. Return sum of pixelCount and resultOffset\\n\\nParameters:\\npixelCount (int, EBP [ESP+8]) - Iteration count, decremented by 2 per loop\\nresultOffset (int, ECX [ESP+4]) - Output offset value, summed with pixelCount\\n\\nReturns:\\nint - Sum of pixelCount + resultOffset, returned in EAX\\n\\nSpecial Cases:\\n- Negative/zero pixelCount: Loop does not execute, immediate return\\n- Bit masks (0xff00ff) used for color channel selection\\n- Dual output via offset indexing into secondary buffer (DAT_0385331c)\\n- All pointers are global and pre-initialized before function call\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:dcbfd1c41ddd2aaf0aedbc35b0095aeb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "dcbfd1c41ddd2aaf0aedbc35b0095aeb",
        "CFG": "e2bfa9d93258b5cddcca01353a935a20",
        "PRO": "b2618b24c832d470805b7958ff50e5bb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "dcbfd1c41ddd2aaf0aedbc35b0095aeb"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_70c8495648c3": {
      "addresses": {
        "LoD/PD2": "0x0382F740"
      },
      "rvas": {
        "LoD/PD2": "0xF740"
      },
      "sizes": {
        "LoD/PD2": 249
      },
      "name": "ConvertPixelFormatWithBlend",
      "signature": "int ConvertPixelFormatWithBlend(int pixelCount, int offset)",
      "calling_convention": "__cdecl",
      "comment": "Converts pixel format by interleaving color channels with bit manipulation.\\n\\nAlgorithm:\\n1. Initialize loop counter by subtracting 2 from pixelCount parameter\\n2. Loop while counter > 0:\\n   a. Load bytes from three source pointers (DAT_038532e8, DAT_038532f4, DAT_038532f0)\\n   b. Combine bytes into 24-bit pixel value via shifts and ORs\\n   c. Extract and mask color channels using 0xff00ff mask (G and B channels)\\n   d. Distribute masked channels across output buffer with bit shifts\\n   e. Process second byte from source pointer (DAT_038532e8 + 1)\\n   f. Repeat pattern for two output buffers (DAT_038532e0 and DAT_038532e4)\\n   g. Advance all pointers and output buffer pointers by fixed amounts\\n   h. Decrement loop counter by 2\\n3. Return sum of input parameters (pixelCount + offset)\\n\\nParameters:\\npixelCount (int): Number of pixels to process; used as loop counter (decremented by 2 per iteration)\\noffset (int): Offset value added to pixelCount in return value\\n\\nReturns:\\nint: Sum of pixelCount and offset parameters\\n\\nSpecial Cases:\\n- If pixelCount \\u2264 0, loop doesn't execute but returns pixelCount + offset\\n- Color mask 0xff00ff extracts green and blue channels, preserves alignment\\n- Bit shift 0x10 (16 bits) positions color components in 32-bit output\\n- Function processes 2 pixels per iteration (hence decrement by 2)\\n- Global pointers are advanced internally; caller must initialize them before invocation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:70c8495648c376804f0b7cc1fe2e35a1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "70c8495648c376804f0b7cc1fe2e35a1",
        "CFG": "6b1c5ae88892b84e999104ec691c99dc",
        "PRO": "1982a10535e065667a8d7fdd5942e8d1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "70c8495648c376804f0b7cc1fe2e35a1"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_c58cd330e598": {
      "addresses": {
        "LoD/PD2": "0x0382F8C0"
      },
      "rvas": {
        "LoD/PD2": "0xF8C0"
      },
      "sizes": {
        "LoD/PD2": 212
      },
      "name": "TransformDataBlock",
      "signature": "int TransformDataBlock(int blockCount, int baseOffset)",
      "calling_convention": "__cdecl",
      "comment": "Transforms a block of data by combining bytes from multiple source buffers.\n\nAlgorithm:\n1. Initialize loop counter by subtracting 2 from blockCount\n2. Load source pointers for three byte streams (DAT_038532f4, DAT_038532f0, DAT_038532e8)\n3. Load output buffer pointers (DAT_038532e0, DAT_038532e4)\n4. Load secondary output offset pointer (DAT_0385331c)\n5. Loop while remainingBlocks > 0:\n   a. Read three bytes from source streams at current positions\n   b. Combine bytes with bit shifts: byte[0] | (byte[1] << 8) | (byte[2] << 16)\n   c. Write first transformed dword to primary output buffer\n   d. Write first transformed dword to secondary offset buffer\n   e. Read two more bytes from another source stream\n   f. Create second output word with masked/shifted combination\n   g. Write second output word to both buffers\n   h. Increment output buffer pointers by 4 bytes each\n   i. Decrement remaining block counter\n6. Return sum of baseOffset and blockCount\n\nParameters:\n  blockCount: int - Number of blocks to process (2-byte units)\n  baseOffset: int - Base offset value to add to return result\n\nReturns:\n  int - Sum of baseOffset + blockCount (used as result indicator)\n\nSpecial Cases:\n  - Function uses global state pointers for source/destination buffers\n  - Loop processes exactly (blockCount - 2) iterations\n  - Output is written to two parallel buffers (primary and offset-based)\n  - Byte ordering follows specific bit-shift pattern for data transformation\n\nStructure Layout:\n  Output Format (8 bytes per iteration):\n  Offset  Size  Field\n  0       4     First transformed dword\n  4       4     Second transformed dword",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c58cd330e598080efbebd364b324fdca",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c58cd330e598080efbebd364b324fdca",
        "CFG": "c4e9ee79836eded9bb4b79e6b6ec8cee",
        "PRO": "31ca9459358f4ac9b83e40f38ed5d50f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c58cd330e598080efbebd364b324fdca"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_318b70d6d439": {
      "addresses": {
        "LoD/PD2": "0x0382FA20"
      },
      "rvas": {
        "LoD/PD2": "0xFA20"
      },
      "sizes": {
        "LoD/PD2": 183
      },
      "name": "ProcessCryptographicRound",
      "signature": "int ProcessCryptographicRound(int numRounds, int returnValue)",
      "calling_convention": "__cdecl",
      "comment": "Processes cryptographic transformation round through byte manipulation and bit shifting.\n\nAlgorithm:\n1. Initialize counter from numRounds parameter\n2. Loop while counter > 0:\n   a. Decrement counter by 2\n   b. Read and concatenate bytes from source pointers (DAT_038532f4, DAT_038532e8, DAT_038532f0)\n   c. Combine bytes to form 24-bit transformed word via CONCAT21/CONCAT11\n   d. Advance source pointer (DAT_038532e8) by 2 bytes\n   e. Write concatenated result to output (DAT_038532e0)\n   f. Read bytes from second input buffer (DAT_038532ec)\n   g. Perform bit shifting: shift high byte left 16, shift middle word left 8\n   h. Combine shifted values via OR operations\n   i. Write result to second output buffer (DAT_038532e4)\n   j. Increment output pointers by 4 bytes\n3. Return sum of input count and return value\n\nParameters:\n  numRounds: Number of transformation iterations (decremented by 2 per loop)\n  returnValue: Value to add to numRounds and return as function result\n\nReturns:\n  int: Sum of returnValue and numRounds (returnValue + numRounds)\n\nSpecial Cases:\n  - Counter decrements by 2 each iteration, effectively halving the iteration count\n  - Function operates on global data buffers via multiple pointer variables\n  - Loop continues while counter > 0, processing exactly (numRounds / 2) complete rounds",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:318b70d6d43949299437c73a152ea9c6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "318b70d6d43949299437c73a152ea9c6",
        "CFG": "c6efb996ba98e455318ff833a2c7957e",
        "PRO": "265bbbaff379d658ae358197f46a4968"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "318b70d6d43949299437c73a152ea9c6"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_9ed9704ca96c": {
      "addresses": {
        "LoD/PD2": "0x0382FAE0"
      },
      "rvas": {
        "LoD/PD2": "0xFAE0"
      },
      "sizes": {
        "LoD/PD2": 130
      },
      "name": "_YUV_blit_YUY2@48",
      "signature": "undefined _YUV_blit_YUY2@48(uint param_1, uint param_2, int param_3, uint param_4, uint param_5, uint param_6, uint param_7, uint param_8, uint param_9, uint param_10, uint param_11, uint param_12)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9ed9704ca96cf7275d6354269c1858eb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9ed9704ca96cf7275d6354269c1858eb",
        "CFG": "336a2b3e7597c88bd3b0149498cccd97",
        "PRO": "d62a3ba6e17bb63145005c4853bb8d8b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9ed9704ca96cf7275d6354269c1858eb"
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "binkw32_MNE_2355c45e8b92": {
      "addresses": {
        "LoD/PD2": "0x0382FDB0"
      },
      "rvas": {
        "LoD/PD2": "0xFDB0"
      },
      "sizes": {
        "LoD/PD2": 217
      },
      "name": "ExpandPixelsToColor32",
      "signature": "int ExpandPixelsToColor32(int pixelCount, int offset)",
      "calling_convention": "__cdecl",
      "comment": "Expands 8-bit pixel values from source buffers to 32-bit color format (RGB with alpha channel 0x80) and writes to destination buffers.\\n\\nAlgorithm:\\n1. Initialize loop counter to pixelCount - 2 (process 2 pixels per iteration)\\n2. Load source byte from DAT_038532e8, duplicate to 32-bit value\\n3. Shift left 16 bits, OR with original byte, shift left 8 bits, OR with 0x800080\\n4. Write result to destination buffer DAT_038532e0\\n5. Load next source byte (offset +1), repeat duplication and write to DAT_038532e0[+4]\\n6. Increment source buffer pointer DAT_038532e8 by 2\\n7. Repeat steps 2-5 for second source buffer DAT_038532ec \\u2192 DAT_038532e4\\n8. Increment both destination pointers by 8 (2 DWORDs)\\n9. Decrement loop counter by 2 and branch if counter > 0\\n10. Calculate return value as pixelCount + offset\\n\\nParameters:\\n- pixelCount: Number of pixels to process (processed as pairs in loop)\\n- offset: Value added to pixelCount for return value\\n\\nReturns:\\n- int: Sum of pixelCount and offset\\n\\nSpecial Cases:\\n- Magic number 0x800080: Creates 32-bit color with format 0xAA_RR_GG_BB where AA=0x80\\n- Loop processes 2 source bytes per iteration \\u2192 8 destination bytes (4 per source byte)\\n- Bit manipulation pattern (value << 16 | value) << 8 | 0x800080 duplicates 8-bit value to RR and GG channels, sets BB=0x00, AA=0x80",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2355c45e8b92e7ad55b52977f56cb34d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2355c45e8b92e7ad55b52977f56cb34d",
        "CFG": "e8cf67d206ddcb445da6431dbd1e9087",
        "PRO": "4a9cf3541b4f3baf3e06b30d8f38de5f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2355c45e8b92e7ad55b52977f56cb34d"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_21d6d963cebc": {
      "addresses": {
        "LoD/PD2": "0x03830190"
      },
      "rvas": {
        "LoD/PD2": "0x10190"
      },
      "sizes": {
        "LoD/PD2": 319
      },
      "name": "ProcessSmackerVideoDataChunk",
      "signature": "uint ProcessSmackerVideoDataChunk(uint iterationCount, uint outputOffset)",
      "calling_convention": "__cdecl",
      "comment": "Processes a chunk of Smacker video data by combining bytes from four source streams and writing transformed pixels to output buffers.\n\nAlgorithm:\n1. Initialize loop counter to (iterationCount - 2) for processing pairs of pixels\n2. For each iteration:\n   a. Read bytes from four global source pointers (0x038532e8, 0x038532f4, 0x038532f0, 0x038532ec)\n   b. Combine bytes into 32-bit packed pixel values using bit shifting and masking\n   c. Create two pixel output values (packedPixelData and transformedPixelData)\n   d. Write packed values to output buffer at 0x038532e0 and 0x038532e4\n   e. Write additional copies to offset output location using 0x0385331c base\n   f. Increment all source and destination pointers by appropriate offsets\n3. Repeat until all iterations complete\n4. Return sum of original iterationCount and outputOffset parameters\n\nParameters:\niterationCount (EBX): Number of pixel pairs to process (will be decremented by 2 per iteration)\noutputOffset (ESP+0x18): Output offset/index value added to return value\n\nReturns:\nEAX: Sum of iterationCount + outputOffset (represents final output position)\n\nSpecial Cases:\n- Loop processes pairs of pixels (decrements by 2 each iteration)\n- Bit masks 0xff00ff preserve specific color channel bits\n- Global pointers serve as state variables modified during processing\n- Second output location indexed by 0x0385331c provides secondary output stream\n\nStructure Layout - Global Data Pointers:\nOffset | Size | Name           | Purpose\n0x038532e8 | 4 | srcPtr1        | Primary source stream pointer (bytes read)\n0x038532f4 | 4 | srcPtr2        | Secondary source stream pointer (bytes read)\n0x038532f0 | 4 | srcPtr3        | Tertiary source stream pointer (bytes read)\n0x038532ec | 4 | srcPtr4        | Quaternary source stream pointer (bytes read)\n0x038532e0 | 4 | dstPtr1        | Primary output stream pointer\n0x038532e4 | 4 | dstPtr2        | Secondary output stream pointer (transformed pixels)\n0x0385331c | 4 | dstBasePtr     | Base address for offset output writes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:21d6d963cebc49c3c99741464ca092e5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "21d6d963cebc49c3c99741464ca092e5",
        "CFG": "0d55f5b05a975e00c17a29b0feb4bd3e",
        "PRO": "2fd8fd674803f1e221e928ff33794394"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "21d6d963cebc49c3c99741464ca092e5"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_ADDR_03830720": {
      "addresses": {
        "LoD/PD2": "0x03830720"
      },
      "rvas": {
        "LoD/PD2": "0x10720"
      },
      "sizes": {
        "LoD/PD2": 130
      },
      "name": "_YUV_blit_UYVY@48",
      "signature": "undefined _YUV_blit_UYVY@48(uint param_1, uint param_2, int param_3, uint param_4, uint param_5, uint param_6, uint param_7, uint param_8, uint param_9, uint param_10, uint param_11, uint param_12)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9ed9704ca96cf7275d6354269c1858eb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9ed9704ca96cf7275d6354269c1858eb",
        "CFG": "336a2b3e7597c88bd3b0149498cccd97",
        "PRO": "d62a3ba6e17bb63145005c4853bb8d8b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9ed9704ca96cf7275d6354269c1858eb"
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "binkw32_MNE_5bfa435de8fb": {
      "addresses": {
        "LoD/PD2": "0x038307B0"
      },
      "rvas": {
        "LoD/PD2": "0x107B0"
      },
      "sizes": {
        "LoD/PD2": 683
      },
      "name": "_YUV_blit_YV12@52",
      "signature": "undefined _YUV_blit_YV12@52(int param_1, uint param_2, uint param_3, uint param_4, int param_5, int param_6, uint param_7, uint param_8, uint param_9, uint param_10, uint param_11, int param_12, uint param_13)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5bfa435de8fb023aabdb7f9c8fef7179",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5bfa435de8fb023aabdb7f9c8fef7179",
        "CFG": "0f39c8bc2c1a31b4f2b90a8d802cc88d",
        "PRO": "40e4c93496148f99101bf7d0f8129670"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5bfa435de8fb023aabdb7f9c8fef7179"
      },
      "param_counts": {
        "LoD/PD2": 13
      }
    },
    "binkw32_ADDR_03830A60": {
      "addresses": {
        "LoD/PD2": "0x03830A60"
      },
      "rvas": {
        "LoD/PD2": "0x10A60"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "_YUV_blit_32bpp_mask@48",
      "signature": "undefined _YUV_blit_32bpp_mask@48(uint param_1, uint param_2, int param_3, uint param_4, byte * param_5, int param_6, uint param_7, uint param_8, uint param_9, byte * param_10, uint param_11, uint param_12)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:512206a0524f73d7cb6b767324468599",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "512206a0524f73d7cb6b767324468599",
        "CFG": null,
        "PRO": "4aa7612d48544b1683e2715d82b72345"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "512206a0524f73d7cb6b767324468599"
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "binkw32_MNE_bedff1fe28c0": {
      "addresses": {
        "LoD/PD2": "0x03830AB0"
      },
      "rvas": {
        "LoD/PD2": "0x10AB0"
      },
      "sizes": {
        "LoD/PD2": 1786
      },
      "name": "ProcessYuvBlitMaskedRegion",
      "signature": "void ProcessYuvBlitMaskedRegion(uint destOffset, uint destStride, int srcY, uint srcX, byte * pSourceMask, int maskPitch, uint destBasePtr, uint srcUOffset, uint srcVOffset, byte * pChromaMask, uint chromaPitch, uint formatFlags, int * pWidth)",
      "calling_convention": "__cdecl",
      "comment": "Processes a masked region of YUV data for blitting with format-specific handling.\n\nAlgorithm:\n1. Check chroma format flag (bits 28-30 of formatFlags) to determine sampling mode (4:4:4, 4:2:2, 4:2:0, etc.)\n2. For 4:2:0 format (0x60000000), halve chroma dimensions and double stride values\n3. Double stride for 4:2:2 formats (0x20000000 and 0x50000000)\n4. Initialize global destination pointers (DAT_038532e0, DAT_038532e4) based on destOffset, destStride, and srcY\n5. Configure YUV blit parameters for both luma and chroma planes via ConfigureYuvBlitParameters\n6. Determine vertical stride multiplier (1 or 2) based on chroma subsampling\n7. Compute local offset values for chroma and edge pixel processing\n8. Configure UV buffer pointers with optional 16-bit word swapping based on 0x10000 format flag\n9. Process main 16x16 pixel blocks in nested loops, testing mask pattern for each 32-pixel wide column\n10. For masked regions, copy blit state to local buffer and dispatch mask-specific processor via DAT_03856340\n11. Process mask pattern 1 (one pixel): 4 columns with reduced width processing\n12. Process mask pattern 2 (different pixel): 8 columns with stride advancement\n13. Process mask pattern 3 (both pixels): 8 columns with doubled chroma stride\n14. Restore blit state from local buffer after each block\n15. Advance to next row by 16 pixels and continue until all rows processed\n16. Handle remaining width via YuvBlitHelper for edge pixels not aligned to 16-pixel blocks\n17. Handle remaining height via YuvBlitHelper for bottom rows not aligned to 16-pixel blocks\n18. Clear MMX state if required by format flags and global MMX state indicator\n\nParameters:\ndestOffset: Base offset into destination buffer (typically 0 for start of region)\ndestStride: Destination scan line stride in bytes (e.g., screen width * bytes_per_pixel)\nsrcY: Source Y coordinate for chroma plane sampling calculation\nsrcX: Source X coordinate offset for luma/chroma alignment\npSourceMask: Pointer to luma alpha/mask buffer (bit 0 = pixel present, bit 1 = adjacent pixel)\nmaskPitch: Scan line stride of source mask in bytes\ndestBasePtr: Destination buffer base pointer (typically frame buffer address)\nsrcUOffset: Absolute offset to U (Cb) plane in source YUV data\nsrcVOffset: Absolute offset to V (Cr) plane in source YUV data\npChromaMask: Pointer to chroma alpha/mask buffer (same bit layout as luma)\nchromaPitch: Scan line stride of chroma mask in bytes\nformatFlags: Format control flags with bit layout: 28-30=chroma_format, 16=uvswap, 17=mmx_clear, 18=reserved\npWidth: Pointer to block width indicator (typically 1 for standard 16-pixel blocks)\n\nReturns: void\n\nSpecial Cases:\n- Format 0x60000000 (4:2:0): Halves source dimensions, doubles strides to account for 2x sampling\n- Format 0x20000000, 0x50000000 (4:2:2): Doubles destination stride for horizontal chroma subsampling\n- Mask pattern 0x01: Only one source pixel valid - use narrow 4-pixel columns\n- Mask pattern 0x02: Alternate source pixel valid - use 8-pixel columns with different stride\n- Mask pattern 0x03: Both source pixels valid - full 8-pixel wide processing\n- Mask pattern 0x00: No valid pixels - skip blitting entirely\n- Edge pixels not aligned to 16-pixel boundaries processed via YuvBlitHelper\n- Remaining rows processed separately via YuvBlitHelper for vertical alignment",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bedff1fe28c087736f7a1ea8cb6a92da",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bedff1fe28c087736f7a1ea8cb6a92da",
        "CFG": "66904f07065bb926c987351faad467e6",
        "PRO": "177000c860c9488ef160e13232439156"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bedff1fe28c087736f7a1ea8cb6a92da"
      },
      "param_counts": {
        "LoD/PD2": 13
      }
    },
    "binkw32_ADDR_038311B0": {
      "addresses": {
        "LoD/PD2": "0x038311B0"
      },
      "rvas": {
        "LoD/PD2": "0x111B0"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "_YUV_blit_24bpp_mask@48",
      "signature": "undefined _YUV_blit_24bpp_mask@48(uint param_1, uint param_2, int param_3, uint param_4, byte * param_5, int param_6, uint param_7, uint param_8, uint param_9, byte * param_10, uint param_11, uint param_12)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:512206a0524f73d7cb6b767324468599",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "512206a0524f73d7cb6b767324468599",
        "CFG": null,
        "PRO": "eb5f6ebd5d95d77cc7748b54b0bc6484"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "512206a0524f73d7cb6b767324468599"
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "binkw32_ADDR_03831200": {
      "addresses": {
        "LoD/PD2": "0x03831200"
      },
      "rvas": {
        "LoD/PD2": "0x11200"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "_YUV_blit_16bpp_mask@48",
      "signature": "undefined _YUV_blit_16bpp_mask@48(uint param_1, uint param_2, int param_3, uint param_4, byte * param_5, int param_6, uint param_7, uint param_8, uint param_9, byte * param_10, uint param_11, uint param_12)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:512206a0524f73d7cb6b767324468599",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "512206a0524f73d7cb6b767324468599",
        "CFG": null,
        "PRO": "b5c3a1381e50335b52b6bd74760d3531"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "512206a0524f73d7cb6b767324468599"
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "binkw32_ADDR_03831250": {
      "addresses": {
        "LoD/PD2": "0x03831250"
      },
      "rvas": {
        "LoD/PD2": "0x11250"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "_YUV_blit_YUY2_mask@48",
      "signature": "undefined _YUV_blit_YUY2_mask@48(uint param_1, uint param_2, int param_3, uint param_4, byte * param_5, int param_6, uint param_7, uint param_8, uint param_9, byte * param_10, uint param_11, uint param_12)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:512206a0524f73d7cb6b767324468599",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "512206a0524f73d7cb6b767324468599",
        "CFG": null,
        "PRO": "cc5382a7984888dd84a00ee419d1e2ae"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "512206a0524f73d7cb6b767324468599"
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "binkw32_ADDR_038312A0": {
      "addresses": {
        "LoD/PD2": "0x038312A0"
      },
      "rvas": {
        "LoD/PD2": "0x112A0"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "_YUV_blit_UYVY_mask@48",
      "signature": "undefined _YUV_blit_UYVY_mask@48(uint param_1, uint param_2, int param_3, uint param_4, byte * param_5, int param_6, uint param_7, uint param_8, uint param_9, byte * param_10, uint param_11, uint param_12)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:512206a0524f73d7cb6b767324468599",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "512206a0524f73d7cb6b767324468599",
        "CFG": null,
        "PRO": "ebc2fc9c1dbb4fd6fa6dc4d7e995e7df"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "512206a0524f73d7cb6b767324468599"
      },
      "param_counts": {
        "LoD/PD2": 12
      }
    },
    "binkw32_MNE_10ceae1bef0f": {
      "addresses": {
        "LoD/PD2": "0x038312F0"
      },
      "rvas": {
        "LoD/PD2": "0x112F0"
      },
      "sizes": {
        "LoD/PD2": 61
      },
      "name": "DetectCPUIDCapability",
      "signature": "uint DetectCPUIDCapability(void)",
      "calling_convention": "__stdcall",
      "comment": "Detects CPU support for CPUID instruction and Hyper-Threading Technology (HTT).\n\nAlgorithm:\n1. Save current EFLAGS register value into EBX for comparison\n2. Toggle the ID flag (bit 21) in EFLAGS to test if it can be modified\n3. Restore EFLAGS with the modified flag value\n4. Read EFLAGS back to verify the ID flag was actually toggled\n5. If flags are unchanged, CPUID instruction is not supported; return 0\n6. If ID flag could be toggled, CPU supports CPUID instruction\n7. Execute CPUID function 1 to retrieve processor feature information\n8. Test bit 23 of EDX (0x800000) to check for HTT capability\n9. If HTT flag is set, return 1 (HTT supported); otherwise return 0\n\nReturns:\n- 1: CPU supports CPUID and Hyper-Threading Technology\n- 0: CPU does not support CPUID or lacks HTT capability\n\nSpecial Cases:\n- Early CPUs without CPUID support: Function detects this and returns 0\n- Single-core CPUs without HTT: CPUID available but HTT bit not set; returns 0\n- HTT disabled in BIOS: May not set the HTT capability bit in CPUID\n\nRelated CPUs:\n- Pentium 4 and later: Typically support CPUID and HTT\n- Pentium III and earlier: May lack CPUID instruction\n- AMD Athlon MP/Opteron: Support HTT equivalent (multiple cores)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:10ceae1bef0fbe6e4b4da5621e81890e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "10ceae1bef0fbe6e4b4da5621e81890e",
        "CFG": "58f038befe5bbad46706be039b30588a",
        "PRO": "8525b137a12098d77c8670d11e1330bd"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "10ceae1bef0fbe6e4b4da5621e81890e"
      }
    },
    "binkw32_MNE_24b3231d8bf5": {
      "addresses": {
        "LoD/PD2": "0x03831370"
      },
      "rvas": {
        "LoD/PD2": "0x11370"
      },
      "sizes": {
        "LoD/PD2": 578
      },
      "name": "ScaleScanlinesBilinear",
      "signature": "void ScaleScanlinesBilinear(int pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Scales image scanlines using bilinear filtering with MMX/SSE SIMD operations.\n\nAlgorithm:\n1. Initialize first output buffer pointer to DAT_038532e0 + pixelCount*8 bytes\n2. Load MMX filter constant from DAT_0384dfc8 into MM7 (used for saturation)\n3. First loop: Process pixelCount pixels from first source scanline\n   - Read source pixel indices from DAT_038532e8 (incremented)\n   - Sample interpolation weights from DAT_038532f0 and DAT_038532f4 lookup tables\n   - Unpack RGBA components using PUNPCKLBW and multiply by weights via PMULHW\n   - Apply packed add/subtract saturating operations on 4x 16-bit values in parallel\n   - Combine color channels with POR and store 8 bytes to output buffer\n   - Advance output pointer by 8 bytes and loop until EDI >= target\n4. Update intermediate state pointers after first loop\n5. Second loop: Process pixelCount pixels from second source scanline\n   - Repeat same SIMD operations on different buffer addresses\n6. Save final state pointers back to global storage\n\nReturns: void (results written to output buffers via global pointers)\n\nParameters:\n- pixelCount: Number of pixels to process in each scanline (Stack[ESP+0x14])\n\nSpecial Cases:\n- Uses saturating word operations (PADDSW/PSUBUSW) to prevent overflow\n- Multiplies 8-bit indices by 4 to access 32-bit table entries\n- Processes two scanlines in sequence, updating different output buffers\n- Global state pointers stored at 0x038532e0, 0x038532e4, 0x038532e8, 0x038532ec, 0x038532f0, 0x038532f4\n\nStructure Layout (Processing Pipeline):\nOffset  Size  Description\n0       4     Output pointer 1 (DAT_038532e0)\n4       4     Output pointer 2 (DAT_038532e4)\n8       4     Source index pointer (DAT_038532e8/ec)\n12      4     Weight table pointer 1 (DAT_038532f0)\n16      4     Weight table pointer 2 (DAT_038532f4)\n20      8     MMX filter constant and control values",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:24b3231d8bf59c06fa0dcd294a5f6243",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "24b3231d8bf59c06fa0dcd294a5f6243",
        "CFG": "331ace91c8846c1e4dbf373cce8c824c",
        "PRO": "396553c84aa97fcbfc5fcd8b98d510ee"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "24b3231d8bf59c06fa0dcd294a5f6243"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_6543be2c1e3e": {
      "addresses": {
        "LoD/PD2": "0x03831F80"
      },
      "rvas": {
        "LoD/PD2": "0x11F80"
      },
      "sizes": {
        "LoD/PD2": 703
      },
      "name": "ProcessPixelPaletteLookup",
      "signature": "void ProcessPixelPaletteLookup(int pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Processes pixel palette lookup using MMX SIMD operations for color transformation.\n\nAlgorithm:\n1. Initialize MMX register MM7 with brightness/contrast value from DAT_0384dfc8\n2. Calculate output buffer end address by multiplying pixelCount by 3 and adding to destination base\n3. FIRST LOOP - Process indexed pixel pairs and generate RGB output:\n   a. Load source pixel index from input buffer (EDX increment +4)\n   b. Load palette indices from input streams at EBP and EBX (+2 per iteration)\n   c. Unpack pixel index to 4 separate palette index values\n   d. Apply brightness shift: subtract threshold (DAT_0384dfb8), multiply by scale (DAT_0384dfc0)\n   e. Look up 4 palette entries from three 256-color lookup tables:\n      - Red values from DAT_03854730 (offset: index*4)\n      - Green/Blue values from DAT_03854f30 and DAT_03854b30 (offset: index*4)\n      - Blue values from DAT_03855330 (offset: index*4)\n   f. Add brightness deltas to each component using saturating arithmetic (PADDSW)\n   g. Clamp values by subtracting brightness constant (PSUBUSW)\n   h. Pack RGB components into 24-bit output: 0x00RRGGBB format\n   i. Write 12 bytes output (3 pixels * 4 bytes per packed result) to destination buffer\n   j. Continue until all pixels processed (compare destPtr to calculated end)\n4. Save input stream pointers (EDX=sourcePixel index pointer, EBP=inputPtr1, EBX=inputPtr2)\n5. SECOND LOOP - Repeat process for second set of pixels with fresh input streams\n6. Restore final stream pointers to global state and return\n\nParameters:\n  pixelCount: int - Number of 2-pixel pairs to process (multiplication factor for buffer traversal)\n\nReturns:\n  void - Results written directly to output buffers at addresses 0x038532e0/0x038532e4\n\nSpecial Cases:\n  - Each iteration processes 2 input pixels and produces 3 output pixels (4 bytes each = 12 bytes total)\n  - Brightness/contrast stored as packed 16-bit values in MM7 register\n  - Palette tables are 256-entry lookup tables indexed by pixel values\n  - Uses MMX unsaturated and saturated arithmetic for clamping\n  - Two independent processing loops allow pipeline optimization\n\nGlobal Data References:\n  DAT_0384dfc8: Brightness/contrast constant (64-bit, loaded into MM7)\n  DAT_0384dfb8: Threshold value for brightness subtraction (64-bit)\n  DAT_0384dfc0: Scale multiplier for brightness shift (64-bit)\n  DAT_038532e0/e4: Output buffer pointers (incremented by pixelCount*3)\n  DAT_038532e8/ec: Input source pixel index pointer (incremented +1 per iteration)\n  DAT_038532f0/f4: Input palette index pointers (incremented +2 per iteration)\n  DAT_03854730/f30/b30/5330: 256-entry color lookup tables (red/green/blue components)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6543be2c1e3e5aeacbb519a16b7bb53d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6543be2c1e3e5aeacbb519a16b7bb53d",
        "CFG": "30afca8ba517008cbdf781f5906422b7",
        "PRO": "9b50e0e47e573f633d55332b80628e66"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6543be2c1e3e5aeacbb519a16b7bb53d"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_56e72c5d93f1": {
      "addresses": {
        "LoD/PD2": "0x03832240"
      },
      "rvas": {
        "LoD/PD2": "0x12240"
      },
      "sizes": {
        "LoD/PD2": 856
      },
      "name": "BlendAndConvertColorsMMX",
      "signature": "void BlendAndConvertColorsMMX(int pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "MMX-optimized color space conversion and blending processor.\n\nProcesses pixel color data through two parallel loops, applying color space\nconversions using lookup tables and saturating arithmetic operations. Each\niteration processes one pixel with color blending across three channels.\n\nAlgorithm:\n1. Calculate loop iteration count as pixelCount * 3 (3 output dwords per pixel)\n2. Initialize pointers to source buffers, lookup tables, and output buffers\n3. First loop: Process pixels from DAT_038532e0/e8 to calculated end address\n   a. Load source color value from EDX and lookup indices from EBP/EBX\n   b. Unpack source color to 16-bit components via PSUBUSW with saturation\n   c. Shift left 2 bits and multiply by color blend factor (PMULHW)\n   d. Load color channel data from 3 lookup tables (0x3854730, 0x3854f30, 0x3855330)\n   e. Add blend factors to each channel component\n   f. Apply saturation limits with PADDSW and PSUBUSW\n   g. Repack components into 3 x 32-bit output values\n   h. Write 12 bytes (3 dwords) per iteration to output buffer\n4. Second loop: Repeat processing for DAT_038532e4/ec output buffer\n5. Restore source pointer registers before return\n\nParameters:\n  pixelCount - int: Number of pixels to process (output count = pixelCount * 3)\n\nReturns:\n  void: Output written directly to global buffers at 0x38532e0/e4\n\nSpecial Cases:\n  - Uses MMX saturation arithmetic (PADDSW/PSUBUSW) for safe overflow handling\n  - Lookup tables provide color space conversion through indexed byte access\n  - Two separate loops process independent color channels in parallel\n  - Register cycling (EBP/EBX/EDX) maintains source buffer state across iterations\n  - Output stride is 12 bytes (3 dwords) per pixel iteration",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:56e72c5d93f196aa638c908c9d1df10c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "56e72c5d93f196aa638c908c9d1df10c",
        "CFG": "3b3958a37c1f83abe553e598c41c9395",
        "PRO": "4dc78847c0ea86dbfa04bdf38383d51b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "56e72c5d93f196aa638c908c9d1df10c"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_c40f3b4483cb": {
      "addresses": {
        "LoD/PD2": "0x038325A0"
      },
      "rvas": {
        "LoD/PD2": "0x125A0"
      },
      "sizes": {
        "LoD/PD2": 826
      },
      "name": "CryptoRoundTransform",
      "signature": "void CryptoRoundTransform(int roundCount)",
      "calling_convention": "__stdcall",
      "comment": "Performs cryptographic substitution-permutation round transformations on data blocks.\\n\\nThis function executes two sequential round transformation passes that apply byte \\nsubstitution and mixing operations using lookup tables. It processes data through \\nglobal input/output buffer pointers, applying the same transformation logic twice \\nwith different state management between passes.\\n\\nAlgorithm:\\n1. Initialize loop counter from roundCount parameter\\n2. First pass: For each round iteration:\\n   - Load input byte from DAT_038532f0 and key byte from DAT_038532f4\\n   - Use bytes as indices into substitution tables (DAT_03853730, DAT_03854330, etc.)\\n   - Perform combined table lookups at table offsets to generate intermediate values\\n   - Shift and combine shifted bytes using bitwise OR operations\\n   - Store 4-byte output blocks at positions calculated from DAT_038532e0 and DAT_038532e4\\n   - Advance output pointers by 6 bytes per iteration\\n3. Restore saved input/key pointers for second pass\\n4. Second pass: Execute identical transformation logic with different state variables\\n   - Uses DAT_038532ec/DAT_038532e4 instead of DAT_038532e8/DAT_038532e0\\n   - Maintains intermediate 16-bit result in temp16BitValue (DAT_0384dff0)\\n5. Decrement round counter and repeat first pass\\n6. Return and restore stack\\n\\nParameters:\\n  roundCount (int): Number of transformation rounds to execute in first pass (DEC at 0x03832736)\\n\\nReturns:\\n  None (void) - All output written to global buffer pointers\\n\\nSpecial Cases:\\n  - Intermediate 16-bit value (DAT_0384dff0) cached between iterations\\n  - Stack frame allocates 0xc bytes for saved pointer values\\n  - __stdcall calling convention: caller must clean 4-byte parameter\\n  - Magic numbers: 0x4, 0x8, 0x10, 0x18 are bit shift amounts (8, 16, 24 bits)\\\"}",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c40f3b4483cb840f36a191338aaef338",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c40f3b4483cb840f36a191338aaef338",
        "CFG": "fa1a7b49fa7288a7779bdbd3388bb741",
        "PRO": "0f8f42973bca75185994eadd8b2ec216"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c40f3b4483cb840f36a191338aaef338"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_759dfa7d72a7": {
      "addresses": {
        "LoD/PD2": "0x03832CB0"
      },
      "rvas": {
        "LoD/PD2": "0x12CB0"
      },
      "sizes": {
        "LoD/PD2": 579
      },
      "name": "ApplyBilinearLighting",
      "signature": "void ApplyBilinearLighting(int nPixelWidth)",
      "calling_convention": "__stdcall",
      "comment": "SIMD-optimized bilinear lighting renderer for 16-bit pixel output\n\nALGORITHM:\n1. Setup: Load global pointers to pixel buffers and lookup tables\n2. Loop 1 - Top row: Process pixel pairs with bilinear filtering\n   - Read source pixels from input buffer (DAT_038532e8)\n   - Lookup color values in 3 LUTs (0x3854730, 0x3854f30, 0x3854b30)\n   - Apply fractional weights via multiply (offset 0x0384dfc0)\n   - Clamp results using PSUBUSW with offset (0x0384dfc8)\n   - Pack RGBA output to 64-bit chunks at output ptr (DAT_038532e0)\n3. Loop 2 - Bottom row: Repeat process for second row (DAT_038532e4)\n   - Uses alternate source buffer (DAT_038532ec)\n   - Same 3-LUT color interpolation process\n4. Cleanup: Store final buffer pointers for next frame\n\nPARAMETERS:\n- nPixelWidth: Pixel stride in 16-bit units (controls loop iterations)\n\nRETURNS: void\n\nSPECIAL CASES:\n- Two separate loops process top/bottom rows independently\n- Each pixel pair generates 16 bytes (2x 64-bit SIMD) of output\n- PSUBUSW clamps negative results to 0 (saturating subtract)\n- Lookup tables span 4KB each at 0x3854730, 0x3854f30, 0x3854b30, 0x3855330",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:759dfa7d72a79b9135f206da0f44ca24",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "759dfa7d72a79b9135f206da0f44ca24",
        "CFG": "f099fb52b68b0dd244eea8d33968d2e4",
        "PRO": "3e75bf95d52c521270d3abc5fc8dc2f0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "759dfa7d72a79b9135f206da0f44ca24"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_e2e05e705480": {
      "addresses": {
        "LoD/PD2": "0x03833500"
      },
      "rvas": {
        "LoD/PD2": "0x13500"
      },
      "sizes": {
        "LoD/PD2": 970
      },
      "name": "ProcessDoublePixelPairs",
      "signature": "void ProcessDoublePixelPairs(int iterationCount)",
      "calling_convention": "__stdcall",
      "comment": "Processes pixel pairs by combining lookup table values into 32-bit pixels.\n\nAlgorithm:\n1. Initialize two source byte pointers and load initial index values\n2. Outer loop: Process specified number of iterations\n3. Inner loop: For each iteration, fetch indices and combine lookup values\n4. Combine 3 bytes from 3 lookup tables using bit shifts and OR operations\n5. Store combined 32-bit pixel value to output buffer\n6. Advance output pointer and repeat for all iterations\n7. Restore original source pointers and return\n\nParameters:\n- iterationCount: Number of pixel pairs to process\n\nReturns:\n- void (no return value)\n\nSpecial Cases:\n- Uses global byte pointers at 0x038532f0, 0x038532f4 for source indices\n- Maintains separate output pointers for two parallel processing streams\n- Uses lookup tables at 0x3853730, 0x3854330, 0x3853f30, 0x3853b30, 0x3858b60\n- Processes pixels in pairs with alternating single and dual index patterns\n\nStructure Layout:\nGlobal State Variables:\nOffset  Size  Field Name        Type      Description\n------  ----  ----------------  --------  -----------\n0x038532f0  4  sourcePointerA    byte*     First source byte stream\n0x038532f4  4  sourcePointerB    byte*     Second source byte stream\n0x038532e0  4  outputBufferA     uint*     First output stream (4-byte aligned)\n0x038532e8  4  indexStreamA      byte*     Index source for first stream\n0x038532e4  4  outputBufferB     uint*     Second output stream\n0x038532ec  4  indexStreamB      byte*     Index source for second stream",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e2e05e7054807f758517605ca4d57309",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e2e05e7054807f758517605ca4d57309",
        "CFG": "f1ea396cda4bf67080ca5306fc2fb37e",
        "PRO": "ad33a2e747fc45b84bafff94d48220b9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e2e05e7054807f758517605ca4d57309"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_4a0cee88ebe0": {
      "addresses": {
        "LoD/PD2": "0x038338D0"
      },
      "rvas": {
        "LoD/PD2": "0x138D0"
      },
      "sizes": {
        "LoD/PD2": 183
      },
      "name": "ScaleImageDataWithMMX",
      "signature": "void ScaleImageDataWithMMX(int pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Scales image data using MMX SIMD operations for efficient pixel processing.\n\nThis function processes image data by reading from multiple source buffers and\nwriting to multiple destination buffers using MMX intrinsics for parallel byte\noperations. The function performs pixel interpolation/scaling by combining values\nfrom three input sources (EBP, EBX, ECX) and mask values from EDX.\n\nAlgorithm:\n1. Load pixelCount parameter and calculate loop iteration count (pixelCount * 16 bytes)\n2. Initialize global pointer registers (ESI, EDI, EBP, EBX, ECX, EDX)\n3. Loop through each iteration:\n   a. Read source bytes from EBP (2 bytes) and EBX (2 bytes)\n   b. Pack and unpack bytes into MMX registers for parallel processing\n   c. Read mask value from EDX (4 bytes)\n   d. Perform byte unpacking on mask (PUNPCKLBW) to expand to 64-bit\n   e. Create two output vectors by interleaving mask high/low with source\n   f. Write 16 bytes of output to both EDI and ESI buffers\n   g. Advance all source and destination pointers\n4. Update global pointers with final positions after loop completion\n5. Return to caller\n\nParameters:\n  pixelCount (int): Number of processing units (each processes 16 bytes)\n\nReturns:\n  void: No return value. Updates global output buffers in-place.\n\nSpecial Cases:\n  - Uses __stdcall convention with callee cleanup (RET 0x4)\n  - Loop iteration count calculated as pixelCount * 0x10 (16 bytes per unit)\n  - Global pointers (0x038532e0-ec) maintain state across calls\n  - MMX registers not preserved (implicit clobber)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4a0cee88ebe08228c4d878d807fe78db",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4a0cee88ebe08228c4d878d807fe78db",
        "CFG": "c6efb996ba98e455318ff833a2c7957e",
        "PRO": "d7d171c628b0ad811e8cda6f1d785900"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4a0cee88ebe08228c4d878d807fe78db"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_b197c3b28632": {
      "addresses": {
        "LoD/PD2": "0x03833AC0"
      },
      "rvas": {
        "LoD/PD2": "0x13AC0"
      },
      "sizes": {
        "LoD/PD2": 186
      },
      "name": "ExpandColorPixelsWithMMX",
      "signature": "void ExpandColorPixelsWithMMX(int nPixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Expands packed color pixels using MMX SIMD instructions.\n\nConverts color data from packed format to expanded 64-bit format using SIMD\nbyte unpacking operations. Processes pixel pairs from up to 4 parallel input\nstreams and writes to 2 output buffers, performing PUNPCKLBW/PUNPCKHBW\nexpansions for format conversion.\n\nAlgorithm:\n1. Calculate loop iteration limit by multiplying nPixelCount by 2\n2. For each iteration:\n   a) Load 16-bit values from input streams 1 and 2 (DAT_038532f0, DAT_038532f4)\n   b) Extract high byte (>>8) and low byte for each input\n   c) Load 32-bit color value from DAT_038532ec\n   d) Extract color components: byte0 (>>24), byte1 (>>8), byte2 (>>16), byte3\n   e) Use PUNPCKLBW to interleave color bytes with input bytes\n   f) Store expanded 64-bit results to DAT_038532e4[0] and DAT_038532e4[1]\n   g) Repeat for second pair using DAT_038532e8 output to pOutputBuffer\n   h) Advance all pointers by 4 bytes (color), 2 bytes (inputs), 16 bytes (outputs)\n3. Loop until pOutputBuffer reaches calculated end address\n4. Update global state pointers before return\n\nParameters:\n  nPixelCount: Number of color pixel pairs to process (scaled by 2 for loop limit)\n\nReturns:\n  void (updates global buffers in place)\n\nSpecial Cases:\n  - Function operates on global state pointers (DAT_038532e0-DAT_038532f4)\n  - Uses MMX registers MM1-MM5 for SIMD operations\n  - Loop count derived from nPixelCount * 2 (not direct iteration count)\n  - Processes data in pairs, advancing pointers by 16 bytes per pair\n  - All global pointers are updated at function exit for next call\n\nGlobal State Modified:\n  DAT_038532e0: Output end marker\n  DAT_038532e4: Primary output buffer pointer\n  DAT_038532e8: Secondary output buffer pointer\n  DAT_038532ec: Color input pointer\n  DAT_038532f0: Input stream 1 pointer\n  DAT_038532f4: Input stream 2 pointer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b197c3b286320fcb4f506a2fee1b3ae7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b197c3b286320fcb4f506a2fee1b3ae7",
        "CFG": "7e9e85dea00054f2886a31b34ce7f1a1",
        "PRO": "3341ded775a7ef3e5849eeea4c39611c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b197c3b286320fcb4f506a2fee1b3ae7"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_39d5c5cc5785": {
      "addresses": {
        "LoD/PD2": "0x03833CB0"
      },
      "rvas": {
        "LoD/PD2": "0x13CB0"
      },
      "sizes": {
        "LoD/PD2": 607
      },
      "name": "ProcessPixelChannel",
      "signature": "void ProcessPixelChannel(int pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Processes pixel data through MMX-accelerated color transformation lookup tables.\n\nAlgorithm:\n1. Initialize source pointers from global state (DAT_038532e0, DAT_038532f0, DAT_038532f4)\n2. Calculate first loop end address: (pixelCount * 16) + current position\n3. Loop 1 - Process first pixel channel:\n   a. Load input byte from EDX and unpack to 16-bit values via MM4\n   b. Subtract base intensity (DAT_0384dfb8) using PSUBUSW (saturating)\n   c. Scale by factor 4 and multiply high words (PMULHW) using DAT_0384dfc0\n   d. Fetch 4 lookup table entries from DAT_03854730/DAT_03854f30/DAT_03854b30/DAT_03855330\n   e. Add filter coefficients and offset (DAT_0384dfc8), then subtract offset\n   f. Right-shift results using per-channel shift amounts (DAT_0385c7f0/f8/00)\n   g. Left-shift by multiplication factors (DAT_0385c7d8/e0/e8)\n   h. Combine results with bitwise OR to create final QWORD output\n   i. Write 2 QWORDs (16 bytes) to output buffer\n   j. Repeat until EDI reaches loop end address\n4. Store updated source pointers to globals\n5. Initialize second loop end address for DAT_038532e4\n6. Loop 2 - Process second pixel channel (identical algorithm with different LUT bases)\n7. Store final pointer state to globals and return\n8. Function uses __stdcall convention: caller removes 4-byte parameter\n\nParameters:\n- pixelCount [int]: Number of pixels to process (each iteration processes 2 pixels)\n\nReturns:\n- void: Results written directly to output buffers in global state\n\nSpecial Cases:\n- Magic numbers 0x4 (stride bytes), 0x2 (pixel pairs), 0x10 (output step 16 bytes)\n- Saturating arithmetic prevents overflow during color transformation\n- MMX registers (MM0-MM7) used for parallel word operations\n- Two sequential loops process independent color channels with identical algorithms\n\nMemory Layout of Global State:\nOffset  Size  Field                Type    Description\n0x0     4     DAT_038532e0        dword*  Output buffer pointer (channel 1)\n0x4     4     DAT_038532e4        dword*  Output buffer pointer (channel 2)\n0x8     4     DAT_038532e8        dword*  Input data pointer (source 1)\n0xC     4     DAT_038532ec        dword*  Input data pointer (source 2)\n0x10    4     DAT_038532f0        dword*  Lookup index source 1\n0x14    4     DAT_038532f4        dword*  Lookup index source 2",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:39d5c5cc5785a8f4441850cf89bcbd0a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "39d5c5cc5785a8f4441850cf89bcbd0a",
        "CFG": "b2cc85b12cd01ea50f0e2af838c054cb",
        "PRO": "4a90d60ee686132285b48e23f54fe72a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "39d5c5cc5785a8f4441850cf89bcbd0a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_d347d96ec0d9": {
      "addresses": {
        "LoD/PD2": "0x03833F10"
      },
      "rvas": {
        "LoD/PD2": "0x13F10"
      },
      "sizes": {
        "LoD/PD2": 760
      },
      "name": "ProcessVideoSamplesMmx",
      "signature": "void ProcessVideoSamplesMmx(int sampleCount)",
      "calling_convention": "__stdcall",
      "comment": "MMX-optimized video codec sample processor for color space filtering and transformation\nProcesses raw byte samples through multiple color channel transformations using packed word operations.\nOperates on two independent sample streams in parallel using global buffer pointers.\nAlgorithm: 1) Load input sample count and initialize buffer pointers from global state\n2) First loop: Process primary color channel samples through psubusw/psllw/pmulhw pipeline with coefficient multiplication\n3) Load interpolated sample values from lookup tables and apply coefficient offsets\n4) Perform signed packed word addition with saturation for color mixing and weighted filtering\n5) Combine R/G/B results through parallel psrlw/psllw bit manipulation to construct output pixels\n6) Store processed 64-bit output pairs to output buffer and advance pointers\n7) Second loop: Repeat processing for secondary color channel with independent input streams\n8) Restore global buffer pointers and exit\nParameters: sampleCount (int) - Number of sample pairs to process (scaled by 16 bytes in initial calculation)\nReturns: void - Output written directly to global buffers at 038532e0/038532e4\nSpecial Cases: Function uses __stdcall convention with caller-cleaned stack. Operates entirely through global state maintained in static data buffers. Coefficient tables and thresholds stored at fixed addresses. No validation of sample count or buffer bounds.\nStructure Layout: Input/Output Buffer Layout (4 global pointers):\nOffset  Size  Name                   Type      Description\n0x0     4     DAT_038532e0           ptr       Output buffer pointer (primary stream)\n0x4     4     DAT_038532e4           ptr       Output buffer pointer (secondary stream)\n0x8     4     DAT_038532e8           ptr       Input index for primary stream\n0xC     4     DAT_038532ec           ptr       Input index for secondary stream\nCoefficient Tables:\nOffset  Size  Name                   Address   Description\n0x0     256   DAT_03854730           0x3854730 Y channel luma lookup (256 bytes)\n0x100   256   DAT_03854f30           0x3854f30 Cb channel chroma lookup\n0x200   256   DAT_03854b30           0x3854b30 Cr channel chroma lookup  \n0x300   256   DAT_03855330           0x3855330 Secondary chroma lookup\nThresholds/Scales:\nAddress  Value   Purpose\n0x0384dfb8  qword   Saturation threshold for psubusw operation\n0x0384dfc0  qword   Coefficient multiplier for pmulhw\n0x0384dfc8  qword   Range threshold for paddsw/psubusw\n0x0385c7d8  qword   Scale factor 1 for psllw result\n0x0385c7e0  qword   Scale factor 2 for psllw result\n0x0385c7e8  qword   Scale factor 3 for psllw result\n0x0385c7f0  qword   Shift amount for psrlw operation\n0x0385c7f8  qword   Shift amount for secondary psrlw\n0x0385c800  qword   Shift amount for tertiary psrlw",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d347d96ec0d94dfddf3ae8c909f6ed5f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d347d96ec0d94dfddf3ae8c909f6ed5f",
        "CFG": "56fdedfa32208132eb56a588ae9db861",
        "PRO": "e182a3028c31248c787d4acee2507f9c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d347d96ec0d94dfddf3ae8c909f6ed5f"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_73c62f166320": {
      "addresses": {
        "LoD/PD2": "0x03834210"
      },
      "rvas": {
        "LoD/PD2": "0x14210"
      },
      "sizes": {
        "LoD/PD2": 768
      },
      "name": "ProcessCryptoRounds",
      "signature": "void ProcessCryptoRounds(int roundCount)",
      "calling_convention": "__stdcall",
      "comment": "Processes cryptographic transformation rounds using table-based lookups.\n\nAlgorithm:\n1. Initialize three source pointers from global state arrays (DAT_038532f0, DAT_038532f4, DAT_038532e8)\n2. For each primary round (roundCount iterations):\n   - Read bytes from three source streams\n   - Look up values in table DAT_03853320 based on byte values\n   - Use these indices to access three lookup tables (DAT_03850694, DAT_0385bfc4, DAT_0385a3a0)\n   - Combine results with bitwise OR operations\n   - Write 8-byte output to DAT_038532e0 (advances by 8 each iteration)\n   - Process two iterations per round (unrolled loop for performance)\n3. Restore initial pointers from saved state\n4. For each secondary round (roundCount iterations):\n   - Repeat same transformation using alternate output stream (DAT_038532e4)\n   - Uses different source stream (DAT_038532ec instead of DAT_038532e8)\n   - Process two iterations per round (unrolled loop)\n\nParameters:\nroundCount: Number of transformation iterations to perform per round phase\n\nReturns:\nvoid - Results written to global output arrays DAT_038532e0 and DAT_038532e4\n\nSpecial Cases:\n- Uses table lookup mechanism suggesting substitution-permutation network\n- Loop unrolling processes 2 iterations per countdown to improve cache efficiency\n- Three separate lookup tables combined with OR operations suggest composite substitution\n- Global state pointers modified during execution; original values saved in stack\n- Likely part of iterative encryption algorithm with multiple rounds",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:73c62f1663200aecfb788e7dc59c4c20",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "73c62f1663200aecfb788e7dc59c4c20",
        "CFG": "0d16a01b8731061989e87ef7cb6e3da8",
        "PRO": "a5580c8bb8e3d334b215fc9550d58be9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "73c62f1663200aecfb788e7dc59c4c20"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_83e334a5e7da": {
      "addresses": {
        "LoD/PD2": "0x03834510"
      },
      "rvas": {
        "LoD/PD2": "0x14510"
      },
      "sizes": {
        "LoD/PD2": 970
      },
      "name": "ExpandCryptographicTables",
      "signature": "void ExpandCryptographicTables(int roundCount)",
      "calling_convention": "__stdcall",
      "comment": "Expands cryptographic lookup tables for multiple rounds of cipher computation.\\n\\nThis function performs cryptographic table operations using pre-computed lookup tables to generate expanded cipher state. It processes two distinct rounds of operations, each performing byte indexing and table lookups with OR-combined results from three separate transformation tables.\\n\\nAlgorithm:\\n1. Load and save initial byte pointers from global state (DAT_038532f0, DAT_038532f4)\\n2. Extract initial byte indices and lookup their table entries (DAT_03853730, DAT_03854330, DAT_03853f30, DAT_03853b30)\\n3. Enter first loop: For roundCount iterations, perform table lookups and OR results into output buffer (DAT_038532e0)\\n4. Within first loop: Process single byte then double byte pairs, combining three table values via OR operation\\n5. Restore byte pointers to initial state for second processing phase\\n6. Enter second loop: For roundCount iterations again, perform identical table operations on different output buffer (DAT_038532e4)\\n7. Decrement global byte position pointers to reset state for next invocation\\n\\nParameters:\\nroundCount (int) - Number of rounds to process; controls loop iteration count for both main loops\\n\\nReturns:\\nvoid - Function modifies global state variables and output buffers in place",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:83e334a5e7daaaacc1cfeb45b9bc65ce",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "83e334a5e7daaaacc1cfeb45b9bc65ce",
        "CFG": "5847b0e258d9154f07c1e68ea2e310d5",
        "PRO": "ad33a2e747fc45b84bafff94d48220b9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "83e334a5e7daaaacc1cfeb45b9bc65ce"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_51afc5d553be": {
      "addresses": {
        "LoD/PD2": "0x038348E0"
      },
      "rvas": {
        "LoD/PD2": "0x148E0"
      },
      "sizes": {
        "LoD/PD2": 1025
      },
      "name": "RenderScanlinePixels",
      "signature": "void RenderScanlinePixels(int scanlineCount)",
      "calling_convention": "__stdcall",
      "comment": "Renders scanline pixel data using MMX SIMD operations. Processes two parallel output streams with color blending and scaling transformations applied to 8-bit indexed pixel data.\n\nAlgorithm:\n1. Calculate output buffer offsets using scanlineCount parameter (multiplied by 6 for stride)\n2. Save current output pointer positions for both primary and secondary buffers\n3. First loop: Process scanlineCount pixels from input source buffer\n   - Load input pixel values from DAT_038532e8 and DAT_038532f0/DAT_038532f4\n   - Perform color lookup using three lookup tables at 0x3854730, 0x3854f30, 0x3855330\n   - Apply delta scaling using shifts and multiplications by table at 0x3854dfc0\n   - Blend colors using saturating add/subtract operations with threshold at 0x3384dfc8\n   - Pack results into 6 consecutive dwords and advance output pointer by 24 bytes\n4. Second loop: Repeat processing for second output stream with different palette data\n5. Update global state pointers for next invocation\n\nParameters:\n  scanlineCount: Number of scanlines to process (determines output stride)\n\nReturns:\n  void\n\nSpecial Cases:\n  - Uses saturating arithmetic (PADDSW/PSUBUSW) to prevent color overflow/underflow\n  - Parallel processing of two independent pixel streams enables dual-layer rendering\n  - Global state pointers must be initialized before calling this function\n  - Stride of 6 dwords per scanline suggests 24-byte pixel blocks or 6 4-byte pixels per line",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:51afc5d553be81e899e30ec6a6f37698",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "51afc5d553be81e899e30ec6a6f37698",
        "CFG": "471b60bec83cbd7fbcac2a3f4dad588c",
        "PRO": "fa92051e8f327a744bd75ed61d5fc616"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "51afc5d553be81e899e30ec6a6f37698"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_6e04e3701d88": {
      "addresses": {
        "LoD/PD2": "0x03834CF0"
      },
      "rvas": {
        "LoD/PD2": "0x14CF0"
      },
      "sizes": {
        "LoD/PD2": 1178
      },
      "name": "ProcessColorTransformSSE",
      "signature": "void ProcessColorTransformSSE(int transformIndex)",
      "calling_convention": "__stdcall",
      "comment": "Processes color data through dual SSE-based transformation pipelines for rendering output.\n\nAlgorithm:\n1. Initialize pointers to source/destination buffers using global state and transform index\n2. First loop: Process initial color transformation sequence\n   - Load color value from input stream\n   - Extract and unpack RGBA color components\n   - Apply saturation subtraction using psubusw with threshold\n   - Scale components by 2x and apply multiplier via pmulhw\n   - Load interpolation coefficients and combine with scaled values using paddsw\n   - Compute three color channel outputs with boundary clamping\n   - Pack results into destination buffer (6 DWORDs per iteration)\n   - Continue until reaching end address\n3. Second loop: Process secondary transformation sequence\n   - Repeat similar color transformation as first loop\n   - Load from different source streams and coefficient tables\n   - Write to secondary destination buffer\n   - Continue until reaching end address\n4. Return to caller\n\nParameters:\ntransformIndex (int): Index selecting which color transformation pair to process (used as multiplier for buffer offsets)\n\nReturns:\nvoid (no return value; modifies global buffers)\n\nSpecial Cases:\n- Both loops terminate when calculated end pointer is reached\n- psubusw provides unsigned saturation (min value is 0, no underflow)\n- paddsw provides signed saturation (-32768 to 32767 range)\n- RGBA components are manipulated as 16-bit signed values in SIMD context\n- Coefficient tables (DAT_03854730, DAT_03854f30, DAT_03854b30, DAT_03855330) store signed 16-bit values\n- Global state variables (DAT_038532e0, DAT_038532e4, DAT_038532e8, DAT_038532ec, DAT_038532f0, DAT_038532f4) maintain stream positions\n\nStructure Layout:\nOutput format uses 6 DWORD per color pixel:\n  Offset  Size  Field               Type    Description\n  0       4     colorChannel0       uint    First color channel packed RGBA\n  4       4     colorChannel1       uint    Second color channel output\n  8       4     colorChannel2       uint    Third color channel output\n  12      4     colorChannel0_High  uint    High word of first channel\n  16      4     colorChannel1_High  uint    High word of second channel\n  20      4     colorChannel2_High  uint    High word of third channel\n  Total: 24 bytes per color pixel",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6e04e3701d88dc41ad988771d46e4b5d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6e04e3701d88dc41ad988771d46e4b5d",
        "CFG": "1b8d9cec6baebaaf25589b6a1ae54ab8",
        "PRO": "227a7edeba9d2f92128be1f642c330a7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6e04e3701d88dc41ad988771d46e4b5d"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_8e4f9fa73272": {
      "addresses": {
        "LoD/PD2": "0x03835510"
      },
      "rvas": {
        "LoD/PD2": "0x15510"
      },
      "sizes": {
        "LoD/PD2": 1070
      },
      "name": "ProcessAESSubstitutionRounds",
      "signature": "void ProcessAESSubstitutionRounds(int roundCount)",
      "calling_convention": "__stdcall",
      "comment": "Processes AES SubBytes transformation across multiple rounds.\n\nAlgorithm:\n1. Load initial input byte pointers from global state (DAT_038532f0, DAT_038532f4)\n2. Save original pointers for second round execution\n3. For each round (first loop, DAT_038532e0 output):\n   - Read bytes from input streams and index lookup tables (DAT_03858b60)\n   - Combine bytes using bit-shift and OR operations (8-bit values shifted to form 32-bit words)\n   - Write processed bytes to output buffer with 6-byte stride\n   - Decrement round counter until zero\n4. Reset input pointers to saved values\n5. Repeat transformation for second round (DAT_038532e4 output) with same algorithm\n6. Decrement input pointer pointers to prepare for next batch\n\nParameters:\n  roundCount (int): Number of AES rounds to process\n\nReturns:\n  void\n\nSpecial Cases:\n  - Uses global state pointers that must be initialized before calling\n  - Modifies global state: advances all pointer positions\n  - Bit-shifting creates 32-bit output from 8-bit lookup table entries\n  - Two independent output buffers (DAT_038532e0, DAT_038532e4) processed separately\n  - Each round processes exactly roundCount iterations\n  - Table arrays are 256-entry lookup tables for byte transformations\n",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8e4f9fa7327245247e1f7aa8c484f3ef",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8e4f9fa7327245247e1f7aa8c484f3ef",
        "CFG": "740225930eaec1e689fe7bf9a726713d",
        "PRO": "954c845cd8fc25114344554abdb67564"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8e4f9fa7327245247e1f7aa8c484f3ef"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_0827e2f12ae6": {
      "addresses": {
        "LoD/PD2": "0x03835940"
      },
      "rvas": {
        "LoD/PD2": "0x15940"
      },
      "sizes": {
        "LoD/PD2": 633
      },
      "name": "ProcessPixelBlockSSE",
      "signature": "void ProcessPixelBlockSSE(int pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Processes pixel blocks using MMX/SSE instructions for image transformations.\\n\\nAlgorithm:\\n1. Initialize output pointers at DAT_038532e0 and DAT_038532e4 with offsets (pixelCount * 32 bytes)\\n2. First loop: Process pixelCount pixels from DAT_038532e8, DAT_038532f0, DAT_038532f4\\n   - Load 32-bit pixel value, unpack to 16-bit channels\\n   - Subtract color adjustment constant (DAT_0384dfb8)\\n   - Scale by multiplier (DAT_0384dfc0) using PMULHW\\n   - Blend color values from three lookup tables: DAT_03854730, DAT_03854f30, DAT_03855330\\n   - Combine and saturate using PADDSW\\n   - Write 32 bytes (8 pixels) to output buffer at DAT_038532e0\\n3. Save loop1 pointers to DAT_038532e8, initialize second loop with DAT_038532e4\\n4. Second loop: Repeat similar processing with DAT_038532ec as input source\\n   - Uses same color lookup tables and blending operations\\n   - Writes to output buffer at DAT_038532e4\\n5. Restore all loop pointers to their global variables\\n\\nParameters:\\n   pixelCount: Number of pixel blocks to process (one iteration = 2 source pixels)\\n\\nReturns:\\n   void (all results written to output buffers at DAT_038532e0 and DAT_038532e4)\\n\\nSpecial Cases:\\n   - Uses unsigned saturated subtraction (PSUBUSW) to prevent underflow\\n   - Uses signed saturated addition (PADDSW) to prevent overflow\\n   - Each iteration processes 2 input pixels and generates 8 output pixels per buffer\\n   - Requires DAT_038532e0-ec, DAT_0384dfb8, DAT_0384dfc0, DAT_0384dfc8 to be initialized\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0827e2f12ae641d0e898a13549be0488",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0827e2f12ae641d0e898a13549be0488",
        "CFG": "07af7631dd984d18ae732ae7a8986d4c",
        "PRO": "2524eafe11b7334e01bd9c0ffb5291f2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0827e2f12ae641d0e898a13549be0488"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_a67df02b5f56": {
      "addresses": {
        "LoD/PD2": "0x038365F0"
      },
      "rvas": {
        "LoD/PD2": "0x165F0"
      },
      "sizes": {
        "LoD/PD2": 154
      },
      "name": "ExpandDataMMXDoubleStream",
      "signature": "void ExpandDataMMXDoubleStream(int nScaleShift)",
      "calling_convention": "__stdcall",
      "comment": "Expands compressed byte data to 16-bit values using MMX SIMD operations on dual parallel streams.\n\nAlgorithm:\n1. Load MMX1 with expansion constant (0x80) from global data for byte unpacking\n2. Load base pointers and limits from globals:\n   - pDestStream0 from 0x038532e0 (destination stream 1)\n   - pDestStream1 from 0x038532e4 (destination stream 2)\n   - pSrcStream0 from 0x038532e8 (source stream 1)\n   - pSrcStream1 from 0x038532ec (source stream 2)\n3. Calculate output limit by adding nScaleShift*16 to initial pDestStream0\n4. Loop: process bytes in parallel:\n   a. Load byte from pSrcStream1, increment pointer\n   b. Unpack low byte using PUNPCKLBW MM5,MM1 to expand to word\n   c. Unpack high byte using PUNPCKHBW MM3,MM1 to expand to word\n   d. Store 16-byte result to pDestStream1[0] and pDestStream1[8]\n   e. Load byte from pSrcStream0, increment pointer\n   f. Repeat unpack/store for stream 0 with offset +8\n   g. Increment both destination pointers by 16 bytes\n   h. Compare pDestStream0 against limit, continue if below\n5. Write back final pointer values to globals\n6. Return (caller pops 4 bytes for nScaleShift parameter)\n\nParameters:\n- nScaleShift: Scale/shift value multiplied by 16 for output buffer size\n\nReturns:\n- void: No return value, modifies global data structures in-place\n\nSpecial Cases:\n- Uses MMX registers (MM1, MM3, MM4, MM5, MM6) for expansion operations\n- Processes two independent byte streams in parallel for performance\n- PUNPCKLBW expands byte to word format by interleaving with 0x80 constants\n- Output buffer size determined by nScaleShift*16 bytes\n- Calling convention is __stdcall (callee pops 4-byte parameter)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a67df02b5f56b4265404723e57bd78f3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a67df02b5f56b4265404723e57bd78f3",
        "CFG": "36af609be59150a2703da74a590941a8",
        "PRO": "10395645a8f04b4fcd301e123ff41df9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a67df02b5f56b4265404723e57bd78f3"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_3aefa5b0160e": {
      "addresses": {
        "LoD/PD2": "0x03836760"
      },
      "rvas": {
        "LoD/PD2": "0x16760"
      },
      "sizes": {
        "LoD/PD2": 145
      },
      "name": "ExpandSIMDBuffer",
      "signature": "void ExpandSIMDBuffer(int iterationCount)",
      "calling_convention": "__stdcall",
      "comment": "Expands SIMD buffer data using MMX byte interleaving.\\n\\nThis function processes image/color data by expanding 32-bit source pixels to 64-bit expanded format using MMX SIMD instructions. It performs byte interleaving and duplication to expand pixel data for display or processing.\\n\\nAlgorithm:\\n1. Load source pointers for input buffers (EDX=sourcePixels, ECX=sourcePixels2)\\n2. Load output pointers for expanded data (EDI=outputA, ESI=outputB)\\n3. Calculate end address by adding iterationCount*16 to initial outputB pointer\\n4. Load expansion mask (MM2) from constant data (0x0384dfe8)\\n5. Enter loop: for each iteration until outputB >= end address\\n6. Load 32-bit pixel value from sourcePixels (EDX)\\n7. Extract color channels: byte0=LL, byte1=LL, byte2=HH, byte3=HH from pixel\\n8. Unpack and duplicate bytes using PUNPCKLBW/PUNPCKHBW to create expanded format\\n9. Write 8 bytes of expanded data to outputA at [EDI] and [EDI+8]\\n10. Load alternate 32-bit pixel from sourcePixels2 (ECX)\\n11. Repeat byte expansion and write 8 bytes to outputB at [ESI] and [ESI+8]\\n12. Advance all pointers: EDX+=4, ECX+=4, EDI+=16, ESI+=16\\n13. Compare ESI to end address, loop if not complete\\n14. Store final output pointer values back to global variables\\n15. Return from function (callee cleanup 4 bytes)\\n\\nParameters:\\n  iterationCount - Number of 16-byte output blocks to process (controls loop count)\\n\\nReturns:\\n  void - Function modifies global output buffers in place\\n\\nSpecial Cases:\\n  - Function uses __stdcall convention (callee cleans 4 bytes from stack)\\n  - Uses MMX registers MM0-MM3 for SIMD operations (no state saved)\\n  - Operates on global pointer variables for input/output buffers\\n  - Expansion mask loaded from constant at 0x0384dfe8\\n  - Loop processes two source streams simultaneously for stereo/dual-channel data",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3aefa5b0160e725b5f48983b69008d0c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3aefa5b0160e725b5f48983b69008d0c",
        "CFG": "7ddaa40ddf3cf9d7ea1ef8d34262c1f7",
        "PRO": "c1c3a0e4640be7b29f5d5f42efc33d1d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3aefa5b0160e725b5f48983b69008d0c"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_60b4aa5bfc39": {
      "addresses": {
        "LoD/PD2": "0x03836800"
      },
      "rvas": {
        "LoD/PD2": "0x16800"
      },
      "sizes": {
        "LoD/PD2": 209
      },
      "name": "TransformPixelBuffers",
      "signature": "void TransformPixelBuffers(int pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Transforms pixel data from two global source buffers into two destination buffers with specific bit encoding. Converts each source byte into a 32-bit encoded pixel value.\n\nAlgorithm:\n1. Read pixelCount parameter and double it (process pairs of bytes)\n2. Load current pointers from global source/dest buffer pairs\n3. Loop for first buffer pair:\n   - Read two consecutive bytes from source buffer\n   - Convert each byte into 32-bit value with pattern: (byte << 24) | 0x800080 | (byte << 8)\n   - Write encoded pixels to destination buffer\n   - Decrement loop counter until zero\n   - Store updated pointers back to globals\n4. Repeat steps 3 for second buffer pair using different global pointers\n5. Return to caller\n\nParameters:\n- pixelCount: Number of pixel pairs to process (0-based count)\n\nReturns:\n- None (void function)\n\nSpecial Cases:\n- Bit pattern 0x800080 is constant for all transformed pixels\n- Each source byte is shifted left 24 bits and 8 bits in the encoded output\n- Function processes two separate buffer pairs sequentially\n- Global pointers are updated after each buffer processing\n\nGlobal Variables Used:\n- DAT_038532e0: Destination buffer 1 pointer\n- DAT_038532e8: Source buffer 1 pointer\n- DAT_038532e4: Destination buffer 2 pointer\n- DAT_038532ec: Source buffer 2 pointer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:60b4aa5bfc3923f4ecac744acc69dc2a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "60b4aa5bfc3923f4ecac744acc69dc2a",
        "CFG": "c64170fb5e0e630810847bf0d721e25a",
        "PRO": "72f8d5b065fe1e2564c38f9d1410e616"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "60b4aa5bfc3923f4ecac744acc69dc2a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_13beb94eea53": {
      "addresses": {
        "LoD/PD2": "0x038368E0"
      },
      "rvas": {
        "LoD/PD2": "0x168E0"
      },
      "sizes": {
        "LoD/PD2": 302
      },
      "name": "ProcessColorConversionBuffers",
      "signature": "void ProcessColorConversionBuffers(int pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Processes two SIMD color conversion buffers using MMX operations.\\n\\nThis function performs vectorized color space transformation on two parallel\\nbuffers of pixels (32 bytes each iteration). It applies saturation arithmetic,\\ncolor space conversion, and component expansion to convert packed color data\\ninto expanded 32-bit values per component.\\n\\nAlgorithm:\\n1. Initialize MMX registers with color transformation constants from global data\\n   - MM7: Color offset (0x0384dfe0)\\n   - MM0: Color threshold (0x0384dfb8) \\n   - MM2: Color multiplier (0x0384dfd0)\\n   - MM5: Color scaling factor (0x0384dfd8)\\n2. Calculate first loop bounds: end pointer = buffer1_base + (pixelCount * 16)\\n3. Process first buffer (DAT_038532e0) in pairs of 32-bit pixels:\\n   - Load 2 consecutive 32-bit pixels from source (DAT_038532e8)\\n   - Unpack bytes to words using PUNPCKLBW with zero-extension\\n   - Apply saturation subtract with colorThreshold using PSUBUSW\\n   - Multiply high words using PMULHW with colorMultiplier\\n   - Apply saturation addition then subtraction with colorOffset (clamping)\\n   - Expand words to dwords using PUNPCKLWD/PUNPCKHWD\\n   - Duplicate each component and write 4 qwords (32 bytes) to output\\n   - Increment source by 8 bytes (2 pixels), output by 32 bytes\\n   - Loop until output pointer >= calculated end\\n4. Update global source/destination pointers for first buffer\\n5. Calculate second loop bounds: end pointer = buffer2_base + (pixelCount * 16)\\n6. Process second buffer (DAT_038532e4) identically using different pointers:\\n   - Uses DAT_038532ec as source, same transformation sequence\\n   - Writes to second buffer destination pointer\\n7. Update global pointers for second buffer completion\\n\\nParameters:\\n  pixelCount [int] - Number of pixels to process in each buffer. Determines\\n                     iteration count. Value is scaled by 16 to compute\\n                     byte offsets for loop termination checks.\\n\\nReturns:\\n  void - No return value. Function updates global buffer pointers and modifies\\n         memory at DAT_038532e0, DAT_038532e4, DAT_038532e8, DAT_038532ec\\n\\nSpecial Cases:\\n  - Empty processing: pixelCount of 0 sets endPointer to current buffer base,\\n    loops execute zero iterations\\n  - MMX state persistence: Function does not EMMS (clear MMX state), caller\\n    must manage MMX state if needed\\n  - Global state updates: All buffer pointer globals are updated; function\\n    has side effects on global state\\n  \\nGlobal Data Dependencies:\\n  Input Constants:\\n    DAT_0384dfe0 - Color offset (MM7)\\n    DAT_0384dfd8 - Color multiplier (MM5)\\n    DAT_0384dfd0 - Color scaling (MM2)\\n    DAT_0384dfb8 - Color threshold (MM0)\\n  \\n  Buffer Pointers (Input/Output):\\n    DAT_038532e0 - Output pointer buffer 1 (advanced by pixelCount*16 bytes)\\n    DAT_038532e8 - Input pointer buffer 1 (advanced by pixelCount*2 dwords)\\n    DAT_038532e4 - Output pointer buffer 2 (advanced by pixelCount*16 bytes)\\n    DAT_038532ec - Input pointer buffer 2 (advanced by pixelCount*2 dwords)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:13beb94eea53a11a16554a8a15f02c75",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "13beb94eea53a11a16554a8a15f02c75",
        "CFG": "10fb45aa849b1660df71d176e9502647",
        "PRO": "27b4b4dee76897c69d26ac374a2f2d47"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "13beb94eea53a11a16554a8a15f02c75"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_36dbf067cd1c": {
      "addresses": {
        "LoD/PD2": "0x03836AF0"
      },
      "rvas": {
        "LoD/PD2": "0x16AF0"
      },
      "sizes": {
        "LoD/PD2": 419
      },
      "name": "ProcessImageColorTransform",
      "signature": "void ProcessImageColorTransform(int colorCount)",
      "calling_convention": "__stdcall",
      "comment": "Transforms image pixel colors using SIMD MMX operations.\n\nAlgorithm:\n1. Calculate end bounds for first source buffer (DAT_038532e8) by multiplying colorCount by 6 and adding to current position\n2. Load scaling constants from global data (MM7=threshold, MM2=matrix coefficients)\n3. First loop: Process source pixels from DAT_038532e8, unpack bytes to words, apply color transformation using matrix multiply and add/subtract operations, store 6 DWORDs per iteration to DAT_038532e0\n4. Update source pointer and loop until reaching calculated end bound\n5. Perform identical transformation for second source buffer (DAT_038532ec) writing to DAT_038532e4\n6. Update both output buffer pointers and source buffer pointers\n7. Return to caller\n\nParameters:\n  colorCount (int): Number of color units to process; multiplied by 6 to calculate stride increment (represents processing 6 output bytes per color unit)\n\nReturns:\n  void: Function modifies global output buffers in-place (DAT_038532e0 and DAT_038532e4)\n\nSpecial Cases:\n  Magic numbers: Multiplication by 6 (colorCount * 6) indicates fixed 6-byte output structure per color unit\n  SIMD operations: Uses MMX registers MM0-MM7 for parallel byte/word unpacking and arithmetic\n  Global data dependencies: Operates on four global pointers (DAT_038532e0, DAT_038532e4, DAT_038532e8, DAT_038532ec) and two global coefficient buffers (DAT_0384dfb8, DAT_0384dfc0)\n  \nAlgorithm Details:\n  The transformation performs: output[i] = (input[i] - threshold) << 2 * matrix_coeff >> shifts + offset\n  Each input byte is expanded to 4 16-bit words, multiplied by matrix coefficients, shifted, and repacked to 4 DWORDs\n  Two source buffers are processed identically with separate output and source pointers maintained",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:36dbf067cd1cc8455ecabee2e6454057",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "36dbf067cd1cc8455ecabee2e6454057",
        "CFG": "75db3859b18a7cf4edfc15212ce3d72b",
        "PRO": "0376d2c447b9994358fc4f25300f3984"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "36dbf067cd1cc8455ecabee2e6454057"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_3e954fc91b35": {
      "addresses": {
        "LoD/PD2": "0x03836E20"
      },
      "rvas": {
        "LoD/PD2": "0x16E20"
      },
      "sizes": {
        "LoD/PD2": 442
      },
      "name": "ScaleColorChannels",
      "signature": "void ScaleColorChannels(int pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Scales ARGB color channels using MMX SIMD operations on two separate pixel buffers.\n\nAlgorithm:\n1. Initialize MMX registers with global color constants (offset 0x0384dfb8, scale multiplier 0x0384dfc0, bias 0x0384dfc8)\n2. Load first loop end address by multiplying pixelCount by 32 bytes per iteration\n3. First loop: Process pixels from DAT_038532e8 (source) to DAT_038532e0 (destination)\n   a. Load two 32-bit ARGB pixels via MOVD into MM3/MM6\n   b. Unpack bytes to words, subtract color offset using PSUBUSW (saturating subtract)\n   c. Scale shifted values (<<2) with multiply-high (PMULHW) against multiplier\n   d. Add and subtract bias values for DC offset adjustment\n   e. Expand words to dwords via PUNPCKLWD/PUNPCKHWD and multiply by mode matrix (MM2 loads)\n   f. Write 8 expanded dword values (32 bytes total) to output buffer\n4. Update pointers: ECX += 8, ESI += 0x40, loop until ESI >= calculated end\n5. Second loop: Same operations on DAT_038532ec (source) to DAT_038532e4 (destination)\n6. Update global state pointers and return\n\nParameters:\n  pixelCount: int - Number of 32-bit ARGB pixels to process (loop count multiplied by 32 = byte offset)\n\nReturns:\n  void - Modifies global color buffers in-place. Updates DAT_038532e0, DAT_038532e8, DAT_038532e4, DAT_038532ec\n\nSpecial Cases:\n  - Uses global color constants at 0x0384dfb8 (color offset), 0x0384dfc0 (scale multiplier), 0x0384dfc8 (bias/DC offset), 0x0384e010 (mode matrix)\n  - Saturating operations (PSUBUSW) ensure underflow wraps to 0\n  - PMULHW takes high 16 bits of 32-bit product, implementing fixed-point scaling\n  - Each input pixel (4 bytes) expands to 8 output dwords (32 bytes) via PUNPCKLDQ duplication\n  - Loop condition uses carry flag (JC) which may indicate signed comparison behavior",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3e954fc91b35aecb4cbd284d72a6d689",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3e954fc91b35aecb4cbd284d72a6d689",
        "CFG": "0e6962363b6bed9836da775f4a8e2fbe",
        "PRO": "d9becd2da52551bd0fad69f26e0cb725"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3e954fc91b35aecb4cbd284d72a6d689"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_ab123c1c9af7": {
      "addresses": {
        "LoD/PD2": "0x038370D0"
      },
      "rvas": {
        "LoD/PD2": "0x170D0"
      },
      "sizes": {
        "LoD/PD2": 220
      },
      "name": "ConvertPackedPixelsToQuads",
      "signature": "void ConvertPackedPixelsToQuads(int elementCount)",
      "calling_convention": "__stdcall",
      "comment": "Converts packed pixels from three source streams to two interleaved quad streams using MMX instructions.\n\nAlgorithm:\n1. Load element count from stack parameter\n2. Calculate destination limits for both output buffers\n3. First loop: Load packed DWORDs from sourceA, sourceB, and sourceC\n4. Unpack bytes using PUNPCKLBW and PUNPCKHBW MMX instructions to interleave low/high bytes\n5. Store 16-byte results (8-byte chunks) to first destination buffer\n6. Increment source pointers and check if limit reached\n7. Second loop: Repeat process for second pair of destinations\n8. Store final pointer positions to global state\n\nParameters:\n- elementCount: Number of 8-byte elements to process for each loop\n\nReturns:\n- No explicit return value (void); return value in EAX is undefined\n\nSpecial Cases:\n- Uses carry flag (JC) as loop terminator; loop continues while EDI < calculated limit\n- Processes data in 16-byte strides per iteration (8-byte output twice)\n- Global state stored at fixed addresses (038532e0, 038532e4, 038532e8, 038532ec)\n\nStructure Layout:\nThis function operates on global pixel/codec buffers:\n- DAT_038532e0: First destination buffer (output)\n- DAT_038532e4: Second destination buffer (output)  \n- DAT_038532e8: Source stream C pointer (8-byte chunks)\n- DAT_038532ec: Source stream C pointer copy (8-byte chunks)\n- DAT_038532f0: Source stream A pointer (4-byte chunks)\n- DAT_038532f4: Source stream B pointer (4-byte chunks)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ab123c1c9af789e56861cac17cfe8edd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ab123c1c9af789e56861cac17cfe8edd",
        "CFG": "848659e8af920bdcf4542618871483e6",
        "PRO": "6e9103f3735b0ce251fd018b314765b4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ab123c1c9af789e56861cac17cfe8edd"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_ADDR_03837280": {
      "addresses": {
        "LoD/PD2": "0x03837280"
      },
      "rvas": {
        "LoD/PD2": "0x17280"
      },
      "sizes": {
        "LoD/PD2": 220
      },
      "name": "InterleavePixelDataMMX",
      "signature": "uint InterleavePixelDataMMX(uint pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Interleaves pixel bytes from two source buffers using MMX SIMD operations.\n\nThis function performs parallel pixel byte reordering by reading from two 32-bit source\npixels and writing interleaved byte patterns to two 64-bit destination locations. It uses\nMMX unpacking instructions (PUNPCKLBW/PUNPCKHBW) to rearrange pixel color channels for\nformat conversion or data layout optimization.\n\nAlgorithm:\n1. Load pixelCount parameter (count * 8 bytes of data to process)\n2. Calculate destination end pointer for first buffer as dest1 + pixelCount*8 - 16\n3. Load source pointers and destination pointer from global variables\n4. First loop: Process pixels from source buffers 0x38532f0/0x38532f4 to dest 0x38532e0\n   - Read 4-byte pixels from srcPtrB and srcPtrA\n   - Read 8-byte pixel data from 0x38532e8 source\n   - Use PUNPCKLBW to unpack low bytes, PUNPCKHBW for high bytes\n   - Write 16 bytes (two 8-byte results) to destination buffer\n   - Continue until destPtr >= destEndPtr\n5. Update global pointers after first loop\n6. Repeat same process for second buffer pair (0x38532f0/0x38532f4 \u2192 0x38532e4)\n7. Return value in EAX (preserved from function entry)\n\nParameters:\n  pixelCount: Number of pixels to process (multiplied by 8 for byte count)\n\nReturns:\n  Value preserved in EAX register at function entry (typically status or count)\n\nSpecial Cases:\n  - Magic number: -0x10 (subtract 16) adjusts destination end calculation for final 16-byte write\n  - Carry flag (JC) used as loop terminator for unsigned comparison\n  - Global variable access: Accesses 8 global pointers for source/dest buffer management\n  - MMX registers: Uses MM1, MM2, MM6 for packed byte operations\n  - No validation: Assumes valid pixelCount and buffer pointers",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ab123c1c9af789e56861cac17cfe8edd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ab123c1c9af789e56861cac17cfe8edd",
        "CFG": "848659e8af920bdcf4542618871483e6",
        "PRO": "6e9103f3735b0ce251fd018b314765b4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ab123c1c9af789e56861cac17cfe8edd"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_a6afb995e05e": {
      "addresses": {
        "LoD/PD2": "0x03837430"
      },
      "rvas": {
        "LoD/PD2": "0x17430"
      },
      "sizes": {
        "LoD/PD2": 260
      },
      "name": "ApplyMMXTransformToPixels",
      "signature": "void ApplyMMXTransformToPixels(int pixelCount)",
      "calling_convention": "__stdcall",
      "comment": "Applies MMX-based SIMD color transformation to pixel buffers using saturating arithmetic and multiplier coefficients. Processes two parallel pixel streams with identical transformations.\n\nAlgorithm:\n1. Load transformation coefficients from global data (colorOffset MM7, colorKey MM0, alphaMultiplier MM5, colorMask MM2)\n2. First loop: Process pixels starting from DAT_038532e0, iterating by count*8 bytes\n   a. Load source pixel pair from input buffer DAT_038532e8 (4 bytes at a time)\n   b. Unpack bytes to 16-bit words using PUNPCKLBW with zero padding\n   c. Apply saturating subtraction (PSUBUSW) with colorKey (offset green/blue channels)\n   d. Multiply by alphaMultiplier using signed multiply (PMULHW)\n   e. Apply saturating addition (PADDSW) with colorOffset (clipping operation)\n   f. Saturating subtract colorOffset again (normalization)\n   g. Multiply final result by color mask (PMULLW) to scale to output range\n   h. Store 8-byte result to destination buffer\n3. Second loop: Identical transformation on second pixel stream starting from DAT_038532ec\n   a. Process DAT_038532e4 output buffer in parallel\n   b. Same SIMD transformations as first loop\n4. Update global state pointers (DAT_038532e0, DAT_038532e8, DAT_038532e4, DAT_038532ec)\n\nParameters:\n- pixelCount (int): Number of pixel pairs to process (multiplied by 8 for byte count)\n\nReturns:\n- void (function updates global pixel buffers in-place)\n\nSpecial Cases:\n- Saturating arithmetic prevents overflow/underflow in color channels\n- PUNPCKLBW expands 8-bit values to 16-bit for processing\n- Two independent loops allow parallel processing of separate data streams\n- Global data pointers track processing progress across calls",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a6afb995e05ed8b4949ab7c47b1a1096",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a6afb995e05ed8b4949ab7c47b1a1096",
        "CFG": "39d10b745040e489c91a7b7222f1714b",
        "PRO": "50cc66d1f2987320f304866916043881"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a6afb995e05ed8b4949ab7c47b1a1096"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_2fa7de2c7354": {
      "addresses": {
        "LoD/PD2": "0x03837630"
      },
      "rvas": {
        "LoD/PD2": "0x17630"
      },
      "sizes": {
        "LoD/PD2": 425
      },
      "name": "BlendColorsMMX",
      "signature": "void BlendColorsMMX(int colorCount)",
      "calling_convention": "__stdcall",
      "comment": "Blends colors using MMX SIMD operations on two parallel data streams.\n\nAlgorithm:\n1. Load color count and calculate loop boundaries for both data streams (A and B)\n2. Initialize MMX registers with color bias, scale, and coefficients from globals\n3. Loop A: Process first data stream pixel pairs\n   - Load 4-byte source pixels from data stream A\n   - Unpack bytes to words and subtract color offset\n   - Scale and multiply by color coefficients\n   - Pack results and write to output buffer\n4. Loop B: Process second data stream pixel pairs similarly\n5. Store final pointers back to globals\n\nParameters:\n  colorCount (int): Number of color entries to process; multiplied by 12 to calculate buffer stride\n\nReturns:\n  void\n\nSpecial Cases:\n  - Uses MMX registers (MM0-MM7) for parallel SIMD operations\n  - Processes two independent color streams in sequence\n  - Each iteration processes 2 source pixels (8 bytes) producing 3 output qwords (24 bytes)\n  - Color data layout uses global pointers at 0x038532e0, 0x038532e4, 0x038532e8, 0x038532ec\n  - Coefficients and bias loaded from globals 0x0384dfc8, 0x0384dfc0, 0x0384dfb8, 0x0384e020",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2fa7de2c7354176ce7249452610adecf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2fa7de2c7354176ce7249452610adecf",
        "CFG": "e7e0be74d27bf487e1de1b1227fbfc76",
        "PRO": "063a1f4c4317492afde1a445301475a4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2fa7de2c7354176ce7249452610adecf"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_a8db7f6923ce": {
      "addresses": {
        "LoD/PD2": "0x038377D9"
      },
      "rvas": {
        "LoD/PD2": "0x177D9"
      },
      "sizes": {
        "LoD/PD2": 289
      },
      "name": "UnpackTableDataFromLookups",
      "signature": "void UnpackTableDataFromLookups(uint dataCount)",
      "calling_convention": "__stdcall",
      "comment": "Unpacks 8-bit indexed byte data into 24-bit unpacked values from lookup tables.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a8db7f6923ceeb2faef0958847dff7ed",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a8db7f6923ceeb2faef0958847dff7ed",
        "CFG": "31583aa057651ebe75e90088c16b509e",
        "PRO": "146cb7ec808eefb7beaa7a1f55222a8d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a8db7f6923ceeb2faef0958847dff7ed"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_218251a95872": {
      "addresses": {
        "LoD/PD2": "0x03837900"
      },
      "rvas": {
        "LoD/PD2": "0x17900"
      },
      "sizes": {
        "LoD/PD2": 332
      },
      "name": "ProcessPixelColorTransform",
      "signature": "void ProcessPixelColorTransform(int blockCount)",
      "calling_convention": "__stdcall",
      "comment": "Applies 2D matrix color transformation to pixel arrays using MMX SIMD processing.\nTransforms 32-bit BGRA color values through matrix multiplication in two parallel loops.\n\nAlgorithm:\n1. Load transformation matrices from memory (stored in MM registers)\n   - MM0: Subtraction bias for color extraction\n   - MM2: 2x2 matrix for per-color multiplication\n   - MM5: Clipping bias for saturation\n   - MM7: Output multiplication matrix (loaded per pixel)\n\n2. First loop processes source array (DAT_038532e8):\n   - Extract BGRA channels via byte unpacking with PSUBUSW\n   - Multiply each channel by matrix row via PMULLW\n   - Apply saturation via PADDSW/PSUBUSW\n   - Store four 32-bit results (4 x 8 bytes) to destination\n\n3. Second loop processes alternate source array (DAT_038532ec):\n   - Identical transformation pipeline for second data stream\n   - Interleaved with first loop to maximize cache locality\n\nReturn: void\nParameters: blockCount - number of 4x4 pixel blocks to process (param @ esp+0x14)\nSpecial Cases: Uses unsaturated arithmetic for color clamping",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:218251a95872327c4c9521d75c6c0d4b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "218251a95872327c4c9521d75c6c0d4b",
        "CFG": "a90da09c5f996c084264596427201a9f",
        "PRO": "0b5417a85e84363f1acc0bf87369df97"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "218251a95872327c4c9521d75c6c0d4b"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_a29c6f6b8852": {
      "addresses": {
        "LoD/PD2": "0x03837B30"
      },
      "rvas": {
        "LoD/PD2": "0x17B30"
      },
      "sizes": {
        "LoD/PD2": 135
      },
      "name": "ExpandByteStreamsWithMMX",
      "signature": "void ExpandByteStreamsWithMMX(int expandCount)",
      "calling_convention": "__stdcall",
      "comment": "MMX-based byte stream expansion with parallel processing.\\n\\nAlgorithm:\\n1. Load MMX template value from global data (0x0384dfe8)\\n2. Loop 1: Read 4 bytes, expand to 8 bytes using MMX shuffle, write to buffer 1\\n   - Reads from input stream at 0x038532e8\\n   - Writes to output buffer at 0x038532e0\\n   - Repeats expandCount times\\n3. Advance output buffer 1 pointer by expandCount*8 bytes\\n4. Loop 2: Read 4 bytes, expand to 8 bytes using MMX shuffle, write to buffer 2\\n   - Reads from input stream at 0x038532ec\\n   - Writes to output buffer at 0x038532e4\\n   - Repeats expandCount times\\n5. Update global output buffer pointers for next operation\\n\\nParameters:\\n  expandCount (ESP+0x14): Number of 4-byte chunks to expand per loop\\n\\nReturns:\\n  void\\n\\nSpecial Cases:\\n  - Uses MMX MOVD to load 32-bit value and PUNPCKLBW for byte interleaving\\n  - Template bytes (bits 8,16,24 of MMX register) used for expansion pattern\\n  - Two parallel streams allow independent buffer processing",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a29c6f6b8852ae51ffee703d5020b178",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a29c6f6b8852ae51ffee703d5020b178",
        "CFG": "296c973b6099cf5e37a1afccb008c828",
        "PRO": "6ebd5c41ddf79395a0653a81874d5721"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a29c6f6b8852ae51ffee703d5020b178"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_27f8216ed3d0": {
      "addresses": {
        "LoD/PD2": "0x03837C60"
      },
      "rvas": {
        "LoD/PD2": "0x17C60"
      },
      "sizes": {
        "LoD/PD2": 150
      },
      "name": "SwapBytesWithMMX",
      "signature": "void SwapBytesWithMMX(uint byteCount)",
      "calling_convention": "__stdcall",
      "comment": "SwapBytesWithMMX - Byte-swap operation using MMX PUNPCKLBW instruction\n\nPerforms endianness conversion on two data buffers using MMX bit manipulation.\nProcesses incoming byte stream through a fixed byte-swap pattern and writes\nresults to two separate output buffers. Uses PUNPCKLBW to rearrange bytes\nin parallel, enabling fast byte reordering for data format conversion.\n\nAlgorithm:\n1. Load MMX swap pattern from global constant (0x0384dfe8)\n2. Calculate end position for buffer1 (DAT_038532e0 + byteCount*8)\n3. Loop: Read 4-byte chunk, apply PUNPCKLBW swap, write 8-byte result to buffer1\n4. Repeat step 3 until buffer1 pointer reaches calculated end\n5. Calculate end position for buffer2 (DAT_038532e4 + byteCount*8)\n6. Loop: Read 4-byte chunk, apply PUNPCKLBW swap, write 8-byte result to buffer2\n7. Update global pointers: DAT_038532e0, DAT_038532e8, DAT_038532e4, DAT_038532ec\n8. Return\n\nParameters:\nbyteCount (param_1) - Number of 4-byte chunks to process (count, not byte length)\n\nReturns:\nvoid - Results written to global buffers\n\nSpecial Cases:\n- Uses MMX registers MM1 and MM2 (8-byte operations on PUNPCKLBW)\n- Both loops process same number of iterations based on byteCount parameter\n- Global pointers DAT_038532e0, DAT_038532e8 used for buffer1 stream\n- Global pointers DAT_038532e4, DAT_038532ec used for buffer2 stream\n- Swap pattern in DAT_0384dfe8 is loaded once and reused for all conversions\n- RET 0x4 indicates callee cleanup (stdcall convention)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:27f8216ed3d05dbba3a5ee80528537a9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "27f8216ed3d05dbba3a5ee80528537a9",
        "CFG": "9beea34542ffda67ce220aa5425847c5",
        "PRO": "42e6a38e2a5a0728776770047851c35c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "27f8216ed3d05dbba3a5ee80528537a9"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_84496cc2c078": {
      "addresses": {
        "LoD/PD2": "0x03837DB0"
      },
      "rvas": {
        "LoD/PD2": "0x17DB0"
      },
      "sizes": {
        "LoD/PD2": 134
      },
      "name": "ProcessVectorWithCapacity",
      "signature": "void ProcessVectorWithCapacity(int dataSize, int signFlag, float * sourceArray, int * capacityPtr, float * destArray)",
      "calling_convention": "__cdecl",
      "comment": "Processes a vector with capacity validation and conditional operations.\n\nAlgorithm:\n1. Check if current capacity (*capacityPtr * 4) is less than dataSize\n2. If capacity exceeded, call FUN_03837e40 with scaled dataSize (dataSize >> 2)\n3. If dataSize > 4 bytes:\n   - Check signFlag: if >= 0, call FUN_03837f20 and FUN_03838300 (positive path)\n   - If signFlag < 0, call FUN_038380e0 and FUN_03838480 (negative path)\n4. Else if dataSize == 4, call FUN_03838300 directly\n5. Return without value\n\nParameters:\n- dataSize: Size of data in bytes to process (typically a power of 2)\n- signFlag: Control flag determining processing path (>= 0 or < 0)\n- sourceArray: Input float array or vector data\n- capacityPtr: Pointer to capacity value (dereferenced as *capacityPtr)\n- destArray: Output float array or result buffer\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- Capacity check: *capacityPtr is multiplied by 4 before comparison\n- Size boundaries: 4-byte threshold determines which processing function is called\n- signFlag threshold: -1 is the boundary for path selection (values >= 0 vs < 0)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:84496cc2c0783229f3d1137e0181356d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "84496cc2c0783229f3d1137e0181356d",
        "CFG": "671604d04112667648946b8cbd957bb7",
        "PRO": "635b1d992f370bad34200be66a5f368e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "84496cc2c0783229f3d1137e0181356d"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_ce2cfe540a9c": {
      "addresses": {
        "LoD/PD2": "0x03837E40"
      },
      "rvas": {
        "LoD/PD2": "0x17E40"
      },
      "sizes": {
        "LoD/PD2": 219
      },
      "name": "InitializeFourierLookupTable",
      "signature": "void InitializeFourierLookupTable(int tableSize, int * pCapacityPtr, float * pLookupTable)",
      "calling_convention": "__cdecl",
      "comment": "Initializes a Fourier transform lookup table with precomputed trigonometric values.\\n\\nAlgorithm:\\n1. Store input tableSize in output capacity (*pCapacityPtr = tableSize)\\n2. Initialize pCapacityPtr[1] = 1 (capacity indicator)\\n3. If tableSize <= 2, return early (insufficient size for processing)\\n4. Calculate halfSize = tableSize >> 1 (divide by 2)\\n5. Compute angleStep using atan(DAT_03847ce8, 1) for angle increment\\n6. Initialize lookup table: pLookupTable[0] = 1.0, pLookupTable[1] = 0.0\\n7. Precompute cos(angleStep) values at halfSize positions\\n8. Fill main lookup table loop from index 2 to halfSize:\\n   - Compute angle = param_1 * (angleStep / halfSize)\\n   - Store cos(angle) and sin(angle) at positions [param_1] and [param_1+1]\\n9. Fill symmetric positions: Mirror lower indices to upper indices\\n   - For each computed value, copy to symmetric position from end\\n10. Call FUN_03837f20 to finalize the lookup table structure\\n\\nParameters:\\n- tableSize: Size of the lookup table to create (must be > 2)\\n- pCapacityPtr: Pointer to capacity integer, updated with tableSize\\n- pLookupTable: Output float array for trigonometric lookup values\\n\\nReturns:\\n- void: No return value; modifies pCapacityPtr and pLookupTable in place\\n\\nSpecial Cases:\\n- If tableSize <= 2, function returns immediately without processing\\n- Uses floating-point operations (FLD, FPATAN, FCOS, FSIN, FMUL, FDIV)\\n- Depends on global data at DAT_03847ce8 for angle calculation\\n- Calls FUN_03837f20 for post-processing when tableSize > 2\\n\\nStructure Layout:\\nThe function populates pLookupTable with cos/sin pairs:\\n  Offset  Size  Field Name         Type     Description\\n  0x0     4     base_cos           float    cos(0.0) = 1.0\\n  0x4     4     base_sin           float    sin(0.0) = 0.0\\n  0x8+    8*N   trig_pairs         float[]  Alternating cos/sin values",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ce2cfe540a9cebc3ca11931145d2bb88",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ce2cfe540a9cebc3ca11931145d2bb88",
        "CFG": "ffa55fbc031f36713c20c057f05d9937",
        "PRO": "8e47e9907f46a3b4449baa41b970f877"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ce2cfe540a9cebc3ca11931145d2bb88"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_6d594acde8dd": {
      "addresses": {
        "LoD/PD2": "0x03837F20"
      },
      "rvas": {
        "LoD/PD2": "0x17F20"
      },
      "sizes": {
        "LoD/PD2": 445
      },
      "name": "BitReversalPermutation",
      "signature": "void BitReversalPermutation(int elementCount, int * indexArray, float * dataArray)",
      "calling_convention": "__cdecl",
      "comment": "Bit-Reversal Permutation (BRP) for FFT preprocessing. Reorders floating-point array elements according to binary-reversed indices, essential for in-place FFT computation.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6d594acde8ddc54df55a8bd26d568037",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6d594acde8ddc54df55a8bd26d568037",
        "CFG": "2579cec2f377ae3df36f988c7bf80f4f",
        "PRO": "ec2c188327c427212f855c719f6821c0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6d594acde8ddc54df55a8bd26d568037"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_6531cfccbbb2": {
      "addresses": {
        "LoD/PD2": "0x038380E0"
      },
      "rvas": {
        "LoD/PD2": "0x180E0"
      },
      "sizes": {
        "LoD/PD2": 532
      },
      "name": "ComputeFFTTransform",
      "signature": "void ComputeFFTTransform(int fftSize, int * strideTable, float * complexData)",
      "calling_convention": "__cdecl",
      "comment": "Computes in-place Cooley-Tukey radix-2 Fast Fourier Transform (FFT) on complex floating-point data.\n\nAlgorithm:\n1. Build stride table: Recursively halve FFT size (right shift) and copy values with stride offsets\n2. Negate imaginary part of first element (twiddle factor w=exp(-2\u03c0i/N))\n3. Perform butterfly operations: Two phases based on size relationship with stride\n   - Phase 1: Process when 4*levelSize == fftSize (exact fit, dual-path butterfly)\n   - Phase 2: Process when 4*levelSize < fftSize (oversized, single-path butterfly)\n4. Within each butterfly phase: Swap and negate complex values in stride pattern\n5. Multiple nested loops iterate through stride levels and buffer positions\n\nParameters:\n- fftSize: Input array size (power of 2, used to build stride table; shifted right each iteration)\n- strideTable: Array of stride offsets for indexing into complexData\n- complexData: Pointer to float array storing complex numbers (real at [i], imaginary at [i+1] for each element)\n\nReturns:\n- void (modifies complexData in-place)\n\nSpecial Cases:\n- fftSize <= 4: Skips stride table computation (no recursion needed)\n- 4*levelSize == fftSize: Uses dual-butterfly path with two butterfly pairs per iteration\n- 4*levelSize < fftSize: Uses single-butterfly path with one butterfly pair per iteration\n- Imaginary components are negated throughout using FCHS (float change sign) instruction\n- All array accesses use scaled indexing (multiply index by 4 bytes per dword, 8 bytes per complex number)\n\nStructure Layout:\nEach complex number occupies 8 bytes:\n  Offset  Size  Field Name  Type   Description\n  0       4     real        float  Real component\n  4       4     imag        float  Imaginary component (stored negated)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6531cfccbbb21b1dc38462acc36d9996",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6531cfccbbb21b1dc38462acc36d9996",
        "CFG": "f73931ed23ac75b4cfb12cc4176e38c7",
        "PRO": "ba64ead09b43fdaa4b53d079bf1e2197"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6531cfccbbb21b1dc38462acc36d9996"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_75c635154499": {
      "addresses": {
        "LoD/PD2": "0x03838300"
      },
      "rvas": {
        "LoD/PD2": "0x18300"
      },
      "sizes": {
        "LoD/PD2": 375
      },
      "name": "FFTStockhamAlgorithm",
      "signature": "void FFTStockhamAlgorithm(int fftSize, float * dataBuffer, int stride)",
      "calling_convention": "__cdecl",
      "comment": "Performs in-place Fast Fourier Transform (FFT) using Stockham algorithm\n\nAlgorithm:\n1. If fftSize > 15: call FUN_038388c0 for base case (16-point transform)\n2. If fftSize > 127: iteratively process split factors (16, 256, 4096, ...)\n   - Loop through split factors: 16, 128, 1024, 8192, etc.\n   - For each split: call FUN_03839140 to perform radix-2/4 butterfly operations\n3. If fftSize == 2*splitFactor: Perform final merge stage\n   - Combine FFT results using simple complex additions/subtractions\n   - Process pairs of complex floats at offsets 0, n, and 2n\n4. If fftSize > 2*splitFactor: Perform Stockham butterfly operations\n   - Process overlapping groups of 4 complex floats at strides n, 2n, 3n\n   - Compute complex arithmetic with twiddle factors\n   - Each butterfly: Y[0] = X[0] + X[2n], Y[n] = X[0] - X[2n], etc.\n\nParameters:\n- fftSize: Size of FFT (number of complex samples)\n- dataBuffer: Pointer to interleaved float pairs (real, imag) forming complex numbers\n- stride: Distance between consecutive elements in data buffer\n\nReturns:\n- void (modifies dataBuffer in-place)\n\nSpecial Cases:\n- fftSize <= 2: No processing needed\n- fftSize in range 3-15: Only base case processing\n- fftSize == 16: Single split factor iteration\n- fftSize > 127: Multiple split factor iterations with geometric progression\n- Butterfly operations use x87 FPU stack for complex arithmetic\n- All arithmetic performed with IEEE 754 single-precision floats",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:75c635154499e74b2fac028cc68f00c7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "75c635154499e74b2fac028cc68f00c7",
        "CFG": "bb28c8709c2470002aef7003d0f248bd",
        "PRO": "f326e25e48136e3d00f9904198614782"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "75c635154499e74b2fac028cc68f00c7"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_44239be557ec": {
      "addresses": {
        "LoD/PD2": "0x03838480"
      },
      "rvas": {
        "LoD/PD2": "0x18480"
      },
      "sizes": {
        "LoD/PD2": 1088
      },
      "name": "ApplyFFTButterflyOperations",
      "signature": "void ApplyFFTButterflyOperations(int dataSize, float * pFloatData, int metadataPtr)",
      "calling_convention": "__cdecl",
      "comment": "Applies FFT butterfly operations for odd-indexed Stockham FFT stages.\n\nAlgorithm:\n1. Determine processing size based on dataSize:\n   - If dataSize <= 0x10: skip preprocessing, set stageSize = 2\n   - If dataSize <= 0x80: skip large preprocessing, set stageSize = 0x10\n   - If dataSize > 0x80: call FUN_038388c0 for preprocessing, then loop calling FUN_03839140\n2. Initialize base pointers to stride-aligned positions:\n   - ptrOutputBase points to first element [dataSize]\n   - Additional pointers point to elements at strides [dataSize*N] for N=1..7\n3. Calculate twiddle factor from metadata at offset +8: *(float*)(metadataPtr + 8)\n4. For each butterfly iteration:\n   - Compute butterfly equations combining pairs of complex inputs\n   - Apply twiddle factor multiplications with sign reversals\n   - Store 8 complex output values back to strided positions\n5. Handle edge cases for remaining iterations when dataSize doesn't align to 4\n\nParameters:\n- dataSize: FFT size (power of 2, typically 16+)\n- pFloatData: Input/output float array containing complex numbers as interleaved real/imaginary pairs\n- metadataPtr: Pointer to metadata structure containing twiddle factors at offset +8\n\nReturns:\n- void: Modifies pFloatData in-place with butterfly operation results\n\nSpecial Cases:\n- Size 2-15: No preprocessing, processes as single stage\n- Size 16-127: Single preprocessing pass, processes remaining elements\n- Size 128+: Multiple preprocessing passes, processes in aligned chunks\n- Edge case handling: Separate paths for dataSize == 4*stageSize and intermediate sizes\n- Floating-point operations: Heavy FPU usage with careful register stack allocation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:44239be557eccfb60e886d0349f6f3db",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "44239be557eccfb60e886d0349f6f3db",
        "CFG": "dce73cdc838a8698289ea193249a7670",
        "PRO": "f437044b8194178cd28213525bb364f6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "44239be557eccfb60e886d0349f6f3db"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_38e7e4d94382": {
      "addresses": {
        "LoD/PD2": "0x038388C0"
      },
      "rvas": {
        "LoD/PD2": "0x188C0"
      },
      "sizes": {
        "LoD/PD2": 2169
      },
      "name": "ComputeFFTButterflyStage",
      "signature": "void ComputeFFTButterflyStage(int stageSize, float * complexDataArray, int twiddleTableOffset)",
      "calling_convention": "__cdecl",
      "comment": "Computes a single FFT butterfly stage with optional twiddle factor scaling\n\nAlgorithm:\n1. Extract twiddle factor cos value from param_3+8\n2. Compute basic butterfly operations on 8 complex values (16 floats)\n   - Load: param_2[0-7] contains first 8 floats\n   - Sums: Add pairs in different combinations\n   - Differences: Subtract pairs in different combinations\n   - Compute 9 intermediate results (fVar1-fVar9)\n3. Apply twiddle factors and store results back to param_2[0-15]\n4. If stageSize > 0x10: Process 8 more complex values (param_2[16-31])\n   - Load additional twiddle factors from param_3+0x10 and +0x14\n   - Compute similar butterfly operations\n   - Apply complex multiplication with twiddle factors\n5. If stageSize > 0x20: Enter loop for remaining 16-byte aligned chunks\n   - For each remaining stage: Load new twiddle factors (param_3+0x18+offset)\n   - Perform 4 butterfly operations on 8 complex values per iteration\n   - Complex multiply each result by twiddle factors\n   - Store results, increment pointers, loop until done\n\nParameters:\n- stageSize (param_1): FFT stage size determining butterfly count (8, 16, 32+)\n- complexDataArray (param_2): Input/output complex data (real,imag pairs as floats)\n- twiddleTableOffset (param_3): Pointer to twiddle factor table with cos/sin pairs\n\nReturns:\n- void (all results stored to complexDataArray)\n\nSpecial Cases:\n- Accesses global _DAT_03847cf0 (constant 1.0) in loop section at address 0x03847cf0\n- Stage size of 8 (no conditional branches) performs single butterfly pass\n- Stage size 16-31 performs two stages and exits\n- Stage size 32+ enters iterative loop processing 16-value blocks\n- Twiddle factors stored as: [cos, sin, cos, sin, ...] pattern\n- Stack allocation: 0x78 bytes (30 local float variables for FPU computations)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:38e7e4d94382f9b6f32d4b3a75691f45",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "38e7e4d94382f9b6f32d4b3a75691f45",
        "CFG": "9954f97af7330b582b809687bbece937",
        "PRO": "678dae85dbacb6d983c909b53111229d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "38e7e4d94382f9b6f32d4b3a75691f45"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_ce7f840a567f": {
      "addresses": {
        "LoD/PD2": "0x03839140"
      },
      "rvas": {
        "LoD/PD2": "0x19140"
      },
      "sizes": {
        "LoD/PD2": 3169
      },
      "name": "ProcessFFTButterflyStage",
      "signature": "void ProcessFFTButterflyStage(int stageNumber, int butterflyCount, float * dataArray, int twiddleFactorAddress)",
      "calling_convention": "__cdecl",
      "comment": "Processes one stage of FFT butterfly operations using Stockham algorithm.\\n\\nAlgorithm:\\n1. Load twiddle factor base value from twiddleFactorAddress+8 for stage 0-2 operations\\n2. Calculate pointer offsets for all 8 butterfly data blocks (stages 0-7) within dataArray\\n3. For stages 0-2: Process small butterflies with single twiddle factor (butterflyCount iterations)\\n4. For stages 3-5: Check if butterflyCount*8 < stageNumber to skip if buffer exhausted\\n5. Process medium butterflies with twiddle factors at offset +0x10, +0x14 (butterflyCount*8 iterations)\\n6. For stages 6-7: Check if butterflyCount*16 < stageNumber to skip if buffer exhausted\\n7. Process large butterflies with 4 complex twiddle factors from twiddleFactorAddress+0x18\\n8. Each butterfly applies rotations using precomputed cos/sin pairs stored at offset +0x28, +0x2c\\n\\nParameters:\\nstageNumber: int - Current FFT stage (0-based), determines data block arrangement and stride\\nbutterflyCount: int - Number of butterfly operations per iteration (controls loop count)\\ndataArray: float * - Complex FFT data array (interleaved real/imaginary as floats)\\ntwiddleFactorAddress: int - Base address of twiddle factor table with 8 complex values per stage\\n\\nReturns:\\nvoid - Modifies dataArray in-place with FFT butterfly operation results\\n\\nSpecial Cases:\\n- Early exit at stage_8_exit if butterflyCount <= 0 (no operations to perform)\\n- Conditional skip for stages 3+ if not enough data elements available\\n- Twiddle factors stored as 4-element float arrays: cos_a, sin_a, cos_b, sin_b\\n- Each iteration processes 8 complex butterfly groups (8 stages per FFT pass)\\n- Uses x87 FPU for floating-point arithmetic with stack-based operations\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ce7f840a567f085fab3cae25d53c484a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ce7f840a567f085fab3cae25d53c484a",
        "CFG": "1277007fc73f503c75b76ed0803582c0",
        "PRO": "8248610b0aec6abad2755255637e6985"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ce7f840a567f085fab3cae25d53c484a"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_0512e960352b": {
      "addresses": {
        "LoD/PD2": "0x03839DB0"
      },
      "rvas": {
        "LoD/PD2": "0x19DB0"
      },
      "sizes": {
        "LoD/PD2": 279
      },
      "name": "AllocateAndInitializeAudioBuffer",
      "signature": "void * AllocateAndInitializeAudioBuffer(uint bufferWidth, uint bufferHeight, uint compressionFlag)",
      "calling_convention": "__stdcall",
      "comment": "Allocate and initialize an audio/media buffer structure for Bink video playback.\n\nAlgorithm:\n1. Calculate allocation size based on compression flag: if compression disabled (param3==1), use larger allocation; otherwise use smaller\n2. Allocate memory block via radmalloc with header size of 0x2688 plus buffer space\n3. Zero-initialize first 0x9a2 (2466) dwords in allocated block\n4. Set up internal pointers: offset +0x10 for buffer data, offset +0xc for extended data\n5. Store fixed size marker 0x3000 at offset +0x2684\n6. Calculate initial frequency/width based on param1 threshold (0xac44 vs 0x5622)\n7. Calculate buffer size = selected frequency * param2 (height)\n8. Store size values at offsets +0 and +0x8 (shifted right 4 bits)\n9. Load magic constant from DAT_03847cf0 and compute inverse frequency via SQRT\n10. Iterate through threshold table (DAT_0384e0a4 to DAT_0384e108) calculating scale factors\n11. Store threshold count at offset +0x18\n12. Initialize remaining fields: offset +0x14 to 1, offset +0x84 to 0\n13. Return pointer to allocated buffer structure\n\nParameters:\n  bufferWidth (param1): Width/sample rate parameter, compared against 0xac44 and 0x5622 thresholds\n  bufferHeight (param2): Height/sample count multiplier for size calculation\n  compressionFlag (param3): Compression mode flag (bit 0 controls allocation size)\n\nReturns:\n  Pointer to initialized buffer structure (void*), or NULL if allocation fails\n\nSpecial Cases:\n  - Allocation failure returns NULL without initializing structure\n  - Threshold table iteration terminates when value exceeds halfDimension (param1*param2+1 >> 1)\n  - Multiple size fields stored for different purposes: offset +0 and +0x8 for size tracking\n  - Magic constant division by SQRT normalizes frequency scaling",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0512e960352bad47e61560d4b5ee5454",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0512e960352bad47e61560d4b5ee5454",
        "CFG": "39626882d653097e57ff24aa5cf3bbbd",
        "PRO": "d21142fb4b5c5ea5792f419196a77aff"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0512e960352bad47e61560d4b5ee5454"
      },
      "api_calls": {
        "LoD/PD2": [
          "_radmalloc@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_21fdab438fe3": {
      "addresses": {
        "LoD/PD2": "0x03839ED0"
      },
      "rvas": {
        "LoD/PD2": "0x19ED0"
      },
      "sizes": {
        "LoD/PD2": 254
      },
      "name": "ProcessBinkAudioFrame",
      "signature": "void ProcessBinkAudioFrame(int * pBinkHandle, int * pOutputBuffer, int * pFrameSize, int nParam4, int * pAudioData)",
      "calling_convention": "__stdcall",
      "comment": "Processes audio frame data for Bink video playback, performing frame interpolation and memory copying.\n\nAlgorithm:\n1. Call FUN_03839fd0 to get current frame timestamp\n2. Check if pBinkHandle[5] == 0 (interpolation flag)\n3. If flag is clear and frameCount > 0:\n   - Perform weighted interpolation between current frame and source frame\n   - Loop through frameCount samples, blending source and destination audio\n   - Formula: dest = (frameCount-i)*source[i]/frameCount + i*dest[i]/frameCount\n4. Copy pBinkHandle->audioData to destination buffer at offset 0x2484\n   - Copy (frameCount*2) bytes using 32-bit copies then 8-bit remainder\n5. If pFrameSize is non-NULL: write calculated frame size (includes 0x7fffffff offset calculation)\n6. If pOutputBuffer is non-NULL: write pBinkHandle[4] (output buffer pointer)\n7. If pAudioData is non-NULL: write currentFrameTime + nParam4\n\nParameters:\npBinkHandle - Pointer to Bink handle structure containing:\n              [0] = total samples, [2] = frameCount, [4] = output buffer,\n              [5] = interpolation flag, [8] = unknown, [10] = audio data pointer\npOutputBuffer - Optional pointer to receive output buffer address\npFrameSize - Optional pointer to receive calculated frame size\nnParam4 - Audio delay parameter added to frame timestamp\npAudioData - Optional pointer to receive adjusted timestamp (currentFrameTime + nParam4)\n\nReturns:\nvoid - All output written through pointer parameters\n\nSpecial Cases:\n- If pBinkHandle[5] != 0, skip interpolation entirely\n- If frameCount == 0, skip interpolation loop\n- Null pointers for output parameters are safely skipped\n- Frame size calculation: (frameCount * 0x7fffffff + total) * 2\n- Uses REP MOVSD/MOVSB for bulk memory copy (count * 2 bytes)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:21fdab438fe32ef8c4b6dfc3b7b3eaab",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "21fdab438fe32ef8c4b6dfc3b7b3eaab",
        "CFG": "cf5756a8edcf1fd56ea9ae714bcff82b",
        "PRO": "1926108d00ea9ba42f193f5d3fe60efa"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "21fdab438fe32ef8c4b6dfc3b7b3eaab"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_4469e6447e7d": {
      "addresses": {
        "LoD/PD2": "0x03839FD0"
      },
      "rvas": {
        "LoD/PD2": "0x19FD0"
      },
      "sizes": {
        "LoD/PD2": 1045
      },
      "name": "DecodeBinkAudioSamples",
      "signature": "uint DecodeBinkAudioSamples(uint * pBitStream, uint bitOffset, float * pOutputAudio, int * pChannelRanges, float * pChannelScales, short * pAudioIndices, int numChannels, uint * pChannelConfig)",
      "calling_convention": "__stdcall",
      "comment": "Decode Bink audio samples from a compressed bitstream.\\n\\nThis function implements Bink audio decoding, extracting encoded audio samples from a packed bitstream and applying frequency-domain transforms. It processes audio data channel by channel, applying range decoding and scale factors to reconstruct PCM samples.\\n\\nAlgorithm:\\n1. Initialize bit reader state and extract initial coefficients from bitstream\\n2. Decode audio sample coefficients using range decoding algorithm\\n3. Apply scale factors per channel to convert coefficients to floating-point\\n4. Perform inverse frequency transform on decoded samples\\n5. Convert transformed samples back to PCM output format\\n\\nParameters:\\n- pBitStream: Pointer to packed audio bitstream data\\n- bitOffset: Initial bit offset within first bitstream word\\n- pOutputAudio: Output buffer for decoded PCM samples (floats)\\n- pChannelRanges: Array of sample ranges per channel\\n- pChannelScales: Array of scale factors per channel\\n- pAudioIndices: Temporary buffer for audio indices during decoding\\n- numChannels: Number of audio channels to decode\\n- pChannelConfig: Channel configuration structure with size and range info\\n\\nReturns:\\n- uint: Bit position after decoding (combined offset and pointer)\\n\\nSpecial Cases:\\n- Zero run: Handles stretches of zero-valued samples efficiently\\n- Bit boundary crossing: Manages multi-word bitstream reads with proper alignment\\n- Sign application: Negative samples marked by bit flags in bitstream",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4469e6447e7d46e81b58caa114d02744",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4469e6447e7d46e81b58caa114d02744",
        "CFG": "b77cea7b452df4f7fce22a3f505777b2",
        "PRO": "9e9e1f73e50ff7fa2c88cfb8c2843d33"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4469e6447e7d46e81b58caa114d02744"
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "binkw32_MNE_c2334ba4711e": {
      "addresses": {
        "LoD/PD2": "0x0383A3F0"
      },
      "rvas": {
        "LoD/PD2": "0x1A3F0"
      },
      "sizes": {
        "LoD/PD2": 59
      },
      "name": "DecodeBinkAudioSample",
      "signature": "float10 DecodeBinkAudioSample(float10 * __return_storage_ptr__, uint encodedSample)",
      "calling_convention": "__cdecl",
      "comment": "Decodes a single Bink audio sample from packed 32-bit representation.\n\nAlgorithm:\n1. Extract mantissa (bits 5-31, mask 0x77fffff) and convert to floating point\n2. Extract exponent index (bits 0-4) to look up scaling factor from table\n3. Retrieve scaling double from lookup table at 0x384e248[exponent_index*8]\n4. Multiply mantissa by scaling factor to produce final sample value\n5. Check sign bit (bit 28, mask 0x10000000)\n6. If sign bit set, negate the result using FCHS\n7. Return 80-bit extended precision floating point sample\n\nParameters:\nencodedSample: uint - Packed audio sample with mantissa, exponent index, and sign bit\n  Bit Layout:\n  [31:5] - Mantissa value (27 bits, mask 0x77fffff)\n  [4:0]  - Exponent/scale index (5 bits, mask 0x1f)\n  [28]   - Sign bit (1 bit, mask 0x10000000)\n\nReturns:\nfloat10 - Decoded audio sample value as 80-bit extended precision float\n  Value = \u00b1(mantissa * scale_table[exponent_index])\n\nSpecial Cases:\n- Lookup table contains 32 double-precision scale factors (256 bytes total)\n- Sign bit (0x10000000) negates entire result via FCHS instruction\n- Extended precision (float10) ensures low error accumulation in audio processing",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c2334ba4711eca8795eac9c89c0e129c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c2334ba4711eca8795eac9c89c0e129c",
        "CFG": "3d7ac2c2df8a331cdbb21fa9dd404d13",
        "PRO": "f44c643bee20247ad585b5d77c309b53"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c2334ba4711eca8795eac9c89c0e129c"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_13734d19830c": {
      "addresses": {
        "LoD/PD2": "0x0383A430"
      },
      "rvas": {
        "LoD/PD2": "0x1A430"
      },
      "sizes": {
        "LoD/PD2": 208
      },
      "name": "ConvertFloatSamplesToPCM",
      "signature": "void ConvertFloatSamplesToPCM(short * pOutputSamples, float * pInputSamples, float scaleMultiplier, uint samplePairCount)",
      "calling_convention": "__cdecl",
      "comment": "Converts floating-point audio samples to 16-bit signed PCM samples with clipping.\n\nAlgorithm:\n1. Compute sample pair count by right-shifting samplePairCount by 1\n2. For each pair of input samples:\n   a. Load two consecutive floats from pInputSamples (offsets 0 and 8 bytes)\n   b. Multiply each float by scaleMultiplier\n   c. Convert to integers using ROUND operation\n   d. Store temporary values at stack offsets -8 and -4\n   e. Increment pInputSamples by 16 bytes (4 floats)\n   f. Clamp first value to range [-0x8000, 0x7fff] (16-bit signed bounds)\n   g. Clamp second value to range [-0x8000, 0x7fff]\n   h. Write clamped values as 16-bit shorts to pOutputSamples\n   i. Increment pOutputSamples by 4 bytes (2 shorts)\n   j. Decrement samplePairCount and repeat until count reaches 0\n\nParameters:\n  pOutputSamples (EDI) - Pointer to output buffer for 16-bit signed PCM samples\n  pInputSamples (ESI) - Pointer to input buffer of floating-point samples\n  scaleMultiplier (ST0/ST1) - Scaling factor to multiply input samples\n  samplePairCount (ECX) - Number of sample pairs to process\n\nReturns:\n  void (no return value)\n\nSpecial Cases:\n  - Magic values: 0x7fff is max positive 16-bit signed (-1), 0xffff8000/-0x8000 is min\n  - Values exceeding 0x7fff clamped to 0x7fff\n  - Values less than -0x8000 clamped to -0x8000\n  - Processes samples in pairs (stereo audio format)\n  - Uses FPU stack registers for floating-point arithmetic\n\nStructure Layout:\n  Input sample pair stride: 16 bytes (4 floats, each 4 bytes)\n  Output sample pair stride: 4 bytes (2 shorts, each 2 bytes)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:13734d19830c36b4b1fbb8448df24608",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "13734d19830c36b4b1fbb8448df24608",
        "CFG": "67efe5b1b93a9ab18cc7297fbad7cc8e",
        "PRO": "dfb4e09d8b884fdb94d27d021eabda06"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "13734d19830c36b4b1fbb8448df24608"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_ea61922022cb": {
      "addresses": {
        "LoD/PD2": "0x0383A500"
      },
      "rvas": {
        "LoD/PD2": "0x1A500"
      },
      "sizes": {
        "LoD/PD2": 13
      },
      "name": "FreeRadMemory",
      "signature": "void FreeRadMemory(void * pMemory)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper function to deallocate memory allocated by RAD codec library.\n\nAlgorithm:\n1. Load the memory pointer parameter from stack [ESP + 0x4]\n2. Push the pointer onto stack as argument\n3. Call radfree() to deallocate the memory block\n4. Return to caller (stdcall cleanup of 4-byte parameter)\n\nParameters:\n  pMemory - void pointer to memory block allocated by RAD codec (radfree compatible)\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  Passes NULL pointers safely to radfree() for optional cleanup patterns\n  Part of the Bink audio/video codec wrapper functions\n  Called from BinkCloseTrack, BinkOpenTrack, and BinkClose to cleanup resources",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ea61922022cb536d70448a5259bdd7e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ea61922022cb536d70448a5259bdd7e0",
        "CFG": null,
        "PRO": "e6f0f34f164f91b76e981de330143430"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ea61922022cb536d70448a5259bdd7e0"
      },
      "api_calls": {
        "LoD/PD2": [
          "_radfree@4"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_STR_1d9e280e1064": {
      "addresses": {
        "LoD/PD2": "0x0383A510"
      },
      "rvas": {
        "LoD/PD2": "0x1A510"
      },
      "sizes": {
        "LoD/PD2": 622
      },
      "name": "_BinkOpenMiles@4",
      "signature": "undefined1 * _BinkOpenMiles@4(undefined1 * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:1d9e280e1064f6246e8c2c671550ccdf",
      "indexes": {
        "EXP": null,
        "STR": "1d9e280e1064f6246e8c2c671550ccdf",
        "API": null,
        "MNE": "567fd1c3cc7f045e29ae1161afbbb105",
        "CFG": "d521a85818442ba49515990eecd1f899",
        "PRO": "181d8a583a5631fd6044fe64c05a0075"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "567fd1c3cc7f045e29ae1161afbbb105"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_d796dc09ec02": {
      "addresses": {
        "LoD/PD2": "0x0383A8C0"
      },
      "rvas": {
        "LoD/PD2": "0x1A8C0"
      },
      "sizes": {
        "LoD/PD2": 82
      },
      "name": "ValidateAndInitializeState",
      "signature": "bool ValidateAndInitializeState(void * pStateObject)",
      "calling_convention": "__stdcall",
      "comment": "Validates and initializes state object, checking initialization status and handling lazy initialization.\n\nAlgorithm:\n1. Check if state field at offset +0x48 equals -1 (uninitialized)\n2. If uninitialized, call function pointer at DAT_0385c838 with parameter from offset +0x44\n3. Store result in offset +0x48\n4. Check if both offset +0x24 and offset +0x54 are zero\n5. If both are zero, call function pointer at DAT_0385c820 with parameter from offset +0x44 and four null arguments\n6. If function returned non-zero, set offset +0x24 to 1\n7. Return true if offset +0x48 is not -1\n\nParameters:\n  pStateObject: void* - Pointer to state structure to validate/initialize\n\nReturns:\n  bool - true if state object is valid (offset +0x48 != -1), false otherwise\n\nSpecial Cases:\n  - Offset -1 indicates uninitialized state that requires initialization\n  - Function pointer calls may perform side effects or validation\n  - Lazy initialization triggered only when both flag fields are zero",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d796dc09ec02c25695faea053e423707",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d796dc09ec02c25695faea053e423707",
        "CFG": "49ae7d019e96c812ee59ec10cfbc9e48",
        "PRO": "ca391fbfa6030aa706dc6ec0f5da0c81"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d796dc09ec02c25695faea053e423707"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_37f80ee4d2eb": {
      "addresses": {
        "LoD/PD2": "0x0383A950"
      },
      "rvas": {
        "LoD/PD2": "0x1A950"
      },
      "sizes": {
        "LoD/PD2": 63
      },
      "name": "ProcessActiveSlot",
      "signature": "int ProcessActiveSlot(void * pSlotManager, undefined4 processingContext)",
      "calling_convention": "__stdcall",
      "comment": "Processes the currently active slot entry and invokes its associated handler callback.\n\nAlgorithm:\n1. Load the active slot index from offset 0x48 in the slot manager structure\n2. Check if the index equals -1 (sentinel value indicating no active slot)\n3. If sentinel found, return 0 to indicate no slot was processed\n4. If valid slot index, retrieve the function pointer from offset 0x44\n5. Load the slot data from the indexed array at offset 0x3c (base + index*4)\n6. Call the handler function with the function pointer, slot index, slot data, and processing context\n7. Clear the processing state flag at offset 0x54\n8. Reset the active slot index to -1 (0xffffffff) at offset 0x48\n9. Return 1 to indicate successful processing\n\nParameters:\npSlotManager: Pointer to a slot management structure containing:\n  - Offset 0x44: Function pointer to slot handler callback\n  - Offset 0x48: Current active slot index (-1 if no active slot)\n  - Offset 0x3c: Base address of indexed slot data array\n  - Offset 0x54: Processing state flag\nprocessingContext: Additional context parameter passed to the handler callback\n\nReturns:\n1 (success) if a valid slot was processed\n0 (no-op) if the sentinel value -1 was found in the active slot field\n\nSpecial Cases:\n- Sentinel value 0xffffffff (-1) is used to indicate \"no active slot\"\n- The function always resets the active slot to -1 after processing\n- The processing state flag is always cleared regardless of slot validity",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:37f80ee4d2eb27099162b10fa8e56585",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "37f80ee4d2eb27099162b10fa8e56585",
        "CFG": "ae5a7295f41b2cc6d381601031fd744e",
        "PRO": "ca9145a8a6125e033c074b6d433f1406"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "37f80ee4d2eb27099162b10fa8e56585"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_5fd74780c7fe": {
      "addresses": {
        "LoD/PD2": "0x0383A990"
      },
      "rvas": {
        "LoD/PD2": "0x1A990"
      },
      "sizes": {
        "LoD/PD2": 67
      },
      "name": "ProcessBinkBufferScale",
      "signature": "void ProcessBinkBufferScale(void * pBinkBuffer, uint scaleValue)",
      "calling_convention": "__stdcall",
      "comment": "Process Bink video buffer scale transformation.\n\nScales a normalized scale value (0-32767) to a 7-bit range (0-127) and applies it\nto a Bink buffer structure. The scaled value is stored at offset +0x58 and a\ncallback function pointer at +0x44 is invoked with the scaled result.\n\nAlgorithm:\n1. Clamp input scaleValue to maximum 0x7fff (32767)\n2. Calculate scaled value: (scaleValue * 0x7f) / 0x7fff (maps to 0-127 range)\n3. Store scaled value at pBinkBuffer+0x58\n4. Call callback function at pBinkBuffer+0x44 with scaled value\n5. Return to caller\n\nParameters:\n  pBinkBuffer: void* - Pointer to Bink buffer structure\n  scaleValue: uint - Scale value in range 0-32767\n\nReturns:\n  void - No return value\n\nStructure Layout (Bink Buffer):\n  Offset  Size  Field Name            Type      Description\n  +0x44    4    scaleCallbackPtr      func*     Callback function\n  +0x58    4    currentScaleValue     uint      Current scaled value (0-127)\n\nSpecial Cases:\n  - If scaleValue > 0x7fff, automatically clamped to 0x7fff\n  - Scaling formula maps 0-32767 range to 0-127 range\n  - Callback always invoked with scaled value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5fd74780c7fe017abf9e88ab4bc4a0a7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5fd74780c7fe017abf9e88ab4bc4a0a7",
        "CFG": "1f402f1fdc7380554654155b8422fe79",
        "PRO": "336d4117e512a6c5db9f987b15f798e4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5fd74780c7fe017abf9e88ab4bc4a0a7"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_aa6941d4ba42": {
      "addresses": {
        "LoD/PD2": "0x0383A9E0"
      },
      "rvas": {
        "LoD/PD2": "0x1A9E0"
      },
      "sizes": {
        "LoD/PD2": 66
      },
      "name": "SetScaledPropertyValue",
      "signature": "void SetScaledPropertyValue(void * pObject, uint scaledInput)",
      "calling_convention": "__stdcall",
      "comment": "Scales an input value and stores it in a structure field.\nConverts a 16-bit unsigned value (0-0x10000 range) to an 8-bit value (0-0x7f range)\nusing fixed-point scaling, then invokes a callback function with the scaled result.\n\nAlgorithm:\n1. Load scaling divisor (0x10000) and maximum output value (0x7f)\n2. Multiply input value by 0x7f to perform fixed-point scaling\n3. Divide result by 0x10000 to complete the scaling calculation\n4. Compare result against maximum value (0x7f)\n5. If result exceeds maximum, clamp to 0x7f\n6. Store scaled/clamped value at structure offset +0x5c\n7. Load function pointer from structure offset +0x44\n8. Call function pointer with scaled value and structure pointer as parameters\n\nParameters:\n- pObject: Pointer to structure containing callback function pointer and property field\n- scaledInput: Unsigned 16-bit value in range 0x0000-0xFFFF to be scaled down\n\nReturns:\n- None (void)\n\nSpecial Cases:\n- Values exceeding 0x7f after scaling are clamped to maximum value 0x7f\n- Callback function is invoked after property update with scaled value\n- Structure layout: callback pointer at +0x44, property field at +0x5c\n\nStructure Layout:\nOffset | Size | Field Name      | Type     | Description\n-------|------|-----------------|----------|------------------\n 0x44  |  4   | pfnCallback     | void*    | Function pointer to callback\n 0x5c  |  4   | scaledValue     | uint     | Property field for scaled value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:aa6941d4ba4270d4f931ca2477744b70",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "aa6941d4ba4270d4f931ca2477744b70",
        "CFG": "0a3586054bbacc4e01d98943cd235cc6",
        "PRO": "6b043dd3c97f9d7b37fdad1ead5ddca6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "aa6941d4ba4270d4f931ca2477744b70"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_3115f038870e": {
      "addresses": {
        "LoD/PD2": "0x0383AA30"
      },
      "rvas": {
        "LoD/PD2": "0x1AA30"
      },
      "sizes": {
        "LoD/PD2": 151
      },
      "name": "InitializeGameObject",
      "signature": "void InitializeGameObject(void * pGameObject)",
      "calling_convention": "__cdecl",
      "comment": "Initializes a game object with object-specific properties and callback handlers.\n\nAlgorithm:\n1. Load object pointer from pGameObject parameter (stored in ESI)\n2. Extract pointer at +0x44 offset (object ID/reference)\n3. Call function pointer at DAT_0385c844 with object ID as first parameter\n4. Determine object mode value based on field at +0x38:\n   - If field at +0x34 equals 0x10: mode = ((field_0x38 != 2) - 1 & 2) + 1\n   - Otherwise: mode = (field_0x38 != 2) - 1 & 2\n5. Call function pointer at DAT_0385c840 with (objectID, mode, isSpecial)\n6. Call DAT_0385c84c with (objectID, field_0x30)\n7. Call DAT_0385c848 with (objectID, field_0x58)\n8. Call DAT_0385c874 with (objectID, field_0x5c)\n9. Call DAT_0385c860 with (objectID, 0, field_0x50)\n10. Call DAT_0385c834 with (objectID, address_0x383aad0)\n\nParameters:\n  pGameObject (void*): Pointer to game object structure containing configuration fields\n\nReturns:\n  void: No return value; function initializes object in-place\n\nStructure Layout (pGameObject):\nOffset | Size | Field Name | Type | Description\n-------|------|------------|------|-------------\n+0x30  |  4   | config1    | uint | Configuration parameter 1\n+0x34  |  4   | typeFlag   | uint | Type flag (0x10 indicates special type)\n+0x38  |  4   | modeValue  | uint | Mode value (compared against 2)\n+0x44  |  4   | objectID   | uint | Object ID/reference pointer\n+0x50  |  4   | config2    | uint | Configuration parameter 2\n+0x58  |  4   | config3    | uint | Configuration parameter 3\n+0x5c  |  4   | config4    | uint | Configuration parameter 4\n\nSpecial Cases:\n- Field at +0x34 == 0x10 triggers special mode calculation: mode becomes (mode & 2) + 1\n- Field at +0x38 value 2 is treated as a special case (inverted logic with SETNZ)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3115f038870e26653ab1e4d31011ea6a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3115f038870e26653ab1e4d31011ea6a",
        "CFG": "7198471cfb35f6111a05eaa92cf48bd4",
        "PRO": "f817112f82428f6a389ec4dc01efff4f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3115f038870e26653ab1e4d31011ea6a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_dacbd34b4e32": {
      "addresses": {
        "LoD/PD2": "0x0383AB50"
      },
      "rvas": {
        "LoD/PD2": "0x1AB50"
      },
      "sizes": {
        "LoD/PD2": 59
      },
      "name": "HandleStateTransition",
      "signature": "int HandleStateTransition(void * pStateObject, int nMode)",
      "calling_convention": "__stdcall",
      "comment": "Handles state transition operations on a state object.\\n\\nAlgorithm:\\n1. Check if nMode equals 1 to determine transition path\\n2. If nMode == 1: invoke state activation callback\\n3. If nMode != 1: invoke state deactivation callback and set active flag\\n4. Return the mode value passed as input\\n\\nParameters:\\npStateObject: Pointer to state object structure (contains callbacks and state flags)\\nnMode: Mode/transition type (1=activation, other=deactivation)\\n\\nReturns:\\nint: Returns the nMode value passed as input parameter\\n\\nSpecial Cases:\\n- Field at offset 0x44: Contains callback function pointer for mode-specific operation\\n- Field at offset 0x54: State/mode flag (set to 1 when mode is not 1)\\n- __stdcall convention: Function callee cleans stack (RET 0x8)\\n\\nStructure Layout:\\nOffset | Size | Field Name        | Type      | Description\\n0x44   | 4    | pModeCallback     | void*     | Function pointer invoked with context\\n0x54   | 4    | nStateFlag        | int       | Status flag (1=active, 0=inactive)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:dacbd34b4e32cc2e46f4421b33173dac",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "dacbd34b4e32cc2e46f4421b33173dac",
        "CFG": "611b0a2738bc697e80a73ce4243ca126",
        "PRO": "83c97abfeb661908dcdc39c4780e3b8a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "dacbd34b4e32cc2e46f4421b33173dac"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_8f626c192d0a": {
      "addresses": {
        "LoD/PD2": "0x0383AB90"
      },
      "rvas": {
        "LoD/PD2": "0x1AB90"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "CleanupAudioResources",
      "signature": "void CleanupAudioResources(void * pAudioContext)",
      "calling_convention": "__stdcall",
      "comment": "Cleanup audio resources by invoking registered cleanup callbacks.\n\nThis function retrieves two audio-related callbacks from an audio context structure\nand invokes them with their respective audio buffer pointers to perform cleanup operations.\nTypically called during shutdown or resource deallocation.\n\nAlgorithm:\n1. Retrieve first cleanup callback address from context offset 0x3c\n2. Push callback parameter (buffer pointer from offset 0x3c) to stack\n3. Invoke first callback via indirect function pointer at 0x385c82c\n4. Retrieve second cleanup callback address from context offset 0x44\n5. Push callback parameter (buffer pointer from offset 0x44) to stack\n6. Invoke second callback via indirect function pointer at 0x385c858\n7. Restore ESI register and return (stdcall: caller cleans 4-byte parameter)\n\nParameters:\n- pAudioContext (void*): Pointer to audio context structure containing cleanup callbacks\n  - Offset 0x3c: First audio buffer pointer (parameter to first callback)\n  - Offset 0x44: Second audio buffer pointer (parameter to second callback)\n\nReturns:\n- void: Function performs cleanup operations and returns control to caller\n\nSpecial Cases:\n- Both callbacks are stored as function pointers in global data\n- This is a stdcall function; the caller cleans up the 4-byte parameter from the stack\n- Called from a single location during shutdown sequence",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8f626c192d0a356f6953a0b8c9f334ee",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8f626c192d0a356f6953a0b8c9f334ee",
        "CFG": null,
        "PRO": "49ff440b8780376a7ab14f20d20d4a19"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8f626c192d0a356f6953a0b8c9f334ee"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_4f731b139551": {
      "addresses": {
        "LoD/PD2": "0x0383ABC0"
      },
      "rvas": {
        "LoD/PD2": "0x1ABC0"
      },
      "sizes": {
        "LoD/PD2": 2473
      },
      "name": "DecompressPlaneData",
      "signature": "void DecompressPlaneData(void * pOutputPlane, BitStreamDecoder * pBitStream)",
      "calling_convention": "__stdcall",
      "comment": "Decompresses PKWARE DCL-style plane data using Huffman decoding.\n\nALGORITHM:\n1. Initialize local Huffman look-up tables (LUT) and output arrays\n2. Extract and parse initial depth value from bit stream (lower 4 bits)\n3. Initialize Huffman tree with 31 tree nodes (one per depth level)\n4. For each depth level from 1 to max depth-1:\n   - Iterate through pending Huffman entries\n   - Decode length information using tree traversal\n   - Apply case-based transformations (0=single code, 1=length code pair, 2=leaf node, 3=special length)\n   - Store resolved codes and values in output arrays\n   - Adjust depth mask for next level\n5. Finalize remaining entries after all depth iterations\n6. Write decoded Huffman values and decoded data to output structure\n7. Update bit stream position (pointer, bits remaining) for next plane\n\nPARAMETERS:\n  pOutputPlane (void *): Pointer to output destination structure (64-byte minimum for decoded values)\n  pBitStream (BitStreamDecoder *): Bit stream state with current position, buffered bits, and remaining bit count\n\nRETURNS:\n  void (no return value; writes results to pOutputPlane and updates pBitStream)\n\nSPECIAL CASES:\n  - If bit_remaining &lt; 4 initially, loads next DWORD and shifts bits\n  - Depth value &lt;= 1 skips main Huffman tree construction\n  - Special handling for bit alignment during stream reads (handles 32-bit word boundaries)\n  - Huffman values sign-extended when bit 0 of length code is set",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4f731b1395511d61e724f9f85ddfb70e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4f731b1395511d61e724f9f85ddfb70e",
        "CFG": "9e2df808a8a9e5ec0c3198d52ac00132",
        "PRO": "27f38dacea82ad0c343a64038354f727"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4f731b1395511d61e724f9f85ddfb70e"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_5c44af704ef3": {
      "addresses": {
        "LoD/PD2": "0x0383B590"
      },
      "rvas": {
        "LoD/PD2": "0x1B590"
      },
      "sizes": {
        "LoD/PD2": 1320
      },
      "name": "DecodeHuffmanSymbols",
      "signature": "void DecodeHuffmanSymbols(byte * pOutputBuffer, int * pBitstreamState, int symbolCount)",
      "calling_convention": "__cdecl",
      "comment": "Decodes Huffman-encoded symbols from bitstream into output buffer.\n\nAlgorithm:\n1. Initializes output buffer to zero (16 DWORDs)\n2. Extracts initial bits from input stream based on alignment\n3. Sets up decode tables from lookup entries\n4. Processes outer loop for each bit depth level\n5. Inner loop iterates through decode table entries until output limit reached\n6. For each table entry, extracts bits and processes based on type\n7. Updates bitstream state upon completion\n\nParameters:\n  pOutputBuffer (byte *): Output buffer for decoded symbols\n  pBitstreamState (int *): Bitstream state array\n  symbolCount (int): Maximum number of symbols to decode\n\nReturns:\n  void. Updates pBitstreamState with new stream position.\n\nSpecial Cases:\n  - Function exits when symbolCount symbols decoded\n  - Bit alignment handled when initial position < 3\n  - Sign bit controls +/- adjustment in decoding",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5c44af704ef34d2f7ac3eeb99f26e7fd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5c44af704ef34d2f7ac3eeb99f26e7fd",
        "CFG": "b953153073119b3d8168e13635cf73b7",
        "PRO": "64ec79867925094559b6d2040bf818a7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5c44af704ef34d2f7ac3eeb99f26e7fd"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_bef3a80cb1c2": {
      "addresses": {
        "LoD/PD2": "0x0383BAD0"
      },
      "rvas": {
        "LoD/PD2": "0x1BAD0"
      },
      "sizes": {
        "LoD/PD2": 825
      },
      "name": "DecodeImagePlaneBlock",
      "signature": "void DecodeImagePlaneBlock(char * pOutputBuffer, int rowStride, int * pDecodedValues, int decodedValueCount, char * pReferencePlane)",
      "calling_convention": "__stdcall",
      "comment": "Decodes and applies delta-decoded image plane block using Huffman symbols\n\nAlgorithm:\n1. Decode 64 Huffman symbols into stack buffer via DecodeHuffmanSymbols call\n2. Add decoded delta values to reference plane values element-by-element\n3. Write resulting byte values to output buffer in 8x8 pixel block layout\n\nThe function processes pixels in 4 sub-blocks of 2x4 pixels each:\n- Block 0: rows 0-1, stride-relative offsets\n- Block 1: rows 2-3, stride-relative offsets  \n- Block 2: rows 4-5, stride-relative offsets\n- Block 3: rows 6-7, stride-relative offsets\n\nParameters:\npOutputBuffer: Destination buffer for decoded pixel values\nrowStride: Width/stride of output buffer in bytes (typically image width)\npDecodedValues: Pointer to decoded Huffman symbols (64 bytes)\ndecodedValueCount: Count of decoded values (typically 64)\npReferencePlane: Previous frame/reference plane with 64 bytes for delta decoding\n\nReturns:\nvoid\n\nSpecial Cases:\nUses __stdcall convention where caller cleans the 0x14 bytes of parameters from stack.\nDelta decoding: each output pixel = reference_pixel + decoded_delta_value\nNo return value; output stored directly to buffer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bef3a80cb1c292d751cc67a95746c0ea",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bef3a80cb1c292d751cc67a95746c0ea",
        "CFG": null,
        "PRO": "1a49c223c73aa26c6ba9ce720aaeeb8a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bef3a80cb1c292d751cc67a95746c0ea"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_44f2e488e61b": {
      "addresses": {
        "LoD/PD2": "0x0383BE10"
      },
      "rvas": {
        "LoD/PD2": "0x1BE10"
      },
      "sizes": {
        "LoD/PD2": 164
      },
      "name": "FindApplicationWindow",
      "signature": "void FindApplicationWindow(void)",
      "calling_convention": "__stdcall",
      "comment": "Finds the application window handle and caches it in DAT_0385c884.\n\nAlgorithm:\n1. Get current process ID and module handle of current process\n2. Check if window handle is already cached; return if found\n3. Iterate through all top-level windows (GetWindow with GW_HWNDNEXT=2)\n4. For each window:\n   a. Get the window's owning process ID via GetWindowThreadProcessId\n   b. If process ID matches current process, check module and window styles\n   c. Get window's module handle via GetWindowLongA(hWnd, GWL_HINSTANCE=-6)\n   d. If module matches and window doesn't have style 0x40000000, cache it\n   e. If no valid window found yet, cache current window as fallback\n5. After loop, if no window cached, get and cache active window\n\nParameters:\nNone. Uses global variable DAT_0385c884 to store result.\n\nReturns:\nvoid. Result stored in DAT_0385c884 (HWND)\n\nSpecial Cases:\n- Window style flag 0x40000000: Likely WS_VISIBLE or similar; windows with this flag are skipped\n- Fallback mechanism: Uses last window in process if no matching style found\n- Final fallback: Uses GetActiveWindow if no windows found in enumeration\n- Only searches windows in same process (GetCurrentProcessId match)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:44f2e488e61bfa0e0e1868351529e08b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "44f2e488e61bfa0e0e1868351529e08b",
        "CFG": "3b17a520b61243785c7be6a1fd9f1432",
        "PRO": "d89af3574846fd504153e46bf01e8cde"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "44f2e488e61bfa0e0e1868351529e08b"
      }
    },
    "binkw32_STR_fabd94e72423": {
      "addresses": {
        "LoD/PD2": "0x0383BEC0"
      },
      "rvas": {
        "LoD/PD2": "0x1BEC0"
      },
      "sizes": {
        "LoD/PD2": 198
      },
      "name": "_BinkOpenDirectSound@4",
      "signature": "undefined * _BinkOpenDirectSound@4(int param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:fabd94e72423594605c6945b67ac4454",
      "indexes": {
        "EXP": null,
        "STR": "fabd94e72423594605c6945b67ac4454",
        "API": null,
        "MNE": "c2d8c82a224ae31858aec44d3b1ed149",
        "CFG": "feb3304a49551e46ae5ffc6eb3820e65",
        "PRO": "9e4a5a65d1cf679303b16c2528ea36dc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c2d8c82a224ae31858aec44d3b1ed149"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_456eb52a137a": {
      "addresses": {
        "LoD/PD2": "0x0383BF90"
      },
      "rvas": {
        "LoD/PD2": "0x1BF90"
      },
      "sizes": {
        "LoD/PD2": 187
      },
      "name": "InitializeDirectSoundDevice",
      "signature": "uint InitializeDirectSoundDevice(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize DirectSound audio device and query capabilities\\n\\nAlgorithm:\\n1. Check if sound function pointer is initialized; return 0 if not\\n2. Increment initialization counter to track re-entrance\\n3. On first call only (counter == 1):\\n   a. Check if sound subsystem is enabled via global flag\\n   b. Call sound initialization function with output buffer pointer\\n   c. If initialization fails, decrement counter and return 0\\n   d. Get sound object from output buffer (offset +0x0)\\n   e. Call FindApplicationWindow() to get main window handle\\n   f. Call device method at vtable offset +0x18 with window handle\\n   g. Store success/failure status flag to global state\\n4. Initialize local capabilities buffer (96 bytes = 24 dwords)\\n5. Set first DWORD to 0x60 (buffer size indicator)\\n6. Call device method at vtable offset +0x10 to query capabilities\\n7. If query succeeds, extract bit 5 from capabilities flags\\n8. Return 1 (success)\\n\\nParameters: None - operates on global device pointers\\n\\nReturns: uint - 1 for success, 0 on initialization failure\\n\\nSpecial Cases:\\n- Uses reference counting via increment/decrement to handle multiple calls\\n- Only performs full initialization on first call (counter == 1)\\n- On error, decrements counter to restore state for retry\\n- Capabilities buffer is 96 bytes (24 dwords \\u00d7 4 bytes each)\\n- Buffer size value 0x60 is hardcoded in capabilities structure\\n- Bit 5 flag extraction: shift right 5, mask with 1\\n\\nStructure Layout - Device Capabilities Buffer:\\nOffset | Size | Field Name | Type | Description\\n0x00   | 4    | dwSize     | uint | Buffer size (always 0x60)\\n0x04   | 92   | reserved   | byte | Reserved capability fields (23 dwords)\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:456eb52a137afb45d56d48d17f5aacf2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "456eb52a137afb45d56d48d17f5aacf2",
        "CFG": "77e8defb9e2a0a81fe6e343213e5eec2",
        "PRO": "a4e1e33881ecff6efe940e6f5e1820f8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "456eb52a137afb45d56d48d17f5aacf2"
      }
    },
    "binkw32_MNE_2ae41d0a48ef": {
      "addresses": {
        "LoD/PD2": "0x0383C050"
      },
      "rvas": {
        "LoD/PD2": "0x1C050"
      },
      "sizes": {
        "LoD/PD2": 48
      },
      "name": "ReleaseDirectSoundOnRefCountZero",
      "signature": "void ReleaseDirectSoundOnRefCountZero(void)",
      "calling_convention": "__stdcall",
      "comment": "Decrements reference counter and releases DirectSound object when counter reaches zero.\n\nAlgorithm:\n1. Decrement the reference counter at 0x0385c8a4\n2. If counter reached 0, check if DirectSound is enabled (0x0385c888 != 0)\n3. Load DirectSound object pointer from 0x0384e34c\n4. Validate pointer is not NULL and not 0xFFFFFFFF (already released)\n5. Call virtual destructor method at offset +8 in the object's vtable\n6. Mark pointer as invalid by setting it to 0xFFFFFFFF\n7. Return to caller\n\nReturns:\nNone. This is a void function with side effects on global state.\n\nSpecial Cases:\n- Reference counter starts positive, decrements on each call\n- Cleanup only occurs when counter reaches exactly 0\n- 0xFFFFFFFF is used as sentinel value indicating \"already released\"\n- Used in Bink DirectSound integration for deferred resource cleanup\n- Called at end of _BinkOpenDirectSound@4 after DirectSound initialization",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2ae41d0a48effc5672a1611866c4811c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2ae41d0a48effc5672a1611866c4811c",
        "CFG": "88809e4ef037bedf4711ca1d73363eab",
        "PRO": "844270ae62dc7c8dc523a153b7a0a6ec"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2ae41d0a48effc5672a1611866c4811c"
      }
    },
    "binkw32_MNE_7701dbbda37c": {
      "addresses": {
        "LoD/PD2": "0x0383C080"
      },
      "rvas": {
        "LoD/PD2": "0x1C080"
      },
      "sizes": {
        "LoD/PD2": 565
      },
      "name": "InitializeAudioSystem",
      "signature": "int InitializeAudioSystem(void * pAudioStructure, int sampleRate, int bitDepth, uint channels)",
      "calling_convention": "__stdcall",
      "comment": "Initializes the audio/sound system with specified parameters.\n\nAlgorithm:\n1. Clear initial 0x2f (47) dwords in audio structure for initialization\n2. Call InitializeDirectSoundDevice to set up DirectSound\n3. If initialization fails, return 0\n4. Extract bit depth and channel information from parameters\n5. Calculate channel/sample size and total buffer size for audio data\n6. If sound context flag set, initialize using vtable function calls\n7. Calculate buffer size: ((flag ? 0x4b : 0x64) * totalBufferSize) / 1000\n8. Double buffer size until exceeds calculated minimum (power-of-2 doubling)\n9. Calculate offset table: offset = size*4, offset2 = size*3\n10. Create audio buffer through COM interface call\n11. If buffer creation fails, return 0\n12. Adjust buffer size for 8-bit audio (double samples) vs other depths\n13. Set volume levels to 0x7fff for left and right channels\n14. Call FUN_0383c2c0 and FUN_0383c390 for additional audio setup\n15. Initialize channel, state, position fields to 0xffffffff or 0\n16. Set function pointers for virtual function table (8 handlers)\n17. Return 1 to indicate success\n\nParameters:\n  pAudioStructure: Pointer to audio subsystem structure to initialize\n  sampleRate: Audio sample rate in Hz (e.g., 22050 or 44100)\n  bitDepth: Bits per sample (8 for 8-bit, 16 for 16-bit audio)\n  channels: Number of audio channels (1 for mono, 2 for stereo)\n\nReturns:\n  1 if successful, 0 if DirectSoundDevice initialization fails or buffer creation fails\n\nSpecial Cases:\n  - Early return (0) if InitializeDirectSoundDevice fails\n  - Early return (0) if COM buffer creation returns negative error code\n  - 8-bit audio (bitDepth == 8) doubles the sample count in internal buffer\n  - Sound context initialization (DAT_0385c898 != 0) uses COM interface calls",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7701dbbda37c6e0f92f43cd6fd834dd8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7701dbbda37c6e0f92f43cd6fd834dd8",
        "CFG": "76d290637670640f102400b24c193d98",
        "PRO": "262360de52711b2847eb7c1ad9771c18"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7701dbbda37c6e0f92f43cd6fd834dd8"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_17cdafd82d7b": {
      "addresses": {
        "LoD/PD2": "0x0383C2C0"
      },
      "rvas": {
        "LoD/PD2": "0x1C2C0"
      },
      "sizes": {
        "LoD/PD2": 204
      },
      "name": "ApplySoundFrequencyModulation",
      "signature": "void ApplySoundFrequencyModulation(int * pSoundParams)",
      "calling_convention": "__stdcall",
      "comment": "Apply audio frequency modulation to a sound object based on frequency and volume parameters.\n\nAlgorithm:\n1. Validate sound object pointer (pSoundParams[0]) - return if null\n2. Clamp frequency parameter (pSoundParams[0x1c]) to maximum 0x7fff (32767)\n3. Calculate pitch adjustment from volume parameter (pSoundParams[0x20]):\n   - If volume >= 0x10000: use negative lookup table (ldexp values)\n   - If volume < 0x10000: use positive lookup table (exponent values)\n4. Validate calculated pitch adjustment is within [-24, 24] range; clamp to 0 if out of range\n5. Call virtual method [pSoundObject+0x44](pSoundObject, pSoundParams[4]) to set frequency\n6. Call virtual method [pSoundObject+0x40](pSoundObject, pitchValue) to set pitch adjustment\n7. Calculate final volume index: (frequencyValue * 127) / 32767, apply lookup table, and call virtual method [pSoundObject+0x3c] to set volume\n\nReturns:\nNone (void function)\n\nParameters:\npSoundParams - Pointer to sound parameter structure containing:\n  [0] - Pointer to sound object (must not be null)\n  [4] - Frequency setup parameter\n  [0x10] - Frequency parameter\n  [0x1c] - Frequency/pitch value (clamped to 0x7fff)\n  [0x20] - Volume parameter (used for pitch adjustment calculation)\n\nSpecial Cases:\n- If sound object pointer is null, function returns immediately without processing\n- Pitch values outside [-24, 24] are clamped to 0 (neutral, no pitch adjustment)\n- Frequency values > 0x7fff are clamped to 0x7fff maximum\n- Volume calculation uses signed arithmetic with rounding for precision",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:17cdafd82d7bde2dd2169e5fa2c76410",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "17cdafd82d7bde2dd2169e5fa2c76410",
        "CFG": "1184ab72a8247641f4d82504b9958b11",
        "PRO": "f0a8746dc4c851f27aa3efb613926566"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "17cdafd82d7bde2dd2169e5fa2c76410"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_43b18e392253": {
      "addresses": {
        "LoD/PD2": "0x0383C390"
      },
      "rvas": {
        "LoD/PD2": "0x1C390"
      },
      "sizes": {
        "LoD/PD2": 166
      },
      "name": "InitializeAudioBuffer",
      "signature": "void InitializeAudioBuffer(void * pAudioBuffer)",
      "calling_convention": "__cdecl",
      "comment": "Initializes DirectSound audio buffer by locking, clearing, and unlocking.\n\nAlgorithm:\n1. Repeatedly call vtable function at offset 0x2c to lock/initialize audio buffer\n2. If DSERR_BUFFERLOST error (0x88780096) occurs, sleep 10ms and call vtable offset 0x50 to restore buffer\n3. Retry loop continues until lock succeeds (result == 0) or different error occurs\n4. If lock succeeded, validate that bufferPositionPtr equals expected buffer size at offset +0x4\n5. Calculate fill pattern: 0x80 for silence (negating bit depth field at offset +0x14 for pattern generation)\n6. Fill entire buffer with silence pattern using REP STOSD for 4-byte aligned portion\n7. Fill remaining 1-3 bytes with silence pattern using REP STOSB\n8. Call vtable function at offset 0x4c to unlock buffer and finalize initialization\n\nParameters:\n  pAudioBuffer: Pointer to COM audio buffer object with vtable at offset 0, size at offset +0x4\n\nReturns:\n  void\n\nSpecial Cases:\n  DSERR_BUFFERLOST (0x88780096): Buffer lost focus, retry with sleep\n  Size mismatch: If bufferPositionPtr != buffer size, skip initialization\n  Fill pattern: Bit depth determines silence byte (0x80 for most, varies by format)\n  Vtable offsets: 0x2c=Lock, 0x50=Restore, 0x4c=Unlock",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:43b18e3922536636b2812d8e4d4d2d2b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "43b18e3922536636b2812d8e4d4d2d2b",
        "CFG": "ca4b01082a0db3827c8ee0f7eccf8748",
        "PRO": "531d1cd40fc6b0c5d857860d958db9e3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "43b18e3922536636b2812d8e4d4d2d2b"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_5094260ea32c": {
      "addresses": {
        "LoD/PD2": "0x0383C620"
      },
      "rvas": {
        "LoD/PD2": "0x1C620"
      },
      "sizes": {
        "LoD/PD2": 74
      },
      "name": "PollOperationWithRetry",
      "signature": "void PollOperationWithRetry(undefined4 * pObject, int retryCount)",
      "calling_convention": "__cdecl",
      "comment": "Polls an async operation with retry logic on EAGAIN (0x88780096) error.\\n\\nAlgorithm:\\n1. Loop until operation succeeds\\n2. Calculate operation size as pObject[0xc] * retryCount\\n3. Call virtual function at pObject[0][0x2c] with operation parameters\\n4. Check if return value equals 0x88780096 (EAGAIN/retry code)\\n5. If not EAGAIN, exit loop successfully\\n6. If EAGAIN, sleep 10ms and call cleanup virtual function at pObject[0][0x50]\\n7. Repeat until operation succeeds\\n\\nParameters:\\n- pObject: Pointer to async operation object with vTable at offset 0\\n- retryCount: Multiplier for operation size calculation\\n\\nReturns:\\n- void (operation result stored in pObject structure)\\n\\nSpecial Cases:\\n- 0x88780096 is the EAGAIN/retry magic number indicating operation in progress\\n- Virtual function at offset 0x2c handles the main operation\\n- Virtual function at offset 0x50 handles cleanup/reset between retries\\n- 10ms sleep between retries prevents busy-waiting",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5094260ea32ccc534b208448eef4b13d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5094260ea32ccc534b208448eef4b13d",
        "CFG": "2d9cf657078f922ce0b30762cead926e",
        "PRO": "b8ce313082d5280a8892c191680c49ca"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5094260ea32ccc534b208448eef4b13d"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_fe822583783b": {
      "addresses": {
        "LoD/PD2": "0x0383C670"
      },
      "rvas": {
        "LoD/PD2": "0x1C670"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "CallAudioCleanupMethod",
      "signature": "void CallAudioCleanupMethod(void * pAudioObject)",
      "calling_convention": "__cdecl",
      "comment": "Calls the cleanup/finalization virtual method on an audio object.\n\nAlgorithm:\n1. Load pAudioObject parameter from stack [ESP+0x4]\n2. Load vtable pointer from pAudioObject+0x0\n3. Load cleanup method address from vtable+0x4c (13th virtual function)\n4. Load parameter values from pAudioObject structure:\n   - offset +0x3c (stored in EAX)\n   - offset +0x38 (stored in ESI)\n   - offset +0x44 (stored in ESI)\n   - offset +0x40 (stored in ESI)\n5. Push parameters and pAudioObject as first argument to stack\n6. Call virtual method through computed address [EDX+0x4c]\n7. Restore ESI register and return\n\nParameters:\n  pAudioObject: Pointer to audio object with vtable at offset 0x0\n\nReturns:\n  void\n\nSpecial Cases:\n  - Virtual method call at offset 0x4c in vtable (4 bytes per entry = 13th function)\n  - Passes pAudioObject as implicit first parameter\n  - Parameters are loaded from audio object offsets before call\n  - ESI register is preserved (saved/restored)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fe822583783b9eaacef7818446dba589",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fe822583783b9eaacef7818446dba589",
        "CFG": null,
        "PRO": "dad8b4a3132035330fd0ba94d7106234"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fe822583783b9eaacef7818446dba589"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_5be5c6d3e579": {
      "addresses": {
        "LoD/PD2": "0x0383C690"
      },
      "rvas": {
        "LoD/PD2": "0x1C690"
      },
      "sizes": {
        "LoD/PD2": 57
      },
      "name": "WaitForObjectReady",
      "signature": "void WaitForObjectReady(GameObjectInstance * * ppObject)",
      "calling_convention": "__cdecl",
      "comment": "Waits for a game object to become ready by polling its status.\n\nAlgorithm:\n1. Load the object pointer from the parameter\n2. Call virtual method at offset 0x30 with arguments (ppObject, 0, 0, 1)\n3. Check if return value equals 0x88780096 (WAIT_PENDING status)\n4. If pending, sleep for 10ms to avoid busy-waiting\n5. Call virtual method at offset 0x50 to refresh object state\n6. Repeat until object is ready (method returns non-pending status)\n7. Clear the ready flag at offset 0x34 to indicate completion\n8. Return to caller\n\nParameters:\n  ppObject: Pointer to pointer of GameObjectInstance to monitor\n           Contains vtable pointer at offset 0 with virtual methods\n           Offset 0x30 = IsObjectReady check function\n           Offset 0x50 = RefreshObjectState function\n           Offset 0x34 = Ready flag storage location\n\nReturns:\n  void - Function returns after object becomes ready\n\nSpecial Cases:\n  The magic number 0x88780096 represents the WAIT_PENDING status code\n  The inverse (-0x7787ff6a) appears in decompiler due to signed comparison\n  This is a polling wait pattern commonly used in game object initialization\n  The ready flag at offset 0x34 is cleared after successful wait completion\n\nStructure Layout (GameObjectInstance virtual methods):\nOffset | Size | Method                 | Purpose\n-------|------|------------------------|-------------------------------------------\n  0x30 |    4 | IsObjectReady(0,0,1)  | Check if object is ready; returns 0x88780096 if pending\n  0x50 |    4 | RefreshObjectState()  | Update object state during wait",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5be5c6d3e5794ca8d7bdee513ab9939a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5be5c6d3e5794ca8d7bdee513ab9939a",
        "CFG": "285d09a7e9b985b0b82a1cfce0632509",
        "PRO": "9d89068245fb7fca2ec7af5997772eec"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5be5c6d3e5794ca8d7bdee513ab9939a"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_248e0fc309e1": {
      "addresses": {
        "LoD/PD2": "0x0383C6D0"
      },
      "rvas": {
        "LoD/PD2": "0x1C6D0"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "CalculateDivisionResult",
      "signature": "uint CalculateDivisionResult(GameObjectInstance * pObject)",
      "calling_convention": "__cdecl",
      "comment": "Calculates a division result by invoking a virtual function and dividing its output.\n\nAlgorithm:\n1. Save registers (ECX, ESI) on stack\n2. Load the input object pointer from parameter into ESI\n3. Dereference object to get vtable pointer (offset +0)\n4. Load virtual function pointer from vtable at offset +0x10\n5. Prepare three arguments on stack for virtual function call:\n   - Pointer to output buffer (ESP+4)\n   - Pointer to object (ESP+0x10)\n   - Object vtable pointer\n6. Call virtual function at vtable+0x10\n7. Check return value: if negative, return 0xffffffff (error)\n8. Otherwise, divide numerator (ESI-unaffected register) by divisor at object offset +0xc\n9. Return quotient in EAX\n\nParameters:\n  pObject: Pointer to GameObjectInstance with vtable at offset +0 and divisor at offset +0xc\n\nReturns:\n  uint: Quotient from division, or 0xffffffff on error\n\nSpecial Cases:\n  - Returns 0xffffffff if virtual function call returns negative value\n  - Division uses unsigned integer division (DIV instruction)\n  - The numerator comes from ESI which is unaffected by the virtual call",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:248e0fc309e1113605b11ca892cc4e6c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "248e0fc309e1113605b11ca892cc4e6c",
        "CFG": "093f36e40cc4a7861754e4e870ef1391",
        "PRO": "eea0b25140867bc9a90dae5eb3655302"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "248e0fc309e1113605b11ca892cc4e6c"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_73e7d6233499": {
      "addresses": {
        "LoD/PD2": "0x0383C700"
      },
      "rvas": {
        "LoD/PD2": "0x1C700"
      },
      "sizes": {
        "LoD/PD2": 66
      },
      "name": "CheckAndPollAsyncOperation",
      "signature": "undefined4 CheckAndPollAsyncOperation(int pAsyncContext, undefined4 * pOutputValue1, undefined4 * pOutputValue2)",
      "calling_convention": "__stdcall",
      "comment": "Checks if an async operation is ready and polls it if conditions are met.\n\nAlgorithm:\n1. Load operation status flag from pAsyncContext[0x6c]\n2. Check if status is not -1 (operation ID is valid)\n3. Load completion flag from pAsyncContext[0x78]\n4. Check if completion flag is 0 (operation not yet complete)\n5. If both conditions pass: Push status and operation pointer address to stack\n6. Call PollOperationWithRetry to poll the async operation\n7. Load completion result from pAsyncContext[0x78] into pOutputValue1\n8. Load secondary result from pAsyncContext[0x74] into pOutputValue2\n9. Return 1 to indicate success\n10. If either condition fails: Return 0 to indicate operation not ready\n\nParameters:\n- pAsyncContext: Pointer to async operation context structure containing operation ID, completion flags, and result buffers at various offsets\n- pOutputValue1: Pointer to dword that receives completion result from context[0x78]\n- pOutputValue2: Pointer to dword that receives secondary result from context[0x74]\n\nReturns:\n- 1 (success): Operation was ready and polled, results written to output parameters\n- 0 (failure): Operation not ready (invalid ID or already completed)\n\nSpecial Cases:\n- Operation ID at offset 0x6c of -1 means operation is invalid\n- Completion flag at offset 0x78 of 0 indicates operation is ready to poll\n- Operation pointer is at offset 0x3c in the async context structure\n- Secondary result at offset 0x74 typically contains error code or additional status\n- Uses stdcall convention: callee cleans 12 bytes (3 dword parameters)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:73e7d62334998be2018eeed2e05edf34",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "73e7d62334998be2018eeed2e05edf34",
        "CFG": "adc640a3489c603170b20e3511a8313a",
        "PRO": "8dadf365bdf479fd28e8b8981f833f40"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "73e7d62334998be2018eeed2e05edf34"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_a91db643414f": {
      "addresses": {
        "LoD/PD2": "0x0383C750"
      },
      "rvas": {
        "LoD/PD2": "0x1C750"
      },
      "sizes": {
        "LoD/PD2": 115
      },
      "name": "ClearAudioBuffer",
      "signature": "uint ClearAudioBuffer(void * pAudioStructure, uint bufferOffset)",
      "calling_convention": "__stdcall",
      "comment": "Clears/initializes an audio buffer region with a pattern based on audio depth.\n\nAlgorithm:\n1. Validate audio structure state via offset +0x6c and +0x78 fields\n2. Calculate byte count from offsets +0x74 and parameter bufferOffset\n3. Determine fill byte (0x80 if offset +0x50 != 0x10, else 0x00)\n4. Fill buffer with pattern: 32-bit aligned fill for bulk, then byte-wise remainder\n5. Call FUN_0383c670 for cleanup/finalization operations\n6. Reset state flags: offset +0x6c to 0xffffffff, offset +0x78 to 0x00\n7. Return 1 on success, 0 if validation fails\n\nParameters:\n  pAudioStructure: Pointer to audio subsystem structure\n  bufferOffset: Starting offset/address for buffer operation\n\nReturns:\n  1 if buffer cleared successfully and state reset\n  0 if validation failed (state fields invalid)\n\nSpecial Cases:\n  - Returns 0 if [pAudioStructure+0x6c] == -1 (invalid state marker)\n  - Returns 0 if [pAudioStructure+0x78] == 0 (buffer size is zero)\n  - Fill pattern is 0x80 if [pAudioStructure+0x50] != 0x10 (depth check)\n  - Uses REP STOSD for bulk fill (32-bit) then REP STOSB for remainder (8-bit)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a91db643414f481392dcb29900bab08a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a91db643414f481392dcb29900bab08a",
        "CFG": "81cab27cecd1d60d77975c0a7ed82460",
        "PRO": "fb4eadfbb3f4323b662387f057a99b40"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a91db643414f481392dcb29900bab08a"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_5f6597f65341": {
      "addresses": {
        "LoD/PD2": "0x0383C910"
      },
      "rvas": {
        "LoD/PD2": "0x1C910"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "CallVirtualMethod48",
      "signature": "void CallVirtualMethod48(void * pObjectWrapper)",
      "calling_convention": "__cdecl",
      "comment": "Calls virtual method at offset 0x48 in object vtable and sets flag at offset 0x34\n\nAlgorithm:\n1. Extract object pointer from first DWORD of input wrapper\n2. Retrieve virtual method table (vtable) from first DWORD of object\n3. Call virtual function at vtable offset 0x48, passing object as argument\n4. Set flag at wrapper offset 0x34 (index 0xd) to 1\n5. Return to caller\n\nParameters:\npObjectWrapper - Pointer to wrapper structure containing object reference at offset 0\n\nReturns:\nvoid - No return value\n\nStructure Layout:\nOffset | Size | Field          | Type     | Description\n0x00   | 4    | pObject        | void*    | Pointer to object instance\n0x34   | 4    | flag           | uint32   | Flag set after method call",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5f6597f6534112837359ef16de154638",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5f6597f6534112837359ef16de154638",
        "CFG": null,
        "PRO": "1796ab06f5fb0fee2ae315488432bedc"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5f6597f6534112837359ef16de154638"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_301bd5440f60": {
      "addresses": {
        "LoD/PD2": "0x0383C960"
      },
      "rvas": {
        "LoD/PD2": "0x1C960"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "_malloc",
      "signature": "void * _malloc(size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _malloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:301bd5440f60703ca7a24a8fb30f1e56",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "301bd5440f60703ca7a24a8fb30f1e56",
        "CFG": null,
        "PRO": "7e9088f68695e390e3d3eb2a96d52b44"
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
    "binkw32_MNE_be05c38d951a": {
      "addresses": {
        "LoD/PD2": "0x0383C972"
      },
      "rvas": {
        "LoD/PD2": "0x1C972"
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
        "PRO": "c23a96deea647357438db7500c249a64"
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
    "binkw32_MNE_4e5e59b9a63f": {
      "addresses": {
        "LoD/PD2": "0x0383C99E"
      },
      "rvas": {
        "LoD/PD2": "0x1C99E"
      },
      "sizes": {
        "LoD/PD2": 54
      },
      "name": "AllocateMemoryFallback",
      "signature": "void * AllocateMemoryFallback(uint allocationSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates memory using a two-tier strategy: pool-based for small allocations, heap-based as fallback.\n\nAlgorithm:\n1. Load allocation size from parameter\n2. Compare size against pool threshold (DAT_0384e494)\n3. If size within pool limits, attempt AllocateFromMemoryPool\n4. If pool allocation succeeds, return allocated pointer\n5. If pool allocation fails or size exceeds threshold, fall back to heap\n6. Handle zero-size allocation by converting to minimum size (1 byte)\n7. Calculate aligned size using formula: (size + 15) & 0xfffffff0 (16-byte alignment)\n8. Call HeapAlloc with aligned size\n9. Return result\n\nParameters:\n  allocationSize (uint): Size in bytes to allocate. Zero is converted to 1.\n\nReturns:\n  void*: Pointer to allocated memory block, or NULL if allocation fails.\n\nSpecial Cases:\n  - Zero-size allocations are converted to 1 byte minimum\n  - Allocation size is always 16-byte aligned before heap allocation\n  - Pool threshold defined by DAT_0384e494 global variable\n  - Heap handle stored in DAT_0385ce0c global variable",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4e5e59b9a63f832f54b3dcf90c4a63d7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "CFG": "92278232420090a1495e8a6ef63d1827",
        "PRO": "915bad49c431c4381036e0d7737fb812"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4e5e59b9a63f832f54b3dcf90c4a63d7"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_b18de4e8dfaa": {
      "addresses": {
        "LoD/PD2": "0x0383C9D4"
      },
      "rvas": {
        "LoD/PD2": "0x1C9D4"
      },
      "sizes": {
        "LoD/PD2": 47
      },
      "name": "FreeMemoryBlock",
      "signature": "void FreeMemoryBlock(void * pMemory)",
      "calling_convention": "__cdecl",
      "comment": "Frees a memory block by delegating to appropriate allocator.\n\nAlgorithm:\n1. Check if pMemory pointer is NULL; if so, return immediately\n2. Query allocator pool to find which allocator owns this memory block\n3. If allocator found, delegate to DeallocateMemoryBlock for pool deallocation\n4. If allocator not found, assume memory was allocated by heap and call HeapFree\n\nParameters:\n- pMemory: Pointer to memory block to deallocate. May be NULL.\n\nReturns:\n- void\n\nSpecial Cases:\n- NULL pointers are safely ignored (no operation performed)\n- Supports dual allocation paths: custom allocator pools and Win32 heap\n- Uses global DAT_0385ce0c handle for heap operations",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b18de4e8dfaa1ea94be3de3b62f2adf9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "CFG": "4e847b889984c71922568191fca6fba0",
        "PRO": "47188dfb919d357b42c261e8dba56040"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b18de4e8dfaa1ea94be3de3b62f2adf9"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_9385a3901497": {
      "addresses": {
        "LoD/PD2": "0x0383CA10"
      },
      "rvas": {
        "LoD/PD2": "0x1CA10"
      },
      "sizes": {
        "LoD/PD2": 140
      },
      "name": "__strcmpi",
      "signature": "int __strcmpi(char * _Str1, char * _Str2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __strcmpi\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9385a39014977010e096b1b65a9621a6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9385a39014977010e096b1b65a9621a6",
        "CFG": "045d072095aa0590f457075a5c76c09c",
        "PRO": "c696608c00b23b4a16ca3d1d8bf60dac"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9385a39014977010e096b1b65a9621a6"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_bff09423b51f": {
      "addresses": {
        "LoD/PD2": "0x0383CAA0"
      },
      "rvas": {
        "LoD/PD2": "0x1CAA0"
      },
      "sizes": {
        "LoD/PD2": 664
      },
      "name": "Memmove",
      "signature": "void * Memmove(void * dest, void * src, uint count)",
      "calling_convention": "__cdecl",
      "comment": "Optimized memory copy with overlap detection and alignment handling.\\n\\nAlgorithm:\\n1. Load source (ESI), destination (EDI), and count (ECX) from stack\\n2. Check for memory overlap: if dest < src && src < (dest + count), use backward copy\\n3. For forward copy: align destination to DWORD boundary, use MOVSD for bulk copy\\n4. For backward copy: copy from end, use STD prefix for reverse direction\\n5. Handle unaligned destinations with byte/word prefix copy before DWORD loop\\n6. Handle remaining bytes with switch statement based on (count & 3)\\n7. Return original destination pointer in EAX\\n\\nParameters:\\n  dest (EBP+8): void * - Destination buffer (may overlap with source)\\n  src (EBP+C): void * - Source buffer to copy from\\n  count (EBP+10): uint - Number of bytes to copy\\n\\nReturns:\\n  EAX: void * - Pointer to destination (unchanged from parameter)\\n\\nSpecial Cases:\\n  - Detects overlap using comparison: if (dest < src) && (src < dest+count)\\n  - Uses backward copy when regions overlap and dest < src\\n  - Aligns destination to 4-byte boundary before using MOVSD\\n  - Optimization requires at least 8 DWORDS to be worthwhile (CMP ECX, 0x8)\\n  - Tail copy handles remaining 1-3 bytes after DWORD loop via switch table",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bff09423b51fd121ea30afec957819f4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bff09423b51fd121ea30afec957819f4",
        "CFG": "6140b24f34cd85599ad606b05441e9d1",
        "PRO": "ff38c497c82643f818ac8c3950b7223d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bff09423b51fd121ea30afec957819f4"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_059e9bb2efc1": {
      "addresses": {
        "LoD/PD2": "0x0383CDD8"
      },
      "rvas": {
        "LoD/PD2": "0x1CDD8"
      },
      "sizes": {
        "LoD/PD2": 32
      },
      "name": "__global_unwind2",
      "signature": "undefined __global_unwind2(PVOID param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __global_unwind2\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:059e9bb2efc1de93bfe21089d0ad96d3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "059e9bb2efc1de93bfe21089d0ad96d3",
        "CFG": null,
        "PRO": "09ddda4df0a4b94968d66dcfc3cca519"
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
    "binkw32_MNE_cd4ab8e23ed6": {
      "addresses": {
        "LoD/PD2": "0x0383CE1A"
      },
      "rvas": {
        "LoD/PD2": "0x1CE1A"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "__local_unwind2",
      "signature": "undefined __local_unwind2(int param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __local_unwind2\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release, Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cd4ab8e23ed6997cd2e2434b8d375458",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd4ab8e23ed6997cd2e2434b8d375458",
        "CFG": "d7e92aa36e4ea61ef8903512dfbaf1bc",
        "PRO": "8991fb038676265817639d7b30841cdb"
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
    "binkw32_MNE_ed17ad9d511f": {
      "addresses": {
        "LoD/PD2": "0x0383CEAE"
      },
      "rvas": {
        "LoD/PD2": "0x1CEAE"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "SaveExceptionContext",
      "signature": "void SaveExceptionContext(void)",
      "calling_convention": "__stdcall",
      "comment": "Saves exception context to global exception handler structure.\n\nAlgorithm:\n1. Load exception context base address from hardcoded global (0x384e450)\n2. Store return address from stack at offset +0x8\n3. Store exception code from EAX at offset +0x4\n4. Store exception frame pointer from EBP at offset +0xc\n5. Return via __stdcall convention (caller pops 4-byte return address)\n\nParameters:\nEAX (implicit) - Exception code/status to store in exception context\nEBP (implicit) - Exception frame pointer (parent stack frame)\n[ESP] (implicit) - Return address (callee pops via RET 0x4)\n\nReturns:\nvoid - Function has no return value\n\nSpecial Cases:\n- Global exception context stored at fixed address 0x384e450\n- Uses __stdcall calling convention with 4-byte return address cleanup\n- Part of Visual Studio C++ exception handling infrastructure\n- Called during exception unwinding by __local_unwind2\n\nStructure Layout:\nOffset  Size  Field Name          Type      Description\n------  ----  ----------          ----      -----------\n0x0     4     unknown_0           uint      Unknown field\n0x4     4     exceptionCode       uint      Exception code/status\n0x8     4     returnAddress       void*     Return address\n0xc     4     framePointer        void*     Exception frame pointer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ed17ad9d511f6e330c2b6a62378d83cf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ed17ad9d511f6e330c2b6a62378d83cf",
        "CFG": "014d2069a1aece9d955ffb144dc9da61",
        "PRO": "39d6b544182fe623338211af29a3f3a9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ed17ad9d511f6e330c2b6a62378d83cf"
      }
    },
    "binkw32_MNE_89d1b6190541": {
      "addresses": {
        "LoD/PD2": "0x0383CF8D"
      },
      "rvas": {
        "LoD/PD2": "0x1CF8D"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "__seh_longjmp_unwind@4",
      "signature": "undefined __seh_longjmp_unwind@4(int param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __seh_longjmp_unwind@4\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release, Visual Studio 2003 Debug, Visual Studio 2003 Release",
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
    "binkw32_MNE_cb09f6b5d979": {
      "addresses": {
        "LoD/PD2": "0x0383CFA8"
      },
      "rvas": {
        "LoD/PD2": "0x1CFA8"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "InitializeProcessorAndFlags",
      "signature": "void InitializeProcessorAndFlags(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes processor detection and clears initialization flags during startup.\n\nAlgorithm:\n1. Call InitializeFunctionPointers to set up runtime library function pointers\n2. Call LoadAndCallIsProcessorFeaturePresent to detect processor capabilities via KERNEL32\n3. Store processor feature detection result in global variable DAT_0385c8ac\n4. Call ClearFlagsMaskWrapper to disable initialization-related flag bits (0x30000) and enable processor-specific flags (0x10000)\n5. Return to caller\n\nReturns:\nvoid - No return value; function performs module initialization side effects\n\nSpecial Cases:\n- Called during module initialization from ExecuteInitializationHandlers\n- Processor feature detection uses IsProcessorFeaturePresent if available (WinXP+) with fallback for older Windows\n- Magic numbers: 0x10000 (processor feature flag set) and 0x30000 (initialization flags to clear)\n- All initialization must complete before main game logic executes\n- This is a critical startup function that must run exactly once during module load",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cb09f6b5d9797072e6568a27cb29dcdf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cb09f6b5d9797072e6568a27cb29dcdf",
        "CFG": null,
        "PRO": "4525054fad93c609ecb58b050b01a717"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "cb09f6b5d9797072e6568a27cb29dcdf"
      }
    },
    "binkw32_MNE_bfc3ed25e915": {
      "addresses": {
        "LoD/PD2": "0x0383CFC0"
      },
      "rvas": {
        "LoD/PD2": "0x1CFC0"
      },
      "sizes": {
        "LoD/PD2": 56
      },
      "name": "InitializeFunctionPointers",
      "signature": "void InitializeFunctionPointers(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes global function pointers to runtime library functions.\n\nAlgorithm:\n1. Load address of __cfltcvt function into EAX (0x383e223)\n2. Store pointer to LAB_0383deb8 in PTR_LAB_0384e49c\n3. Store __cfltcvt pointer in PTR___cfltcvt_0384e498\n4. Store pointer to __fassign (0x383df1e) in PTR___fassign_0384e4a0\n5. Store pointer to RotateStringCharacters (0x383de5e) in PTR_RotateStringCharacters_0384e4a4\n6. Store pointer to LAB_0383df06 in PTR_LAB_0384e4a8\n7. Store __cfltcvt pointer in PTR___cfltcvt_0384e4ac\n8. Return to caller\n\nReturns:\nvoid - No return value; function performs initialization side effects\n\nSpecial Cases:\n- Called during program initialization (from FUN_0383cfa8)\n- Initializes multiple global pointer variables for use by other functions\n- The function pointers point to runtime library functions and code labels used for dynamic dispatch\n- Part of the initialization sequence that must run before main program logic",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bfc3ed25e9152f457419d9112a775bc2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bfc3ed25e9152f457419d9112a775bc2",
        "CFG": null,
        "PRO": "c55a401edca1b8e4cfe9fcc831da2da0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bfc3ed25e9152f457419d9112a775bc2"
      }
    },
    "binkw32_MNE_2a518bd4b0b9": {
      "addresses": {
        "LoD/PD2": "0x0383D000"
      },
      "rvas": {
        "LoD/PD2": "0x1D000"
      },
      "sizes": {
        "LoD/PD2": 47
      },
      "name": "StackProbe",
      "signature": "void StackProbe(void)",
      "calling_convention": "__stdcall",
      "comment": "Stack probe function for allocating large stack space safely.\n\nThis function is called before allocating large amounts of stack space to ensure\nall stack pages are committed and available. It probes memory in 4KB increments\nto trigger page faults and commit stack pages before actual use.\n\nAlgorithm:\n1. Check if requested stack size (in EAX) exceeds 4096 bytes\n2. If yes, enter loop: decrement probe pointer by 4KB, test memory at that address\n3. Repeat until remaining size is less than 4KB\n4. Adjust stack pointer by remaining size and test final page\n5. Restore registers and return to caller\n\nParameters:\n- EAX (implicit): Size of stack space to allocate in bytes\n\nReturns:\n- Stack pointer adjusted by requested size\n- All memory pages within allocated range committed and accessible\n\nSpecial Cases:\n- Allocations less than 4096 bytes skip the loop and test directly\n- Memory access at each probe address ensures page commitment\n- Function must preserve all registers except ESP",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "CFG": "4e847b889984c71922568191fca6fba0",
        "PRO": "c71205845eb17fcc2718f716924d07ee"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6"
      }
    },
    "binkw32_MNE_73c3f7bd7828": {
      "addresses": {
        "LoD/PD2": "0x0383D030"
      },
      "rvas": {
        "LoD/PD2": "0x1D030"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "__ftol",
      "signature": "longlong __ftol(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __ftol\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:73c3f7bd7828903a97f293ba1dae2fe1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "73c3f7bd7828903a97f293ba1dae2fe1",
        "CFG": null,
        "PRO": "c9e7cc5db24167bf45f1b93a01a6754c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "73c3f7bd7828903a97f293ba1dae2fe1"
      }
    },
    "binkw32_MNE_f4e79a937471": {
      "addresses": {
        "LoD/PD2": "0x0383D060"
      },
      "rvas": {
        "LoD/PD2": "0x1D060"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "ComputeAudioCoefficientLogarithm",
      "signature": "float10 ComputeAudioCoefficientLogarithm(float10 * __return_storage_ptr__, double base, double value, uint stackParam)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper function to compute logarithm of audio coefficient for Bink audio decoding.\n\nThis is a thin wrapper around ComputeLogarithm that adapts floating-point values\nfrom the FPU stack for use in the audio decoding pipeline. It marshals two double\nvalues and a stack parameter into the ComputeLogarithm function call.\n\nAlgorithm:\n1. Allocate 16 bytes on stack for local variables\n2. Exchange ST0 and ST1 floating-point registers\n3. Store base value (originally in ST1) at [ESP]\n4. Store audio value (originally in ST0) at [ESP+8]\n5. Load stack parameter into EAX from [ESP+0xc]\n6. Call ComputeLogarithm with marshaled parameters\n7. Clean up stack and return result in ST0 (float10)\n\nParameters:\n- base: Base value for logarithm calculation (double, from FPU ST1)\n- value: Audio coefficient value (double, from FPU ST0)\n- stackParam: Additional stack parameter (uint, from [ESP+0xc])\n\nReturns:\n- float10: Extended-precision floating-point result containing log value\n\nSpecial Cases:\n- FPU stack exchange (FXCH) required because parameters arrive in reverse order\n- Result returned in ST0 as extended precision float (float10)\n- Uses __stdcall calling convention (callee cleans stack)\n- Part of Bink audio sample decoding pipeline called from DecodeBinkAudioSamples",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f4e79a9374712478a96f5f0af7ec0c2f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f4e79a9374712478a96f5f0af7ec0c2f",
        "CFG": null,
        "PRO": "a93c7dfdf9a2c8dea1976762e7b22479"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f4e79a9374712478a96f5f0af7ec0c2f"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_512beb3274e3": {
      "addresses": {
        "LoD/PD2": "0x0383D082"
      },
      "rvas": {
        "LoD/PD2": "0x1D082"
      },
      "sizes": {
        "LoD/PD2": 467
      },
      "name": "ComputeLogarithm",
      "signature": "double ComputeLogarithm(double baseValue, uint baseBits, double exponentValue, uint exponentBits)",
      "calling_convention": "__cdecl",
      "comment": "Computes logarithm of base raised to the power of exponent using FPU instructions.\n\nAlgorithm:\n1. Save and check FPU control word for proper rounding mode (0x27f)\n2. Extract exponent bits from base value using bit masking (0x7ff00000)\n3. Call helper function to validate base value and extract properties\n4. Check if base is special value (infinity/NaN) by testing exponent bits\n5. If base is normal number, extract sign byte and compute log2(base) using FYL2X\n6. Apply scaling factor and check sign bit to determine sign of result\n7. If base is infinity, check mantissa bits for NaN condition\n8. If base is zero, check exponent value for special handling\n9. For normal exponent values, perform power computation using allocated FPU state\n10. Save current FPU stack values, call Pow2 computation, restore FPU state\n11. Return computed result in FPU ST0 register or error code in EAX\n\nParameters:\nbaseValue: Base number (passed as double in EAX:EDX or FPU stack)\nbaseBits: Bit representation of base (uint parameter)\nexponentValue: Exponent to raise base to (passed as double)\nexponentBits: Bit representation of exponent (uint parameter)\n\nReturns:\nST0: Computed logarithm result (extended double in FPU stack)\nEAX: Error code (0 = success, 1,2,7 = special case errors)\n\nSpecial Cases:\n- Base = 1.0: Returns 0.0\n- Base = 0.0: Returns negative infinity or special value\n- Base = -Infinity: Returns NaN (0x7fffffff pattern)\n- Base = Infinity: Returns infinity based on exponent sign\n- Base = NaN: Returns NaN propagated\n- Exponent = 0: Returns 1.0 (any number to power 0)\n- Sign handling: Result negated when base is negative\n- FPU exception handling with dedicated error handlers",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:512beb3274e38dd5f9dc6106693805f5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "512beb3274e38dd5f9dc6106693805f5",
        "CFG": "f87d33bf25c2c522a948bc1ac422ee48",
        "PRO": "c77f6039960f14bd3c8539ec4bc44851"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "512beb3274e38dd5f9dc6106693805f5"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_634f5fd2b38b": {
      "addresses": {
        "LoD/PD2": "0x0383D255"
      },
      "rvas": {
        "LoD/PD2": "0x1D255"
      },
      "sizes": {
        "LoD/PD2": 40
      },
      "name": "CountFractionalDigits",
      "signature": "byte CountFractionalDigits(void)",
      "calling_convention": "__stdcall",
      "comment": "Counts the number of fractional digit positions in a floating-point value.\\n\\nAlgorithm:\\n1. Load floating-point value from ST0 and round it to nearest integer\\n2. Compare rounded value against original to check for fractional part\\n3. If values match (no fraction), skip both iterations\\n4. If mismatch, multiply by 10 (located at 0x0384e480) and increment count\\n5. Repeat the comparison twice to detect fractional digits\\n6. Return count of fractional digit positions in CL register (0, 1, or 2)\\n\\nParameters:\\n Implicit: ST0 register contains floating-point value to analyze\\n\\nReturns:\\n CL: Byte count of fractional digit positions (0-2)\\n\\nSpecial Cases:\\n- Magic address 0x0384e480 contains constant 10.0 for scaling\\n- Uses x87 FPU floating-point operations\\n- Detects only up to 2 significant fractional digits\\n- Zero fractional digits returns count of 0\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:634f5fd2b38b5a9728c3cfaee438889f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "634f5fd2b38b5a9728c3cfaee438889f",
        "CFG": "9f0e6dcc6217912767c0e6d0aa226117",
        "PRO": "c4bcc9c1cfeb654811107e7f522425c9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "634f5fd2b38b5a9728c3cfaee438889f"
      }
    },
    "binkw32_MNE_83b97549df2e": {
      "addresses": {
        "LoD/PD2": "0x0383D27D"
      },
      "rvas": {
        "LoD/PD2": "0x1D27D"
      },
      "sizes": {
        "LoD/PD2": 184
      },
      "name": "DllInitialization",
      "signature": "int DllInitialization(int dllHandle, int initializationCode)",
      "calling_convention": "__stdcall",
      "comment": "DLL Initialization and Termination Handler\\n\\nManages DLL lifecycle including initialization on process attach and cleanup on process detach. Handles version detection, memory heap setup, environment configuration, and registration of cleanup handlers.\\n\\nAlgorithm:\\n1. Check initialization code parameter for DLL_PROCESS_ATTACH (1) or DLL_PROCESS_DETACH (0)\\n2. On DLL_PROCESS_ATTACH: Query Windows version and extract major/minor components\\n3. Initialize memory heap and verify success; return 0 on failure\\n4. Cache command line arguments and environment strings for runtime access\\n5. Initialize handle table and parse command line arguments into argv-style array\\n6. Build environment variable array from cached environment strings\\n7. Execute all registered initialization handlers (C++ static constructors)\\n8. Increment initialization counter to track DLL nesting/recursion depth\\n9. Return 1 (success) for attach operation\\n10. On DLL_PROCESS_DETACH: Decrement initialization counter\\n11. Verify counter is positive; return 0 if this is not innermost DLL instance\\n12. Execute cleanup handlers if cleanup flag not set (atexit callbacks)\\n13. Clean global pointer arrays and free all allocated memory\\n14. Return 1 (success)\\n\\nParameters:\\n- dllHandle (int): Module handle passed by Windows loader (unused in this implementation)\\n- initializationCode (int): Operation code - 1 for DLL_PROCESS_ATTACH, 0 for DLL_PROCESS_DETACH\\n\\nReturns:\\n- 1: Success - initialization completed successfully or cleanup performed\\n- 0: Failure - heap initialization failed, or detach called before attach completed\\n\\nSpecial Cases:\\n- Nested DLL loads: Counter tracks recursion depth; only innermost instance performs cleanup\\n- Cleanup flag (DAT_0385c940): When set, skips atexit handler execution during detach\\n- Version storage: Windows version encoded as (minor << 8) | major for Win98/NT compatibility\\n- Environment caching: Lazy-loaded environment strings reused across multiple accesses",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:83b97549df2e40c28a16c5f86c2df6f2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "83b97549df2e40c28a16c5f86c2df6f2",
        "CFG": "84722a843568370bfd19dcc25ae78914",
        "PRO": "7a8c1eb4b5a4d5058be2a1dc83392475"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "83b97549df2e40c28a16c5f86c2df6f2"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_bafce56213ce": {
      "addresses": {
        "LoD/PD2": "0x0383D335"
      },
      "rvas": {
        "LoD/PD2": "0x1D335"
      },
      "sizes": {
        "LoD/PD2": 157
      },
      "method": "MNE",
      "index": "MNE:bafce56213ce6cb4a7088c594df572ea",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bafce56213ce6cb4a7088c594df572ea",
        "CFG": "843195b551b739c45da5196e06b02088",
        "PRO": "3ff0ec10389d92e20dc3ad6e9f1601ba"
      },
      "display_name": "MNE_bafce56213ce6cb4",
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bafce56213ce6cb4a7088c594df572ea"
      }
    },
    "binkw32_MNE_bed936c73fe1": {
      "addresses": {
        "LoD/PD2": "0x0383D3D2"
      },
      "rvas": {
        "LoD/PD2": "0x1D3D2"
      },
      "sizes": {
        "LoD/PD2": 48
      },
      "name": "__amsg_exit",
      "signature": "void __amsg_exit(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __amsg_exit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bed936c73fe1864937225129603e250c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bed936c73fe1864937225129603e250c",
        "CFG": "2555e203409cbc2d4a46fa3a51b3c448",
        "PRO": "7f98f9063b4c10fd5f6e7a2cdf4f00a0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bed936c73fe1864937225129603e250c"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_ee4facdaccbd": {
      "addresses": {
        "LoD/PD2": "0x0383D405"
      },
      "rvas": {
        "LoD/PD2": "0x1D405"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "CallConditionalCallback",
      "signature": "int CallConditionalCallback(int value)",
      "calling_convention": "__cdecl",
      "comment": "Conditionally invokes a callback function if registered\n\nAlgorithm:\n1. Load callback function pointer from global address 0x0385c8c8\n2. If callback pointer is null, skip invocation and return false (0)\n3. Push the input value parameter onto stack\n4. Call the callback function pointer with the value as argument\n5. Test the return value from callback (EAX)\n6. If callback return is non-zero, return true (1) to indicate success\n7. If callback return is zero, return false (0) to indicate failure\n\nParameters:\n- value (int): The input value to pass to the callback function\n\nReturns:\n- int: 1 if callback exists and returns non-zero, 0 otherwise\n\nSpecial Cases:\n- If global callback pointer at 0x0385c8c8 is null, function returns 0 without calling\n- Callback invocation only succeeds if result is non-zero (truthy)\n- Used as a conditional hook/dispatch mechanism for callback-based operations",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ee4facdaccbd6fc5f3297fd5b85b73c2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "CFG": "c514545fcce289b8241e149ad12d442a",
        "PRO": "02248df169c3cca2531f062388b6e93d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ee4facdaccbd6fc5f3297fd5b85b73c2"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_e33a4c6c562d": {
      "addresses": {
        "LoD/PD2": "0x0383D420"
      },
      "rvas": {
        "LoD/PD2": "0x1D420"
      },
      "sizes": {
        "LoD/PD2": 60
      },
      "name": "InitializeMemoryHeap",
      "signature": "int InitializeMemoryHeap(int heapFlags)",
      "calling_convention": "__cdecl",
      "comment": "Initializes the application's private memory heap for dynamic allocation.\n\nAlgorithm:\n1. Create a private heap using Windows HeapCreate API with initial size 0x1000\n2. Set HEAP_NO_SERIALIZE flag (0x1) if heapFlags is 0 (moveable), otherwise unset\n3. Store heap handle in global variable g_heapHandle for later use\n4. If heap creation fails, return 0 (failure)\n5. Call InitializeMemoryBuffer to set up memory management structures\n6. If buffer initialization succeeds, return 1 (success)\n7. If buffer initialization fails, destroy the heap and return 0 (cleanup on error)\n\nParameters:\n  heapFlags (int): Heap behavior flags. 0 = create moveable heap with HEAP_NO_SERIALIZE,\n                   non-zero = create serialized heap without HEAP_NO_SERIALIZE\n\nReturns:\n  1 (int): Success - heap and memory buffer initialized successfully\n  0 (int): Failure - heap creation or buffer initialization failed\n\nSpecial Cases:\n  - HEAP_NO_SERIALIZE (0x1): Used for single-threaded heap access (faster, no locking)\n  - HEAP_INITIAL_SIZE (0x1000): Initial heap size is 4KB, grows as needed\n  - On buffer init failure, heap is destroyed to avoid resource leaks\n  - g_heapHandle stores the heap handle for use by memory allocation functions",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e33a4c6c562d51a2fcc8e07bee94f1d6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "CFG": "d7e96f9927eb9ca21b2899c502c7f39a",
        "PRO": "16847fa79110f65f85652b26f0a066ad"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e33a4c6c562d51a2fcc8e07bee94f1d6"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_95a95faa5aba": {
      "addresses": {
        "LoD/PD2": "0x0383D45C"
      },
      "rvas": {
        "LoD/PD2": "0x1D45C"
      },
      "sizes": {
        "LoD/PD2": 117
      },
      "name": "CleanupMemoryAllocations",
      "signature": "void CleanupMemoryAllocations(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleans up all allocated memory and destroys the memory heap.\n\nThis function iterates through all allocated memory blocks in a global array,\nfreeing both virtual and heap-allocated memory, then destroys the heap itself.\nUsed during application shutdown or emergency cleanup.\n\nAlgorithm:\n1. Initialize loop counter to 0\n2. Load the allocation count from DAT_0385ce04\n3. If count is 0 or less, skip to main allocation cleanup\n4. Load base address of allocation array from DAT_0385ce08\n5. For each allocation block (stride of 20 bytes / 0x14):\n   a. Call VirtualFree with flags 0x4000 (MEM_DECOMMIT) on offset+0 pointer\n   b. Call VirtualFree with flags 0x8000 (MEM_RELEASE) on offset+0 pointer  \n   c. Call HeapFree on offset+4 pointer using DAT_0385ce0c heap\n   d. Increment block pointer by 20 bytes (0x14)\n   e. Increment loop counter\n6. After all blocks freed, call HeapFree on main allocation array\n7. Call HeapDestroy to destroy the heap object\n\nParameters:\nNone - uses global variables for state\n\nReturns:\nvoid\n\nGlobal Dependencies:\n- DAT_0385ce04: Number of allocated blocks\n- DAT_0385ce08: Pointer to allocation block array\n- DAT_0385ce0c: Heap handle\n\nSpecial Cases:\n- Handles empty allocation list (count <= 0)\n- Uses two-step virtual memory decommit/release pattern\n- Each block is 20 bytes, with pointers at offsets +0 and +4\n\nStructure Layout (Allocation Block):\nOffset | Size | Field Name        | Type      | Description\n-------|------|-------------------|-----------|---------------------------------------------\n+0x00  | 4    | virtualMemPtr     | void*     | Virtual memory allocation from VirtualAlloc\n+0x04  | 4    | heapMemPtr        | void*     | Heap memory allocation from HeapAlloc\n+0x08  | 12   | reserved          | byte[12]  | Unused padding\n\nBlock Array Size: DAT_0385ce04 * 20 (0x14) bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:95a95faa5abab405c460e2774e3dc41a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "95a95faa5abab405c460e2774e3dc41a",
        "CFG": "664846e500463189314de1dac1cecd37",
        "PRO": "201b839f6defbaba2f2197cfd953f4f7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "95a95faa5abab405c460e2774e3dc41a"
      }
    },
    "binkw32_MNE_9714d3ad2dee": {
      "addresses": {
        "LoD/PD2": "0x0383D4D1"
      },
      "rvas": {
        "LoD/PD2": "0x1D4D1"
      },
      "sizes": {
        "LoD/PD2": 62
      },
      "name": "InitializeMemoryBuffer",
      "signature": "int InitializeMemoryBuffer(void)",
      "calling_convention": "__stdcall",
      "comment": "Allocates and initializes a 320-byte heap buffer with associated global state variables.\\n\\nAlgorithm:\\n1. Call HeapAlloc to allocate 0x140 (320) bytes\\n2. Test if allocation succeeded (EAX != NULL)\\n3. If allocation failed, return 0 (failure status)\\n4. If successful, zero-initialize two global state counters\\n5. Store heap buffer pointer in global DAT_0385cdfc\\n6. Set initialization size marker to 0x10\\n7. Return 1 (success status)\\n\\nParameters:\\n  None\\n\\nReturns:\\n  int - 1 on successful allocation and initialization, 0 if heap allocation failed\\n\\nSpecial Cases:\\n  - Returns immediately with 0 if HeapAlloc fails (out of memory)\\n  - Initializes multiple global variables that may be accessed by other functions\\n  - Allocates fixed 0x140 (320) byte buffer\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9714d3ad2deea30ac943f1376fae33d4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9714d3ad2deea30ac943f1376fae33d4",
        "CFG": "ad60745e7a538a03b6fca85abc2d64ca",
        "PRO": "5fdc9a2f8d2f549aedf82c9ea60b86b9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9714d3ad2deea30ac943f1376fae33d4"
      }
    },
    "binkw32_MNE_2a0dd1f395da": {
      "addresses": {
        "LoD/PD2": "0x0383D50F"
      },
      "rvas": {
        "LoD/PD2": "0x1D50F"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "FindAllocatorPoolEntry",
      "signature": "void * FindAllocatorPoolEntry(void * pSearchValue)",
      "calling_convention": "__cdecl",
      "comment": "Finds an allocator pool entry that contains the specified pointer value.\n\nAlgorithm:\n1. Load pool limit: DAT_0385ce04 * 0x14 + DAT_0385ce08 (calculate max address)\n2. Load initial pool iterator from DAT_0385ce08 (pool base address)\n3. Loop: compare iterator against pool limit\n4. If iterator >= limit, return NULL (entry not found)\n5. Load search value parameter from stack (ESP + 4)\n6. Subtract value at offset 0xc from pool entry: param - poolEntry[0xc]\n7. Check if difference is < 0x100000 (1MB threshold)\n8. If match found (difference < 1MB), return pool entry address\n9. If no match, advance iterator by 0x14 bytes (pool entry size) and retry\n10. Continue until boundary or match found\n\nParameters:\npSearchValue - The pointer value to search for in the pool\n\nReturns:\nPointer to the pool entry containing the search value, or NULL if not found\n\nSpecial Cases:\n- Pool entries are 0x14 (20) bytes in size\n- Each entry has a value field at offset 0xc\n- The function checks if parameter minus entry[0xc] is within 1MB (0x100000)\n- Returns first matching entry where this distance condition is satisfied\n- Search is sequential from pool base address",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2a0dd1f395da0f8e13609d337843c676",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2a0dd1f395da0f8e13609d337843c676",
        "CFG": "dc0623423d93fb21da8f1c1461d32590",
        "PRO": "80248ac75e5b09a45fe6a50c97e1db89"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2a0dd1f395da0f8e13609d337843c676"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_9bfd98dbbd3e": {
      "addresses": {
        "LoD/PD2": "0x0383D53A"
      },
      "rvas": {
        "LoD/PD2": "0x1D53A"
      },
      "sizes": {
        "LoD/PD2": 811
      },
      "name": "DeallocateMemoryBlock",
      "signature": "void DeallocateMemoryBlock(uint * pAllocator, uint blockAddress)",
      "calling_convention": "__cdecl",
      "comment": "Deallocates a memory block from the heap allocator and performs coalescing with adjacent free blocks. Manages bitmap tracking of free blocks and virtual memory pages. Updates linked list of free blocks and handles cleanup when entire heap pages become unused.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9bfd98dbbd3e5d7edb553bd7666739e4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "CFG": "b0c977cba6daa99c8a216043b57a2ddc",
        "PRO": "00e2fa60d81eb194d407fbc1353f620d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9bfd98dbbd3e5d7edb553bd7666739e4"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_ff64648b3e6e": {
      "addresses": {
        "LoD/PD2": "0x0383D865"
      },
      "rvas": {
        "LoD/PD2": "0x1D865"
      },
      "sizes": {
        "LoD/PD2": 777
      },
      "name": "AllocateFromMemoryPool",
      "signature": "int * AllocateFromMemoryPool(uint allocationSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates memory from a pool of pre-allocated blocks with buddy allocator pattern. Algorithm: 1) Calculate bit masks for allocation size using right-shift operations; 2) Search pools for free block matching size requirements; 3) If all pools exhausted, allocate new pool; 4) Find optimal bucket via bit scanning; 5) Reuse or allocate from bucket linked list; 6) Update block size and linked list pointers; 7) Increment counters and set allocation bits; 8) Return pointer with 4-byte offset. Returns pointer to allocated memory or NULL on failure.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ff64648b3e6e32bc28a5e4bc8d984c1e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "CFG": "8bfb5a50412c4903afd2744f0435c9df",
        "PRO": "3d32d6fc38dd51790c04146c3d4bbac6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ff64648b3e6e32bc28a5e4bc8d984c1e"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_b59a8a7d2c8f": {
      "addresses": {
        "LoD/PD2": "0x0383DB6E"
      },
      "rvas": {
        "LoD/PD2": "0x1DB6E"
      },
      "sizes": {
        "LoD/PD2": 177
      },
      "name": "AllocateGameObject",
      "signature": "GameObjectInstance * AllocateGameObject(void)",
      "calling_convention": "__stdcall",
      "comment": "Allocates and initializes a new game object instance.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b59a8a7d2c8fdcc2aac183f01f99a847",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "CFG": "72afefb82939fd195fb2c24c9e65a427",
        "PRO": "b541c99359abd6a546d3b544ec8b1a16"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b59a8a7d2c8fdcc2aac183f01f99a847"
      }
    },
    "binkw32_MNE_0002c858ef39": {
      "addresses": {
        "LoD/PD2": "0x0383DC1F"
      },
      "rvas": {
        "LoD/PD2": "0x1DC1F"
      },
      "sizes": {
        "LoD/PD2": 251
      },
      "name": "AllocateMemoryPool",
      "signature": "int AllocateMemoryPool(int * pPoolManager)",
      "calling_convention": "__cdecl",
      "comment": "Allocates and initializes a 32KB memory pool for a memory management system.\\n\\nAlgorithm:\\n1. Count the number of memory pool tiers by counting set bits in the tier bitmap (offset +0x8)\\n2. Calculate the pool header address by multiplying tier count by 0x204 and adding base offset 0x144\\n3. Initialize 64 free list nodes (0x3F) in the pool header, setting each node's forward/backward pointers to itself (empty list)\\n4. Calculate virtual memory address: tierIndex * 0x8000 + base address (offset +0xc)\\n5. Allocate 32KB (0x8000 bytes) of virtual memory via VirtualAlloc with PAGE_EXECUTE_READWRITE (0x40)\\n6. If allocation fails, return -1 (error indicator)\\n7. Initialize memory pool free list nodes:\\n   - Set node prev/next pointers for doubly-linked list structure\\n   - Nodes are 0x1000 bytes (4KB) apart\\n   - Each node has forward pointer at +0x7000 offset (sentinel)\\n   - Initialize 7 nodes covering 0x7000 bytes of the 0x8000 allocation\\n8. Link pool into the free list tree:\\n   - Set tree pointers: forward pointer at header +0x1fc, backward pointer at memory +0x5\\n   - Set tail pointers: backward pointer at header +0x200, forward pointer at memory +0x1c04\\n9. Update tier tracking:\\n   - Clear tier reference counter at tier+0x44 to 0\\n   - Set tier active flag at tier+0xc4 to 1\\n   - Increment global tier active count at offset +0x43\\n   - If first tier (count was 0), set bit in pool status flags (offset +0x4) to 1\\n   - Clear the tier bit in available tiers bitmap (offset +0x8)\\n10. Return tierIndex (0-based tier number)\\n\\nParameters:\\npPoolManager: Pointer to pool manager structure containing:\\n  [+0x8]  = Tier availability bitmap (bit N set = tier N available)\\n  [+0xc]  = Base virtual memory address for tier pools\\n  [+0x10] = Pointer to tier tracking array\\n\\nReturns:\\nint: Tier index (0-31) on success, -1 if VirtualAlloc fails\\n\\nSpecial Cases:\\n- Tier index must be < 32 due to bitmap size\\n- Assumes 32 tier maximum with 64 free list nodes per tier\\n- Free list nodes are linked bidirectionally (circular when empty)\\n- Memory allocation size is always 0x8000 (32KB) per tier\\n- Each free list node is 0x1000 (4KB) bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0002c858ef3942a0b403454c72674bfe",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0002c858ef3942a0b403454c72674bfe",
        "CFG": "578171bf058641c3b5e7f1cef37bba9b",
        "PRO": "dea8c343a18f51e1084181af8b8e840f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "0002c858ef3942a0b403454c72674bfe"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_cc0e19248bdb": {
      "addresses": {
        "LoD/PD2": "0x0383DD1A"
      },
      "rvas": {
        "LoD/PD2": "0x1DD1A"
      },
      "sizes": {
        "LoD/PD2": 203
      },
      "name": "ApplyCharacterLocaleTransform",
      "signature": "uint ApplyCharacterLocaleTransform(void * this, void * pThis, uint inputCharacter)",
      "calling_convention": "__thiscall",
      "comment": "Applies locale-aware character transformation including case conversion.\n\nThis function performs character transformation based on locale settings. It handles:\n1. Simple ASCII uppercase-to-lowercase conversion if locale mapping is disabled\n2. Character class validation to determine if transformation applies\n3. Locale-specific character mapping for single and multi-byte characters\n4. Support for both simple transformation tables and complex locale handlers\n\nAlgorithm:\n1. Check if locale mapping is enabled (DAT_0385c8d4)\n2. If disabled: convert ASCII uppercase (0x41-0x5A) to lowercase (+0x20)\n3. If enabled:\n   a. Validate character against class attributes\n   b. Look up high byte in transformation table for multi-byte support\n   c. Prepare character buffer with proper byte ordering\n   d. Call locale mapping handler to transform character\n   e. Extract result from mapping buffer based on output count\n\nParameters:\n- pThis: Implicit this pointer (ECX register, __thiscall convention)\n- inputCharacter: Character code to transform (uint, 0x00-0xFFFF)\n\nReturns:\n- uint: Transformed character code\n\nSpecial Cases:\n- Characters outside 0x00-0xFF range: Returns unchanged\n- DAT_0385c8d4 = 0: Simple ASCII uppercase conversion only\n- DAT_0384e914 >= 2: Uses GetCharacterClassAttribute for class lookup\n- DAT_0384e914 < 2: Uses simple table lookup via PTR_DAT_0384e708\n\nStructure Layout:\nCharacter transformation uses stack buffer at [EBP-0x4]:\nOffset  Size  Field\n------  ----  -----\n0       1     High byte result\n1       1     Low byte result\n2       1     Extended byte result (for 2-byte transforms)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cc0e19248bdb90cb6bf790db102f9ddf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cc0e19248bdb90cb6bf790db102f9ddf",
        "CFG": "d59138f44100bd891d1023b7740338fc",
        "PRO": "840d24f650e292ac52bddcf9684888d0"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "cc0e19248bdb90cb6bf790db102f9ddf"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_ADDR_0383DDE5": {
      "addresses": {
        "LoD/PD2": "0x0383DDE5"
      },
      "rvas": {
        "LoD/PD2": "0x1DDE5"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "ClearFlagsMaskWrapper",
      "signature": "void ClearFlagsMaskWrapper(void * pObject)",
      "calling_convention": "__fastcall",
      "comment": "Clears and sets bit flags on an object through a wrapper function.\n\nAlgorithm:\n1. Accept object pointer in ECX (fastcall convention)\n2. Push clearMask value 0x30000 onto stack\n3. Push setMask value 0x10000 onto stack\n4. Call ClearBitMaskFlags with object pointer and mask parameters\n5. Clean up stack and return to caller\n\nParameters:\npObject (ECX): Pointer to object whose flags will be modified\n\nReturns:\nvoid - No return value; modifies object state in-place\n\nSpecial Cases:\nMagic Numbers:\n- 0x10000 = setMask value (bit 16) - bits to enable in flag operation\n- 0x30000 = clearMask value (bits 16-17) - bits to disable in flag operation\nThese specific mask values are passed through to ClearBitMaskFlags for processing,\nwhich further masks them before applying the bit operations.\n\nFunction Purpose:\nThis is a thin wrapper that handles the __fastcall convention translation by pushing\npredefined mask constants onto the stack before delegating to ClearBitMaskFlags.\nThe function is used as part of a game state management system for flag manipulation.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:301bd5440f60703ca7a24a8fb30f1e56",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "301bd5440f60703ca7a24a8fb30f1e56",
        "CFG": null,
        "PRO": "9fdc1640ba42e4f0cd00e306b4e805b5"
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
    "binkw32_MNE_49e318c9f118": {
      "addresses": {
        "LoD/PD2": "0x0383DDF7"
      },
      "rvas": {
        "LoD/PD2": "0x1DDF7"
      },
      "sizes": {
        "LoD/PD2": 62
      },
      "name": "CheckModuloCondition",
      "signature": "undefined4 CheckModuloCondition(void)",
      "calling_convention": "__stdcall",
      "comment": "Checks if a value meets a modulo condition.\\n\\nAlgorithm:\\n1. Load divisor from global memory (_DAT_038482d0)\\n2. Load dividend from global memory (_DAT_038482c8)\\n3. Calculate modulo: remainder = dividend - (dividend / divisor) * divisor\\n4. Compare threshold value (_DAT_03847ce8) with calculated remainder\\n5. Return 1 if threshold < remainder, 0 otherwise\\n\\nParameters:\\n  None - uses global data values\\n\\nReturns:\\n  EAX: 1 if condition is true, 0 if false\\n\\nSpecial Cases:\\n  - Uses FPU floating-point instructions for division and modulo calculation\\n  - Global values determine the comparison behavior\\n  - Threshold comparison determines return value\\n\\nStructure Layout:\\n  This function accesses three global double-precision floating-point values\\n  for timing or synchronization checks in a processor feature detection routine",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:49e318c9f11868b2ccda0cc5be0e6fb1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "49e318c9f11868b2ccda0cc5be0e6fb1",
        "CFG": "f16ee01fce64ac425fc77137800a8352",
        "PRO": "7202d1af3f26d2661651e373a06d35d2"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "49e318c9f11868b2ccda0cc5be0e6fb1"
      }
    },
    "binkw32_STR_28768683ecd1": {
      "addresses": {
        "LoD/PD2": "0x0383DE35"
      },
      "rvas": {
        "LoD/PD2": "0x1DE35"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "LoadAndCallIsProcessorFeaturePresent",
      "signature": "void LoadAndCallIsProcessorFeaturePresent(void)",
      "calling_convention": "__stdcall",
      "comment": "Dynamically loads and calls IsProcessorFeaturePresent from KERNEL32 with fallback\n\nAlgorithm:\n1. Load KERNEL32.dll module via GetModuleHandleA\n2. If module loaded, attempt to get IsProcessorFeaturePresent function via GetProcAddress\n3. If function found, call it with parameter 0 to check processor features\n4. If module or function not found, jump to fallback alternative function\n\nParameters:\nNone - Function takes no parameters\n\nReturns:\nvoid - Function returns no value\n\nSpecial Cases:\n- Uses __stdcall calling convention (callee cleans stack)\n- Supports systems where IsProcessorFeaturePresent is unavailable (pre-WinXP)\n- Magic number 0 passed to IsProcessorFeaturePresent indicates checking base processor features\n- Fallback path calls FUN_0383ddf7 for compatibility on older Windows versions\n\nNotes:\nThis function provides runtime compatibility checking for modern Windows APIs.\nIf IsProcessorFeaturePresent is available, it's called directly.\nIf unavailable (older Windows), the fallback function handles the operation.",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:28768683ecd1bb6c4e5ee8c2282cbc71",
      "indexes": {
        "EXP": null,
        "STR": "28768683ecd1bb6c4e5ee8c2282cbc71",
        "API": null,
        "MNE": "f8699cbba1b01584e66dc48ae13d6b14",
        "CFG": "e6f5aaef1039a61daa103ba7f60faedc",
        "PRO": "80d75c4001ec5f04da5248e958258154"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f8699cbba1b01584e66dc48ae13d6b14"
      }
    },
    "binkw32_MNE_76bcdc60e227": {
      "addresses": {
        "LoD/PD2": "0x0383DE5E"
      },
      "rvas": {
        "LoD/PD2": "0x1DE5E"
      },
      "sizes": {
        "LoD/PD2": 90
      },
      "name": "RotateStringCharacters",
      "signature": "void RotateStringCharacters(void * this, char * pString)",
      "calling_convention": "__thiscall",
      "comment": "Rotates characters in a string by shifting all characters left and placing a replacement character at the start.\n\nAlgorithm:\n1. Load the first character and validate it via FUN_0383dd1a\n2. If validation result is not 0x65, scan forward through the string to find a valid character\n3. For each character in the loop, check global flag DAT_0384e914 to determine validation method\n4. If flag < 2, use lookup table PTR_DAT_0384e708 with bit mask 0x4 for validation\n5. Otherwise, call GetCharacterClassAttribute with attribute ID 4 for validation\n6. Continue scanning until a character with validation result 0 is found\n7. Initialize rotation by loading the replacement character from global DAT_0384e918\n8. Perform character rotation: load current char, write previous char value, repeat until null terminator\n9. String is effectively rotated left by one position with replacement char at index 0\n\nParameters:\n- this (ECX): Implicit object pointer, passed to validation functions\n- pString: Pointer to null-terminated string to rotate\n\nReturns:\n- void: String is modified in-place\n\nSpecial Cases:\n- First character validation check: if result equals 0x65, skip to rotation\n- Global flag DAT_0384e914 determines validation method (table lookup vs function call)\n- Sentinel value 0x65 used as special case marker in validation\n- String rotation uses null terminator as loop exit condition\n- Replacement character read from global DAT_0384e918",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:76bcdc60e2279c3182537e650d7ffd3e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "76bcdc60e2279c3182537e650d7ffd3e",
        "CFG": "f7a480f5087b3f579d153b9201ef810a",
        "PRO": "154d618ad49076728347c7861daea7d1"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "76bcdc60e2279c3182537e650d7ffd3e"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_ce3e17d01f8a": {
      "addresses": {
        "LoD/PD2": "0x0383DF1E"
      },
      "rvas": {
        "LoD/PD2": "0x1DF1E"
      },
      "sizes": {
        "LoD/PD2": 62
      },
      "name": "__fassign",
      "signature": "void __fassign(int flag, char * argument, char * number)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __fassign\n\nLibrary: Visual Studio 2003 Release",
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
    "binkw32_STR_16032f476aba": {
      "addresses": {
        "LoD/PD2": "0x0383DF5C"
      },
      "rvas": {
        "LoD/PD2": "0x1DF5C"
      },
      "sizes": {
        "LoD/PD2": 260
      },
      "name": "FormatScientificNotationString",
      "signature": "char * FormatScientificNotationString(double dValue, char * pBuffer, int nPrecision, int bUseLowerE)",
      "calling_convention": "__cdecl",
      "comment": "Formats a double value into a string with scientific notation (E notation).\n\nAlgorithm:\n1. Check if float format state is initialized (DAT_0385c8f0)\n2. If not initialized, call InitializeFloatFormatState() and IncrementDecimalString() to set up state\n3. If initialized, call InsertNullTerminatorAtOffset() to reuse existing state\n4. Copy sign character ('-') to output buffer if the number is negative\n5. If precision > 0, shift first digit and insert decimal point (e.g., \"1.23E+02\")\n6. Copy base exponent string (\"e+00\" or \"e-00\") to output buffer\n7. If bUseLowerE is non-zero, change 'e' to 'E' (uppercase exponent marker)\n8. Format exponent value from pFloatFormatState[3]:\n   a. Extract exponent from state (offset +0xc)\n   b. Adjust exponent value from offset +0x4 (subtract 1)\n   c. If exponent < 0, negate and set '-' sign at position 1 of exponent string\n   d. If |exponent| >= 100, extract hundreds digit and add to offset +2 in string\n   e. If remaining value >= 10, extract tens digit and add to offset +3 in string\n   f. Add ones digit to offset +4 in string\n9. Return pointer to output buffer\n\nParameters:\ndValue (double): The floating point number to format\npBuffer (char*): Output buffer where formatted string is written\nnPrecision (int): Number of significant digits after decimal point\nbUseLowerE (int): Flag - non-zero to use uppercase 'E', zero for lowercase 'e'\n\nReturns:\nchar*: Pointer to pBuffer (input parameter), containing formatted scientific notation string\n\nSpecial Cases:\n- If pFloatFormatState[3] is '0' (digit 0), exponent field is not modified/formatted\n- Negative exponents are handled with '-' sign at position 1 of exponent string\n- Exponents >= 100 are formatted with 3 digits; < 10 use 2 digits\n- The function modifies global state variables (DAT_0385c8ec, DAT_0385c8f0, DAT_0384e918)\n- Decimal point character is obtained from DAT_0384e918 (typically '.' or locale-specific)\n\nStructure Layout:\nFloat Format State (pFloatFormatState):\nOffset  Size  Field Name      Type    Description\n0       4     Sign/Flags      int     Contains sign character or flags\n4       4     ExponentValue   int     The exponent adjustment value\n8       4     Reserved1       int     Unknown field\n12      4     ExponentDigit   byte    Control digit for exponent formatting ('0' = skip formatting)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:16032f476aba0e42e163f0f1660d4b55",
      "indexes": {
        "EXP": null,
        "STR": "16032f476aba0e42e163f0f1660d4b55",
        "API": null,
        "MNE": "3450d1940496a7a0a18b4e9e94121a01",
        "CFG": "a92b3bc7b13f790b383332d843be644f",
        "PRO": "abc5addcf6c6da37acebb44a52ff3fa9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "3450d1940496a7a0a18b4e9e94121a01"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_d6754fcc5d62": {
      "addresses": {
        "LoD/PD2": "0x0383E060"
      },
      "rvas": {
        "LoD/PD2": "0x1E060"
      },
      "sizes": {
        "LoD/PD2": 222
      },
      "name": "FormatDecimalString",
      "signature": "char * FormatDecimalString(undefined4 floatContext, char * outputBuffer, size_t decimalPrecision)",
      "calling_convention": "__cdecl",
      "comment": "Formats a pre-computed decimal mantissa string with proper decimal point placement and exponent-based zero padding. Handles sign, decimal point insertion, and fractional digit padding based on floating-point exponent context. Returns formatted string buffer.\n\nAlgorithm:\n1. Check if float formatting context needs initialization by testing DAT_0385c8f0\n2. If uninitialized, call InitializeFloatFormatState() to prepare context\n3. Call IncrementDecimalString() to adjust decimal for proper rounding\n4. Compare stored exponent (pFormatContext[1]) against decimal precision\n5. If exponent matches precision, set digit at offset and null-terminate\n6. Copy negative sign to output if mantissa is negative\n7. If exponent <= 0, insert '0' followed by decimal point and zeros\n8. If exponent > 0, advance buffer pointer by exponent count\n9. If decimal precision > 0, insert decimal point and fractional zeros\n10. Handle negative exponent by padding with leading zeros before fractional part\n11. Return pointer to formatted output buffer\n\nParameters:\n- floatContext: undefined4 - State parameter (unused, passes through; formatting state in global DAT_0385c8ec)\n- outputBuffer: char * - Output string buffer for formatted decimal digits\n- decimalPrecision: size_t - Number of decimal fractional digits to format\n\nReturns:\n- char * - Pointer to outputBuffer with formatted decimal string\n\nSpecial Cases:\n- Negative mantissa marked by 0x2d ('-') stored at pFormatContext[0]\n- Exponent in pFormatContext[1] determines decimal point position and zero padding\n- Global state DAT_0385c8f0 indicates first-time initialization\n- Global state DAT_0385c8f4 stores previous exponent for comparison\n- Decimal separator retrieved from global DAT_0384e918\n- Zero padding performed with ASCII '0' (0x30)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d6754fcc5d62e9f41e8fd2908ff905da",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d6754fcc5d62e9f41e8fd2908ff905da",
        "CFG": "fc5872668649714cc9f5756d0001db11",
        "PRO": "c60243c16a316975027d0a18c1b7e586"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d6754fcc5d62e9f41e8fd2908ff905da"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_a21e46af6ec4": {
      "addresses": {
        "LoD/PD2": "0x0383E13E"
      },
      "rvas": {
        "LoD/PD2": "0x1E13E"
      },
      "sizes": {
        "LoD/PD2": 155
      },
      "name": "FormatFloatStringWithValidation",
      "signature": "void FormatFloatStringWithValidation(double floatValue, char * pBuffer, size_t bufferSize, int formatFlags)",
      "calling_convention": "__cdecl",
      "comment": "Formats a floating-point number into a string buffer with validation and decimal adjustment.\n\nAlgorithm:\n1. Initialize float formatting state and retrieve exponent/precision information\n2. Calculate decimal position offset (exponent - 1)\n3. Increment the decimal string at appropriate position, handling sign character\n4. Check if result exceeds valid precision range: if decimal position < -4 or >= buffer size, use alternate formatting with all digits\n5. If within valid range and overflow detected, scan to null terminator and remove last character\n6. Call appropriate float formatter with validation results\n\nParameters:\nfloatValue (EDI): Double-precision floating-point value to format\npBuffer (EBP+0xC): Pointer to output buffer for formatted string\nbufferSize (EBX): Maximum size of output buffer in bytes\nformatFlags (EBP+0x14): Format control flags (used in alternate path only)\n\nReturns:\nvoid - Result written to pBuffer\n\nSpecial Cases:\n- Magic number -4: Minimum decimal position before switching to exponential notation\n- Sign character handling: If first character is minus sign (0x2D), offset pointer by 1\n- Null terminator removal: When overflow detected, removes character before final null terminator",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a21e46af6ec4270dfffa0986c67abd1a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a21e46af6ec4270dfffa0986c67abd1a",
        "CFG": "affbf7be97762a304498c1314bdbae8d",
        "PRO": "c6525c37d7d6ca91ce78b772ed4bdb6e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a21e46af6ec4270dfffa0986c67abd1a"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_fd1d6842ea7f": {
      "addresses": {
        "LoD/PD2": "0x0383E1D9"
      },
      "rvas": {
        "LoD/PD2": "0x1E1D9"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "FormatFloatWithReentrancyGuard",
      "signature": "void FormatFloatWithReentrancyGuard(uint formatContext, char * buffer, int decimalPlaces, int useUppercaseE)",
      "calling_convention": "__cdecl",
      "comment": "Formats a floating-point number into a string with reentrancy protection.\\n\\nAlgorithm:\\n1. Set reentrancy guard flag to prevent recursive calls to float formatting\\n2. Call the actual formatting function with buffer, decimal places, and format context\\n3. Clear the reentrancy guard flag to allow subsequent calls\\n\\nParameters:\\n- formatContext: Format state context containing digit position and sign information\\n- buffer: Output string buffer for formatted result\\n- decimalPlaces: Number of decimal places to format (0-based index within buffer)\\n- useUppercaseE: Flag indicating whether to use uppercase 'E' (1) or lowercase 'e' (0) for exponent\\n\\nReturns:\\nNothing (void function)\\n\\nSpecial Cases:\\n- Function acts as a guard wrapper for reentrancy protection - prevents FUN_0383df5c from being called recursively\\n- The global flag DAT_0385c8f0 is used to detect and prevent recursive calls\\n- All formatting logic is delegated to FUN_0383df5c\\n\\nStructure Layout:\\nNone (function operates on external global state and provided parameters)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fd1d6842ea7fc60309d2fe367f862d42",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fd1d6842ea7fc60309d2fe367f862d42",
        "CFG": null,
        "PRO": "cc70a1fd6d792f63eab260f0b6b93c6f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fd1d6842ea7fc60309d2fe367f862d42"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_2668ddf225e6": {
      "addresses": {
        "LoD/PD2": "0x0383E200"
      },
      "rvas": {
        "LoD/PD2": "0x1E200"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "FormatFloatWithReentrancyGuard",
      "signature": "char * FormatFloatWithReentrancyGuard(uint formatFlags, char * outputBuffer, size_t precisionOrScale)",
      "calling_convention": "__cdecl",
      "comment": "Wrapper function that manages reentrancy control for float formatting operations.\n\nThis function implements a guard mechanism to prevent recursive calls to the core\nfloat formatting routine. It sets a global reentrancy flag before delegating to\nthe actual formatting implementation, then clears the flag upon completion.\n\nAlgorithm:\n1. Set global reentrancy flag (DAT_0385c8f0) to 1\n2. Call FUN_0383e060 with all three parameters to perform actual formatting\n3. Clear the reentrancy flag (AND with 0x0)\n4. Return the formatted string pointer\n\nParameters:\n- formatFlags: Control flags for formatting behavior (passed to formatter)\n- outputBuffer: Pointer to output buffer for formatted string\n- precisionOrScale: Precision value or scale factor for decimal places\n\nReturns:\n- char*: Pointer to the formatted output buffer (from FUN_0383e060)\n\nSpecial Cases:\n- Global reentrancy flag at 0x0385c8f0 prevents recursive formatting calls\n- When flag is non-zero, the inner function FUN_0383e060 takes alternative code path\n- All three parameters are passed through unchanged to the inner formatter",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2668ddf225e6573817b0d0cf649daaf6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2668ddf225e6573817b0d0cf649daaf6",
        "CFG": null,
        "PRO": "bb733e16f7c97d4917fdc04028ef3960"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2668ddf225e6573817b0d0cf649daaf6"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_f50494c5982a": {
      "addresses": {
        "LoD/PD2": "0x0383E223"
      },
      "rvas": {
        "LoD/PD2": "0x1E223"
      },
      "sizes": {
        "LoD/PD2": 81
      },
      "name": "__cfltcvt",
      "signature": "errno_t __cfltcvt(double * arg, char * buffer, size_t sizeInBytes, int format, int precision, int caps)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __cfltcvt\n\nLibrary: Visual Studio 2003 Release",
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
    "binkw32_MNE_b7d4a5a4939b": {
      "addresses": {
        "LoD/PD2": "0x0383E274"
      },
      "rvas": {
        "LoD/PD2": "0x1E274"
      },
      "sizes": {
        "LoD/PD2": 37
      },
      "name": "InsertNullTerminatorAtOffset",
      "signature": "void InsertNullTerminatorAtOffset(char * pSourceString, int offsetToInsert)",
      "calling_convention": "__cdecl",
      "comment": "Inserts a null terminator at a specified offset to make space in a string buffer during floating-point formatting operations.\n\nAlgorithm:\n1. Validate that offsetToInsert is non-zero (if zero, skip operation)\n2. Calculate length of source string using strlen()\n3. Call memmove-like function (FUN_0383caa0) to:\n   - Copy source string to destination (pSourceString + offsetToInsert)\n   - Copy from pSourceString for (strlen + 1) bytes to include null terminator\n4. Return to caller\n\nParameters:\n- pSourceString: Source string to copy with space insertion\n- offsetToInsert: Offset where to insert the space (buffer length to skip)\n\nReturns:\n- void: Modifies buffer in-place, no return value\n\nSpecial Cases:\n- If offsetToInsert is 0, function returns immediately without modification\n- Used in floating-point number formatting context\n- The memmove function (FUN_0383caa0) handles overlapping memory regions correctly\n- Null terminator is included in the copy (strlen + 1 bytes)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b7d4a5a4939b00399701a93fe243a594",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b7d4a5a4939b00399701a93fe243a594",
        "CFG": "dc31fd8ae2ce6da459435b7f021fe995",
        "PRO": "9eadceaeb70106b350bf4863bfe68181"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b7d4a5a4939b00399701a93fe243a594"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_a4fde7ab6624": {
      "addresses": {
        "LoD/PD2": "0x0383E299"
      },
      "rvas": {
        "LoD/PD2": "0x1E299"
      },
      "sizes": {
        "LoD/PD2": 691
      },
      "name": "PrepareFPUExceptionRecord",
      "signature": "void PrepareFPUExceptionRecord(EXCEPTION_RECORD * pExceptionRecord, uint * pFloatingPointStatus, uint exceptionCode, uint exceptionType, undefined8 * pExceptionData1, undefined8 * pExceptionData2)",
      "calling_convention": "__cdecl",
      "comment": "Prepares FPU exception record for Windows exception handling.\\n\\nAlgorithm:\\n1. Initialize exception record fields [1], [2], [3] to zero\\n2. Map FPU exception flags to EXCEPTION_RECORD.ExceptionFlags:\\n   - If exceptionCode & 0x10: Set code 0xc000008f (invalid operation)\\n   - If exceptionCode & 0x02: Set code 0xc0000093 (denormal operand)\\n   - If exceptionCode & 0x01: Set code 0xc0000091 (divide by zero)\\n   - If exceptionCode & 0x04: Set code 0xc000008e (overflow)\\n   - If exceptionCode & 0x08: Set code 0xc0000090 (underflow)\\n3. Process FPU control word bits from pFloatingPointStatus\\n4. Get FPU status word and map status bits to record field [3]\\n5. Process rounding control bits from pFloatingPointStatus & 0xc00\\n6. Process precision control bits from pFloatingPointStatus & 0x300\\n7. Update record[0] bits 5-16 with (exceptionType & 0xfff) << 5\\n8. Copy exception data fields to record offsets [4] and [0x10]\\n9. Clear FPU status and call RaiseException with prepared record\\n10. Restore FPU control word bits after exception handling\\n11. Restore rounding control bits from record[0]\\n12. Restore precision control bits from record[0]\\n13. Copy final exception data from record[0x10] to pExceptionData2\\n\\nParameters:\\n- pExceptionRecord (EXCEPTION_RECORD*): Exception record to prepare\\n- pFloatingPointStatus (uint*): FPU control word pointer\\n- exceptionCode (uint): FPU status flags (bits 0-4)\\n- exceptionType (uint): Exception type code\\n- pExceptionData1 (undefined8*): Exception data field 1\\n- pExceptionData2 (undefined8*): Exception data field 2\\n\\nReturns:\\n- void: Record modified in-place, data copied to pExceptionData2\\n\\nSpecial Cases:\\n- FPU status flags map to Windows NTSTATUS exception codes\\n- Control word bits undergo inverse transformation (~value & mask)\\n- Rounding control is 2-bit field; precision is 3-bit field",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a4fde7ab66242cc6a0f98892cc769636",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a4fde7ab66242cc6a0f98892cc769636",
        "CFG": "ca4a9f948f3bb20265440a9288a64a07",
        "PRO": "b6bce4d220af312c813d737e90762c42"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a4fde7ab66242cc6a0f98892cc769636"
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "binkw32_MNE_21ebbf809f07": {
      "addresses": {
        "LoD/PD2": "0x0383E54C"
      },
      "rvas": {
        "LoD/PD2": "0x1E54C"
      },
      "sizes": {
        "LoD/PD2": 535
      },
      "name": "ValidateAndHandleFloatingPointException",
      "signature": "int ValidateAndHandleFloatingPointException(uint exceptionFlags, double * pDenormalizedValue, uint roundingControlBits)",
      "calling_convention": "__cdecl",
      "comment": "Validates floating-point exception flags and handles subnormal/denormalized number recovery.\\n\\nAlgorithm:\\n1. Extract exception flag bits (0x1f) into result flags EDI\\n2. Check for invalid operation exception (bit 0x08):\\n   - If set and roundingControlBits bit 0x01 enabled: call HandleFloatingPointException(1), clear bit 0x08\\n   - Jump to final precision check\\n3. Check for overflow exception (bit 0x04):\\n   - If set and roundingControlBits bit 0x04 enabled: call HandleFloatingPointException(4), clear bit 0x04\\n   - Jump to final precision check\\n4. Check for underflow exception (bit 0x01):\\n   - If NOT set or roundingControlBits bit 0x08 NOT enabled: continue to inexact check\\n   - If set and roundingControlBits bit 0x08 enabled:\\n     - Call HandleFloatingPointException(8)\\n     - Load rounding mode (roundingControlBits & 0xc00)\\n     - Based on rounding mode, load appropriate constant:\\n       - 0x000: If pDenormalizedValue <= 0.0, use -INF, else use +INF\\n       - 0x400: If pDenormalizedValue <= 0.0, use -INF, else use +LARGEST_DENORMAL\\n       - 0x800: If pDenormalizedValue <= 0.0, use -LARGEST_DENORMAL, else use +INF\\n       - 0xc00: If pDenormalizedValue <= 0.0, use -LARGEST_DENORMAL, else use +LARGEST_DENORMAL\\n     - Store result in *pDenormalizedValue\\n5. Check for inexact exception (bit 0x02):\\n   - If NOT set or roundingControlBits bit 0x10 NOT enabled: jump to final precision check\\n   - If set and roundingControlBits bit 0x10 enabled:\\n     - Set ESI = 0 (precision flag), ESI tracks rounding adjustments\\n     - Check for precision flag in exceptionFlags (bit 0x10): if set, ESI = 1\\n     - Load *pDenormalizedValue into FP stack\\n     - Compare against 0.0 and decompose to mantissa/exponent\\n     - Call DecomposeDoubleToMantissaExponent to get exponent (stored at ESP+0, size 4)\\n     - Adjust exponent: exponentAdjustment = exponent - 0x600\\n     - Check if exponentAdjustment < -0x432 (underflow threshold):\\n       - If yes: set mantissaBits = 0.0, ESI = 1 (precision issue)\\n       - If no: reconstruct mantissa with implicit bit (0x10000000000000)\\n     - If exponentAdjustment < -0x3fd (subnormal threshold):\\n       - Shift mantissa right by (-0x3fd - exponentAdjustment) positions\\n       - Loop through each right shift:\\n         - If LSB != 0 and ESI == 0: set ESI = 1 (precision loss detected)\\n         - Right shift mantissa and high dword\\n         - Check for borrow from high dword (0x100000000 set): merge with carry\\n     - If original value < 0.0: negate mantissaBits\\n     - Store adjusted mantissaBits back to *pDenormalizedValue\\n   - If ESI != 0: call HandleFloatingPointException(0x10)\\n   - Clear bits 0x02 and 0x01 from result flags EDI\\n6. Check for precision exception (bit 0x10):\\n   - If set and roundingControlBits bit 0x20 enabled: call HandleFloatingPointException(0x20), clear bit 0x10\\n7. Return (result flags EDI == 0) as boolean (1 if no exceptions, 0 if any exceptions remain)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:21ebbf809f077a14550cdc7271d10c0f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "21ebbf809f077a14550cdc7271d10c0f",
        "CFG": "98d3612bca667bf3f47977c0930d5370",
        "PRO": "b64cdae7247af72de9992991263dbbbe"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "21ebbf809f077a14550cdc7271d10c0f"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_ed5d8332b54d": {
      "addresses": {
        "LoD/PD2": "0x0383E763"
      },
      "rvas": {
        "LoD/PD2": "0x1E763"
      },
      "sizes": {
        "LoD/PD2": 38
      },
      "name": "SetExceptionHandlingState",
      "signature": "void SetExceptionHandlingState(uint exceptionType)",
      "calling_convention": "__cdecl",
      "comment": "Sets the exception handling state code in global variable 0x0385c8fc based on exception type.\n\nAlgorithm:\n1. Load exception type parameter from stack (param via ESP + 4)\n2. Compare exception type against 0x1 (divide error indicator)\n3. If exception type == 0x1: Jump to type_1_handler\n4. If exception type <= 0x1: Jump to return_no_change (no state change)\n5. If exception type < 0x1: Jump to return_no_change (early exit)\n6. Compare exception type against 0x3 (upper bound)\n7. If exception type > 0x3: Jump to return_no_change (out of range)\n8. At type_2_3_handler: Set global DAT_0385c8fc = 0x22 (state code for type 2-3)\n9. Return\n10. At type_1_handler: Set global DAT_0385c8fc = 0x21 (state code for type 1)\n11. Return\n12. At return_no_change: Return without modifying global state\n\nParameters:\n- exceptionType (uint): Exception type identifier; valid values are 0x1 (divide error), 0x2-0x3 (other error types)\n\nReturns:\n- void: No return value; modifies global exception state variable as side effect\n\nSpecial Cases:\n- Exception type 0x1 sets state to 0x21\n- Exception types 0x2-0x3 set state to 0x22\n- Other exception types (0, 4+) leave global state unchanged\n- Global variable 0x0385c8fc holds the exception handling state code used by cleanup handlers\n\nStructure Layout:\nNone - function operates on scalar values and updates global state",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ed5d8332b54d28b982dbc31e264d087d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ed5d8332b54d28b982dbc31e264d087d",
        "CFG": "76db6c382c26eeeef0f0e1f77aac8844",
        "PRO": "0e5444a3561cbeb8bd411ae77c0d4ff3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ed5d8332b54d28b982dbc31e264d087d"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_afa3defe2b24": {
      "addresses": {
        "LoD/PD2": "0x0383E789"
      },
      "rvas": {
        "LoD/PD2": "0x1E789"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "__frnd",
      "signature": "float10 __frnd(double param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __frnd\n\nLibraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:afa3defe2b24d87908c421b2ad8a6bd9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "afa3defe2b24d87908c421b2ad8a6bd9",
        "CFG": null,
        "PRO": "4fc837b503f893d099417b020b7b63a7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "afa3defe2b24d87908c421b2ad8a6bd9"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_96ef86ea161c": {
      "addresses": {
        "LoD/PD2": "0x0383E79B"
      },
      "rvas": {
        "LoD/PD2": "0x1E79B"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "ReconstructDoubleFromMantissaExponent",
      "signature": "double ReconstructDoubleFromMantissaExponent(double doubleValue, short exponentValue)",
      "calling_convention": "__cdecl",
      "comment": "Reconstructs a double-precision floating-point number from mantissa and exponent.\n\nThis function combines decomposed floating-point components back into an IEEE 754 double.\nIt adjusts the binary exponent by adding the IEEE bias (0x3fe = 1022) and combines the\nexponent with the mantissa's sign/control bits to reconstruct the complete double value.\n\nAlgorithm:\n1. Load double value from stack parameter\n2. Add exponent bias (0x3fe) to the provided exponent value\n3. Mask lower 16 bits from first parameter (preserves sign and key control bits)\n4. Combine bias-adjusted exponent with masked mantissa bits via shift and OR\n5. Store combined value back to local variable\n6. Load and return the reconstructed double in extended precision\n\nParameters:\n- doubleValue (double): The mantissa value as a decomposed double\n- exponentValue (short): The binary exponent to apply (before bias addition)\n\nReturns:\n- double: The reconstructed IEEE 754 double-precision floating-point number\n\nSpecial Cases:\n- The function is called by DecomposeDoubleToMantissaExponent to reverse decomposition\n- Exponent bias (0x3fe = 1022) is standard for IEEE 754 double precision\n- The AND 0x800f operation preserves sign bit and mode flags from the mantissa",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:96ef86ea161c5c47c2f79058ef6d533b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "96ef86ea161c5c47c2f79058ef6d533b",
        "CFG": null,
        "PRO": "6000cc2182a7cdfbcad0aae8c6ee83e4"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "96ef86ea161c5c47c2f79058ef6d533b"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_05d8e97733e4": {
      "addresses": {
        "LoD/PD2": "0x0383E7C4"
      },
      "rvas": {
        "LoD/PD2": "0x1E7C4"
      },
      "sizes": {
        "LoD/PD2": 90
      },
      "name": "ClassifyDoublePrecisionValue",
      "signature": "int ClassifyDoublePrecisionValue(uint lowBits, uint highBits)",
      "calling_convention": "__cdecl",
      "comment": "Classifies IEEE 754 double-precision floating-point values.\\n\\nAnalyzes the exponent and mantissa fields of a 64-bit double value to determine its classification (normal, infinity, NaN, or special case).\\n\\nAlgorithm:\\n1. Extract high 32 bits (exponent + sign) and low 32 bits (mantissa)\\n2. Check for positive infinity (0x7ff00000 with all mantissa bits 0) - returns 1\\n3. Check for negative infinity (0xfff00000 with all mantissa bits 0) - returns 2\\n4. Test high 16 bits of upper word (0x7ff8 mask) for NaN pattern - returns 3 if match\\n5. Test for special denormalized/subnormal case (exponent 0x7ff0 with mantissa) - returns 4\\n6. Default to normal number classification - returns 0\\n\\nParameters:\\n  lowBits: Lower 32 bits of IEEE 754 double (mantissa/significand)\\n  highBits: Upper 32 bits of IEEE 754 double (sign + exponent)\\n\\nReturns:\\n  0 = Normal floating-point value\\n  1 = Positive infinity (sign=0, exponent=0x7ff, mantissa=0)\\n  2 = Negative infinity (sign=1, exponent=0x7ff, mantissa=0)\\n  3 = Not-a-Number (NaN) with mantissa bits set\\n  4 = Infinity or special case with non-zero mantissa bits\\n\\nSpecial Cases:\\n  - Checks exponent field 0x7ff for special values (infinity/NaN)\\n  - Masks mantissa bits 0x7ffff to detect non-zero fractional part\\n  - Uses 0x7ff8 mask to detect NaN pattern in high bits\\n  - Denormalized numbers (exponent=0) classified as normal if mantissa=0",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:05d8e97733e4c41533ceefe44bc4bac2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "05d8e97733e4c41533ceefe44bc4bac2",
        "CFG": "7deeaa169c40e9b69717ce2c9b0cb0ef",
        "PRO": "9f8e71d80a5d8c4c03ac9d4ac51f44a7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "05d8e97733e4c41533ceefe44bc4bac2"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_07c53c70ca23": {
      "addresses": {
        "LoD/PD2": "0x0383E81E"
      },
      "rvas": {
        "LoD/PD2": "0x1E81E"
      },
      "sizes": {
        "LoD/PD2": 193
      },
      "name": "DecomposeDoubleToMantissaExponent",
      "signature": "float10 DecomposeDoubleToMantissaExponent(float10 * __return_storage_ptr__, uint mantissaLow, uint mantissaHigh, int * pExponent)",
      "calling_convention": "__cdecl",
      "comment": "Decomposes IEEE 754 double-precision float into mantissa and exponent components.\\n\\nHandles three cases: zero values, subnormal (denormalized) numbers, and normal numbers. For subnormal numbers, performs normalization by shifting the mantissa and adjusting the exponent until the implicit bit is set. Returns the mantissa as an extended-precision float (float10) and outputs the binary exponent via pointer parameter.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:07c53c70ca23fa302c00136544982339",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "07c53c70ca23fa302c00136544982339",
        "CFG": "0fc4f5d435361cb894376c39e50ebc79",
        "PRO": "3e4a1c70fc31a3a9760c942953b5e796"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "07c53c70ca23fa302c00136544982339"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_f75de985f89e": {
      "addresses": {
        "LoD/PD2": "0x0383E8DF"
      },
      "rvas": {
        "LoD/PD2": "0x1E8DF"
      },
      "sizes": {
        "LoD/PD2": 14
      },
      "name": "GetFPUStatusWord",
      "signature": "short GetFPUStatusWord(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the current FPU (Floating Point Unit) status word.\n\nAlgorithm:\n1. Allocate 2 bytes of local stack space for temporary storage\n2. Execute FSTSW instruction to store FPU status word to local variable\n3. Sign-extend the 16-bit status value to 32-bit integer\n4. Return the status word in EAX\n\nReturns:\nReturns the FPU status word as a signed 16-bit integer (sign-extended to 32-bit).\nThe status word contains flags for:\n- Exception flags (Invalid, Denormalized, Divide-by-Zero, Overflow, Underflow, Precision)\n- Condition codes (C0-C3)\n- Stack top pointer (TOP)\n- Busy flag\n\nSpecial Cases:\nThis function directly accesses the FPU status word without clearing or modifying any flags.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f75de985f89ec0796fb5e3ad0eeb7130",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f75de985f89ec0796fb5e3ad0eeb7130",
        "CFG": null,
        "PRO": "43c7dafc2e66435e98c2739ed2be47fe"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f75de985f89ec0796fb5e3ad0eeb7130"
      }
    },
    "binkw32_MNE_ae75ffc6ea20": {
      "addresses": {
        "LoD/PD2": "0x0383E8ED"
      },
      "rvas": {
        "LoD/PD2": "0x1E8ED"
      },
      "sizes": {
        "LoD/PD2": 15
      },
      "name": "GetAndClearFPUStatus",
      "signature": "int GetAndClearFPUStatus(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the FPU status word and clears FPU exceptions\n\nAlgorithm:\n1. Save FPU status word to stack variable at [EBP-0x2]\n2. Clear all FPU exceptions with FNCLEX instruction\n3. Sign-extend the status word from word to dword\n4. Return the sign-extended status value\n\nReturns:\nint - FPU status word sign-extended to 32-bit integer. Contains FPU state flags\n      including exception masks, rounding mode, and precision control bits.\n\nSpecial Cases:\n- Called immediately before RaiseException in exception handling code\n- The status word is preserved before clearing exceptions to return the previous state\n- FNCLEX clears all FPU exception flags without generating exceptions\n- FNSTSW is used instead of FSTSW to avoid causing pending FPU exceptions",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ae75ffc6ea20c40cb82d5b28aa748d3f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ae75ffc6ea20c40cb82d5b28aa748d3f",
        "CFG": null,
        "PRO": "b6f4823b79c490a44815cccef2312035"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ae75ffc6ea20c40cb82d5b28aa748d3f"
      }
    },
    "binkw32_MNE_e652a465dd7d": {
      "addresses": {
        "LoD/PD2": "0x0383E8FC"
      },
      "rvas": {
        "LoD/PD2": "0x1E8FC"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "SetFPUControlWordBits",
      "signature": "uint SetFPUControlWordBits(uint clearMask, uint setMask)",
      "calling_convention": "__stdcall",
      "comment": "Modifies FPU control word by clearing and setting specific bits.\n\nAlgorithm:\n1. Save current FPU control word using FSTCW\n2. Load clearMask parameter (bits to clear)\n3. AND with current control word to clear specified bits\n4. Load setMask parameter (bits to set)\n5. Complement clearMask and AND with current control word to preserve other bits\n6. OR the two results to combine clear and set operations\n7. Load modified control word back into FPU using FLDCW\n8. Return original control word (sign-extended to 32-bit)\n\nParameters:\n- clearMask (EBP+0x8): Bit mask specifying which bits to clear from FPU control word\n- setMask (EBP+0xc): Bit mask specifying which bits to set in FPU control word\n\nReturns:\n- uint: Original FPU control word value before modification (sign-extended from word)\n\nSpecial Cases:\n- FPU control word is 16-bit value accessed via FSTCW/FLDCW instructions\n- Operation is atomic with respect to FPU state\n- Used in exception handling context (called by ProcessExceptionInfo)\n\nFPU Control Word Layout:\n- Bits 0-2: Exception masks (IM, DM, ZM)\n- Bits 3-4: Precision control\n- Bits 5-6: Rounding control\n- Bit 7: Infinity control\n- Bits 8-10: Interrupt enable bits",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e652a465dd7d9cb07580972eb3eb0f96",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e652a465dd7d9cb07580972eb3eb0f96",
        "CFG": null,
        "PRO": "0a45eea177801f01b05268df3f748301"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e652a465dd7d9cb07580972eb3eb0f96"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_d2372372c417": {
      "addresses": {
        "LoD/PD2": "0x0383E91F"
      },
      "rvas": {
        "LoD/PD2": "0x1E91F"
      },
      "sizes": {
        "LoD/PD2": 86
      },
      "name": "HandleFloatingPointException",
      "signature": "void HandleFloatingPointException(byte exceptionFlags)",
      "calling_convention": "__stdcall",
      "comment": "Handles floating-point exceptions by setting FPU registers based on exception flags.\n\nAlgorithm:\n1. Save stack frame and allocate local storage for FPU state\n2. Test bit 0 (0x1): If set, load constant from 0x0384e5b0 to EAX/EDX\n3. Test bit 3 (0x8): If set, save FPU status word to AX and load 0x0384e5b0 to ST0\n4. Test bit 4 (0x10): If set, load constant 0x0384e5bc to ST0\n5. Test bit 2 (0x4): If set, compute infinity (FLDZ / FLD1 / FDIVRP)\n6. Test bit 5 (0x20): If set, load pi (FLDPI) to ST0\n7. Restore stack frame and return\n\nParameters:\n- exceptionFlags (byte, EBP+0x8): Bit flags indicating which FPU exceptions to handle\n  - Bit 0 (0x1): Load constant at 0x0384e5b0\n  - Bit 3 (0x8): FPU status operation\n  - Bit 4 (0x10): Load constant at 0x0384e5bc\n  - Bit 2 (0x4): Generate infinity\n  - Bit 5 (0x20): Load pi constant\n\nReturns:\n- void: No return value. Function modifies FPU state only.\n\nSpecial Cases:\n- Constants at 0x0384e5b0 and 0x0384e5bc are magic values (likely IEEE 754 special values)\n- WAIT instructions ensure FPU pipeline synchronization after each operation\n- Function preserves all general-purpose registers except EBP\n- Used by FUN_0383e54c for floating-point exception handling in IEEE 754 operations",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d2372372c4179c2cdb1a710877220f60",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d2372372c4179c2cdb1a710877220f60",
        "CFG": "7502e22954c3d2f1a19df576ed7ccc51",
        "PRO": "a453fef7ed5b6d07425c8db5d5eff38f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d2372372c4179c2cdb1a710877220f60"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_f0a75c57169f": {
      "addresses": {
        "LoD/PD2": "0x0383E980"
      },
      "rvas": {
        "LoD/PD2": "0x1E980"
      },
      "sizes": {
        "LoD/PD2": 102
      },
      "name": "ComputeExponentialWithModification",
      "signature": "void ComputeExponentialWithModification(uint mantissaAndExponent, byte flags)",
      "calling_convention": "__fastcall",
      "comment": "Computes exponential function with optional reciprocal and scaling\n\nAlgorithm:\n1. Check if mantissaAndExponent high byte is non-zero (special case indicator)\n2. If special case: call error handler FUN_0383eb21() to validate inputs\n3. Load FPU operands and perform logarithm-based computation (FYL2X)\n4. Call FloatPowModExp helper to compute power with modular exponent\n5. Add 1 to result: 1 + exp(x)\n6. Check reciprocal flag in byte at [EBP - 0x9F]\n7. If reciprocal flag set:\n   - Check global config at 0x0385C8AC\n   - If config == 1: call FloatUnpackWrapper() for special unpacking\n   - Otherwise: compute 1 / (1 + exp(x)) via FDIVRP\n8. Check scale flag (0x40) in flags state\n9. If scale flag not set: apply FPU FSCALE operation\n10. Check sign bit in CH (high byte of flags)\n11. If sign set: negate result via FCHS\n12. Call PopFPUStack() to clean up FPU stack\n13. Return with result in ST(0)\n\nParameters:\n  mantissaAndExponent (ECX): uint - Packed mantissa and exponent value\n  flags (DL): byte - Control flags (bits: 6=scale_disable, 7=sign)\n\nReturns:\n  Result in FPU ST(0) register - Computed exponential or reciprocal value\n\nSpecial Cases:\n  - High byte != 0: Error case triggers FUN_0383eb21() validation loop\n  - Error code 0: Fatal error, call FUN_0383ed36() and exit\n  - Error code 1: Single adjustment iteration\n  - Error code 2: Special flag adjustment (CH = 0xFF instead of inverted)\n  - Config 0x0385C8AC == 1: Use unpacking mode instead of division\n  - Scale flag (0x40) set: Skip FSCALE operation\n  - Sign flag (0x80) set: Negate final result\n\nStructure Layout:\n  Stack at [EBP - 0x90]: Marker byte (0xFE) - operation start sentinel\n  Stack at [EBP - 0x9F]: Control byte (bit 0 = reciprocal flag)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f0a75c57169f7149d74a2236cce98a2e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f0a75c57169f7149d74a2236cce98a2e",
        "CFG": "ffe48a55e9f191d3c956c5f40dadbeab",
        "PRO": "112c6879ca5f69c40baa1caeb058c865"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f0a75c57169f7149d74a2236cce98a2e"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_d5f0d2733adf": {
      "addresses": {
        "LoD/PD2": "0x0383EADE"
      },
      "rvas": {
        "LoD/PD2": "0x1EADE"
      },
      "sizes": {
        "LoD/PD2": 114
      },
      "name": "FloatPowModExp",
      "signature": "double FloatPowModExp(uint exponent, byte flags)",
      "calling_convention": "__fastcall",
      "comment": "Computes floating-point exponential transformation on fractional part.\n\nThis function implements a specialized floating-point operation that extracts the\nfractional portion of an input value and applies exponential computation via the\nF2XM1 (2^x - 1) instruction. It handles rounding, comparison against threshold\nconstants, and conditional negation based on control flags passed in registers.\n\nAlgorithm:\n1. Load input value from ST0 and compute its absolute value\n2. Compare absolute value against threshold constant at 0x0384e5ee\n3. Store comparison flags in local FPU status word at EBP-0xa0\n4. Check if rounding path should be taken based on flags at EBP-0x9f\n5. If rounding enabled: round value to nearest integer, compute fractional part\n6. Test fractional part and store status flags\n7. Load flags byte from EBP-0x9f to check for negative output flag\n8. Exchange ST0 and ST1, then subtract rounded from original (fractional part)\n9. Compute absolute value of fractional part\n10. Apply F2XM1 exponential transformation (2^x - 1) to fractional part\n11. Return result with status flags in DL register\n\nParameters:\n  exponent (ECX): Packed exponent value - bit 8+ contains exponent data\n  flags (DL): Control flags - bit 0 enables special handling, bit 6 controls output format\n\nReturns:\n  double: Result in ST0/ST1 with FPU status flags in DL\n\nStructure Layout:\n  Offset | Size | Field        | Type   | Purpose\n  ------ | ---- | ------------ | ------ | --------\n  -0xa0  | 2    | fpu_status   | ushort | FPU status word from comparison\n  -0x9f  | 1    | ctrl_flags   | byte   | Control flags for rounding/negation\n  -0x90  | 1    | temp_marker  | byte   | Temporary flag marker storage\n  -0x88  | 8+   | temp_floats  | float  | Temporary floating-point storage\n\nSpecial Cases:\n  - If comparison result non-zero and bit 0 of flags set, calls ReturnZeroFloat\n  - If input zero and no special flag, returns early without computation\n  - F2XM1 applied only to fractional part for numerical stability\n  - Status flags affect whether final result is negated or returned as-is",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d5f0d2733adf4d1dce64e7fb83efd1d4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d5f0d2733adf4d1dce64e7fb83efd1d4",
        "CFG": "e207c01523be4d9e2ab842a571789cac",
        "PRO": "d03c0d1699b8180175a0622a5be7c601"
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
    "binkw32_MNE_df587a37c863": {
      "addresses": {
        "LoD/PD2": "0x0383EB21"
      },
      "rvas": {
        "LoD/PD2": "0x1EB21"
      },
      "sizes": {
        "LoD/PD2": 52
      },
      "name": "ValidateFloatModularCongruence",
      "signature": "uint ValidateFloatModularCongruence(void)",
      "calling_convention": "__stdcall",
      "comment": "Validates floating-point number and checks modular congruence.\n\nAlgorithm:\n1. Check if input (ST0) is an integer by rounding and comparing\n2. If not an integer, return 0 (invalid)\n3. If integer, multiply by constant (0x0384e602) and check if result is integer\n4. If product is not an integer, return 1 (integer but not modular congruent)\n5. If product is also integer, return 2 (valid and modular congruent)\n\nParameters:\n- ST0 (FPU): Input floating-point number to validate\n\nReturns:\n- 0: Input is not an integer\n- 1: Input is integer but product is not integer\n- 2: Both input and product are integers\n\nSpecial Cases:\n- Uses FPU (x87) floating-point operations\n- Constant at 0x0384e602 determines modular relationship\n- SAHF transfers FPU flags to CPU flags for conditional jumps",
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
    "binkw32_MNE_1e5021910108": {
      "addresses": {
        "LoD/PD2": "0x0383EB90"
      },
      "rvas": {
        "LoD/PD2": "0x1EB90"
      },
      "sizes": {
        "LoD/PD2": 103
      },
      "name": "ClassifyFloatAndDispatch",
      "signature": "void ClassifyFloatAndDispatch(undefined4 fpuValue, int handlerTableOffset)",
      "calling_convention": "__fastcall",
      "comment": "Classifies floating-point value and dispatches to appropriate handler.\\n\\nAlgorithm:\\n1. Check FPU mode flag (offset +0xe) to determine control word setup\\n2. Configure FPU control word: special mode (0x023F) or default (0x133F)\\n3. Load control word to prepare FPU for value examination\\n4. Examine FPU value in ST0 using FXAM instruction\\n5. Extract classification flags from FPU status word\\n6. Combine classification bits with sign bit extraction\\n7. Use XLAT lookup to convert classification bits to handler offset\\n8. Dispatch to handler using indirect jump with offset calculation\\n\\nParameters:\\n- fpuValue (ECX): FPU value in ST0 to classify\\n- handlerTableOffset (EDX): Base address of handler vtable\\n\\nReturns:\\nVoid (dispatches to handler)\\n\\nSpecial Cases:\\nFPU classification categories (bits in status word):\\n- NaN: Not a number (special value)\\n- Infinity: Positive or negative infinity\\n- Normal: Regular floating-point number\\n- Zero: Positive or negative zero\\n- Denormal: Subnormal floating-point number\\nControl word values:\\n- 0x133F: Default FPU control word (round to nearest)\\n- 0x023F: Special mode control word (different rounding/precision)\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1e502191010869fca5d6ea71e353f408",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1e502191010869fca5d6ea71e353f408",
        "CFG": "37d38e63f6ee4a3a988685613c81cb30",
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
    "binkw32_MNE_2efd2f634b43": {
      "addresses": {
        "LoD/PD2": "0x0383EC88"
      },
      "rvas": {
        "LoD/PD2": "0x1EC88"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "PopFPUStack",
      "signature": "void PopFPUStack(void)",
      "calling_convention": "__stdcall",
      "comment": "Pops and discards the top of the FPU stack after floating-point operations.\n\nAlgorithm:\n1. Exchange ST0 and ST1 on the floating-point stack (FXCH)\n2. Pop the new ST0 value (original ST1) and discard it\n3. Return to caller\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Used after fscale or similar FPU operations to clean up intermediate results\n- Critical: Caller must set up ST0/ST1 correctly before calling this function\n- Typical in math-heavy code for managing FPU stack state",
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
    "binkw32_MNE_038f21ccadf0": {
      "addresses": {
        "LoD/PD2": "0x0383EC96"
      },
      "rvas": {
        "LoD/PD2": "0x1EC96"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "ReturnZeroFloat",
      "signature": "float10 ReturnZeroFloat(float10 * __return_storage_ptr__)",
      "calling_convention": "__stdcall",
      "comment": "Returns a zero value on the x87 floating-point stack.\n\nAlgorithm:\n1. Pop any value from ST(0)\n2. Load 0.0 onto the floating-point stack\n3. Return with callee cleanup (__stdcall)\n\nReturns:\n  float10 - 0.0 on the x87 FPU stack (ST(0))\n\nSpecial Cases:\n  - Function pops ST(0) before loading zero, allowing it to clear the stack\n  - Used in floating-point calculation chains as a reset or zero value source",
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
    "binkw32_MNE_58c3c7e175be": {
      "addresses": {
        "LoD/PD2": "0x0383ED36"
      },
      "rvas": {
        "LoD/PD2": "0x1ED36"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "ReturnFatalErrorValue",
      "signature": "void ReturnFatalErrorValue(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns fatal error sentinel value from global data\n\nCalled when exponential computation encounters a fatal error condition (error code 0). \nThis function loads a pre-computed 10-byte extended precision floating point value \nfrom global memory at 0x0384E640 and updates an error marker byte on the stack.\n\nAlgorithm:\n1. Clear FPU stack by popping two values (ST0, ST1)\n2. Load the fatal error value from global data address 0x0384E640\n3. Check error marker byte at [EBP - 0x90] (operation status flag)\n4. If marker byte is 0 (no previous error), set it to 1 (error occurred)\n5. Return with error value in FPU ST(0) register\n\nReturns:\n  ST(0): 10-byte extended precision floating point value (fatal error sentinel)\n  Side effect: Sets error marker byte at [EBP - 0x90] to 1\n\nSpecial Cases:\n  Error marker byte: 0 = clean state, 1+ = error already occurred\n  Global data address 0x0384E640: Contains pre-computed error value (likely NaN or infinity)\n  Calling convention: __stdcall (callee cleans stack)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:58c3c7e175be8c196c57976e375f315f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "58c3c7e175be8c196c57976e375f315f",
        "CFG": "82ab21280f7756b94aebf888fcf167cf",
        "PRO": "001b5f551e3eec8ec8df7053021c5bad"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "58c3c7e175be8c196c57976e375f315f"
      }
    },
    "binkw32_MNE_3c4be6dbcf12": {
      "addresses": {
        "LoD/PD2": "0x0383ED49"
      },
      "rvas": {
        "LoD/PD2": "0x1ED49"
      },
      "sizes": {
        "LoD/PD2": 10
      },
      "name": "SetStackFlag",
      "signature": "void SetStackFlag(void)",
      "calling_convention": "__stdcall",
      "comment": "Sets a flag byte on the caller's stack frame to indicate completion or state change.\n\nAlgorithm:\n1. Write value 0x1 to stack offset -0x90 (relative to EBP)\n2. Test CL register (caller-supplied flag or status value)\n3. Return with __stdcall convention\n\nReturns:\nvoid - No explicit return value; CL register set by caller for conditional logic\n\nSpecial Cases:\n- The OR CL, CL instruction sets CPU flags based on CL value for conditional execution by caller\n- Stack offset -0x90 corresponds to a local variable in caller's frame\n- Typical use: initialization callback or state setter for conditional branch logic",
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
    "binkw32_MNE_d63502919c4c": {
      "addresses": {
        "LoD/PD2": "0x0383ED60"
      },
      "rvas": {
        "LoD/PD2": "0x1ED60"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "HandleFPUException_Type0x1d",
      "signature": "float10 HandleFPUException_Type0x1d(float10 * __return_storage_ptr__, int exceptionCode, uint exceptionType, ushort savedControlWord, int param3, int param4, int param5, int param6, int param7)",
      "calling_convention": "__fastcall",
      "comment": "FPU Exception Handler for Type 0x1d Exceptions\n\nThis is a specialized FPU (Floating-Point Unit) exception handler that routes and processes\ntype 0x1d exceptions detected by HandleFPUException. The function preserves the FPU state,\ndelegates to ProcessExceptionInfo for handling, and returns the original FPU value.\n\nAlgorithm:\n1. Save FPU register ST0 (extended precision value) to preserve FPU state\n2. Set up local stack variables for parameter passing (params 6-7 stored locally)\n3. Set up stack frame for parameters (params 4-5 stored at specific offsets)\n4. Call ProcessExceptionInfo with exception info (exceptionType, savedControlWord, etc.)\n5. Restore FPU value from ST0 and return as extended precision float\n\nParameters:\n- exceptionCode (EDX): Exception identifier code from FPU\n- exceptionType (uint): Exception type indicator (0x1d for this handler)\n- savedControlWord (word): FPU control word saved by exception dispatcher\n- param3-param7 (int): Additional exception context parameters passed through\n\nReturns:\n- float10 (ST0): The original FPU value that triggered the exception, restored after processing\n\nSpecial Cases:\n- ST0 register contains the extended precision float that caused the exception\n- Function uses __fastcall convention: exceptionCode in EDX, exceptionType in parameter 2\n- ProcessExceptionInfo modifies the FPU state during exception handling\n- Return value preservation allows calling code to continue FPU operations\n\nStructure Layout:\nThe stack frame contains saved parameters and FPU state:\n  Offset  Size  Field Name          Type      Description\n  ------  ----  ------------------  --------  -----------\n  EBP+8   4     exceptionCode       int       First exception parameter\n  EBP+12  4     exceptionType       uint      Type 0x1d identifies this handler\n  EBP+16  2     savedControlWord    ushort    FPU control word from dispatcher\n  EBP+20  4     param3              int       Exception context param 3\n  EBP+24  4     param4              int       Exception context param 4\n  EBP+28  4     param5              int       Exception context param 5\n  EBP+32  4     param6              int       Exception context param 6\n  EBP+36  4     param7              int       Exception context param 7\n  EBP-4   10    fpuValue            float10   Preserved ST0 register value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d63502919c4c985cfbdccf3184dd15d0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d63502919c4c985cfbdccf3184dd15d0",
        "CFG": null,
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
    "binkw32_MNE_9215dd175454": {
      "addresses": {
        "LoD/PD2": "0x0383ED77"
      },
      "rvas": {
        "LoD/PD2": "0x1ED77"
      },
      "sizes": {
        "LoD/PD2": 60
      },
      "name": "__startOneArgErrorHandling",
      "signature": "float10 __startOneArgErrorHandling(undefined4 param_1, uint param_2, ushort param_3, undefined4 param_4, undefined4 param_5, undefined4 param_6)",
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
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9215dd17545429f5a2114f3f9c06e96c"
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "binkw32_MNE_3f015c1c75c5": {
      "addresses": {
        "LoD/PD2": "0x0383EDC0"
      },
      "rvas": {
        "LoD/PD2": "0x1EDC0"
      },
      "sizes": {
        "LoD/PD2": 21
      },
      "name": "Pow2",
      "signature": "double Pow2(double exponent)",
      "calling_convention": "__stdcall",
      "comment": "Calculates 2 raised to the power of exponent using x87 floating-point arithmetic.\n\nAlgorithm:\n1. Load input value (exponent) from x87 FPU stack\n2. Round input to nearest integer to separate integer and fractional parts\n3. Subtract rounded integer from original value to isolate fractional part\n4. Exchange stack values to prepare for fractional exponent calculation\n5. Negate fractional part as preparation for F2XM1 instruction\n6. Calculate 2^(fractional_part) using F2XM1 (which computes 2^x - 1 for small x)\n7. Load 1.0 to add back the result of F2XM1\n8. Add 1.0 to fractional exponent result (convert from 2^x-1 to 2^x)\n9. Scale result by 2^(integer_part) using FSCALE to combine both parts\n10. Store final result and pop from FPU stack\n11. Return to caller with result in ST(0) x87 register\n\nParameters:\n- exponent: The exponent value for which to calculate 2^exponent\n\nReturns:\n- double: Returns 2^exponent as a double-precision floating-point value in x87 ST(0)\n\nSpecial Cases:\n- Input must be valid double-precision floating-point value\n- Result is returned on x87 FPU stack in ST(0) register\n- Follows __stdcall calling convention (callee cleans stack)",
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
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_2499e8fc5969": {
      "addresses": {
        "LoD/PD2": "0x0383EDD5"
      },
      "rvas": {
        "LoD/PD2": "0x1EDD5"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "SetFPUControlWord",
      "signature": "void SetFPUControlWord(uint controlWord)",
      "calling_convention": "__stdcall",
      "comment": "Modifies and loads the FPU control word register with caller-specified precision and exception mask bits.\n\nAlgorithm:\n1. Extract precision control bits (bits 8-9) from the input parameter\n2. Apply exception mask bits (bits 0-6) set to 0x7f (all exceptions masked)\n3. Store the combined control word value to stack\n4. Load the modified control word into the FPU control register via FLDCW\n\nParameters:\n- controlWord: uint - Input FPU control word value containing precision bits to preserve\n\nReturns:\n- void - Modifies FPU state, no return value\n\nSpecial Cases:\n- Bit masking: Input AND 0x300 preserves precision bits, OR 0x7f sets all exception masks\n- Stack Layout: Control word stored at ESP+0x6 for FLDCW instruction\n- FPU Register: FLDCW loads 16-bit value from memory into the FPU control register\n\nNotes:\n- This is a low-level FPU state manipulation function\n- Used to configure floating point exception handling and precision modes\n- Calling convention __stdcall means callee cleans stack",
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
    "binkw32_MNE_7e73328c30de": {
      "addresses": {
        "LoD/PD2": "0x0383EE05"
      },
      "rvas": {
        "LoD/PD2": "0x1EE05"
      },
      "sizes": {
        "LoD/PD2": 67
      },
      "name": "__fload_withFB",
      "signature": "uint __fload_withFB(undefined4 param_1, int param_2)",
      "calling_convention": "__fastcall",
      "comment": "Library Function - Single Match\n __fload_withFB\n\nLibrary: Visual Studio",
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
    "binkw32_MNE_118a84069540": {
      "addresses": {
        "LoD/PD2": "0x0383EE5E"
      },
      "rvas": {
        "LoD/PD2": "0x1EE5E"
      },
      "sizes": {
        "LoD/PD2": 13
      },
      "name": "RestoreFPUControlWord",
      "signature": "void RestoreFPUControlWord(void)",
      "calling_convention": "__stdcall",
      "comment": "Restores the x87 FPU control word to standard state (0x27f) if needed.\n\nThis function conditionally restores the floating-point processor control word to ensure proper FPU state for floating-point operations. It is called before and after operations that require specific FPU precision/rounding modes.\n\nAlgorithm:\n1. Load the FPU control word value from the stack (caller-provided parameter)\n2. Compare it against the standard control word value (0x27f)\n3. If equal, skip the restoration and go to cleanup\n4. If different, load the control word into the FPU via FLDCW instruction\n5. Clean up the stack by popping EDX\n6. Return to caller\n\nParameters:\nNone. The FPU control word value (typically 0x27f) is passed on the stack by the caller and must be present when this function is called.\n\nReturns:\nvoid. No return value. The function modifies only the x87 FPU state.\n\nSpecial Cases:\n- Control word value 0x27f represents: precision = 64-bit double precision, rounding mode = round to nearest\n- The function assumes the value is already on the stack (pushed by caller)\n- This is a common pattern in code using x87 floating-point operations for state management",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:118a84069540ef5bdaff27e56dcaadec",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "118a84069540ef5bdaff27e56dcaadec",
        "CFG": "8c35684bf37f290ed4e35e4eb8e7fd2a",
        "PRO": "8cb32a0d56a2452e759161b6ffdb7e9f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "118a84069540ef5bdaff27e56dcaadec"
      }
    },
    "binkw32_MNE_0c71b5715e2e": {
      "addresses": {
        "LoD/PD2": "0x0383EEA9"
      },
      "rvas": {
        "LoD/PD2": "0x1EEA9"
      },
      "sizes": {
        "LoD/PD2": 163
      },
      "name": "HandleFPUException",
      "signature": "void HandleFPUException(int exceptionCode, uint exceptionFlags, int param3, int param4, int param5, int param6, int param7)",
      "calling_convention": "__fastcall",
      "comment": "FPU Exception Handler - Detects and routes floating-point exceptions\n\nAlgorithm:\n1. Extract exponent bits from FPU input value (upper 32 bits)\n2. Check if exponent is zero (denormalized number) - scale with constant\n3. Check if exponent is maximum value (infinity/NaN) - scale differently\n4. Load saved FPU control word from return address location\n5. Validate control word against magic value 0x27f or check precision exception\n6. Read current FPU status word to detect pending exceptions\n7. Route exception: if code is 0x1d call FUN_0383ed60, else call error handler\n8. Restore FPU control word and return\n\nSpecial Cases:\n- Denormalized numbers (exponent=0): Scale with _DAT_038483ec constant\n- Infinity/NaN (exponent=0x7ff): Scale with _DAT_038483e4 constant\n- Magic value 0x27f in control word indicates pre-handled exception\n- Precision exception flag (0x20) in control word allows early exit\n- Exception code 0x1d routes to dedicated handler\n- Other exception codes route to generic error handler\n\nParameters:\nexceptionCode - First parameter (EDX register, __fastcall)\nexceptionFlags - Exception type indicator (second parameter)\nAdditional parameters passed through to called handlers",
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
    "binkw32_MNE_196c90d967af": {
      "addresses": {
        "LoD/PD2": "0x0383EF4C"
      },
      "rvas": {
        "LoD/PD2": "0x1EF4C"
      },
      "sizes": {
        "LoD/PD2": 304
      },
      "name": "ComputePowerWithSpecialCases",
      "signature": "int ComputePowerWithSpecialCases(int baseHi, int baseLo, double exponent, double * pResult)",
      "calling_convention": "__cdecl",
      "comment": "Computes a double-precision floating-point power result with special handling for infinity and negative values.\n\nAlgorithm:\n1. Reconstruct double from two 32-bit parameters (baseHi, baseLo)\n2. Take absolute value by comparing against magic constant at 0x03847cf8\n3. Check if exponent is positive infinity (0x7ff00000)\n4. Handle infinity cases with NaN and sign checks\n5. Check if exponent is negative infinity (0xfff00000)\n6. Validate sign and call ValidateFloatingPointValue for special cases\n7. Compare absolute base against threshold (0x03847ce8)\n8. Return computed result in pResult with status code\n\nParameters:\n  baseHi: High 32 bits of base as double (EBP+0xc)\n  baseLo: Low 32 bits of base as double (EBP+0x8)\n  exponent: Exponent value (EBP+0x10)\n  pResult: Pointer to result storage (EBP+0x18)\n\nReturns:\n  1 = Special result stored (when base == 1.0)\n  0 = Normal result stored in pResult\n\nSpecial Cases:\n  - Base == 1.0: Returns 1.0 regardless of exponent\n  - Exponent == +INFINITY: Returns +INF if |base| > threshold, 0 if |base| &lt; threshold\n  - Exponent == -INFINITY: Returns similar results inverted\n  - NaN handling: Validates exponent sign and stores appropriately\n  - Magic threshold: 0x03847ce8 used for base magnitude comparison\n  - Constants: 0x0384e588 (+INF), 0x0384e5a8 (special zero), 0x0384e590 (1.0 value)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:196c90d967af5bf2d30c255ccea793be",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "196c90d967af5bf2d30c255ccea793be",
        "CFG": "1cc4dcab1ccdfe407dc1ef8869f71be8",
        "PRO": "f240cca4eed4bb749aa8c96868b9ff7b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "196c90d967af5bf2d30c255ccea793be"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_1252459d5bf6": {
      "addresses": {
        "LoD/PD2": "0x0383F07C"
      },
      "rvas": {
        "LoD/PD2": "0x1F07C"
      },
      "sizes": {
        "LoD/PD2": 101
      },
      "name": "ValidateFloatingPointValue",
      "signature": "uint ValidateFloatingPointValue(double value)",
      "calling_convention": "__cdecl",
      "comment": "Validates if a floating-point value is a power of 2 and returns exponent parity.\n\nAlgorithm:\n1. Classify input value using ClassifyFloatingPointValue\n2. If value is subnormal/infinity/NaN, return 0 (not a power of 2)\n3. Round input to nearest integer using __frnd\n4. If rounded != input, return 0 (not an exact integer)\n5. Divide by magic constant (stored at 0x03847f70)\n6. Round quotient to nearest integer\n7. If rounded quotient == quotient, return 2 (even exponent)\n8. Otherwise return 1 (odd exponent)\n\nParameters:\n- value: double - Floating-point number to validate\n\nReturns:\n- 0: Value is not a valid power of 2 (subnormal, infinity, NaN, or not integer)\n- 1: Value is power of 2 with odd exponent\n- 2: Value is power of 2 with even exponent\n\nSpecial Cases:\n- Subnormal numbers are rejected (classification bit 0x80)\n- Infinities are rejected (classification bit 0x10)\n- NaN values are rejected (classification bits 0x20)\n- Magic constant at 0x03847f70 likely represents 2.0 or similar base",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1252459d5bf6fc7fa6bd21d0f60e6017",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1252459d5bf6fc7fa6bd21d0f60e6017",
        "CFG": "23a0f299cbbbcc6ee256176a35d753f3",
        "PRO": "836d20515ffabe338a5e702391938d03"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "1252459d5bf6fc7fa6bd21d0f60e6017"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_91b5192dddb8": {
      "addresses": {
        "LoD/PD2": "0x0383F0E1"
      },
      "rvas": {
        "LoD/PD2": "0x1F0E1"
      },
      "sizes": {
        "LoD/PD2": 45
      },
      "name": "ExecuteInitializationHandlers",
      "signature": "void ExecuteInitializationHandlers(void)",
      "calling_convention": "__stdcall",
      "comment": "Executes initialization handlers during application startup.\n\nAlgorithm:\n1. Check if optional initialization handler pointer (PTR_FUN_0384e468) is non-NULL\n2. If non-NULL, call the optional initialization handler\n3. Execute first callback array (DAT_0384a008 to DAT_0384a010) by iterating through function pointers\n4. Execute second callback array (DAT_0384a000 to DAT_0384a004) by iterating through function pointers\n5. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid: No return value\n\nSpecial Cases:\n- The optional initialization handler at PTR_FUN_0384e468 may be NULL (skipped if so)\n- Each callback array is processed by CallFunctionArray which safely handles NULL function pointers\n- Called during module initialization phase when param_2==1 in parent function",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:91b5192dddb89e963abc2be4471149da",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "91b5192dddb89e963abc2be4471149da",
        "CFG": "7db700d6fea6bf8bb6e1c45f4f727c0d",
        "PRO": "2dccca79d6cd4d2e0d533b711200f4bb"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "91b5192dddb89e963abc2be4471149da"
      }
    },
    "binkw32_MNE_cd85d17a6b19": {
      "addresses": {
        "LoD/PD2": "0x0383F10E"
      },
      "rvas": {
        "LoD/PD2": "0x1F10E"
      },
      "sizes": {
        "LoD/PD2": 17
      },
      "name": "__exit",
      "signature": "void __exit(int _Code)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __exit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cd85d17a6b193c95680d3fdca645abba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd85d17a6b193c95680d3fdca645abba",
        "CFG": null,
        "PRO": "c80ea614abfd3bcd1af49cec01e55660"
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
    "binkw32_MNE_7a5e6ed384be": {
      "addresses": {
        "LoD/PD2": "0x0383F11F"
      },
      "rvas": {
        "LoD/PD2": "0x1F11F"
      },
      "sizes": {
        "LoD/PD2": 15
      },
      "name": "ExecuteCleanupHandlers",
      "signature": "void ExecuteCleanupHandlers(void)",
      "calling_convention": "__stdcall",
      "comment": "Executes registered exit/cleanup handlers during program termination.\n\nAlgorithm:\n1. Push three arguments onto stack: 0x1 (flag), 0x0 (param2), 0x0 (param1)\n2. Call ExecuteExitHandlers(0, 0, 1) to invoke all registered cleanup handlers\n3. Clean up stack by adding 0xc (12) bytes to ESP (3 arguments * 4 bytes each)\n4. Return to caller\n\nReturns:\nvoid - No return value. This function is called during cleanup and does not return a value to its caller.\n\nSpecial Cases:\n- Called only when cleanup flag (DAT_0385c940) is zero, indicating normal program exit\n- Uses __stdcall calling convention where the callee (ExecuteExitHandlers) cleans the stack\n- Arguments are magic constants: 0 for param1, 0 for param2, 1 for the handler execution flag\n- Part of the DLL/executable cleanup chain invoked before process termination",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7a5e6ed384be31095abb7960c9f1d6d0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7a5e6ed384be31095abb7960c9f1d6d0",
        "CFG": null,
        "PRO": "ece079ef0dcc93f72e43c57c565dc1c3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7a5e6ed384be31095abb7960c9f1d6d0"
      }
    },
    "binkw32_MNE_45d9b348a966": {
      "addresses": {
        "LoD/PD2": "0x0383F12E"
      },
      "rvas": {
        "LoD/PD2": "0x1F12E"
      },
      "sizes": {
        "LoD/PD2": 153
      },
      "name": "ExecuteExitHandlers",
      "signature": "void ExecuteExitHandlers(UINT exitCode, int callDynamicAtExitHandlers, int promptForDebugger)",
      "calling_convention": "__cdecl",
      "comment": "Executes C++ runtime exit handlers and terminates the process.\n\nThis function manages the program termination sequence in the Visual C++ runtime, executing \nregistered atexit handlers and calling destructors in reverse order. It implements the \nstandard C/C++ program exit sequence with support for the atexit() function callbacks.\n\nAlgorithm:\n1. Check if already initialized via DAT_0385c944 flag\n2. If first call, capture exit code and immediately terminate via GetCurrentProcess/TerminateProcess\n3. Mark termination in progress (DAT_0385c940 = 1)\n4. Store debugger prompt flag in DAT_0385c93c\n5. If callDynamicAtExitHandlers is 0:\n   a. Iterate backwards through atexit function pointers stored at DAT_0385cdf0\n   b. For each non-null function pointer, execute it via CALL\n   c. Walk array from DAT_0385cdec-4 down to DAT_0385cdf0 boundary\n6. Execute static destructors via CallFunctionArray(&DAT_0384a014, &DAT_0384a018)\n7. Execute additional exit handlers via CallFunctionArray(&DAT_0384a01c, &DAT_0384a020)\n8. If promptForDebugger is 0: Mark initialized and call ExitProcess with exit code\n9. Return (with debugger prompt if promptForDebugger != 0)\n\nParameters:\n- exitCode (UINT): Exit code to pass to ExitProcess\n- callDynamicAtExitHandlers (int): 0 to execute atexit handlers, 1 to skip them\n- promptForDebugger (int): 0 to call ExitProcess, 1 to return (allows debugger prompt)\n\nReturns:\n- void: Does not return normally (calls ExitProcess)\n\nSpecial Cases:\n- DAT_0385c944 check detects if already initialized - terminates immediately if true\n- DAT_0385cdf0 NULL check prevents crashes if no atexit handlers registered\n- Function pointer validation (TEST EAX) prevents calls to NULL handlers\n- Array bounds maintained by comparing ESI against DAT_0385cdf0 threshold\n\nStructure Layout:\nAtexit Function Array (backward iteration):\n  DAT_0385cdf0: Array start pointer (lowest address)\n  DAT_0385cdec: Array end pointer (highest address)\n  Array contains function pointers, walked backward from (end-4) to start",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:45d9b348a966df89d3a7165f288b5d47",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "45d9b348a966df89d3a7165f288b5d47",
        "CFG": "e0f0d2c411c7f078ad0625f7753a8d48",
        "PRO": "1a126880d04a560e03bb1a74fb405590"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "45d9b348a966df89d3a7165f288b5d47"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_f1060dff4c8b": {
      "addresses": {
        "LoD/PD2": "0x0383F1C7"
      },
      "rvas": {
        "LoD/PD2": "0x1F1C7"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "CallFunctionArray",
      "signature": "void CallFunctionArray(pointer pCallbackArrayStart, pointer pCallbackArrayEnd)",
      "calling_convention": "__cdecl",
      "comment": "Iterates through an array of function pointers and calls each non-null callback.\\n\\nAlgorithm:\\n1. Load start pointer from stack parameter (ESI = param_1)\\n2. Compare current pointer with end pointer\\n3. If current pointer >= end pointer, exit loop (all callbacks processed)\\n4. Load function pointer from current array element\\n5. Test if function pointer is non-null (check for NULL before calling)\\n6. If non-null, call the function via indirect call\\n7. Increment pointer by 4 bytes (next array element)\\n8. Jump back to step 2 to process next callback\\n9. Pop saved register and return to caller\\n\\nParameters:\\n  pCallbackArrayStart (pointer): Start address of function pointer array\\n  pCallbackArrayEnd (pointer): End address of function pointer array (one past last element)\\n\\nReturns:\\n  void: No return value\\n\\nSpecial Cases:\\n  - Array can contain NULL pointers which are safely skipped\\n  - End pointer should point one element past the last valid callback\\n  - Iteration stops when current pointer >= end pointer\\n  - ESI is preserved via PUSH/POP around the loop\\n\\nStructure Layout:\\n  The array is a contiguous sequence of 4-byte function pointers:\\n  Offset | Size | Content\\n  -------|------|--------\\n  +0x00  |  4   | Callback function pointer 0\\n  +0x04  |  4   | Callback function pointer 1\\n  +0x08  |  4   | Callback function pointer 2\\n  ...    | ...  | ...\\n  End    |  -   | Sentinel (end pointer parameter)\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f1060dff4c8b86b7cd32c42f8f136fb6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "CFG": "8df2c0dc7c783306593f4d1d07d16756",
        "PRO": "c5843f3db205987ea5094c55a1bdaf18"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f1060dff4c8b86b7cd32c42f8f136fb6"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_b09f16c0e6a5": {
      "addresses": {
        "LoD/PD2": "0x0383F1E1"
      },
      "rvas": {
        "LoD/PD2": "0x1F1E1"
      },
      "sizes": {
        "LoD/PD2": 427
      },
      "name": "InitializeHandleTable",
      "signature": "void InitializeHandleTable(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes the C runtime handle table for standard I/O streams (stdin, stdout, stderr).\n\nAlgorithm:\n1. Allocate initial 256-byte (0x100) block from heap for handle table array\n2. If allocation fails, call error exit handler with code 0x1b\n3. Initialize handle table entries: clear flag byte, set handle to 0xffffffff, set entry type to 0x0a\n4. Call GetStartupInfoA to retrieve process startup information and inherited file handles\n5. If startup info contains inherited handles (cbReserved2 > 0 and lpReserved2 != NULL):\n   a. Read handle count from first DWORD of inherited data\n   b. Cap handle count at 0x800 (2048) maximum\n   c. If required handle count exceeds current capacity (0x20), allocate additional 256-byte blocks\n   d. Copy valid inherited handles to handle table, marking with inheritance flags\n6. For each standard stream (stdin=0, stdout=1, stderr=2):\n   a. Check if current entry is uninitialized (0xffffffff)\n   b. If uninitialized, retrieve handle via GetStdHandle for STD_INPUT_HANDLE (-11), STD_OUTPUT_HANDLE (-12), or STD_ERROR_HANDLE (-13)\n   c. Validate handle is not INVALID_HANDLE_VALUE (-1) and get file type via GetFileType\n   d. If file is a character device (type 0x2), mark entry as character device (0x40 flag)\n   e. If file is a pipe (type 0x3), mark entry as pipe (0x8 flag)\n   f. Set handle value in table\n7. Call SetHandleCount with capacity value to notify CRT of final handle table size\n8. Return to caller\n\nParameters:\nNone - function uses CRT global variables DAT_0385cce0 (handle table base) and DAT_0385cde0 (handle count)\n\nReturns:\nvoid - no return value, function initializes global state\n\nSpecial Cases:\n- If initial malloc fails, error exit with code 0x1b is triggered\n- Inherited handles are limited to 0x800 entries maximum\n- Character devices are marked with 0x40 flag for special handling\n- Pipes are marked with 0x8 flag for special handling\n- Allocation failures during secondary allocations skip handle processing\n- Standard streams use magic constant values: -10 (stdin), -11 (stdout), -13 (stderr)\n\nStructure Layout:\nHandle Table Entry Format (8 bytes per entry):\nOffset  Size  Field Name         Type     Description\n0       4     handle             HANDLE   File handle or 0xffffffff if uninitialized\n4       1     flags              byte     Status and type flags (0x80=used, 0x40=console, 0x8=pipe, 0x81=default)\n5       1     reserved1          byte     Reserved byte (unused)\n6       2     reserved2          word     Reserved word (unused)\n",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b09f16c0e6a5014f6b150653e76f58a2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b09f16c0e6a5014f6b150653e76f58a2",
        "CFG": "dbd056a7491ee7a8893ba932b320d4b9",
        "PRO": "eda085c40c24f83fea7f5bc20f13125b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b09f16c0e6a5014f6b150653e76f58a2"
      }
    },
    "binkw32_MNE_299148f3d45b": {
      "addresses": {
        "LoD/PD2": "0x0383F38C"
      },
      "rvas": {
        "LoD/PD2": "0x1F38C"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "CleanupGlobalPointerArray",
      "signature": "void CleanupGlobalPointerArray(void)",
      "calling_convention": "__stdcall",
      "comment": "Iterates through global pointer array and deallocates all non-null entries.\n\nAlgorithm:\n1. Initialize ESI to point to first entry in global array (0x385cce0)\n2. Load pointer from current array entry\n3. If pointer is non-null, push pointer and call FUN_0383c9d4 (deallocation function)\n4. Zero out the current array entry\n5. Advance ESI to next entry (increment by 4 bytes)\n6. Loop until ESI >= end address (0x385cde0)\n7. Restore saved registers and return\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - Array bounds are from 0x385cce0 to 0x385cde0 (64 bytes = 16 entries)\n  - Only non-null entries are processed; null entries are skipped\n  - Each entry is zeroed after processing to prevent double-deallocation\n  - Called during application shutdown to free all dynamically allocated memory",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:299148f3d45b20053c668d97232dffbf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "299148f3d45b20053c668d97232dffbf",
        "CFG": "a76e0273b3e592eaee672793f78290ba",
        "PRO": "cbb085d4d1ba936a78e0f2cc167f82a6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "299148f3d45b20053c668d97232dffbf"
      }
    },
    "binkw32_MNE_6e538b3bbbee": {
      "addresses": {
        "LoD/PD2": "0x0383F3AF"
      },
      "rvas": {
        "LoD/PD2": "0x1F3AF"
      },
      "sizes": {
        "LoD/PD2": 185
      },
      "name": "InitializeEnvironmentStringArray",
      "signature": "void InitializeEnvironmentStringArray(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes global environment string array from raw environment strings.\n\nAlgorithm:\n1. Check if global initialization flag (DAT_0385cde8) is set; if not, call InitializeGlobalOnce()\n2. Count non-equals-prefixed environment entries from raw string buffer (DAT_0385c8b4)\n3. Allocate array of pointers (size = count*4 + 4 bytes) using malloc()\n4. Copy each environment string (excluding equals-prefixed entries) to allocated memory\n5. Append null terminator to array\n6. Clean up raw environment buffer and mark initialization complete\n\nParameters:\n(none)\n\nReturns:\nvoid\n\nSpecial Cases:\n- Entries starting with '=' are skipped during processing (system-added entries)\n- Magic value 0x9 passed to __amsg_exit on malloc failures (out of memory)\n- Array is null-terminated with 0 pointer at end\n- Raw environment buffer (DAT_0385c8b4) is freed and cleared after processing",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6e538b3bbbeec8f94bef058bdad701fe",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6e538b3bbbeec8f94bef058bdad701fe",
        "CFG": "48cfb634102b5d72e404e02e44594130",
        "PRO": "a47efe5f4c663f1619a88951652b5ac7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6e538b3bbbeec8f94bef058bdad701fe"
      }
    },
    "binkw32_STR_ef8d6b30e6f2": {
      "addresses": {
        "LoD/PD2": "0x0383F468"
      },
      "rvas": {
        "LoD/PD2": "0x1F468"
      },
      "sizes": {
        "LoD/PD2": 153
      },
      "name": "InitializeApplicationArguments",
      "signature": "void InitializeApplicationArguments(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes application command-line arguments by parsing and storing them in global variables.\n\nAlgorithm:\n1. Check if global initialization has already been performed\n2. If not initialized, call InitializeGlobalOnce() to initialize globals\n3. Retrieve the module's executable path using GetModuleFileNameA\n4. Determine the command line to parse (from environment or module path)\n5. Call ParseCommandLineArguments first time to get argument count and data size\n6. Allocate memory buffer using malloc for the parsed arguments\n7. Check if memory allocation succeeded; exit with error code 8 if it failed\n8. Call ParseCommandLineArguments second time to populate the allocated buffer\n9. Store the argument array pointer and argument count in global variables\n\nParameters:\nNone - Function takes no parameters\n\nReturns:\nvoid - Function returns nothing; sets global variables _DAT_0385c91c (argument array) and _DAT_0385c918 (argument count - 1)\n\nSpecial Cases:\n- If custom command line is provided (DAT_0385ce10 is non-empty), uses custom line instead of module path\n- Memory allocation failure triggers process exit with error code 8\n- Argument count is stored decremented by 1 in _DAT_0385c918\n- Uses __stdcall convention with stack cleanup by callee\n\nStructure Layout:\nThe function operates on argument array structures passed to ParseCommandLineArguments.\nEach argument is stored as a pointer in the allocated buffer.\nTotal allocation size = (argCount * 4) + argDataSize bytes",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:ef8d6b30e6f2854d83646b8368320355",
      "indexes": {
        "EXP": null,
        "STR": "ef8d6b30e6f2854d83646b8368320355",
        "API": null,
        "MNE": "78c0be793b204c577b78460711bf70fb",
        "CFG": "cea6ce415732f40bbae9c1758ccf2bd8",
        "PRO": "929753114515822faefe826ebb9d3704"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "78c0be793b204c577b78460711bf70fb"
      }
    },
    "binkw32_MNE_50cd6b6fd69b": {
      "addresses": {
        "LoD/PD2": "0x0383F501"
      },
      "rvas": {
        "LoD/PD2": "0x1F501"
      },
      "sizes": {
        "LoD/PD2": 436
      },
      "name": "ParseCommandLineArguments",
      "signature": "void ParseCommandLineArguments(char * cmdLine, char * * argArray, char * outputBuffer, int * argCount, int * charCount)",
      "calling_convention": "__cdecl",
      "comment": "Parses command-line arguments from a string into an array, handling quoted strings and escape sequences.\n\nAlgorithm:\n1. Initialize output buffers (charCount and argCount set to 0 and 1)\n2. If argArray provided, store output buffer pointer at first position and advance array pointer\n3. Parse initial token:\n   - If starts with quote (\\\"), process quoted string: preserve escaped quotes, skip other escapes, handle quote as terminator\n   - Otherwise process unquoted token: skip leading whitespace, terminate on space/tab/null, handle backslash escapes\n4. Null-terminate first token in output buffer\n5. Skip whitespace to find next argument\n6. For each remaining argument:\n   - Store output buffer pointer in argArray (if provided) and increment argCount\n   - Count backslashes before each quote to determine if quote is escaped (even count = quote is literal terminator, odd count = escaped quote)\n   - Copy backslashes (halved count) and process quoted/unquoted content\n   - Handle quote toggle state and escape sequence processing\n   - Terminate with null when unescaped quote or whitespace found outside quotes\n7. Finalize argArray with null terminator (if provided)\n8. Return with argCount incremented\n\nParameters:\n  cmdLine (char*) - Input command line string to parse\n  argArray (char**) - Array to store pointers to parsed argument strings (can be NULL)\n  outputBuffer (char*) - Output buffer to store parsed strings with null terminators (can be NULL)\n  argCount (int*) - Pointer to argument counter (starts at 1, incremented for each argument found)\n  charCount (int*) - Pointer to character counter (tracks total characters in output)\n\nReturns:\n  void - Results stored through output pointers (argCount and charCount)\n\nSpecial Cases:\n  - Backslash escapes quote chars within quoted strings only\n  - Pairs of backslashes collapse to single backslash (e.g., \\\\\\\\ -> \\\\)\n  - Trailing backslash followed by quote toggles quoted mode (allows quote in quoted string)\n  - argArray/outputBuffer can be NULL for parsing without storage (count-only mode)\n  - Multiple consecutive spaces/tabs treated as single separator\n  - Quote at start of string triggers quoted string mode with special escape handling",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:50cd6b6fd69b78c0380659763fce7ea0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "50cd6b6fd69b78c0380659763fce7ea0",
        "CFG": "fb29ae4ee2676389ff0892a75897cdce",
        "PRO": "298c11e8b7f6fb45479beaa4f4f2c6d3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "50cd6b6fd69b78c0380659763fce7ea0"
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "binkw32_MNE_ee22dcb18299": {
      "addresses": {
        "LoD/PD2": "0x0383F6B5"
      },
      "rvas": {
        "LoD/PD2": "0x1F6B5"
      },
      "sizes": {
        "LoD/PD2": 306
      },
      "name": "GetEnvironmentStringsCached",
      "signature": "LPSTR GetEnvironmentStringsCached(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves cached environment strings in ANSI format, converting from Unicode if necessary.\n\nAlgorithm:\n1. Check DAT_0385ca4c cache flag to determine initialization state\n2. If uninitialized (0), attempt to fetch wide character environment strings via GetEnvironmentStringsW\n3. If wide strings available, scan for double null terminator and convert to ANSI format using WideCharToMultiByte\n4. Cache the conversion result and return allocated ANSI buffer\n5. If wide strings unavailable, fall back to GetEnvironmentStringsA for direct ANSI strings\n6. For ANSI mode, scan for double null terminator and copy strings to allocated buffer using MemMove\n7. Free temporary environment string buffers retrieved from Windows API\n8. Return dynamically allocated string buffer or NULL on error\n\nParameters:\nvoid - No parameters; operates on system environment obtained via Windows API\n\nReturns:\nLPSTR - Pointer to dynamically allocated buffer containing null-separated environment variable strings (each string formatted as NAME=VALUE), or NULL if retrieval fails. Caller must free returned pointer.\n\nSpecial Cases:\n- Cache value 0 = uninitialized, 1 = wide character mode available, 2 = ANSI mode fallback\n- Function prefers wide character strings and converts to ANSI; falls back to ANSI only if wide unavailable\n- Returns NULL if neither GetEnvironmentStringsW nor GetEnvironmentStringsA available\n- Allocation failures (malloc returns NULL) result in NULL return with original strings freed\n- WideCharToMultiByte conversion failures free allocated buffer and return NULL\n- Environment strings are obtained fresh on each call but cache mode for future calls\n- Double null terminator indicates end of environment string block (two consecutive null bytes for ANSI, two consecutive null wchars for Unicode)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ee22dcb18299b51eb994a57f32a5df1d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ee22dcb18299b51eb994a57f32a5df1d",
        "CFG": "251ad66a10e4d45c7bcd5b4f701e532d",
        "PRO": "8c696976331480e2abbece2421ba0f43"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ee22dcb18299b51eb994a57f32a5df1d"
      }
    },
    "binkw32_MNE_9765460a3049": {
      "addresses": {
        "LoD/PD2": "0x0383F7E7"
      },
      "rvas": {
        "LoD/PD2": "0x1F7E7"
      },
      "sizes": {
        "LoD/PD2": 57
      },
      "name": "HandleRuntimeErrorCleanup",
      "signature": "undefined HandleRuntimeErrorCleanup(void)",
      "calling_convention": "__stdcall",
      "comment": "Executes runtime error cleanup handlers based on error flags.\n\nAlgorithm:\n1. Load error status flag from global 0x0385c8bc\n2. Check if error condition exists:\n   - Flag == 0x1 (immediate error), OR\n   - Flag == 0x0 AND global 0x0385c8c0 == 0x1 (delayed error)\n3. If error condition true:\n   a) Call ProcessRuntimeError(0xfc) - error handler setup\n   b) Load function pointer from global 0x0385ca50\n   c) If pointer non-NULL, execute callback function\n   d) Call ProcessRuntimeError(0xff) - error handler teardown\n4. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid\n\nSpecial Cases:\n- 0xfc: Error handler initialization code\n- 0xff: Error handler finalization code\n- Function pointer at 0x0385ca50 can be NULL (checked before call)\n- Global state flags control execution flow",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9765460a30498931557fab10cfc0be00",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9765460a30498931557fab10cfc0be00",
        "CFG": "285d09a7e9b985b0b82a1cfce0632509",
        "PRO": "7502cce0f0faed280fe9470193f6a18b"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9765460a30498931557fab10cfc0be00"
      }
    },
    "binkw32_STR_ff7880d11813": {
      "addresses": {
        "LoD/PD2": "0x0383F820"
      },
      "rvas": {
        "LoD/PD2": "0x1F820"
      },
      "sizes": {
        "LoD/PD2": 339
      },
      "name": "ProcessRuntimeError",
      "signature": "void ProcessRuntimeError(DWORD errorCode)",
      "calling_convention": "__cdecl",
      "comment": "Displays a runtime error dialog or writes error message to stdout based on debug mode.\n\nAlgorithm:\n1. Search through error code lookup table (DAT_0384e678) for matching errorCode\n2. Calculate error index and verify match against table\n3. If debug mode enabled (DAT_0385c8bc=1 or DAT_0385c8c0=1):\n   - Write error message string to stdout using WriteFile\n4. Else if errorCode != 0xfc (special sentinel):\n   - Get module filename using GetModuleFileNameA\n   - Build error message by concatenating:\n     * \"Runtime Error: Program: \"\n     * Module file path (or default message if retrieval fails)\n     * \" \"\n     * Error message string from table\n   - Validate message length (max 0x3c characters)\n   - Display error dialog using DynamicMessageBoxA\n\nParameters:\n  errorCode (DWORD) - Error code to process, matched against error table\n\nReturns:\n  void - Function displays error dialog or writes to stdout\n\nSpecial Cases:\n  - Magic value 0xfc: Special error code that triggers early exit without dialog\n  - Magic value 0x104: Buffer size for module filename (260 bytes)\n  - Magic value 0x38: Min path length check for truncation logic\n  - pathSuffix buffer: Stores path suffix bytes (7 chars) - encoded/control chars\n  - Structure fields accessed:\n    * DAT_0384e678: Error code lookup table (8-byte stride entries)\n    * DAT_0385c8bc: Debug mode flag (1=debug, 0=normal)\n    * DAT_0385c8c0: Alternative debug flag (1=debug mode)\n    * Error table entry +0: Error code value\n    * Error table entry +4: Pointer to error message string",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:ff7880d11813b11bf7ac9bc241be5c60",
      "indexes": {
        "EXP": null,
        "STR": "ff7880d11813b11bf7ac9bc241be5c60",
        "API": null,
        "MNE": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "CFG": "e9e3238573fb8758cb6dacb6540ea203",
        "PRO": "48c6f07dea88f11565b2c007fb6d275c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "6bfb7faf8650903f50cd7e2ef7eba7fe"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_c1d05e132bc8": {
      "addresses": {
        "LoD/PD2": "0x0383F973"
      },
      "rvas": {
        "LoD/PD2": "0x1F973"
      },
      "sizes": {
        "LoD/PD2": 511
      },
      "name": "ApplyLocaleStringMapping",
      "signature": "int ApplyLocaleStringMapping(LCID locale, uint mappingFlags, char * sourceAnsi, int sourceLength, LPWSTR destBuffer, int destSize, UINT codePage, int useCodePageFlags)",
      "calling_convention": "__cdecl",
      "comment": "Applies locale-specific string mapping with encoding conversion.\n\nThis function performs bidirectional string mapping and character set conversion\nusing the appropriate Windows locale mapping API based on system capabilities.\nIt supports ANSI-to-Unicode and Unicode-to-ANSI conversion pipelines with\nintermediate buffer allocation and exception handling.\n\nAlgorithm:\n1. Check encoding support flag (0x0385ca54) to detect Unicode/ANSI capabilities\n2. If not cached, detect system capabilities via LCMapStringW and LCMapStringA\n3. Validate input string length using ComputeBoundedStringLength\n4. Route based on detected encoding:\n   - ANSI path: Direct call to LCMapStringA with original parameters\n   - Unicode path: Multi-stage conversion (ANSI->Unicode->LCMap->Unicode->ANSI)\n5. For Unicode path with PRESERVE_WIDTH flag (0x400):\n   - Calculate temporary buffer size (2x input + 3, aligned to 4)\n   - Allocate stack buffer via exception handling\n   - Convert ANSI to Unicode (using UTF-8 or specified codepage)\n   - Apply LCMapStringW transformation\n   - Convert back to ANSI via WideCharToMultiByte\n6. For Unicode path without PRESERVE_WIDTH:\n   - Return mapped length if output buffer not provided\n   - Verify output buffer has sufficient space\n   - Apply LCMapStringW directly to wide buffer\n   - Return mapped character count\n\nParameters:\n  locale - LCID specifying the locale for mapping operations\n  mappingFlags - Flags controlling mapping behavior (0x100=lowercase, 0x400=preserve width)\n  sourceAnsi - Pointer to input ANSI string buffer\n  sourceLength - Length of input in bytes; -1 for null-terminated string\n  destBuffer - Optional pointer to output buffer; NULL to get required size\n  destSize - Size of output buffer in bytes/chars depending on Unicode/ANSI\n  codePage - Windows code page for ANSI conversion (0=default)\n  useCodePageFlags - Flags for MultiByteToWideChar (bit 3 controls strict validation)\n\nReturns:\n  Number of characters/bytes written to output buffer, or required buffer size\n  if destBuffer is NULL. Returns 0 on failure (unsupported encoding, conversion\n  failure, or buffer overflow).\n\nSpecial Cases:\n  - If sourceLength <= 0 on entry, ComputeBoundedStringLength validates bounds\n  - Encoding detection is cached in global 0x0385ca54 after first call\n  - Exception handling (push/pop via FS:[0]) manages stack cleanup on errors\n  - PRESERVE_WIDTH flag (0x400) triggers dual-buffer conversion for safe mapping\n  - If codePage parameter is 0, uses default from global 0x0385c8e4\n  - No dest buffer provided: returns character count without mapping\n  - Insufficient output space: returns 0 to signal failure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c1d05e132bc8c3bc87e7a971916e9b9b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "CFG": "d8a6049770e510e2f27b5ad4175a1524",
        "PRO": "2a00c56a0c52d5b18e3fd28db487dfab"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c1d05e132bc8c3bc87e7a971916e9b9b"
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "binkw32_MNE_c365f0335b7b": {
      "addresses": {
        "LoD/PD2": "0x0383FB97"
      },
      "rvas": {
        "LoD/PD2": "0x1FB97"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "ComputeBoundedStringLength",
      "signature": "int ComputeBoundedStringLength(char * pString, int maxLength)",
      "calling_convention": "__cdecl",
      "comment": "Computes the length of a null-terminated string up to a maximum limit.\\n\\nAlgorithm:\\n1. Load string pointer and maximum length from stack parameters\\n2. Validate inputs: if maxLength is 0, jump to early exit\\n3. Loop through string characters while decrementing counter:\\n   a. Check if current character is null terminator\\n   b. If null found, exit loop\\n   c. If length counter exhausted, exit loop\\n   d. Otherwise advance to next character and continue\\n4. After loop, determine final return value:\\n   a. If string is null-terminated within limit, return actual length\\n   b. If length limit was reached, return maxLength\\n\\nParameters:\\n- pString: Pointer to input string (may not be null-terminated)\\n- maxLength: Maximum number of characters to scan\\n\\nReturns:\\n- If null terminator found within maxLength: actual string length\\n- If no null terminator found: maxLength (limit indicator)\\n\\nSpecial Cases:\\n- Empty string (maxLength=0): Returns 0\\n- NULL pointer input: Behavior undefined (no validation)\\n- Non-null-terminated string: Returns maxLength as sentinel value\\n- String exactly maxLength characters: Returns maxLength",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c365f0335b7bc4452623cbc78de16e67",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c365f0335b7bc4452623cbc78de16e67",
        "CFG": "dc0623423d93fb21da8f1c1461d32590",
        "PRO": "44eb51cb2190f284eca0a4e49c8cfa09"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c365f0335b7bc4452623cbc78de16e67"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_d858691b25ff": {
      "addresses": {
        "LoD/PD2": "0x0383FBC2"
      },
      "rvas": {
        "LoD/PD2": "0x1FBC2"
      },
      "sizes": {
        "LoD/PD2": 117
      },
      "name": "GetCharacterClassAttribute",
      "signature": "uint GetCharacterClassAttribute(void * this, void * pCharTypeTable, int charValue, uint attributeMask)",
      "calling_convention": "__thiscall",
      "comment": "Retrieves character classification attributes from Unicode/locale-aware character type table.\n\nQueries character class information for a single byte or multi-byte character using either\na fast lookup table (for ASCII range 0x00-0xFF) or the Windows GetStringTypeWithEncodingDetection API\n(for extended characters > 0xFF). Returns the requested character class attributes (digit, letter,\nspace, punctuation, etc.) masked and filtered according to the provided attribute mask parameter.\n\nAlgorithm:\n1. Check if character value is in ASCII range (charValue + 1 <= 0x100, i.e., char < 0xFF)\n2. If ASCII: load word from pre-computed lookup table at offset [charValue * 2]\n3. If extended (>= 0x100): decompose character into high and low bytes\n4. Check high-byte flag at table[(high_byte)*2 + 1] for encoding type\n5. If flag has 0x80 bit clear: character uses single-byte encoding\n6. If flag has 0x80 bit set: character uses multi-byte encoding (2 bytes)\n7. Call GetStringTypeWithEncodingDetection to retrieve character class word\n8. On API failure (return=0): return 0 immediately\n9. Load character class word from output parameter\n10. Apply attribute mask with AND operation\n11. Return masked result\n\nParameters:\npCharTypeTable (ECX): Pointer to character type lookup table base\n                      - Offset 0: Fast lookup for ASCII (256 entries \u00d7 2 bytes)\n                      - Offset [char*2]: Word with character class flags\ncharValue (param_1): Character code to classify (0x00-0xFFFF or higher)\n                     - Values 0x00-0xFF: indexed directly in lookup table\n                     - Values >= 0x100: requires decomposition and API call\nattributeMask (param_2): Bitmask for requested attributes (e.g., 0x0004=digit)\n\nReturns:\nEAX: Masked character class word\n     - Bit 0x0001: Letter/alphabetic character\n     - Bit 0x0004: Decimal digit (0-9)\n     - Bit 0x0008: Space/whitespace character\n     - Other bits: Locale-specific attributes\n     - Value 0x0000: No matching attributes or invalid character\n\nSpecial Cases:\n- Magic 0x100: ASCII boundary for fast table lookup optimization\n- Magic 0x80: Flag indicating multi-byte encoding requirement\n- ASCII optimization: Direct lookup 10x faster than API call\n- Encoding detection: High byte flag determines single vs multi-byte handling",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d858691b25ff9d68f1965dc04bb2a9aa",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d858691b25ff9d68f1965dc04bb2a9aa",
        "CFG": "b2617940305b6e1d0cf3c25e221e2cae",
        "PRO": "c8d89ad94f3c34809611625b9d2466f5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d858691b25ff9d68f1965dc04bb2a9aa"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_01839c0631f6": {
      "addresses": {
        "LoD/PD2": "0x0383FC37"
      },
      "rvas": {
        "LoD/PD2": "0x1FC37"
      },
      "sizes": {
        "LoD/PD2": 53
      },
      "name": "ApplyBitMaskFlags",
      "signature": "DWORD ApplyBitMaskFlags(void * this, DWORD setMask, DWORD clearMask)",
      "calling_convention": "__thiscall",
      "comment": "Applies a set/clear bitmask to update flag state through bit translation functions.\\n\\nAlgorithm:\\n1. Save FPU control word to stack for preservation during operation\\n2. Load saved FPU control word and call TranslateBitFlags to translate current flags\\n3. Apply bitmask operation: (translated & ~clearMask) | (setMask & clearMask)\\n4. Call ConvertBitMaskToFlags to convert result to hardware format\\n5. Restore FPU control word from stack\\n6. Return the merged bitmask value in EAX\\n\\nParameters:\\nthis (ECX): Pointer to object containing flag state\\nsetMask (Stack +0x8): Bits to enable in the operation (logically ANDed with clearMask)\\nclearMask (Stack +0xC): Bits to disable in the operation (inverted and ANDed with result)\\n\\nReturns:\\nEAX (DWORD): The final merged bitmask after applying set/clear operations\\n\\nSpecial Cases:\\nThis function uses a set/clear mask pattern where:\\n- Bits set in both setMask and clearMask will be set (1) in the output\\n- Bits set only in clearMask will be cleared (0) in the output\\n- Bits set in neither mask remain unchanged\\nThe function preserves and restores the FPU control word, suggesting it may be called in contexts where FPU state is critical.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:01839c0631f6879602250d0f45268558",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "01839c0631f6879602250d0f45268558",
        "CFG": null,
        "PRO": "17e4599fad4ffc1e4e07e516b86e9d30"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "01839c0631f6879602250d0f45268558"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_03d2d9a1894b": {
      "addresses": {
        "LoD/PD2": "0x0383FC6C"
      },
      "rvas": {
        "LoD/PD2": "0x1FC6C"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "ClearBitMaskFlags",
      "signature": "void ClearBitMaskFlags(void * this, void * pThis, uint setMask, uint clearMask)",
      "calling_convention": "__thiscall",
      "comment": "Clears specific bits in a bitmask while setting new bits through a masked operation.\n\nAlgorithm:\n1. Extract setMask parameter from stack (param at offset +4)\n2. Extract clearMask parameter from stack (param at offset +8)\n3. Apply bit mask operation: AND clearMask with 0xfff7ffff to clear bits 19, 18, and 3\n4. Call TranslateBitFlags routine with this pointer and masked values\n5. Return to caller after bit flag translation completes\n\nParameters:\nthis (ECX): Pointer to object containing flag state\nsetMask (Stack +4): Bits to enable in the mask (0x10000 from caller)\nclearMask (Stack +8): Bits to disable in the mask (0x30000 from caller)\n\nReturns:\nvoid - No return value; operation modifies object state through this pointer\n\nSpecial Cases:\nThe clearMask is ANDed with 0xfff7ffff before being passed to the called function.\nThis clears bits 3, 18, and 19 from the clearMask parameter, effectively preventing\nthose bits from being cleared in the actual flag operation. This is a safety mechanism\nto preserve certain critical flag bits (18 and 19 are control/status bits).\n\nMagic Numbers:\n0xfff7ffff = Binary: 11111111 11111111 11111011 11111111\nThis masks out bits 18 and 19 (0x00080000), preventing them from being cleared.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:03d2d9a1894bad6481c3d75928ae7b95",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "03d2d9a1894bad6481c3d75928ae7b95",
        "CFG": null,
        "PRO": "db7f065a3a0aff847bc45b0698d2699f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "03d2d9a1894bad6481c3d75928ae7b95"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_2d415c643620": {
      "addresses": {
        "LoD/PD2": "0x0383FC82"
      },
      "rvas": {
        "LoD/PD2": "0x1FC82"
      },
      "sizes": {
        "LoD/PD2": 146
      },
      "name": "TranslateBitFlags",
      "signature": "uint TranslateBitFlags(uint inputFlags)",
      "calling_convention": "__cdecl",
      "comment": "Translates input bitfield to output bitfield using predefined mappings\\nPerforms bit-by-bit translation of input flags to a different flag format.\\n\\nAlgorithm:\\n1. Initialize output accumulator to 0\\n2. Check input bit 0 (0x1): if set, set output bit 4 (0x10)\\n3. Check input bit 2 (0x4): if set, OR output with 0x8\\n4. Check input bit 3 (0x8): if set, OR output with 0x4\\n5. Check input bit 4 (0x10): if set, OR output with 0x2\\n6. Check input bit 5 (0x20): if set, OR output with 0x1\\n7. Check input bit 1 (0x2): if set, OR output with 0x80000\\n8. Extract and check bits 10-11 (mask 0xc00):\\n   - If 0x400: OR output with 0x100\\n   - If 0x800: OR output with 0x200\\n   - If 0xc00: OR output with 0x300\\n9. Extract and check bits 8-9 (mask 0x300):\\n   - If zero: OR output with 0x20000 (default)\\n   - If 0x200: OR output with 0x10000\\n10. Check input bit 12 (0x1000): if set, OR output with 0x40000\\n11. Return final output bitfield\\n\\nParameters:\\n- inputFlags (uint): Bitmask containing input flags to translate\\n\\nReturns:\\n- uint: Translated output bitmask with remapped flags\\n\\nSpecial Cases:\\n- Bits 10-11 are checked as a group for multi-way translation\\n- Bits 8-9 have default behavior (0x20000) if neither is set\\n- Bit 12 is independent and always processed last",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2d415c643620c5a6b5394f7144cab162",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2d415c643620c5a6b5394f7144cab162",
        "CFG": "7c92d5ce9ce96a5b20c1e87fc6aa8353",
        "PRO": "5ce4766fb84912d00337fe9e8e4c4a28"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2d415c643620c5a6b5394f7144cab162"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_13aed512c644": {
      "addresses": {
        "LoD/PD2": "0x0383FD14"
      },
      "rvas": {
        "LoD/PD2": "0x1FD14"
      },
      "sizes": {
        "LoD/PD2": 137
      },
      "name": "ConvertBitMaskToFlags",
      "signature": "uint ConvertBitMaskToFlags(uint inputMask)",
      "calling_convention": "__cdecl",
      "comment": "Converts a hardware bit-mask format into standardized flag format through bit permutation and selective grouping.\n\nAlgorithm:\n1. Initialize outputFlags from bit 4 (0x10) of inputMask to bit 0 of result\n2. Conditionally set result bits based on individual input bits:\n   - Bit 3 (0x8) sets output bit 2 (0x4)\n   - Bit 2 (0x4) sets output bit 3 (0x8)\n   - Bit 1 (0x2) sets output bit 4 (0x10)\n   - Bit 0 (0x1) sets output bit 5 (0x20)\n   - Bit 19 (0x80000) sets output bit 1 (0x2)\n3. Extract mode field from bits 8-9 (mask 0x300):\n   - 0x100 maps to output bits 10-11 as 0x400\n   - 0x200 maps to output bits 10-11 as 0x800\n   - 0x300 maps to output bits 10-11 as 0xc00\n4. Process state field from bits 16-17 (mask 0x30000):\n   - No bits set (0x0) adds 0x300 to output\n   - Only bit 16 (0x10000) adds 0x200 to output\n   - Other values add 0x300 to output\n5. Test bit 18 (0x40000) and set output bit 12 (0x1000) if set\n6. Return the fully transformed outputFlags value\n\nParameters:\n  inputMask (uint): 32-bit value containing packed bit fields requiring transformation\n\nReturns:\n  (uint): Transformed flag value with bits redistributed and mode/state fields remapped\n\nSpecial Cases:\n  - Bits are not simply mapped 1:1; several inputs are permuted or combined\n  - The 0x300 mask field has special handling for all-bits-zero case\n  - High bits (0x80000, 0x40000, 0x30000) control lower output bits",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:13aed512c644fb08ccd536c95b2ae182",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "13aed512c644fb08ccd536c95b2ae182",
        "CFG": "de7abdfcc72b5526895c38f13ff7f424",
        "PRO": "b6fee50c54d338862b5fb8893da15032"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "13aed512c644fb08ccd536c95b2ae182"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_546b5c43c0ef": {
      "addresses": {
        "LoD/PD2": "0x0383FD9D"
      },
      "rvas": {
        "LoD/PD2": "0x1FD9D"
      },
      "sizes": {
        "LoD/PD2": 73
      },
      "name": "CheckBitsCleared",
      "signature": "int CheckBitsCleared(uint * pBitsetArray, int bitIndex)",
      "calling_convention": "__cdecl",
      "comment": "Checks if a bit position and all higher-order bits in a bitset are cleared.\n\nAlgorithm:\n1. Calculate dword index from bitIndex / 0x20 (bitIndex / 32)\n2. Calculate bit position within dword as 0x1f - (bitIndex % 0x20)\n3. Test if target bit is set in dword using bitmask ~(-1 << bitPosition)\n4. If target bit is set, return 0 (bits not all clear)\n5. Starting from next dword (dwordIndex + 1), loop while dwordIndex < 3\n6. For each remaining dword up to index 3, test if dword equals 0\n7. If any dword is non-zero, return 0 (higher bits not clear)\n8. If all dwords 0 and target bit 0, return 1 (all bits clear)\n\nParameters:\npBitsetArray: Pointer to array of 3 dwords (96-bit bitset)\nbitIndex: 0-based bit index to check (0-95)\n\nReturns:\n1 if target bit and all higher bits are clear (zero)\n0 if target bit is set or any higher dword is non-zero\n\nSpecial Cases:\n- Bitset is limited to 3 dwords (hardcoded)\n- Dword index 0 holds bits 0-31, dword 1 holds bits 32-63, dword 2 holds bits 64-95\n- Caller (ClearBitAndPropagate) uses this to verify carry propagation is safe\n- CDQ/IDIV pattern: divide by 0x20 to get dword index and remainder for bit position\n\nStructure Layout:\nBitset Array Format (param_1 as base):\nOffset  Size  Field Name      Type   Description\n0x00    4     dword[0]        uint   Bits 0-31\n0x04    4     dword[1]        uint   Bits 32-63\n0x08    4     dword[2]        uint   Bits 64-95",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:546b5c43c0effce0a0403e1069ea2e2c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "546b5c43c0effce0a0403e1069ea2e2c",
        "CFG": "cdc070696849588c280e846bd6455d11",
        "PRO": "0eb08426ce3c35a25f65cd11e4f89b2a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "546b5c43c0effce0a0403e1069ea2e2c"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_a1fd1f83ab5d": {
      "addresses": {
        "LoD/PD2": "0x0383FDE6"
      },
      "rvas": {
        "LoD/PD2": "0x1FDE6"
      },
      "sizes": {
        "LoD/PD2": 86
      },
      "name": "PropagateCarryBit",
      "signature": "void PropagateCarryBit(uint * pArrayBase, int bitPosition)",
      "calling_convention": "__cdecl",
      "comment": "Propagates a carry bit through an array of 32-bit integers when a bit is set.\n\nAlgorithm:\n1. Calculate the array index and bit offset from bitPosition (divmod by 0x20)\n2. Set the target bit in pArrayBase[bitPosition/0x20] using CheckAdditionOverflow\n3. If overflow occurred (carryFlag != 0), propagate the carry backward through preceding array elements\n4. For each preceding element, add 1 using CheckAdditionOverflow and continue if overflow occurs\n5. Stop propagation when no overflow occurs (carryFlag == 0) or all preceding elements processed\n\nParameters:\npArrayBase (uint*): Base pointer to array of 32-bit unsigned integers\nbitPosition (int): Bit position to set (0-based, interpreted as array index and offset)\n\nReturns:\nvoid: Function modifies the array in place through pointer operations\n\nSpecial Cases:\n- Magic value 0x20 (32): Number of bits per array element\n- Magic value 0x1f (31): Used for calculating bit offset within 32-bit word\n- The function propagates carries backward (toward lower indices) not forward\n- Negative array indices (after subtraction) terminate the loop\n- Carry propagation stops immediately when no overflow occurs",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a1fd1f83ab5d96b4bef4e8817dd3ae88",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a1fd1f83ab5d96b4bef4e8817dd3ae88",
        "CFG": "971923f45045cfb1fa7a76868deb7c00",
        "PRO": "f97182f02d4310098ac617e17342d491"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a1fd1f83ab5d96b4bef4e8817dd3ae88"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_ef6cff05ab48": {
      "addresses": {
        "LoD/PD2": "0x0383FE3C"
      },
      "rvas": {
        "LoD/PD2": "0x1FE3C"
      },
      "sizes": {
        "LoD/PD2": 140
      },
      "name": "ClearBitAndPropagate",
      "signature": "uint ClearBitAndPropagate(uint * pBitsetArray, int bitIndex)",
      "calling_convention": "__cdecl",
      "comment": "Clears a bit in a bitset array and propagates carry if the bit was set.\n\nAlgorithm:\n1. Calculate the dword index (bitIndex / 32) and bit position within dword\n2. Check if the target bit is set in the bitset\n3. If set, call FUN_0383fd9d to check if all higher bits are zero\n4. If check passes, call FUN_0383fde6to propagate the clear/carry backward\n5. Clear the target bit by ANDing with ~(1 << bitPosition)\n6. Zero all dwords after the current dword up to index 3\n\nParameters:\npBitsetArray: Pointer to array of 3 dwords representing a 96-bit bitset\nbitIndex: 0-based bit index to clear (0-95)\n\nReturns:\nCarry result from FUN_0383fde6 if bit was set and check passed, 0 otherwise\n\nSpecial Cases:\n- Bit indices 0-31 are in dword 0, 32-63 in dword 1, 64-95 in dword 2\n- Maximum 3 dwords in bitset (hardcoded limit of 3 in loop)\n- Returns carry propagation result from lower dword if applicable",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ef6cff05ab48173ef496ad6dbe48e5ef",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ef6cff05ab48173ef496ad6dbe48e5ef",
        "CFG": "3af0887aa0a5e14bc546ff8d3e498545",
        "PRO": "7bf1802f382071d29458abf1515ec23e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ef6cff05ab48173ef496ad6dbe48e5ef"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_15ec667135b1": {
      "addresses": {
        "LoD/PD2": "0x0383FEC8"
      },
      "rvas": {
        "LoD/PD2": "0x1FEC8"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "CopyDecimalBuffer",
      "signature": "void CopyDecimalBuffer(int destOffset, uint * pSourceBuffer)",
      "calling_convention": "__cdecl",
      "comment": "Copies 3 DWORD values from source buffer to destination offset.\n\nAlgorithm:\n1. Calculate destination address from source pointer and offset\n2. Initialize copy counter to 3\n3. Load source DWORD at current position\n4. Write source DWORD to destination at calculated offset\n5. Increment source pointer by 4 bytes\n6. Decrement counter and jump to step 3 if counter not zero\n7. Return\n\nParameters:\n- destOffset: Destination offset (difference between destination and source base addresses)\n- pSourceBuffer: Pointer to source buffer containing DWORD values to copy\n\nReturns:\n- void\n\nSpecial Cases:\n- Fixed copy count of 3 DWORDs (12 bytes total)\n- Used in decimal processing to copy working buffer values\n- Destination address is calculated as (destOffset + pSourceBuffer)\n- Preserves ESI register via stack\n\nStructure Layout:\nUsed to copy uint arrays (3 elements), each 4 bytes\nOffset  Size  Field\n0       4     low component\n4       4     mid component\n8       4     high component\nTotal: 12 bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:15ec667135b11a0873a61b429d37dd78",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "15ec667135b11a0873a61b429d37dd78",
        "CFG": "c514545fcce289b8241e149ad12d442a",
        "PRO": "51d638096a06d3d432396f8b50483296"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "15ec667135b11a0873a61b429d37dd78"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_06356139b9d2": {
      "addresses": {
        "LoD/PD2": "0x0383FEE3"
      },
      "rvas": {
        "LoD/PD2": "0x1FEE3"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "ClearDecimalWorkingBuffer",
      "signature": "void ClearDecimalWorkingBuffer(uint * pBuffer)",
      "calling_convention": "__cdecl",
      "comment": "Clears a 12-byte decimal working buffer by zeroing three consecutive DWORDs.\n\nAlgorithm:\n1. Save EDI register on stack\n2. Load buffer pointer from stack parameter (ESP + 0x8)\n3. Zero EAX register via XOR\n4. Store EAX to buffer offset +0 (first DWORD)\n5. Store EAX to buffer offset +4 (second DWORD)\n6. Store EAX to buffer offset +8 (third DWORD)\n7. Restore EDI register from stack\n8. Return to caller\n\nParameters:\n- pBuffer: Pointer to 12-byte buffer containing three DWORDs to clear\n\nReturns:\n- void\n\nSpecial Cases:\n- Function uses STOSD instruction which automatically increments EDI after each store\n- EDI must be properly restored as it is a callee-saved register\n- This is a utility function called during decimal exponent processing for buffer initialization",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:06356139b9d27a571ec4e5eae9a16f67",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "06356139b9d27a571ec4e5eae9a16f67",
        "CFG": null,
        "PRO": "18a54f4e6e70cf9d99acaff0ebb9cc96"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "06356139b9d27a571ec4e5eae9a16f67"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_7ef9c351fc7b": {
      "addresses": {
        "LoD/PD2": "0x0383FEEF"
      },
      "rvas": {
        "LoD/PD2": "0x1FEEF"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "ValidateAllComponentsZero",
      "signature": "int ValidateAllComponentsZero(uint * pDecimalComponent)",
      "calling_convention": "__cdecl",
      "comment": "Validates that all three decimal components (low, mid, high) are zero.\n\nAlgorithm:\n1. Initialize loop counter to zero\n2. Loop through 3 iterations checking consecutive dword values\n3. For each iteration: load dword at current pointer offset, check if non-zero\n4. If any component is non-zero, jump to component_nonzero and return 0\n5. If component is zero, increment counter and advance pointer by 4 bytes\n6. After all 3 components validated as zero, return 1\n\nParameters:\n- pDecimalComponent: Pointer to decimal component array (typically offset +0 in decimal structure containing low, mid, high uint values)\n\nReturns:\n- 0: One or more components is non-zero\n- 1: All three components are zero\n\nSpecial Cases:\n- Checks exactly 3 consecutive dword values (12 bytes total)\n- Used to validate decimal buffer zero state before special case handling in exponent processing",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7ef9c351fc7bceec813ab833e5911666",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7ef9c351fc7bceec813ab833e5911666",
        "CFG": "2eedfb88a02f888dd480b53d641d0184",
        "PRO": "ba2f402be6d43c400b181e901a2b0ba9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7ef9c351fc7bceec813ab833e5911666"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_b5aa33b0420f": {
      "addresses": {
        "LoD/PD2": "0x0383FF0A"
      },
      "rvas": {
        "LoD/PD2": "0x1FF0A"
      },
      "sizes": {
        "LoD/PD2": 141
      },
      "name": "ShiftBitArrayRight",
      "signature": "void ShiftBitArrayRight(uint * bitArray, uint shiftBits)",
      "calling_convention": "__cdecl",
      "comment": "Shifts a 32-bit word array to the right by a specified number of bits.\n\nAlgorithm:\n1. Compute the number of complete 32-bit word shifts (shiftBits / 32) and remaining bits (shiftBits % 32)\n2. Right-shift the array words, propagating carry bits from higher words to lower words through a loop\n3. Clear or copy the high-order words depending on whether the shift count exceeds the remaining words\n4. Return the shifted array in-place\n\nParameters:\n- bitArray: Pointer to a 3-word (96-bit) array to be shifted right\n- shiftBits: Number of bits to shift right (0-96)\n\nReturns:\n- void (modifies bitArray in-place)\n\nSpecial Cases:\n- If shiftBits >= 96, all words become 0\n- If shiftBits is a multiple of 32, a complete word rotation occurs\n- Remaining bits < 32 are handled via carry bit propagation\n\nStructure Layout:\nbitArray points to a 3-word structure:\nOffset  Size  Field Name  Type  Description\n0       4     word0       uint  High-order word\n4       4     word1       uint  Middle word  \n8       4     word2       uint  Low-order word\nTotal size: 12 bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b5aa33b0420f2d311658da83496527f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b5aa33b0420f2d311658da83496527f7",
        "CFG": "42b841fbe75f0c0c5d8bf9ab5b91a778",
        "PRO": "21cae60e2eb8edab6a4a6c00021e1e37"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b5aa33b0420f2d311658da83496527f7"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_7af322ad22a8": {
      "addresses": {
        "LoD/PD2": "0x0383FF97"
      },
      "rvas": {
        "LoD/PD2": "0x1FF97"
      },
      "sizes": {
        "LoD/PD2": 364
      },
      "name": "ProcessDecimalExponent",
      "signature": "uint ProcessDecimalExponent(ushort * pDecimalBuffer, uint * pOutputBuffer, int * pExponentConfig)",
      "calling_convention": "__cdecl",
      "comment": "Processes decimal exponent values and applies scaling adjustments.\n\nAlgorithm:\n1. Extract exponent word and component values from decimal buffer\n2. Check if exponent equals special sentinel value (0x3fff) indicating zero value\n3. For zero case: validate zero state, copy result, and return 0\n4. For non-zero case: scale decimal based on exponent bounds\n5. If exponent below minimum: copy result and return 0\n6. If exponent above maximum: apply sign, scale up, and return 1\n7. If exponent in valid range: scale decimal appropriately and return 2\n8. Finalize result with proper sign bit and output format\n\nParameters:\n- pDecimalBuffer: Pointer to decimal value (ushort array with sign flag, low value, mid value, high value, exponent)\n- pOutputBuffer: Pointer to output buffer for result (uint array)\n- pExponentConfig: Pointer to exponent configuration array containing min/max bounds and output format\n\nReturns:\n- 0: Zero value or exponent underflow\n- 1: Exponent overflow (value too large)\n- 2: Exponent in valid range (normal case)\n\nSpecial Cases:\n- Exponent value of 0x3fff (-0x3fff in signed calculation) indicates zero decimal\n- Sign bit (0x8000) is preserved and applied to final result\n- Output format determined by pExponentConfig[4]: 0x40 outputs both words, 0x20 outputs single word",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7af322ad22a8e231117c7fe6d2adf33c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7af322ad22a8e231117c7fe6d2adf33c",
        "CFG": "ade70882ac03ce3f609657714a7f6db8",
        "PRO": "0b059f9828ad4bc5476b0b06b812187c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "7af322ad22a8e231117c7fe6d2adf33c"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_09d6403e834e": {
      "addresses": {
        "LoD/PD2": "0x03840103"
      },
      "rvas": {
        "LoD/PD2": "0x20103"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "ConvertDecimalBufferToUint",
      "signature": "void ConvertDecimalBufferToUint(ushort * pDecimalBuffer, uint * pOutputValue)",
      "calling_convention": "__cdecl",
      "comment": "Converts a parsed decimal buffer to an unsigned 32-bit integer output value.\n\nAlgorithm:\n1. Push configuration parameter address (0x384e920) onto stack\n2. Push output value pointer (param_2) onto stack\n3. Push decimal buffer pointer (param_1) onto stack\n4. Call FUN_0383ff97 to perform decimal buffer conversion and bit manipulation\n5. Clean up stack (remove 3 parameters \u00d7 4 bytes = 12 bytes)\n6. Return control to caller\n\nParameters:\n- pDecimalBuffer (Stack[0x4]): Pointer to ushort array containing parsed decimal data from ParseDecimalString. Array contains mantissa and exponent fields used for conversion.\n- pOutputValue (Stack[0x8]): Pointer to uint that receives the converted decimal value as 32-bit integer representation.\n\nReturns:\n- void: Conversion result stored in *pOutputValue via side effects of FUN_0383ff97.\n\nSpecial Cases:\n- This function serves as a simple wrapper/adapter between ParseDecimalString output format and final uint value format.\n- The configuration structure at 0x384e920 (24 bytes) contains precision parameters, exponent bounds, and output format flags used by FUN_0383ff97.\n- Always called immediately after ParseDecimalString in the parsing pipeline.\n- Assumes pDecimalBuffer contains valid parsed decimal structure with properly initialized fields.\n\nStructure Layout:\nConfiguration Parameter Block @ 0x384e920 (24 bytes):\n+0x00: uint [4 bytes] - Minimum exponent bound\n+0x04: uint [4 bytes] - Precision/mantissa information  \n+0x08: uint [4 bytes] - Maximum exponent bound\n+0x0C: uint [4 bytes] - Exponent offset/adjustment value\n+0x10: uint [4 bytes] - Output format flags (0x20=32-bit, 0x40=64-bit)\n+0x14: uint [4 bytes] - Additional control flags",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:09d6403e834e217532debf7a54bafa14",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "09d6403e834e217532debf7a54bafa14",
        "CFG": null,
        "PRO": "7eb86d6edc84dd81c49d4f208d19826f"
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
    "binkw32_ADDR_03840119": {
      "addresses": {
        "LoD/PD2": "0x03840119"
      },
      "rvas": {
        "LoD/PD2": "0x20119"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "ApplyDecimalComponents",
      "signature": "void ApplyDecimalComponents(ushort * pComponentBuffer, uint * pOutputMantissa)",
      "calling_convention": "__cdecl",
      "comment": "Applies parsed decimal components to construct floating-point output.\n\nThis is a wrapper function that applies previously parsed decimal number\ncomponents (mantissa, exponent, and sign information) to generate a floating-\npoint or extended-precision representation. It delegates the core conversion\nlogic to ApplyComponentsInternal with a reference to the conversion parameters\ntable (DAT_0384e938).\n\nAlgorithm:\n1. Push conversion parameters table address (DAT_0384e938) to stack\n2. Push component buffer pointer (pComponentBuffer) to stack\n3. Push output pointer (pOutputMantissa) to stack\n4. Call ApplyComponentsInternal to perform conversion\n5. Clean up 12 bytes from stack (3 parameters)\n6. Return to caller with result in EAX\n\nParameters:\npComponentBuffer (param_1): Pointer to component structure (12 bytes) containing:\n  - mantissa bits (uint at offset +0)\n  - exponent value (ushort at offset +4)\n  - sign/flags (ushort at offset +6)\npOutputMantissa (param_2): Pointer to output buffer (8 bytes) for result:\n  - low dword (offset +0): mantissa bits\n  - high dword (offset +4): exponent and sign\n\nReturns:\nEAX: Status code from ApplyComponentsInternal\n  - 0: Normal completion (zero or normal result)\n  - 1: Overflow occurred (result clamped to max value)\n  - 2: Invalid/subnormal input (result set to zero)\n\nSpecial Cases:\n- Zero exponent: Component buffer is treated as zero/denormal\n- Overflow: Overflow flag set, magnitude clamped to max representable value\n- Underflow: Result set to zero, no underflow flag generated\n- Parameters table at DAT_0384e938 contains precision/rounding config\n\nRelated Functions:\n- ParseDecimalString: Parses text into component buffer (called before this)\n- ApplyComponentsInternal (FUN_0383ff97): Performs actual component application\n- ParseAndApplyDecimalComponents: High-level wrapper for both functions",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:09d6403e834e217532debf7a54bafa14",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "09d6403e834e217532debf7a54bafa14",
        "CFG": null,
        "PRO": "8623e353967d1f4f4e6ab6f785ef086d"
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
    "binkw32_MNE_e78d3e11a492": {
      "addresses": {
        "LoD/PD2": "0x0384012F"
      },
      "rvas": {
        "LoD/PD2": "0x2012F"
      },
      "sizes": {
        "LoD/PD2": 45
      },
      "name": "ParseAndAssignDecimal",
      "signature": "void ParseAndAssignDecimal(void * this, uint * pOutValue, byte * pInputString)",
      "calling_convention": "__thiscall",
      "comment": "Parses a decimal string and assigns the result to an output value.\n\nAlgorithm:\n1. Initialize local buffer on stack (12 bytes allocated at [EBP-0xc])\n2. Call ParseDecimalString with:\n   - this pointer (object context)\n   - local parse buffer as output\n   - pInputString converted to ushort pointer for parsing\n   - pInputString value as int parameter\n   - NULL terminator indicator\n   - Additional flags (0,0,0) and stack marker\n3. Call FUN_03840103 to process parsed buffer and assign to pOutValue\n4. Return void\n\nParameters:\n- this (ECX): Object context pointer for __thiscall calling convention\n- pOutValue (Stack[0x4]): Pointer to uint that receives the parsed decimal value\n- pInputString (Stack[0x8]): Pointer to byte string containing decimal digits\n\nReturns:\n- void: Result stored in *pOutValue by FUN_03840103\n\nSpecial Cases:\n- Local buffer at [EBP-0xc] serves as intermediate parse result (12 bytes)\n- Assumes pInputString points to null-terminated ASCII decimal string\n- FUN_03840103 handles conversion from parse buffer to uint output",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e78d3e11a4929c0669f2164a27decb87",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e78d3e11a4929c0669f2164a27decb87",
        "CFG": null,
        "PRO": "0ba2b7323206503e54061e49d8c46fee"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e78d3e11a4929c0669f2164a27decb87"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_ADDR_0384015C": {
      "addresses": {
        "LoD/PD2": "0x0384015C"
      },
      "rvas": {
        "LoD/PD2": "0x2015C"
      },
      "sizes": {
        "LoD/PD2": 45
      },
      "name": "ParseAndApplyDecimalComponents",
      "signature": "void ParseAndApplyDecimalComponents(void * this, uint * pOutputMantissa, byte * pInputString)",
      "calling_convention": "__thiscall",
      "comment": "Parses decimal string and applies parsed components to output.\n\nHelper function in Visual Studio CRT that parses a decimal number string\n(e.g., \"3.14159\") into binary mantissa and exponent components, then applies\nthose components to construct a floating-point or extended-precision number\nrepresentation. Used by __fassign for float assignment operations.\n\nAlgorithm:\n1. Allocate 12 bytes on stack for temporary component structure\n2. Call ParseDecimalString to parse input string into mantissa/exponent\n3. Call FUN_03840119 to apply parsed components to output\n4. Return after stack cleanup\n\nParameters:\nthis (ECX): Instance pointer, context object for parsing\npOutputMantissa (param_1): Pointer to receive mantissa output value\npInputString (param_2): Pointer to input decimal number string\n\nReturns:\nvoid - Output stored via pOutputMantissa parameter\n\nSpecial Cases:\n- Stack-allocated component buffer (12 bytes) is temporary\n- Both ParseDecimalString and FUN_03840119 operate on same buffer\n- Component structure layout: offsets 0-10 for mantissa/exponent/flags",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e78d3e11a4929c0669f2164a27decb87",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e78d3e11a4929c0669f2164a27decb87",
        "CFG": null,
        "PRO": "0ba2b7323206503e54061e49d8c46fee"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "e78d3e11a4929c0669f2164a27decb87"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_70593f43ea0b": {
      "addresses": {
        "LoD/PD2": "0x03840190"
      },
      "rvas": {
        "LoD/PD2": "0x20190"
      },
      "sizes": {
        "LoD/PD2": 7
      },
      "name": "strcpy",
      "signature": "char * strcpy(char * pDestination, char * pSource)",
      "calling_convention": "__cdecl",
      "comment": "Copy source string to destination until null terminator\nThunk that delegates to CopyStringAligned\n\nAlgorithm:\n1. Pushes EDI to preserve register\n2. Loads destination address from stack\n3. Jumps to CopyStringAligned for actual copy operation\n\nParameters:\n- pDestination (char*): Pointer to destination buffer\n- pSource (char*): Pointer to source string to copy\n\nReturns:\n- char*: Pointer to destination buffer (same as input)\n\nSpecial Cases:\n- This is a wrapper function that delegates to CopyStringAligned\n- Preserves EDI register across the call",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:70593f43ea0b0d7692df2cd60ddf29e8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "70593f43ea0b0d7692df2cd60ddf29e8",
        "CFG": null,
        "PRO": "0893ef4135ff92704b4a57726c2e8b67"
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
    "binkw32_MNE_845fc5044ff1": {
      "addresses": {
        "LoD/PD2": "0x038401A0"
      },
      "rvas": {
        "LoD/PD2": "0x201A0"
      },
      "sizes": {
        "LoD/PD2": 224
      },
      "name": "CopyStringAligned",
      "signature": "char * CopyStringAligned(char * pDestination, char * pSource)",
      "calling_convention": "__cdecl",
      "comment": "Copies a null-terminated string from source to destination with DWORD-aligned optimization.\n\nAlgorithm:\n1. Align source pointer to DWORD boundary by processing bytes individually\n2. Use DWORD-level null-byte detection (0x7efefeff magic constant) for fast scanning\n3. Find the null terminator position\n4. Align destination pointer to DWORD boundary by processing bytes individually\n5. Copy DWORD blocks from aligned source using DWORD null-byte detection\n6. Handle remaining 1-3 bytes and null terminator\n7. Return original destination pointer\n\nParameters:\n- pDestination (char*): Output buffer where string will be copied\n- pSource (char*): Input null-terminated string to copy\n\nReturns:\n- Original pDestination pointer (enables chaining)\n\nSpecial Cases:\n- Handles unaligned source/destination pointers\n- Uses 0x7efefeff pattern for efficient null-byte detection in aligned reads\n- Copies up to 4 bytes at a time on aligned boundaries\n- Processes remaining bytes individually to avoid buffer overrun",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:845fc5044ff181fe96e2ae868d3aa1f6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "845fc5044ff181fe96e2ae868d3aa1f6",
        "CFG": "aeb55b4783665a2e303e9caef603a1f6",
        "PRO": "91a93f07a9ad6d3f1f33172e65653a41"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "845fc5044ff181fe96e2ae868d3aa1f6"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_91502dc0968a": {
      "addresses": {
        "LoD/PD2": "0x03840280"
      },
      "rvas": {
        "LoD/PD2": "0x20280"
      },
      "sizes": {
        "LoD/PD2": 119
      },
      "name": "IncrementDecimalString",
      "signature": "void IncrementDecimalString(char * pBuffer, int nMaxDigits, int * pContext)",
      "calling_convention": "__cdecl",
      "comment": "Increments a decimal string representation in a buffer with carry propagation.\\n\\nAlgorithm:\\n1. Initialize first character to '0' and set write pointer to buffer+1\\n2. If count > 0, copy characters from source buffer to output buffer, replacing nulls with '0'\\n3. Null-terminate the result string\\n4. If count > 0 and next source char is '5' or greater, increment the decimal value with carry\\n5. Handle carry propagation by decrementing position and incrementing digits from right to left\\n6. If result starts with '1', increment counter at context+4; otherwise call FUN_0383caa0 to format\\n\\nParameters:\\npBuffer (char*): Output buffer where incremented decimal string is written\\nnMaxDigits (int): Maximum number of digits to process from source\\npContext (int*): Context structure containing source buffer pointer at offset +0xc and counter at offset +4\\n\\nReturns:\\nvoid - Modifies output buffer and may update context counter\\n\\nSpecial Cases:\\n- Null bytes in source are replaced with '0' character\\n- Carry propagation handles incrementing '9' digits to '0' with carry to next position\\n- Magic value 0x30 ('0') used as replacement for null bytes in source\\n- Magic value 0x35 ('5') used as rounding threshold\\n- Magic value 0x39 ('9') used for carry detection during increment",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:91502dc0968a39359be974ca352b925c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "91502dc0968a39359be974ca352b925c",
        "CFG": "d07cb40aeb07237476d52676c927435a",
        "PRO": "c48e90df8b8c809a024c282082382895"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "91502dc0968a39359be974ca352b925c"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_5a025588439c": {
      "addresses": {
        "LoD/PD2": "0x038402F7"
      },
      "rvas": {
        "LoD/PD2": "0x202F7"
      },
      "sizes": {
        "LoD/PD2": 100
      },
      "name": "InitializeFloatFormatState",
      "signature": "int InitializeFloatFormatState(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize floating-point formatting state and cache converted values in global data structures.\n\nThis function converts a double-precision floating-point number from the calling convention stack parameter to custom extended precision format, formats it as a string with exponent and mantissa digits, and stores the results in global data for use by formatting functions like FUN_0383df5c.\n\nAlgorithm:\n1. Extract exponent field from calling convention parameter (bits 16-31 of stack param)\n2. Call ConvertDoubleToExtended to convert stack parameter to extended precision format\n3. Call FormatCustomFloatToString with converted mantissa/exponent and format parameters\n4. Sign-extend byte at DAT_0385ca5a and cache in DAT_0385ca78\n5. Sign-extend word at DAT_0385ca58 and cache in DAT_0385ca7c\n6. Store pointer to DAT_0385ca5c in DAT_0385ca84\n7. Return pointer to DAT_0385ca78 containing cached sign byte\n\nParameters:\nNone - Uses __stdcall calling convention with double on stack\n\nReturns:\nint - Pointer to global cache location DAT_0385ca78\n\nSpecial Cases:\nGlobal data at 0x385ca78/7c/80/84 acts as format cache to avoid redundant formatting\nZero mantissa and exponent handled as special case by FormatCustomFloatToString",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5a025588439cc101ffb982cfa5323a2c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5a025588439cc101ffb982cfa5323a2c",
        "CFG": "cf1ec2f32156f561350bce94c3a89bc2",
        "PRO": "0a08b3b35d1bd6969cd20f7147842fd9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5a025588439cc101ffb982cfa5323a2c"
      }
    },
    "binkw32_MNE_d7ddf3c1b7f3": {
      "addresses": {
        "LoD/PD2": "0x0384035B"
      },
      "rvas": {
        "LoD/PD2": "0x2035B"
      },
      "sizes": {
        "LoD/PD2": 182
      },
      "name": "ConvertDoubleToExtended",
      "signature": "void ConvertDoubleToExtended(void * pOutputExt, void * pInputDouble)",
      "calling_convention": "__cdecl",
      "comment": "Converts a 64-bit IEEE 754 double precision floating-point to extended precision format (80-bit x87 style).\n\nAlgorithm:\n1. Extract exponent (bits 52-62) from input double and right-shift by 4 positions\n2. Extract sign bit (bit 63) and mantissa bits (bits 0-51) from input double\n3. Check if exponent is zero (denormalized/zero input):\n   - If both exponent and mantissa are zero, output zero\n   - Otherwise set exponent to bias value 0x3c01 (adjusted for extended format)\n4. Check if exponent is 0x7ff (infinity or NaN):\n   - If so, set exponent to 0x7fff (extended precision infinity/NaN marker)\n5. For normal exponents, add bias offset 0x3c00 to convert from double bias (1023) to extended bias (16383)\n6. Assemble mantissa high from sign and exponent high bits\n7. Construct mantissa by shifting: (mantissaLow >> 21) | (mantissaHigh << 11)\n8. Normalize mantissa by left-shifting until bit 63 is set (implicit leading 1 bit)\n9. For each normalization shift, decrement exponent and continue until mantissa high bit is set\n10. Store final exponent with sign bit and computed mantissa into output structure\n\nParameters:\n  pOutputExt (void *): Pointer to output extended precision value (12 bytes total: low mantissa at +0, high mantissa at +4, exponent/sign at +8)\n  pInputDouble (void *): Pointer to input IEEE 754 double precision value (8 bytes total: mantissa at +0, exponent/sign at +4)\n\nReturns:\n  None (void function, result stored via pOutputExt pointer)\n\nSpecial Cases:\n  - Zero input (exponent=0, mantissa=0): Output all zeros\n  - Denormalized input (exponent=0, mantissa!=0): Uses exponent 0x3c01 (bias for subnormal)\n  - Infinity/NaN (exponent=0x7ff): Converts to extended format representation 0x7fff\n\nStructure Layout:\n  Input Double (8 bytes):\n    Offset  Size  Field        Type     Description\n    0       4     mantissa_lo  uint     Lower 32 bits of 52-bit mantissa\n    4       4     exp_sign     uint     Upper 20 mantissa bits (bits 0-19) and exponent (bits 20-30) and sign (bit 31)\n\n  Output Extended (12 bytes):\n    Offset  Size  Field        Type     Description\n    0       4     mantissa_lo  uint     Lower 32 bits of 64-bit implicit mantissa\n    4       4     mantissa_hi  uint     Upper 32 bits of 64-bit implicit mantissa\n    8       2     exponent     ushort   15-bit exponent (bits 0-14) and sign bit (bit 15)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d7ddf3c1b7f31503b888765ebbb66d57",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d7ddf3c1b7f31503b888765ebbb66d57",
        "CFG": "0a8625eed7b581f4049c6ac7cb8f285a",
        "PRO": "e7568cac4ee06fffdda0d126cce6927f"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d7ddf3c1b7f31503b888765ebbb66d57"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_b99d3962c0b2": {
      "addresses": {
        "LoD/PD2": "0x03840420"
      },
      "rvas": {
        "LoD/PD2": "0x20420"
      },
      "sizes": {
        "LoD/PD2": 88
      },
      "name": "_memset",
      "signature": "void * _memset(void * _Dst, int _Val, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memset\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b99d3962c0b26901db87269607fbf85a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b99d3962c0b26901db87269607fbf85a",
        "CFG": "5bee1cd61f1c7a0889c4c4c9d42b3ffe",
        "PRO": "e29656b1d5576c12f534a0f00ea1c858"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b99d3962c0b26901db87269607fbf85a"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_2e762c1c6c45": {
      "addresses": {
        "LoD/PD2": "0x03840480"
      },
      "rvas": {
        "LoD/PD2": "0x20480"
      },
      "sizes": {
        "LoD/PD2": 123
      },
      "name": "_strlen",
      "signature": "size_t _strlen(char * _Str)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strlen\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2e762c1c6c457f4a0349d0f895009434",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2e762c1c6c457f4a0349d0f895009434",
        "CFG": "e856537001a175bb721e73bd5fbf24f7",
        "PRO": "218e20f78ff67609d741b817a576974e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "2e762c1c6c457f4a0349d0f895009434"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_acbc2c857bf1": {
      "addresses": {
        "LoD/PD2": "0x03840504"
      },
      "rvas": {
        "LoD/PD2": "0x20504"
      },
      "sizes": {
        "LoD/PD2": 3
      },
      "name": "CheckEventStatus",
      "signature": "uint CheckEventStatus(void)",
      "calling_convention": "__stdcall",
      "comment": "Checks event status and returns current state.\n\nThis minimal function serves as an event status checker used during exception\nrecovery operations. Called from ProcessExceptionInfo to determine if exception\nhandling should proceed or terminate early.\n\nAlgorithm:\n1. Clear EAX register (XOR EAX, EAX)\n2. Return with 0 in EAX\n\nReturns:\n- uint: Always returns 0; used as event status check in conditional logic\n\nSpecial Cases:\n- Used in conjunction with global DAT_0384e950 flag for abort decision logic\n- Part of exception recovery flow; early exit when both conditions are met:\n  (exception type != 8) AND (DAT_0384e950 == 0) AND (CheckEventStatus() returns non-zero)",
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
    "binkw32_MNE_35a926809c02": {
      "addresses": {
        "LoD/PD2": "0x03840510"
      },
      "rvas": {
        "LoD/PD2": "0x20510"
      },
      "sizes": {
        "LoD/PD2": 279
      },
      "name": "DivideExtendedFloats",
      "signature": "ushort DivideExtendedFloats(int dividendLow, uint dividendMid, ushort dividendHigh, int divisorLow, uint divisorMid, ushort divisorHigh)",
      "calling_convention": "__cdecl",
      "comment": "Divides two 80-bit IEEE 754 extended-precision floating-point numbers.\\n\\nAlgorithm:\\n1. Load dividend and divisor from FPU stack/parameters\\n2. Check dividend exponent: if zero, return 0; if not denormalized, skip to division\\n3. Check divisor exponent: if zero, check dividend; if denormalized, apply scaling factor\\n4. Handle exponent arithmetic and biasing with carry propagation\\n5. If both are normal numbers, perform FPU division (FDIVP)\\n6. Handle special cases: infinity (0x7fff), denormalized (scale by 2^-16382), NaN detection\\n7. Return packed result: sign+exponent in AX, status codes for special values\\n\\nParameters:\\n- dividendLow (int): Low 32 bits of 80-bit dividend mantissa\\n- dividendMid (uint): Middle 32 bits of dividend mantissa\\n- dividendHigh (ushort): Sign bit (bit 15) and 15-bit exponent of dividend\\n- divisorLow (int): Low 32 bits of 80-bit divisor mantissa\\n- divisorMid (uint): Middle 32 bits of divisor mantissa\\n- divisorHigh (ushort): Sign bit (bit 15) and 15-bit exponent of divisor\\n\\nReturns:\\n- EAX (ushort): Packed result with sign/exponent in high bits; special values:\\n  - 0x0: If dividend and divisor are both zero\\n  - 0x7fff: Infinity (exponent overflow or explicit infinity operand)\\n  - Exponent value: Normal division result\\n  - Status code: Special handling indicators from table lookup\\n\\nSpecial Cases:\\n- Denormalized numbers (exponent=0): Scaled by 2^-16382 using multiplication constant\\n- Infinity (exponent=0x7fff): Returns 0x7fff unless other operand is zero\\n- Zero dividend: Returns 0 if divisor is nonzero\\n- Zero divisor with nonzero dividend: Returns infinity (0x7fff)\\n- NaN propagation: Result inherits NaN from operands via exponent checks\\n- FPU control word management: Modifies and restores rounding mode during computation\\n\\nIEEE 754 Extended Format:\\n- Bit 79: Sign bit (0=positive, 1=negative)\\n- Bits 78-64: 15-bit exponent (biased by 0x3fff)\\n- Bits 63-0: 64-bit mantissa (implicit leading 1 for normal, explicit 0 for denormal)\\n- Exponent 0x0000: Denormalized (mantissa interpreted as 0.f)\\n- Exponent 0x7fff: Infinity or NaN\\n- Exponent 0x1-0x7ffe: Normal numbers",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:35a926809c02214f1c021da8fe53c5e6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "35a926809c02214f1c021da8fe53c5e6",
        "CFG": "4046beb47bc7613c200bb164d32efb47",
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
    "binkw32_MNE_0e6c60682690": {
      "addresses": {
        "LoD/PD2": "0x03840AC6"
      },
      "rvas": {
        "LoD/PD2": "0x20AC6"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "DivideExtendedFloatsWrapper",
      "signature": "void DivideExtendedFloatsWrapper(void)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper function for extended floating-point division using x87 FPU stack.\n\nAlgorithm:\n1. Reserve 44 bytes of stack space for temporary storage (SUB ESP, 0x2c)\n2. Pop extended double from ST0 (divisor) and store at [ESP]\n3. Pop extended double from ST1 (dividend) and store at [ESP + 0xc]\n4. Call DivideExtendedFloats with extracted components from both operands\n5. Clean up stack and return (ADD ESP, 0x2c; RET)\n\nParameters:\n- fpuDivisor (ST0): Extended double value to divide by, passed on x87 FPU stack\n- fpuDividend (ST1): Extended double value to be divided, passed on x87 FPU stack\n\nReturns:\n- void: Result is left on x87 FPU stack (ST0)\n\nSpecial Cases:\n- Uses x87 FPU stack registers ST0 and ST1 for implicit parameters\n- Called by HandleFloatOperation during FPU error handling\n- Works with extended 80-bit floating-point precision\n- Stack space is used to extract extended double components for DivideExtendedFloats",
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
    "binkw32_ADDR_03840AD9": {
      "addresses": {
        "LoD/PD2": "0x03840AD9"
      },
      "rvas": {
        "LoD/PD2": "0x20AD9"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "DivideExtendedFloatsWrapper",
      "signature": "void DivideExtendedFloatsWrapper(void)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper for x87 FPU extended floating-point division operation.\n\nExtracts extended double operands from x87 FPU stack, stores them on the stack,\nand calls DivideExtendedFloats to perform the actual division. Result is returned\non the FPU stack.\n\nAlgorithm:\n1. Allocate 44 bytes (0x2c) of stack space for extended double storage\n2. Pop ST0 (divisor) from FPU stack and store at [ESP + 0x0]\n3. Pop ST1 (dividend) from FPU stack and store at [ESP + 0xc]\n4. Call DivideExtendedFloats with stack-based extended double operands\n5. Clean stack (deallocate 44 bytes) and return to caller\n\nParameters (Implicit):\n- ST0 (extendedDivisor): Extended 80-bit divisor value on x87 FPU stack\n- ST1 (extendedDividend): Extended 80-bit dividend value on x87 FPU stack\n\nReturns:\n- void: Division result left on x87 FPU stack at ST0\n\nSpecial Cases:\n- Uses __stdcall convention where callee cleans stack on return\n- Works exclusively with x87 FPU stack for parameter passing\n- Extended doubles are 10 bytes (80-bit format: 1 sign + 15 exp + 64 mantissa)\n- Called during FPU exception handling in HandleFloatOperation\n- Stack space allocated provides temporary storage for operand extraction\n\nStructure Layout (FPU Stack Extended Double):\nOffset | Size | Field       | Type    | Description\n-------|------|-------------|---------|---------------------------\n+0x0   | 10   | divisor     | ext80   | Divisor on FPU stack ST0\n+0xc   | 10   | dividend    | ext80   | Dividend on FPU stack ST1",
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
    "binkw32_MNE_fa9a30d8df14": {
      "addresses": {
        "LoD/PD2": "0x03840AEC"
      },
      "rvas": {
        "LoD/PD2": "0x20AEC"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "DivideFloatWithExceptionHandling",
      "signature": "float DivideFloatWithExceptionHandling(float floatValue)",
      "calling_convention": "__stdcall",
      "comment": "Divides a floating-point value while handling special cases for infinity and FPU exceptions.\n\nAlgorithm:\n1. Extract exponent bits from float parameter (0x7f800000 mask) to check for infinity\n2. If value is infinity (exponent == 0x7f800000), perform simple FDIV and return\n3. Check FPU status word exception flags (0x3800 mask) for invalid operation/domain errors\n4. If no exceptions, perform extended-precision division via DivideExtendedFloatsWrapper\n5. If exceptions detected, swap ST0/ST1, allocate 12 bytes stack space, save ST0 as extended-double\n6. Load original float value, call DivideExtendedFloatsWrapper, restore extended result to ST1\n7. Deallocate stack space and return result in EAX\n\nParameters:\n- floatValue (uint): Bit pattern of floating-point value to divide\n\nReturns:\n- eax_result (float): Result of division operation in EAX register\n\nSpecial Cases:\n- Infinity detection: Exponent field equals 0x7f800000 (11 bits all set)\n- FPU exceptions: Status word bits 11, 12, 13 indicate invalid operation or domain errors\n- Extended-precision fallback: Used when FPU exception flags are set\n- Stack frame: 12 bytes allocated for extended-double temporary during exception case\n\nStructure Access Patterns:\n- Float bit pattern extracted via AND with 0x7f800000 mask (exponent isolation)\n- FPU status word checked via AND with 0x3800 mask (exception flag bits 11-13)\n- Parameter accessed from [ESP + 0x8] (stack offset due to PUSH EAX at entry)\n- Extended double stored at [ESP] during exception handling path",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fa9a30d8df145c43da3992fb15aef931",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fa9a30d8df145c43da3992fb15aef931",
        "CFG": "9ee740eae2758b00f904633bf0c5e501",
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
    "binkw32_ADDR_03840B38": {
      "addresses": {
        "LoD/PD2": "0x03840B38"
      },
      "rvas": {
        "LoD/PD2": "0x20B38"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "HandleFloatOperation",
      "signature": "double HandleFloatOperation(double value, uint exponentBits)",
      "calling_convention": "__stdcall",
      "comment": "Handles special cases and FPU exception checking for floating-point division operations.\n\nAlgorithm:\n1. Check if exponentBits represents a special IEEE 754 value (NaN or Infinity) by testing if all exponent bits are set (0x7ff00000)\n2. If special value detected, perform direct division operation and return result immediately\n3. If normal value, check FPU status word (bits 11-13, mask 0x3800) for floating-point exceptions\n4. If FPU exception flags are set, call DivideExtendedFloatsWrapper() to handle exception case\n5. If no exceptions detected, also call DivideExtendedFloatsWrapper() for normal computation\n6. Return the computed extended-precision floating-point result as a double\n\nParameters:\n- value (double): The dividend value for the division operation\n- exponentBits (uint): The upper 32 bits of the double value containing IEEE 754 exponent and sign fields\n\nReturns:\n- double: The result of the floating-point division operation\n\nSpecial Cases:\n- When exponentBits & 0x7ff00000 == 0x7ff00000: Input is NaN or Infinity, performs direct hardware division\n- FPU status bits (0x3800) indicate: bit 11=invalid operation, bit 12=denormalized, bit 13=zero divide\n- Function works with both 64-bit doubles and 80-bit extended precision FPU format\n\nStructure Layout:\nIEEE 754 Double (64-bit):\nOffset  Size  Field Name    Type      Description\n0x0     4     sign_exp      uint      Sign (bit 31) + Exponent (bits 30-20)\n0x4     4     mantissa      uint      Mantissa high 32 bits\n0x8     8     full_value    double    Complete 64-bit IEEE 754 value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fa9a30d8df145c43da3992fb15aef931",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fa9a30d8df145c43da3992fb15aef931",
        "CFG": "19b5aac2d60824e43b0a3ed47c9722dc",
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
    "binkw32_MNE_269b7d5856cd": {
      "addresses": {
        "LoD/PD2": "0x03840BEC"
      },
      "rvas": {
        "LoD/PD2": "0x20BEC"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "HandleFloatDivisionWithExceptionCheck",
      "signature": "double HandleFloatDivisionWithExceptionCheck(float floatValue)",
      "calling_convention": "__stdcall",
      "comment": "Handles floating-point division with exception checking and extended-precision handling.\n\nAlgorithm:\n1. Extract and validate exponent bits (0x7f800000) from input float\n2. If exponent indicates special value (infinity/NaN), perform direct division\n3. Check FPU status word (0x3800) for pending exceptions\n4. If exception flag set, handle via extended-precision division routine\n5. If no exception, perform normal extended-precision division\n6. Return result as double-precision floating-point\n\nParameters:\n- floatValue: 32-bit IEEE 754 floating-point value\n\nReturns:\n- double: Result of floating-point division operation\n\nSpecial Cases:\n- Special values (infinity, NaN): Handled via direct division at offset 0x03840c30\n- FPU exception pending: Triggers exception-aware division path at 0x03840c06\n- Normal path: Standard extended-precision division at 0x03840c13\n- Magic number 0x7f800000: IEEE 754 exponent mask for single-precision\n- Magic number 0x3800: FPU status word exception flag bits (bits 11-13)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:269b7d5856cdb9005a57b4cc52158551",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "269b7d5856cdb9005a57b4cc52158551",
        "CFG": "92a4bfab0fc7a41edd95f045db6bec51",
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
    "binkw32_ADDR_03840C38": {
      "addresses": {
        "LoD/PD2": "0x03840C38"
      },
      "rvas": {
        "LoD/PD2": "0x20C38"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "CheckFloatingPointValue",
      "signature": "int CheckFloatingPointValue(int fpValue_Low, uint fpValue_High)",
      "calling_convention": "__stdcall",
      "comment": "Validates and processes floating-point values with special case handling\n\nAlgorithm:\n1. Extract high word (exponent/mantissa bits) from second parameter\n2. Check if value represents NaN or Infinity (exponent all 1s: 0x7ff00000 mask)\n3. If NaN/Infinity detected: FDIVR with value to raise exception, return\n4. Check FPU status word for pending exceptions (invalid op, denormalized, div-by-zero)\n5. If exceptions pending: Load value from stack, call handler, return\n6. If no exceptions: Perform FXCH, save extended value to temp, load param1, call handler, restore temp, return\n\nParameters:\n- fpValue_Low: Low 32-bits (mantissa) of IEEE 754 double-precision value\n- fpValue_High: High 32-bits (sign and exponent) of IEEE 754 double-precision value\n\nReturns:\n- Result in EAX (return value from handler or error code)\n\nSpecial Cases:\n- Exponent field 0x7ff00000 indicates NaN or Infinity\n- FPU exception bits (0x3800) check: invalid op (0x0001), denormalized (0x0200), div-by-zero (0x0400)\n- Uses __stdcall convention: callee cleans 8 bytes (two 32-bit params) from stack\n- Extended precision (10-byte) values used for intermediate calculation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:269b7d5856cdb9005a57b4cc52158551",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "269b7d5856cdb9005a57b4cc52158551",
        "CFG": "16f53664428f8c91348299558b4d8bd3",
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
    "binkw32_MNE_d9fc9881c66f": {
      "addresses": {
        "LoD/PD2": "0x03840D01"
      },
      "rvas": {
        "LoD/PD2": "0x20D01"
      },
      "sizes": {
        "LoD/PD2": 21
      },
      "name": "FloatUnpackWrapper",
      "signature": "uint FloatUnpackWrapper(void)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper function that unpacks two extended-precision floating-point values (ST0 and ST1) and passes them as unpacked components to FUN_03840510.\n\nAlgorithm:\n1. Receives two extended-precision float values in ST0 and ST1 FPU registers\n2. Allocates 0x2c bytes on stack for local variables\n3. Stores ST1 at [ESP + 0xc] and ST0 at [ESP]\n4. Unpacks both float values into 6 integer parameters (low, mid, high for each)\n5. Calls FUN_03840510 with unpacked components\n6. Returns the result from FUN_03840510 in EAX\n\nParameters:\n- ST1 (implicit): Extended-precision floating-point value (10 bytes)\n- ST0 (implicit): Extended-precision floating-point value (10 bytes)\n\nReturns:\n- EAX: Result from FUN_03840510 (status or computed value)\n\nSpecial Cases:\n- Function uses __stdcall convention; caller is responsible for cleaning stack after return\n- FPU registers are used for parameter passing (implicit parameters)\n- Extended-precision format: 1 sign bit + 15 exponent bits + 64 mantissa bits\n- Stack frame allocation of 0x2c (44 bytes) stores unpacked float components\n\nStructure Layout:\nOffset | Size | Field Name      | Type      | Description\n-------|------|-----------------|-----------|----------------------------------\n0x0    | 4    | unpacked_low0   | uint      | Low 32 bits of ST0 mantissa\n0x4    | 4    | unpacked_mid0   | uint      | Mid 32 bits of ST0 mantissa  \n0x8    | 2    | unpacked_high0  | ushort    | High 16 bits (exponent+sign) ST0\n0xa    | 4    | unpacked_low1   | uint      | Low 32 bits of ST1 mantissa\n0xe    | 4    | unpacked_mid1   | uint      | Mid 32 bits of ST1 mantissa\n0x12   | 2    | unpacked_high1  | ushort    | High 16 bits (exponent+sign) ST1",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d9fc9881c66fc4db9c90a259ff286a44",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d9fc9881c66fc4db9c90a259ff286a44",
        "CFG": "661de8ddac683e46dfc1f93e05a5a83e",
        "PRO": "4174b02bd8ca39f9fb30e0a24a42e84d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d9fc9881c66fc4db9c90a259ff286a44"
      }
    },
    "binkw32_MNE_c70484661a7b": {
      "addresses": {
        "LoD/PD2": "0x03840D16"
      },
      "rvas": {
        "LoD/PD2": "0x20D16"
      },
      "sizes": {
        "LoD/PD2": 518
      },
      "name": "ComputeFPRemainder",
      "signature": "double ComputeFPRemainder(double dividend, uint exponentBits, ushort signAndExponent)",
      "calling_convention": "__cdecl",
      "comment": "Computes IEEE 754 floating-point remainder using iterative subtraction.\n\nThis helper function implements IEEE 754 remainder semantics by:\n1. Validating both dividend and divisor are within normal exponent range\n2. Verifying special values (denormalized, infinity, NaN) are not present\n3. Performing iterative remainder calculation using either fast or slow algorithm\n4. Handling sign and exponent bits during remainder operations\n5. Applying IEEE 754 rounding modes and exception flags\n6. Restoring FPU control word before return\n\nAlgorithm:\n1. Validate dividend exponent (bits 16-30) is not all 0s or all 1s\n2. Validate divisor exponent (bits 16-30) is not all 0s or all 1s\n3. Check dividend and divisor mantissas are non-zero\n4. Select algorithm based on exponent difference:\n   - If (divisor_exp - dividend_exp) >= 64: fast path with single iteration\n   - If (divisor_exp - dividend_exp) >= 0: slow path with multiple iterations\n5. Execute iterative remainder: repeatedly subtract scaled divisor from remainder\n6. Apply sign correction based on original dividend sign bit\n7. Handle IEEE 754 floating-point exceptions via FPU control word\n\nParameters:\n  dividend: Extended precision dividend (80-bit on x87 FPU stack)\n  exponentBits: Combined exponent bits from divisor (upper 16 bits) and dividend (lower 16 bits)\n  signAndExponent: Sign and exponent of dividend (16-bit value on stack)\n\nReturns:\n  double: Computed IEEE 754 remainder as extended precision value on FPU stack\n\nSpecial Cases:\n  - If dividend or divisor exponent == 0x7FFF (infinity/NaN): uses fast path remainder\n  - If dividend or divisor is denormalized: uses fast path remainder\n  - Sign bit preserved from original dividend throughout computation\n  - Rounding mode controlled by FPU control word",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c70484661a7b6b9a5f1519c92e672da0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c70484661a7b6b9a5f1519c92e672da0",
        "CFG": "06d59bed9002b942f2e7dbe6cd8c0de6",
        "PRO": "a69a7d0355f70bc5a84a52904bc4615c"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "c70484661a7b6b9a5f1519c92e672da0"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_ba64e7d70c2b": {
      "addresses": {
        "LoD/PD2": "0x03840F1C"
      },
      "rvas": {
        "LoD/PD2": "0x20F1C"
      },
      "sizes": {
        "LoD/PD2": 178
      },
      "name": "FloatingPointRemainder",
      "signature": "float10 FloatingPointRemainder(float10 * __return_storage_ptr__, float10 dividend, float10 divisor)",
      "calling_convention": "__stdcall",
      "comment": "Computes floating-point remainder (modulo) of dividend by divisor using x87 FPU.\\n\\nAlgorithm:\\n1. Check if dividend is special case (denormalized or special value) via exponent test\\n2. If special, delegate to FUN_03840d16 helper function and return early\\n3. For normal values, check if divisor is zero\\n4. If divisor is zero, return dividend (NaN case)\\n5. For non-zero divisor with normal dividend, scale dividend by calibration factor\\n6. Set FPU to round-toward-zero mode via control word manipulation\\n7. If exponent exceeds threshold (0x7fbe), use alternative scaling path\\n8. Perform floating-point multiplication by scaling factor\\n9. Execute FPREM instruction to compute remainder in quotient bits\\n10. Restore original FPU control word and return result\\n\\nParameters:\\n  dividend (ST1): First operand, x87 extended-precision floating-point value\\n  divisor (ST0): Second operand, x87 extended-precision floating-point value\\n\\nReturns:\\n  ST0: The floating-point remainder of dividend modulo divisor\\n       Special cases: NaN if divisor is zero, delegates special handling to FUN_03840d16\\n\\nSpecial Cases:\\n  - Denormalized or special values (exponent test at 0x03840f2d) call FUN_03840d16\\n  - Zero divisor returns dividend unchanged (NaN case)\\n  - High exponent values (>=0x7fbe) use alternative scaling at 0x03840f99\\n  - FPU control word manipulated for rounding mode (FNSTCW/FLDCW pattern)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ba64e7d70c2bcd8b3838963a89363cf4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ba64e7d70c2bcd8b3838963a89363cf4",
        "CFG": "1d8e900f76ef1de91ec9c1d3963a2928",
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
    "binkw32_MNE_e28850ae7dbb": {
      "addresses": {
        "LoD/PD2": "0x03840FCE"
      },
      "rvas": {
        "LoD/PD2": "0x20FCE"
      },
      "sizes": {
        "LoD/PD2": 518
      },
      "name": "fmod_x87",
      "signature": "longdouble fmod_x87(longdouble x, longdouble y)",
      "calling_convention": "__cdecl",
      "comment": "IEEE 754 Extended Precision Floating-Point Modulo Function\n\nALGORITHM:\n1. Extract and validate exponent fields from IEEE 754 extended precision inputs\n2. Check for NaN, infinity, and zero special cases using exponent masks\n3. Verify y parameter is not zero or special value (NaN/infinity)\n4. Branch based on exponent difference: large (>=64) vs small (<64)\n5. For large exponent differences: iteratively scale and reduce using FMUL by 0.5\n6. For small exponent differences: implement Euclidean remainder using FPREM loop\n7. Apply IEEE 754 remainder correction using FPREM1 modulo \u03c0\n8. Conditionally adjust sign based on original sign bit and rounding mode flags\n\nPARAMETERS:\n- x: First extended precision float (passed via xLow, xHigh, xExponent)\n- y: Second extended precision float (passed on stack)\n\nRETURNS:\n- Extended precision result in ST(0) representing x mod y with IEEE 754 semantics\n\nSPECIAL CASES:\n- If x or y has exponent 0x7fff (infinity/NaN): early exit using FPREM1\n- If y has exponent 0 or sign bits set: validation fails, uses fast path\n- Exponent difference determines algorithm: large uses scaling, small uses iteration\n- Sign correction applied at end based on original x sign bit\n\nSTRUCTURE LAYOUT:\nStack layout during execution (ESP offsets):\n  +0x10: x extended precision value (10 bytes)\n  +0x18: x exponent/control value (4 bytes)\n  +0x1c: temporary/result storage (4 bytes)\n  +0x28: y extended precision value (10 bytes)\n  +0x30: y exponent/control value (4 bytes)\n  +0x34: FPU control word backup (2 bytes)\n  +0x38: FPU control word modified (4 bytes)\n  +0x3c: FPU status word (2 bytes)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e28850ae7dbb08bbb7fa3d1ca4ff2803",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e28850ae7dbb08bbb7fa3d1ca4ff2803",
        "CFG": "ec4f3bf43992ba671e1747e895d617e7",
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
    "binkw32_MNE_15fd41782864": {
      "addresses": {
        "LoD/PD2": "0x038411D4"
      },
      "rvas": {
        "LoD/PD2": "0x211D4"
      },
      "sizes": {
        "LoD/PD2": 181
      },
      "name": "fmod_x87",
      "signature": "float10 fmod_x87(float10 * __return_storage_ptr__)",
      "calling_convention": "__stdcall",
      "comment": "Calculates the floating-point remainder (modulo) of two X87 extended precision numbers.\n\nAlgorithm:\n1. Extract high DWORD of divisor from ST1 to determine if it is zero\n2. Check if divisor has zero bits in low position (special case handling)\n3. If divisor is nonzero, check if dividend is also nonzero\n4. If both dividend and divisor are zero, return zero via FPREM instruction\n5. If dividend is nonzero and divisor is nonzero, multiply dividend by constant at 0x0384e994 (approx 4096.0)\n6. Call helper function FUN_03840fce to perform modulo operation\n7. If exponent check at 0x3841235 fails (exponent >= 0x7fbe), use alternative truncate mode\n8. Restore FPU control word and return result in ST0\n\nParameters:\n  ST0: dividend (extended precision float) - the number to be divided\n  ST1: divisor (extended precision float) - the number to divide by\n\nReturns:\n  ST0: floating-point remainder of dividend modulo divisor\n  The result has the same sign as the dividend and magnitude less than divisor\n\nSpecial Cases:\n  - If divisor is zero, returns NaN or invalid result\n  - Uses FPREM instruction as fallback for zero dividend case\n  - Scaling by 4096 may be used for numerical stability in certain cases\n  - FPU control word is modified and restored during computation\n\nCalling Convention:\n  __stdcall: FPU stack parameters (ST0, ST1), callee cleans stack",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:15fd41782864ffd4b958e0ed4ed4dea9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "15fd41782864ffd4b958e0ed4ed4dea9",
        "CFG": "7e6a8c0afd1d5370cdabc91d81b24ded",
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
    "binkw32_MNE_fd9902cfddcc": {
      "addresses": {
        "LoD/PD2": "0x0384129B"
      },
      "rvas": {
        "LoD/PD2": "0x2129B"
      },
      "sizes": {
        "LoD/PD2": 208
      },
      "name": "ProcessExceptionInfo",
      "signature": "void ProcessExceptionInfo(uint exceptionType, int * pExceptionData, ushort * pExceptionCode)",
      "calling_convention": "__cdecl",
      "comment": "Processes exception/error information and performs recovery operations.\n\nAlgorithm:\n1. Dereference exception code from pointer parameter to get actual exception code value\n2. Load exception data type field from exception data structure (offset 0)\n3. Switch on exception data type to determine exception code mapping:\n   - Type 1 or 5: Set code to 0x08\n   - Type 2: Set code to 0x04\n   - Type 3: Set code to 0x11\n   - Type 4: Set code to 0x12\n   - Type 7: Set exception data type to 1 and skip to cleanup\n   - Type 8: Set code to 0x10\n   - Other types: Jump to cleanup\n4. Call FUN_0383e54c to validate exception code against exception data\n5. If validation fails (returns 0):\n   - Check if exception type is 0x10, 0x16, or 0x1d:\n     - If yes: Load field from offset +4 and set flags to (flags & 0xffffffe3) | 0x03\n     - If no: Clear LSB of flags (flags & 0xfffffffe)\n   - Call FUN_0383e299 to process exception information and buffer data\n6. Call FUN_0383e8fc to perform cleanup/finalization\n7. Check abort conditions:\n   - If exception data type != 8 AND global DAT_0384e950 == 0 AND FUN_03840504 returns non-zero, exit\n8. Call FUN_0383e763 with exception data type\n9. Return to caller\n\nParameters:\n- exceptionType (uint): Exception category or subtype for classification\n- pExceptionData (int*): Pointer to exception data structure containing type and additional fields\n- pExceptionCode (ushort*): Pointer to exception code value to be mapped\n\nReturns:\n- void: No return value; modifies exception data and flags in-place\n\nSpecial Cases:\n- Magic exception type 7 resets the exception data type field to 1\n- Exception types 0x10, 0x16, 0x1d receive special flag handling (bits 1-5 set to 0x03)\n- Early exit path triggered if both conditions met: non-type-8 AND event status check fails\n- Global abort check uses DAT_0384e950 flag to determine if error recovery should proceed",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fd9902cfddcce5a55494181fb300821e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fd9902cfddcce5a55494181fb300821e",
        "CFG": "ce7ec282051a6cfc0cdf10b84b9dd8ff",
        "PRO": "7807631519558ab1e5fb13b4cf30170a"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "fd9902cfddcce5a55494181fb300821e"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_051b6ba20f4f": {
      "addresses": {
        "LoD/PD2": "0x0384136B"
      },
      "rvas": {
        "LoD/PD2": "0x2136B"
      },
      "sizes": {
        "LoD/PD2": 146
      },
      "name": "ClassifyFloatingPointValue",
      "signature": "int ClassifyFloatingPointValue(double dValue)",
      "calling_convention": "__cdecl",
      "comment": "Classifies a floating-point value according to IEEE 754 special values.\\n\\nAlgorithm:\\n1. Extract exponent from high 16 bits (mask 0x7ff0)\\n2. If exponent is 0x7ff0 (NaN/Infinity), call FUN_0383e7c4 to determine type\\n3. If exponent is 0 (subnormal/zero), check mantissa bits and return sign-based mask\\n4. If value equals constant at 0x03847cf8, return sign-adjusted mask 0xe0 + 0x40\\n5. For normal values, return sign-adjusted mask 0x08 + 0x100\\n\\nParameters:\\n  dValue_Low: uint - Low 32 bits of 64-bit double (mantissa)\\n  dValue_High: uint - High 32 bits of 64-bit double (sign + exponent)\\n\\nReturns:\\n  int - Classification code: 0x01=NaN, 0x02=Inf, 0x04=SNaN, 0x80=Subnormal+/-,\\n        0x90=Subnormal, 0x40=Special constant, 0x100=Normal value, 0x200=Inf result\\n\\nSpecial Cases:\\n  - IEEE 754 NaN: exponent=0x7ff0, mantissa!=0\\n  - Infinity: exponent=0x7ff0, mantissa=0\\n  - Subnormal: exponent=0, mantissa!=0\\n  - Zero: exponent=0, mantissa=0\\n  - Sign bit (0x80000000) used for sign-dependent return values",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:051b6ba20f4f945c367717acc576ceaa",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "051b6ba20f4f945c367717acc576ceaa",
        "CFG": "7b5e3ff2355b8bffe8d8a28bc8d88d4d",
        "PRO": "56d8754a5951a0cf26ee8a3a85d871d7"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "051b6ba20f4f945c367717acc576ceaa"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_4a5a68bf4164": {
      "addresses": {
        "LoD/PD2": "0x038413FD"
      },
      "rvas": {
        "LoD/PD2": "0x213FD"
      },
      "sizes": {
        "LoD/PD2": 409
      },
      "name": "InitializeCodePageCharacterTables",
      "signature": "int InitializeCodePageCharacterTables(int localeFlag)",
      "calling_convention": "__cdecl",
      "comment": "Initializes character classification and case conversion tables for a specified code page.\n\nAlgorithm:\n1. Convert locale flag to code page ID using GetCodePageForLocaleFlag()\n2. Return early if code page matches cached value (optimization)\n3. Search predefined code page table for matching code page\n4. If found: Initialize character table from predefined range tables\n5. If not found: Call Windows GetCPInfo() to retrieve code page information\n6. Build character classification table marking lead bytes (0x4) and trail bytes (0x8)\n7. Initialize case conversion tables by calling InitializeCharacterCaseConversionTables()\n8. Cache code page ID and mark initialization as complete\n\nParameters:\nlocaleFlag: Locale identifier flag for determining target code page (e.g., LOCALE_USER_DEFAULT)\n\nReturns:\n0 on success, 0xFFFFFFFF on failure (game memory not initialized)\n\nSpecial Cases:\n- Code page 0 skips initialization and calls InitializeGameMemory()\n- Cached code pages return immediately without reinitialization\n- Unsupported code pages without GetCPInfo fall back to InitializeGameMemory()\n- MaxCharSize < 2 indicates single-byte character set\n- LeadByte array format: range pairs [start1, end1, start2, end2, ...] terminated by null\n\nStructure Layout:\nCharacter classification table at 0x385cbc0 (257 bytes):\nOffset  Size  Field Name      Type    Description\n0x0     1     reserved        byte    Unused entry (always 0)\n0x1-0x100 1   charClass[255]  byte    Classification bits for each character code\n                                      Bit 0x4 = Lead byte in multibyte sequence\n                                      Bit 0x8 = Trail byte (always set for SBCS)\n\nCode page table entry structure (12 bytes each):\nOffset  Size  Field Name      Type    Description\n0x0     4     codePageId      uint    Windows code page identifier\n0x4     4     charTablePtr    void*   Pointer to range table arrays\n0x8     4     caseTablePtr    void*   Pointer to case conversion data",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4a5a68bf41640182f32d03a3c91e5fdc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4a5a68bf41640182f32d03a3c91e5fdc",
        "CFG": "3629d20d4f6f5d9956e445b6752288cf",
        "PRO": "fccb21a6a871c7122e2713f7dcd5a6af"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "4a5a68bf41640182f32d03a3c91e5fdc"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_8f2a733057dd": {
      "addresses": {
        "LoD/PD2": "0x03841596"
      },
      "rvas": {
        "LoD/PD2": "0x21596"
      },
      "sizes": {
        "LoD/PD2": 74
      },
      "name": "GetCodePageForLocaleFlag",
      "signature": "uint GetCodePageForLocaleFlag(int localeFlag)",
      "calling_convention": "__cdecl",
      "comment": "Resolves code page from locale flag parameter values.\n\nTranslates special flag values to system code pages for locale operations.\nThe function supports three special flags:\n- LCMAP_OEMCP (-2): Returns OEM code page for console operations\n- LCMAP_ACP (-3): Returns ANSI/system code page for text operations\n- LCMAP_CACHED (-4): Returns cached/registered code page\n\nFor all other input values, the function returns the parameter unchanged,\ntreating it as a direct code page identifier.\n\nThe function also manages a global flag at 0x0385ca88 to track whether\nsystem code page initialization has been performed for the requested page.\n\nAlgorithm:\n1. Load locale flag parameter from stack\n2. Clear the global initialization flag at 0x0385ca88 (set to 0)\n3. Check if localeFlag == -2 (LCMAP_OEMCP):\n   - If true: Set flag to 1, call GetOEMCP(), return result\n4. Check if localeFlag == -3 (LCMAP_ACP):\n   - If true: Set flag to 1, call GetACP(), return result\n5. Check if localeFlag == -4 (LCMAP_CACHED):\n   - If true: Load cached code page from 0x0385c8e4, set flag to 1\n6. Return result in EAX (either API result or parameter value)\n\nParameters:\n  localeFlag (int): Locale flag or code page identifier\n    - LCMAP_OEMCP (-2): Request OEM code page\n    - LCMAP_ACP (-3): Request ANSI code page\n    - LCMAP_CACHED (-4): Request cached code page\n    - Other positive values: Direct code page identifier\n\nReturns:\n  Code page identifier (uint) for use in locale operations\n    - System code page (from GetOEMCP/GetACP) for flag values\n    - Cached code page for LCMAP_CACHED flag\n    - Unchanged parameter for non-flag values\n\nSpecial Cases:\n  Magic Values: -2, -3, -4 are locale flag constants\n  Global State: 0x0385ca88 initialization flag affects subsequent operations\n  Cached Page: 0x0385c8e4 stores previously registered code page",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8f2a733057dd5a290f0e17d077c53986",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8f2a733057dd5a290f0e17d077c53986",
        "CFG": "bec558cea24edd749490288e03df1fe4",
        "PRO": "935d56f816bfea96f64f6858b849d467"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "8f2a733057dd5a290f0e17d077c53986"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_f31c6439952c": {
      "addresses": {
        "LoD/PD2": "0x038415E0"
      },
      "rvas": {
        "LoD/PD2": "0x215E0"
      },
      "sizes": {
        "LoD/PD2": 51
      },
      "name": "MapCodePageToIdentifier",
      "signature": "int MapCodePageToIdentifier(int codePageValue)",
      "calling_convention": "__cdecl",
      "comment": "Map Windows code page identifiers to system-specific identifiers.\n\nAlgorithm:\n1. Load the code page value from the first parameter\n2. Compare against supported code page values (932, 936, 949, 950)\n3. Return corresponding system identifier for matched code page\n4. Return 0 for unknown or unsupported code pages\n\nParameters:\n- codePageValue (int): Windows code page identifier to map\n  * 0x3a4 (932): Japanese Shift-JIS\n  * 0x3a8 (936): Simplified Chinese GB2312\n  * 0x3b5 (949): Korean Unified Hangul\n  * 0x3b6 (950): Traditional Chinese Big5\n\nReturns:\n- 0x411 (1041): Japanese Shift-JIS system identifier\n- 0x804 (2052): Simplified Chinese GB2312 system identifier\n- 0x412 (1042): Korean Unified Hangul system identifier\n- 0x404 (1028): Traditional Chinese Big5 system identifier\n- 0: Unknown or unsupported code page\n\nSpecial Cases:\n- Only supports East Asian code pages (CJK)\n- Used by initialization routines to configure character encoding\n- Part of code page detection and configuration system\n- Magic values (0x3a4, 0x3a8, 0x3b5, 0x3b6) correspond to Windows LCID codes\n- Return values correspond to system locale identifiers",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f31c6439952ca9c3e10694cce3d833df",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f31c6439952ca9c3e10694cce3d833df",
        "CFG": "a69d19b675e647b533e35dc736d86ba6",
        "PRO": "252bd71e2f7f97e91ef40be3ccbd06e8"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "f31c6439952ca9c3e10694cce3d833df"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_05d3556ba26e": {
      "addresses": {
        "LoD/PD2": "0x03841613"
      },
      "rvas": {
        "LoD/PD2": "0x21613"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "InitializeGameMemory",
      "signature": "void InitializeGameMemory(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize global game memory by zeroing data structures.\\n\\nAlgorithm:\\n1. Clear 0x40 (64) DWORDs starting at address 0x385cbc0 using REP STOSD\\n2. Clear 1 additional byte at the end of the first region\\n3. Clear 3 specific game state memory locations (0x385caa4, 0x385cabc, 0x385ccc4)\\n4. Clear 3 DWORDs starting at address 0x385cab0\\n\\nReturns:\\nvoid - No return value. Sets global memory to initial state.\\n\\nSpecial Cases:\\n- Uses REP STOSD instruction for efficient bulk memory clearing\\n- The 0x40 (64) DWORD count suggests this region is 256 bytes (64 * 4)\\n- Final byte clear handles odd byte alignment after DWORD loop\\n- Multiple disjoint memory regions initialized suggests multiple independent data structures\\n\\nStructure Layout:\\nThe function initializes game state memory regions:\\n- Region 1: 0x385cbc0 - 0x385cbff (64 bytes clear + 1 byte) = ~257 bytes\\n- Region 2: 0x385cab0 - 0x385cbbc (12+ bytes cleared)\\n- State flags: 0x385caa4, 0x385cabc, 0x385ccc4 (individual locations)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:05d3556ba26e52c51954a1255d97c525",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "05d3556ba26e52c51954a1255d97c525",
        "CFG": null,
        "PRO": "9f808fc97e6513c540fcfdcca05bacf6"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "05d3556ba26e52c51954a1255d97c525"
      }
    },
    "binkw32_MNE_63906d1f35f7": {
      "addresses": {
        "LoD/PD2": "0x0384163C"
      },
      "rvas": {
        "LoD/PD2": "0x2163C"
      },
      "sizes": {
        "LoD/PD2": 389
      },
      "name": "InitializeCharacterCaseConversionTables",
      "signature": "void InitializeCharacterCaseConversionTables(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes character case conversion and character type lookup tables for the current code page.\n\nThis function establishes two key mappings: (1) uppercase-to-lowercase and lowercase-to-uppercase character conversion tables that support the current code page's character set, and (2) character type flags indicating whether each character is uppercase, lowercase, or other. It handles both code page-specific implementations via GetCPInfo() and fallback ASCII conversion for code pages without extended case mappings.\n\nAlgorithm:\n1. Call GetCPInfo to retrieve lead byte information for multibyte character support\n2. If GetCPInfo succeeds (Windows code page):\n   a) Initialize character array [0-255] with byte values [0-255]\n   b) Set index 0 to space (0x20) for special handling\n   c) Parse lead byte ranges from cpinfo structure (pairs of start-end values)\n   d) For each range, fill corresponding table entries with spaces (0x20) for lead bytes\n   e) Call GetStringTypeWithEncodingDetection to populate character type information\n   f) Call FUN_0383f973 twice to generate case conversion mappings (lowercase\u2192uppercase and uppercase\u2192lowercase)\n   g) Loop through 256 characters: for each character, check its type flags\n   h) If character is uppercase (flag 0x01), set conversion table byte 0x10 and store uppercase mapping\n   i) If character is lowercase (flag 0x02), set conversion table byte 0x20 and store lowercase mapping\n   j) If character is neither, clear conversion entry to 0\n3. If GetCPInfo fails (ASCII code page):\n   a) Loop through all 256 character positions\n   b) For uppercase ASCII letters (A-Z, codes 0x41-0x5A): store lowercase equivalent and set 0x10 flag\n   c) For lowercase ASCII letters (a-z, codes 0x61-0x7A): store uppercase equivalent and set 0x20 flag\n   d) For all other characters: clear conversion entry to 0\n\nParameters:\nNone. Function uses global variables:\n  - DAT_0385caa4: Current code page identifier\n  - DAT_0385ccc4: Locale identifier handle\n  - DAT_0385cac0: 256-byte case conversion table (output)\n  - DAT_0385cbc0: 256-byte character type flags (output)\n\nReturns:\nNone. Updates global character conversion and type tables.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:63906d1f35f7842042066a6643d2050c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "63906d1f35f7842042066a6643d2050c",
        "CFG": "5fe797495a41ff625bd07a8c3e071a53",
        "PRO": "9f903305dac24c951f3cebb45cf66933"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "63906d1f35f7842042066a6643d2050c"
      }
    },
    "binkw32_MNE_750c71b47c1a": {
      "addresses": {
        "LoD/PD2": "0x038417C1"
      },
      "rvas": {
        "LoD/PD2": "0x217C1"
      },
      "sizes": {
        "LoD/PD2": 28
      },
      "name": "InitializeGlobalOnce",
      "signature": "void InitializeGlobalOnce(void)",
      "calling_convention": "__stdcall",
      "comment": "Performs one-time initialization of global data structures using a guard flag.\n\nAlgorithm:\n1. Check if initialization flag (DAT_0385cde8) is already set to 1\n2. If not initialized (flag == 0), call FUN_038413fd with parameter -3\n3. Set initialization flag to 1 to prevent future initialization\n4. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Uses a global DWORD flag at 0x0385cde8 to ensure initialization runs exactly once\n- Calling convention is __stdcall (callee cleans stack)\n- Guard flag prevents re-initialization even if function is called multiple times\n\nStructure Layout:\nGlobal Flag at 0x0385cde8:\n  Offset  Size  Field Name     Type    Description\n  0       4     initialized    DWORD   Guard flag: 0=not initialized, 1=initialized",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:750c71b47c1aaa7e04385ca0c70f7831",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "750c71b47c1aaa7e04385ca0c70f7831",
        "CFG": "e67ee52de705150869e2ef2baa9939af",
        "PRO": "7609b42820c9bebb1ae281ab657ae348"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "750c71b47c1aaa7e04385ca0c70f7831"
      }
    },
    "binkw32_ADDR_038417E0": {
      "addresses": {
        "LoD/PD2": "0x038417E0"
      },
      "rvas": {
        "LoD/PD2": "0x217E0"
      },
      "sizes": {
        "LoD/PD2": 664
      },
      "name": "MemMove",
      "signature": "void * MemMove(void * pDest, void * pSrc, uint numBytes)",
      "calling_convention": "__cdecl",
      "comment": "Optimized memory mover that copies memory regions efficiently, handling overlapping regions with forward or backward copying to prevent data corruption.\n\nAlgorithm:\n1. Check if source and destination overlap: if (pSrc < pDest < pSrc+numBytes) then copy backward, else copy forward\n2. For backward copy: calculate end pointers, then copy from end to start using STD flag for descending order\n3. For forward copy: copy from start to end\n4. Check destination alignment: if ((pDest & 3) == 0) then use fast aligned DWORD copying, else use byte-by-byte alignment\n5. For aligned copy: divide numBytes by 4 to get DWORD count, remainder bytes handled separately\n6. Use REP MOVSD for bulk copying when dwordCount >= 8, unroll smaller copies\n7. Handle remainder bytes (1-3 bytes) with individual byte moves using jump table dispatch\n8. Return original pDest pointer\n\nParameters:\n- pDest: void* Destination buffer to receive copied data\n- pSrc: void* Source buffer containing data to copy\n- numBytes: uint Number of bytes to copy\n\nReturns:\n- void* Original pDest pointer (same as input)\n\nSpecial Cases:\n- Overlapping regions: when source overlaps destination, backward copy is used to prevent data loss\n- Alignment optimization: 4-byte aligned destinations use fast DWORD bulk copy with REP MOVSD\n- Unaligned destinations: handled by aligning to 4-byte boundary then bulk copying, with byte remainder handling\n- Small copies: less than 8 DWORDs use unrolled loops to avoid REP MOVSD overhead\n- Remainder bytes: 1-3 byte tails handled via jump table dispatch for efficiency\n\nStructure Layout:\nThis function operates on raw memory buffers without structured data access.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bff09423b51fd121ea30afec957819f4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bff09423b51fd121ea30afec957819f4",
        "CFG": "c161df564c60311b16227fed31b88e66",
        "PRO": "ff38c497c82643f818ac8c3950b7223d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bff09423b51fd121ea30afec957819f4"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_STR_1d436b74681e": {
      "addresses": {
        "LoD/PD2": "0x03841B15"
      },
      "rvas": {
        "LoD/PD2": "0x21B15"
      },
      "sizes": {
        "LoD/PD2": 137
      },
      "name": "DynamicMessageBoxA",
      "signature": "int DynamicMessageBoxA(HWND parentWindow, LPCSTR messageText, LPCSTR captionText, UINT uType)",
      "calling_convention": "__cdecl",
      "comment": "Dynamically loads and calls MessageBoxA through function pointers.",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:1d436b74681e11a9bd214b6331c37f94",
      "indexes": {
        "EXP": null,
        "STR": "1d436b74681e11a9bd214b6331c37f94",
        "API": null,
        "MNE": "d28466b802ff41201d4ac81308d22266",
        "CFG": "a667fa7e4ef51e6c972e43d39bb1aee4",
        "PRO": "30fa94c5195763c3c72f163e796620b9"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "d28466b802ff41201d4ac81308d22266"
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "binkw32_MNE_60fb4369558c": {
      "addresses": {
        "LoD/PD2": "0x03841BA0"
      },
      "rvas": {
        "LoD/PD2": "0x21BA0"
      },
      "sizes": {
        "LoD/PD2": 254
      },
      "name": "_strncpy",
      "signature": "char * _strncpy(char * _Dest, char * _Source, size_t _Count)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strncpy\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:60fb4369558c571ee3e9892006835a82",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "60fb4369558c571ee3e9892006835a82",
        "CFG": "718f85c40159f96fda1115fa8c7ee616",
        "PRO": "5dfddeed7b00a61835a5cf192d4d7c3e"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "60fb4369558c571ee3e9892006835a82"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_a7046d73bbd2": {
      "addresses": {
        "LoD/PD2": "0x03841C9E"
      },
      "rvas": {
        "LoD/PD2": "0x21C9E"
      },
      "sizes": {
        "LoD/PD2": 318
      },
      "name": "GetStringTypeWithEncodingDetection",
      "signature": "BOOL GetStringTypeWithEncodingDetection(DWORD dwInfoType, LPCSTR lpSrcStr, int cchSrc, LPWORD lpCharType, UINT CodePage, LCID Locale, int dwFlags)",
      "calling_convention": "__cdecl",
      "comment": "Wrapper for GetStringTypeA/GetStringTypeW with automatic encoding detection and conversion.\\\"",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a7046d73bbd286a50d5e7204509858d2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a7046d73bbd286a50d5e7204509858d2",
        "CFG": "bd1baf3c10f4c38ee5897833f12342fb",
        "PRO": "9c5def42369082df4fbc7ae0b1af7e49"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "a7046d73bbd286a50d5e7204509858d2"
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "binkw32_MNE_bff073652f00": {
      "addresses": {
        "LoD/PD2": "0x03841DE7"
      },
      "rvas": {
        "LoD/PD2": "0x21DE7"
      },
      "sizes": {
        "LoD/PD2": 33
      },
      "name": "CheckAdditionOverflow",
      "signature": "uint CheckAdditionOverflow(uint operandA, uint operandB, uint * pResult)",
      "calling_convention": "__cdecl",
      "comment": "Detects overflow in unsigned 32-bit addition.\nAdds two unsigned integers and returns 1 if the result overflows, 0 otherwise.\n\nAlgorithm:\n1. Calculate sum of operandA + operandB\n2. Check overflow condition: if sum < operandA OR sum < operandB, overflow occurred\n3. Store result sum at *pResult\n4. Return 1 if overflow detected, 0 if no overflow\n\nParameters:\n  operandA (uint): First addend\n  operandB (uint): Second addend\n  pResult (uint*): Pointer to store the sum result\n\nReturns:\n  1 if unsigned overflow occurred during addition\n  0 if addition completed without overflow\n\nSpecial Cases:\n  - Result stored even if overflow occurs; caller must check return value\n  - Overflow detection uses commutativity: sum < A OR sum < B is equivalent to (A+B) > 2^32-1\n  - Magic constant: 1 indicates overflow flag (boolean-like return)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bff073652f00cbfc0b0f227bb7a313e1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bff073652f00cbfc0b0f227bb7a313e1",
        "CFG": "b60f21f7bfb012dbc03ce5de63df71ff",
        "PRO": "80902d476b18e9c5470aec96bcc26d6d"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "bff073652f00cbfc0b0f227bb7a313e1"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_8d620fa28637": {
      "addresses": {
        "LoD/PD2": "0x03841E08"
      },
      "rvas": {
        "LoD/PD2": "0x21E08"
      },
      "sizes": {
        "LoD/PD2": 94
      },
      "name": "___add_12",
      "signature": "undefined ___add_12(uint * param_1, uint * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___add_12\n\nLibrary: Visual Studio 2003 Release",
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
    "binkw32_MNE_58ce78ec7b76": {
      "addresses": {
        "LoD/PD2": "0x03841E66"
      },
      "rvas": {
        "LoD/PD2": "0x21E66"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "LeftShiftLarge96Bit",
      "signature": "void LeftShiftLarge96Bit(uint * pValue)",
      "calling_convention": "__cdecl",
      "comment": "Left shifts a 96-bit value stored in three consecutive DWORDs by 1 bit.\n\nAlgorithm:\n1. Load three 32-bit words from pValue array (low, mid, high dwords)\n2. Left shift low word by 1 bit, store result back to offset +0\n3. Left shift mid word by 1 bit and OR with carry from low word (bit 31), store to offset +4\n4. Left shift high word by 1 bit and OR with carry from mid word (bit 31), store to offset +8\n5. Return with all carries propagated through the 96-bit value\n\nParameters:\npValue: Pointer to array of 3 DWORDs representing a 96-bit value in little-endian order\n  [0] = bits 0-31 (low dword)\n  [4] = bits 32-63 (mid dword)  \n  [8] = bits 64-95 (high dword)\n\nReturns:\nvoid - modifies array in-place\n\nSpecial Cases:\n- The 96-bit value is shifted left by exactly 1 bit position\n- Bit 31 of each word becomes the carry-in for the next higher word\n- Bit 0 of the low word is filled with 0\n- The most significant bit (bit 95) is shifted out and lost\n- Used for custom floating-point mantissa operations with extended precision\n\nStructure Layout:\nOffset  Size  Field Name    Type   Description\n------  ----  ----------    ----   -----------\n+0      4     lowDword      uint   Bits 0-31 of 96-bit value\n+4      4     midDword      uint   Bits 32-63 of 96-bit value\n+8      4     highDword     uint   Bits 64-95 of 96-bit value\nTotal: 12 bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:58ce78ec7b76961d09886d9a93b93cae",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "58ce78ec7b76961d09886d9a93b93cae",
        "CFG": "42bdec2f11c73aa6056b6c694ab2bc19",
        "PRO": "b6a962e4ef395dd7722b24cf1670d2f3"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "58ce78ec7b76961d09886d9a93b93cae"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_31be27c1480e": {
      "addresses": {
        "LoD/PD2": "0x03841E94"
      },
      "rvas": {
        "LoD/PD2": "0x21E94"
      },
      "sizes": {
        "LoD/PD2": 45
      },
      "name": "RotateMantissaRight",
      "signature": "void RotateMantissaRight(uint * pMantissa)",
      "calling_convention": "__cdecl",
      "comment": "Rotate a 96-bit mantissa right by 1 bit\n\nThis function performs a right rotate operation on a 96-bit floating-point mantissa\nstored as three consecutive 32-bit words (at offsets +0x0, +0x4, +0x8). The rotation\npreserves the bit pattern by cycling the least significant bit from the bottom word\nback to the most significant bit of the top word.\n\nAlgorithm:\n1. Extract the low 32-bit word (offset +0x4) and save its LSB\n2. Rotate word at +0x4 right by 1: (word >> 1) | (word at +0x8 << 31)\n3. Rotate word at +0x8 right by 1: (word at +0x8 >> 1)\n4. Rotate word at +0x0 right by 1: (word >> 1) | (saved LSB << 31)\n\nParameters:\n  pMantissa: Pointer to 96-bit mantissa structure (3 x 32-bit words)\n    Offset +0x0: Low 32 bits of mantissa\n    Offset +0x4: Middle 32 bits of mantissa\n    Offset +0x8: High 32 bits of mantissa\n\nReturns:\n  void (modifies mantissa in-place)\n\nSpecial Cases:\n  All-zero mantissa rotates to all-zero (no change)\n  Pattern: Each bit shifts right one position; LSB wraps to MSB of upper word\n\nUsage Context:\n  Called by FormatCustomFloatToString during decimal digit generation\n  Called by MultiplyCustomFloatNumbers for exponent normalization shifts\n  Used in custom floating-point arithmetic with 96-bit precision mantissas",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:31be27c1480e9c363bab7437010362e2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "31be27c1480e9c363bab7437010362e2",
        "CFG": null,
        "PRO": "b94ad2a12c7a850745434420db9ece86"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "31be27c1480e9c363bab7437010362e2"
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "binkw32_MNE_b41de5b81e6f": {
      "addresses": {
        "LoD/PD2": "0x03841EC1"
      },
      "rvas": {
        "LoD/PD2": "0x21EC1"
      },
      "sizes": {
        "LoD/PD2": 199
      },
      "name": "ConvertMantissa",
      "signature": "void ConvertMantissa(char * digitBuffer, int digitCountSmall, uint * pMantissaComponents)",
      "calling_convention": "__cdecl",
      "comment": "Convert decimal digit buffer into binary mantissa and exponent representation.\n\nTransforms a sequence of decimal digits (0-9) stored in a buffer into a \nnormalized binary mantissa value with accompanying exponent adjustment. Supports \nup to 24 digits of precision and performs iterative shifting to achieve \nnormalization with the high bit set in the mantissa.\n\nAlgorithm:\n1. Initialize output mantissa array to zero (3 dwords)\n2. Set exponent adjustment to 0x404e (16718 decimal)\n3. If digit count is zero, skip to normalization phase\n4. For each digit in buffer:\n   a. Load current mantissa components (3 dwords)\n   b. Call FUN_03841e66 twice to shift mantissa left by 2 bits\n   c. Call ___add_12 with saved components to apply multiplication factor\n   d. Call FUN_03841e66 to shift mantissa left by another 2 bits\n   e. Clear intermediate storage values\n   f. Load next digit character as byte, convert to value\n   g. Call ___add_12 to add digit to accumulated mantissa\n   h. Advance digit buffer pointer and decrement digit count\n5. Normalize mantissa: while high word (offset +8) is zero:\n   a. Extract high 16 bits of word at offset +4 to word at offset +8\n   b. Subtract 0x1000 from exponent (equivalent to -4096 in two's complement as 0xfff0)\n   c. Rotate word at offset +4: shift left 16, OR with high word of offset +0\n   d. Shift word at offset +0 left 16 bits\n6. Normalize high bit: while bit 15 of word at offset +8 is clear:\n   a. Call FUN_03841e66 to shift mantissa left by 2 bits\n   b. Add 0xffff to exponent (equivalent to -1)\n7. Store final exponent value as word at offset +10\n\nParameters:\ndigitBuffer (param_1): Pointer to buffer containing ASCII digit characters ('0'-'9')\ndigitCountSmall (param_2): Number of digits to process from buffer (0-24)\npMantissaComponents (param_3): Pointer to output array of 3 dwords:\n  - Offset +0: Mantissa low word (bits 0-31)\n  - Offset +4: Mantissa mid word (bits 32-63)\n  - Offset +8: Mantissa high word (bits 64-95, contains high bits after normalization)\n  - Offset +10: Exponent adjustment value (written as signed word)\n\nReturns:\nvoid - Returns mantissa in pMantissaComponents[0-2] and exponent in pMantissaComponents[5] as word\n\nSpecial Cases:\n- Magic number 0x404e (16718): Initial exponent bias for normalization\n- Magic number 0xfff0 (-16, sign-extended): Exponent decrement per 4-bit shift in normalization\n- Magic number 0xffff (-1, sign-extended): Exponent decrement per 2-bit shift in high-bit normalization\n- Bit 15 (0x8000): High bit check for mantissa normalization\n- Maximum 24 digits supported; behavior undefined for digit counts > 24\n- Assumes ASCII digit encoding (0x30-0x39 for '0'-'9')\n- Mantissa components use 32-bit arithmetic with carries managed by called functions\n\nStructure Layout (Mantissa Components):\nOffset  Size  Field Name         Type    Description\n------  ----  ---------------    ------  -----------\n+0      4     mantissaLow        uint    Bits 0-31 of mantissa\n+4      4     mantissaMid        uint    Bits 32-63 of mantissa  \n+8      4     mantissaHigh       uint    Bits 64-95 (high bits for normalization)\n+10     2     exponentAdjust     word    Signed exponent adjustment after normalization\n+12     -     (padding)          -       (3 unused bytes to align next field)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b41de5b81e6f5c290111b6d697b33467",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b41de5b81e6f5c290111b6d697b33467",
        "CFG": "b29a4a023562483ad0c5eb096d7fb0dd",
        "PRO": "85fb6b8719deac8650a5d5c59f6456a5"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "b41de5b81e6f5c290111b6d697b33467"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_ab787578be0f": {
      "addresses": {
        "LoD/PD2": "0x03841F88"
      },
      "rvas": {
        "LoD/PD2": "0x21F88"
      },
      "sizes": {
        "LoD/PD2": 1185
      },
      "name": "ParseDecimalString",
      "signature": "uint ParseDecimalString(void * this, void * pThis, ushort * pOutputComponents, int * pEndPos, byte * pInputString, int precision, int minExponent, int maxExponent, int allowExponent)",
      "calling_convention": "__thiscall",
      "comment": "Parse decimal string into mantissa and exponent components.\\n\\nParses a formatted decimal number string (e.g., \\\"1.23E+4\\\") into binary\\ncomponents suitable for constructing floating-point or extended-precision\\nrepresentations. Handles optional whitespace, sign characters, decimal points,\\nand exponent notation. Returns status codes indicating overflow/underflow\\nconditions and stores parsed mantissa and exponent values in output structure.\\n\\nAlgorithm:\\n1. Skip leading whitespace (space, tab, newline, carriage return)\\n2. Parse optional sign prefix (+ or -)\\n3. Scan mantissa: integer digits, optional decimal point, fractional digits\\n4. Process decimal point and decimal exponent indicators (D or E)\\n5. Parse optional signed exponent value with bounds checking\\n6. Convert digit sequence to packed representation using ConvertMantissa\\n7. Apply exponent adjustment using ApplyExponentToMantissa\\n8. Check for overflow (>5328) and underflow (<-5328) conditions\\n9. Store final mantissa and flags to output structure\\n\\nParameters:\\npThis (ECX): Instance pointer for potential member data access\\npOutputComponents (param_1): Output structure receiving parsed components\\n  - Offset +0: Mantissa low word (digits 0-4)\\n  - Offset +2: Mantissa high word (digits 5-9) \\n  - Offset +6: Mantissa flag word (includes sign in 0x8000 bit)\\n  - Offset +10: Status code (0=valid, 1=underflow, 2=overflow, 4=no input)\\npEndPos (param_2): Pointer to store final input position after parsing\\npInputString (param_3): Pointer to start of input string\\nprecision (param_4): Requested precision (bits) for mantissa conversion\\nminExponent (param_5): Minimum allowed exponent before underflow\\nmaxExponent (param_6): Maximum allowed exponent before overflow  \\nallowExponent (param_7): Non-zero to allow E/D exponent notation\\n\\nReturns:\\nStatus code stored in local_18 and returned via EAX:\\n0 = Successfully parsed valid number\\n1 = Exponent underflow detected (exponent < minExponent)\\n2 = Exponent overflow detected (exponent > maxExponent)\\n4 = No valid digits found in input\\n\\nSpecial Cases:\\n- Magic number 0x1450 (5328 decimal): Exponent overflow boundary\\n- Magic number 0x19 (25 decimal): Maximum digits before overflow to large counter\\n- Whitespace skip includes space(0x20), tab(0x09), LF(0x0A), CR(0x0D)\\n- States 0-11: Parser states for different input contexts\\n- Exponent range clamping at 0x1451 (5329) for overflow\\n- Leading zeros are counted separately before decimal point",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ab787578be0f52440df577da55f0ef97",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ab787578be0f52440df577da55f0ef97",
        "CFG": "3de5e9c1cf4a6912df37112a9ddffafb",
        "PRO": "fd4734235db9a43145b5c1c355253f58"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "ab787578be0f52440df577da55f0ef97"
      },
      "param_counts": {
        "LoD/PD2": 9
      }
    },
    "binkw32_STR_caf0293062c4": {
      "addresses": {
        "LoD/PD2": "0x03842459"
      },
      "rvas": {
        "LoD/PD2": "0x22459"
      },
      "sizes": {
        "LoD/PD2": 659
      },
      "name": "FormatCustomFloatToString",
      "signature": "int FormatCustomFloatToString(uint mantissaLow, uint mantissaHigh, uint exponentField, int precision, byte formatFlags, char * pResultBuffer)",
      "calling_convention": "__cdecl",
      "comment": "Converts a custom floating-point number to ASCII string representation.\n\nImplements decimal digit generation for extended precision numbers, handling special\ncases (infinity, NaN) and performing precision-based rounding. The custom float format\nuses a 15-bit exponent field (bits 15-31 of param_3), sign bit (bit 15 of param_3),\nand 64-bit mantissa (param_1 as low 32 bits, param_2 as high 32 bits).\n\nAlgorithm:\n1. Initialize output buffer with sign character (0x20='+', 0x2D='-' based on sign bit)\n2. Check for zero mantissa and exponent; if both zero, format as \"0\" and return\n3. For exponent 0x7FFF (special values): detect infinity/NaN cases and copy appropriate string\n4. Extract exponent value from bits 8-14 of param_3 (15-bit exponent field)\n5. Calculate adjusted exponent from mantissa bit position and precision parameter\n6. Normalize mantissa by shifting: right shift 8 bits for bit position 0x3ffe\n7. Apply precision clipping: limit output digits to range [-0x15, 0x15]\n8. Generate decimal digits by iteratively multiplying by 10 and extracting digit\n9. Perform rounding based on last generated digit (round up if > '4')\n10. Handle rounding propagation through digit string, incrementing exponent if needed\n11. Construct final formatted string with exponent and mantissa digits\n12. Set precision length field in output buffer and null-terminate result\n\nParameters:\n  mantissaLow: Low 32 bits of 64-bit mantissa\n  mantissaHigh: High 32 bits of 64-bit mantissa\n  exponentField: Exponent (bits 15-31) and sign flag (bit 15); bits 0-14 are mantissa bits\n  precision: Base precision value for digit generation count\n  formatFlags: Bit 0 set: add mantissa to precision; clear: use precision directly\n  pResultBuffer: Pointer to output string buffer (minimum 18 bytes for \"0.XXXXXXXXXXXE+XXX\")\n\nReturns:\n  1 on success\n  0 if exponent field indicates special value (infinity/NaN)\n\nSpecial Cases:\n  - Exponent 0x7FFF with zero mantissa: infinity (uses \"1.INF\" or \"-1.IND\")\n  - Exponent 0x7FFF with mantissa bit 30 set: quiet NaN (uses \"1.QNAN\")\n  - Exponent 0x7FFF with other mantissa bits: signaling NaN (uses \"1.SNAN\")\n  - Zero mantissa and exponent: formats as \"0\" with single digit\n  - Rounding propagation: may increment exponent if all digits round to 9\n\nStructure Layout (output buffer):\n  Offset  Size  Field         Type    Description\n  0       2     exponent      short   Adjusted exponent value for mantissa\n  1       1     sign          byte    Sign character (0x20=+, 0x2D=-)\n  2..n    1     digits[n]     char    Decimal digits (ASCII '0'-'9')\n  n+1     1     length        byte    Number of significant digits\n  n+2     1     precision     byte    Mantissa precision field\n  n+3     1     null_term     byte    Null terminator (0x00)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:caf0293062c4e4caabf207f9f9a0ab4c",
      "indexes": {
        "EXP": null,
        "STR": "caf0293062c4e4caabf207f9f9a0ab4c",
        "API": null,
        "MNE": "26994a8b2417d3844158a85646dcdf3d",
        "CFG": "742f28ffe8e24534d1d3322e4ed545cf",
        "PRO": "b0d95e97f9d77fff349e76b44758be34"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "26994a8b2417d3844158a85646dcdf3d"
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "binkw32_MNE_9164e0864235": {
      "addresses": {
        "LoD/PD2": "0x038426EC"
      },
      "rvas": {
        "LoD/PD2": "0x226EC"
      },
      "sizes": {
        "LoD/PD2": 544
      },
      "name": "MultiplyCustomFloatNumbers",
      "signature": "void MultiplyCustomFloatNumbers(int * pFirstNumber, int * pSecondNumber)",
      "calling_convention": "__cdecl",
      "comment": "Multiplies two numbers in custom floating-point format (exponent + mantissa).\n\nAlgorithm:\n1. Extract exponents and sign bits from both input numbers\n2. Validate that exponents are in valid range (< 0x7fff each)\n3. Calculate combined exponent sum and verify against overflow limit (0xbffe) and underflow limit (0x3fc0)\n4. Perform 5x5 digit multiplication of mantissas using convolution with helper FUN_03841de7\n5. Normalize result by adjusting exponent based on accumulation carries using bit shifts\n6. Apply left-shift operations for positive exponent adjustments (via FUN_03841e66)\n7. Apply right-shift operations for negative exponent adjustments (via FUN_03841e94)\n8. Check for rounding conditions when result bits overflow (0x18000)\n9. Handle increment/decrement of result fields based on rounding\n10. Combine result fields and apply sign bit, then store to output\n11. On error: set output to overflow marker (0x7fff8000) with appropriate sign bit\n\nParameters:\npFirstNumber: First custom floating-point number [exponent at +0xa, mantissa fields at +0x0,+0x4,+0x8]\npSecondNumber: Second custom floating-point number [exponent at +0xa, mantissa fields at +0x0,+0x4,+0x8]\n\nReturns:\nvoid (stores result directly into pFirstNumber)\n\nSpecial Cases:\n- Underflow condition (combined exponent < 0x3fc0): result set to zero\n- Overflow condition (combined exponent > 0xbffe): result set to special overflow marker 0x7fff8000\n- Zero operand handling: either input being zero results in zero output\n- Sign bit is preserved from XOR of input signs\n- Rounding occurs when accumulated mantissa bits exceed 0x18000\n- Exponent adjustment via addition of 0xc002 (equivalent to -0x3ffe offset)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9164e08642353fc9b6a5a942bb4e12cf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9164e08642353fc9b6a5a942bb4e12cf",
        "CFG": "c6de2c84cf9c53ce02390cbcc001c60c",
        "PRO": "52465f99954b9b1250f9c31f27370e89"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "9164e08642353fc9b6a5a942bb4e12cf"
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "binkw32_MNE_5da54fa8fcd8": {
      "addresses": {
        "LoD/PD2": "0x0384290C"
      },
      "rvas": {
        "LoD/PD2": "0x2290C"
      },
      "sizes": {
        "LoD/PD2": 124
      },
      "name": "ApplyExponentToMantissa",
      "signature": "void ApplyExponentToMantissa(int * pMantissaDigits, uint exponent, int shouldRound)",
      "calling_convention": "__cdecl",
      "comment": "Applies an exponent to a mantissa digit array by shifting digits and scaling.\n\nAlgorithm:\n1. Check if exponent is zero - if so, return immediately\n2. Handle negative exponent by negating and using alternative digit table\n3. Initialize digit table pointer based on exponent sign\n4. Main loop: for each bit in exponent (8 bits at a time)\n   a. Advance to next segment in digit table (offset +0x54)\n   b. Extract 3-bit digit group from exponent\n   c. If digit group non-zero: locate digit entry in table\n   d. Check if mantissa is non-zero (0x7fff threshold)\n   e. If mantissa exists: copy digit word to local storage\n   f. Call FUN_038426ec to apply digit scaling to mantissa\n5. Continue until exponent fully processed\n\nParameters:\npMantissaDigits - Pointer to mantissa digit array (int pointer)\nexponent - Exponent value to apply (unsigned, processed in 3-bit groups)\nshouldRound - Rounding flag (1=round, 0=truncate)\n\nReturns:\nvoid - Modifies mantissa array in-place\n\nSpecial Cases:\n- Zero exponent: returns immediately without modification\n- Negative exponent: uses alternative digit table (0x384ed48)\n- Mantissa zero check: 0x7fff is threshold for non-zero mantissa\n- Digital scaling: Each 3-bit digit group accesses offset [base + digit*0xc]",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5da54fa8fcd8f9f672e8d39458e0992c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5da54fa8fcd8f9f672e8d39458e0992c",
        "CFG": "93f34182cfdc2bfa690949baa08688cf",
        "PRO": "0516b207b87d20782e29c1b84f00cd35"
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "mnemonic_hashes": {
        "LoD/PD2": "5da54fa8fcd8f9f672e8d39458e0992c"
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "binkw32_MNE_e3e7225badfc": {
      "addresses": {
        "LoD/PD2": "0x03842988"
      },
      "rvas": {
        "LoD/PD2": "0x22988"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "RtlUnwind",
      "signature": "void RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "79ac4b165d48389ac586a56822b7ed6f"
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
    }
  }
};

if (typeof FUNCTION_DATA === 'undefined') FUNCTION_DATA = {};
FUNCTION_DATA['binkw32.dll'] = FUNCTIONS_binkw32_dll;
