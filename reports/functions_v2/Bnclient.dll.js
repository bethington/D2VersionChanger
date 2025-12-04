// Auto-generated from function_registry_v2.json
// Generated: 2025-12-03T18:26:13.185974
// Functions for Bnclient.dll
// Versions: LoD/1.07, LoD/1.08, LoD/1.09, LoD/1.09b, LoD/1.09d, LoD/1.10, LoD/1.11, LoD/1.11b, LoD/1.12a, LoD/1.13c, LoD/1.13d

var FUNCTIONS_Bnclient_dll = {
  "versions": [
    "LoD/1.07",
    "LoD/1.08",
    "LoD/1.09",
    "LoD/1.09b",
    "LoD/1.09d",
    "LoD/1.10",
    "LoD/1.11",
    "LoD/1.11b",
    "LoD/1.12a",
    "LoD/1.13c",
    "LoD/1.13d"
  ],
  "functions": {
    "Bnclient_API_004dc48a3554": {
      "addresses": {
        "LoD/1.07": "0x6FF2A100",
        "LoD/1.08": "0x6FF2A120",
        "LoD/1.09": "0x6FF0AD30",
        "LoD/1.09b": "0x6FF0AD30",
        "LoD/1.09d": "0x6FF0AF80",
        "LoD/1.10": "0x6FF0B7C0",
        "LoD/1.11": "0x6FF221EB",
        "LoD/1.11b": "0x6FF221CC",
        "LoD/1.12a": "0x6FF22244",
        "LoD/1.13c": "0x6FF22242",
        "LoD/1.13d": "0x6FF22241"
      },
      "rvas": {
        "LoD/1.07": "0xA100",
        "LoD/1.08": "0xA120",
        "LoD/1.09": "0xAD30",
        "LoD/1.09b": "0xAD30",
        "LoD/1.09d": "0xAF80",
        "LoD/1.10": "0xB7C0",
        "LoD/1.11": "0x21EB",
        "LoD/1.11b": "0x21CC",
        "LoD/1.12a": "0x2244",
        "LoD/1.13c": "0x2242",
        "LoD/1.13d": "0x2241"
      },
      "name": "CleanupGlobalHandles",
      "signature": "void CleanupGlobalHandles(void)",
      "comment": "Cleanup function that releases two global resource handles and resets their values.\n\nAlgorithm:\n1. Check if first global resource handle (g_hFirstResource) is non-null\n2. If valid, call Ordinal_280 (likely CloseHandle) to release the handle\n3. Zero out the handle storage area (4 bytes at global buffer offset 0x1f8)\n4. Check if second global resource handle (g_hSecondResource) is non-null  \n5. If valid, call Ordinal_280 to release the second handle\n6. Zero out the second handle storage area (4 bytes at global buffer offset 0x200)\n7. Return to caller\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nvoid - no return value\n\nSpecial Cases:\n- Handles already null: No action taken, safe to call multiple times\n- Function is idempotent and can be called repeatedly without side effects\n\nMagic Numbers Reference:\n0x6ff39be8 - Address of first resource handle (g_hFirstResource)\n0x6ff39bf0 - Address of second resource handle (g_hSecondResource)\n0x1f8 - Buffer offset for first handle storage (504 decimal)\n0x200 - Buffer offset for second handle storage (512 decimal)\n\nError Handling:\n- No explicit error checking performed\n- Ordinal_280 (CloseHandle) failures are not handled\n- Function assumes global handles are either null or valid",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:004dc48a3554d8a9ec4e93457de59eeb"
    },
    "Bnclient_API_0505096db454": {
      "addresses": {
        "LoD/1.11": "0x6FF2A8C0",
        "LoD/1.11b": "0x6FF2A8C0",
        "LoD/1.12a": "0x6FF2AEF0",
        "LoD/1.13c": "0x6FF2AED0",
        "LoD/1.13d": "0x6FF2AEE0"
      },
      "rvas": {
        "LoD/1.11": "0xA8C0",
        "LoD/1.11b": "0xA8C0",
        "LoD/1.12a": "0xAEF0",
        "LoD/1.13c": "0xAED0",
        "LoD/1.13d": "0xAEE0"
      },
      "method": "API",
      "index": "API:0505096db4546abcdf97e9ee391a6794"
    },
    "Bnclient_API_05a76bf6a4ea": {
      "addresses": {
        "LoD/1.08": "0x6FF26550",
        "LoD/1.10": "0x6FF07470"
      },
      "rvas": {
        "LoD/1.08": "0x6550",
        "LoD/1.10": "0x7470"
      },
      "method": "API",
      "index": "API:05a76bf6a4ea8a1c9b7c5902052c64b7",
      "candidates": {
        "LoD/1.09": {
          "address": "0x6FF07330",
          "rva": "0x7330",
          "confidence": 0.394,
          "method": "minhash",
          "direction": "forward",
          "source": "LoD/1.08"
        },
        "LoD/1.09b": {
          "address": "0x6FF07330",
          "rva": "0x7330",
          "confidence": 0.224,
          "method": "minhash",
          "direction": "forward",
          "source": "LoD/1.09"
        },
        "LoD/1.11b": {
          "address": "0x6FF21070",
          "rva": "0x1070",
          "confidence": 0.392,
          "method": "minhash",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.07": {
          "address": "0x6FF26AB0",
          "rva": "0x6AB0",
          "confidence": 0.394,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.08"
        }
      }
    },
    "Bnclient_API_0ed301c8b3b0": {
      "addresses": {
        "LoD/1.11": "0x6FF31750",
        "LoD/1.11b": "0x6FF31DC0",
        "LoD/1.12a": "0x6FF30840",
        "LoD/1.13c": "0x6FF33A00",
        "LoD/1.13d": "0x6FF2F9C0"
      },
      "rvas": {
        "LoD/1.11": "0x11750",
        "LoD/1.11b": "0x11DC0",
        "LoD/1.12a": "0x10840",
        "LoD/1.13c": "0x13A00",
        "LoD/1.13d": "0xF9C0"
      },
      "method": "API",
      "index": "API:0ed301c8b3b0673cc03c09dad4f7bf33"
    },
    "Bnclient_API_11f5c7a2301e": {
      "addresses": {
        "LoD/1.11": "0x6FF2B510",
        "LoD/1.11b": "0x6FF336A0",
        "LoD/1.12a": "0x6FF33370",
        "LoD/1.13c": "0x6FF2BB40",
        "LoD/1.13d": "0x6FF327C0"
      },
      "rvas": {
        "LoD/1.11": "0xB510",
        "LoD/1.11b": "0x136A0",
        "LoD/1.12a": "0x13370",
        "LoD/1.13c": "0xBB40",
        "LoD/1.13d": "0x127C0"
      },
      "method": "API",
      "index": "API:11f5c7a2301e311fdfc961210b4cbbc9"
    },
    "Bnclient_API_130e02e774bf": {
      "addresses": {
        "LoD/1.07": "0x6FF229E0",
        "LoD/1.08": "0x6FF22A00",
        "LoD/1.09": "0x6FF03360",
        "LoD/1.09b": "0x6FF03360",
        "LoD/1.09d": "0x6FF03370",
        "LoD/1.10": "0x6FF033C0"
      },
      "rvas": {
        "LoD/1.07": "0x29E0",
        "LoD/1.08": "0x2A00",
        "LoD/1.09": "0x3360",
        "LoD/1.09b": "0x3360",
        "LoD/1.09d": "0x3370",
        "LoD/1.10": "0x33C0"
      },
      "name": "ProcessFileAsyncOperation",
      "signature": "void ProcessFileAsyncOperation(FileProcessThreadParams * pContext, uint dwFlags, uint dwSourceId, uint dwDestId, FILETIME * pFileTime, byte * pbSourcePath, char * lpszDestPath)",
      "comment": "Process file asynchronously with optional time validation and thread creation\n\nAlgorithm:\n1. Validate input parameters (file path buffer exists and non-empty)\n2. Set default destination path if null (points to global string at 0x6ff39514)\n3. Store local copies of context pointer and flags for thread safety\n4. Call FUN_6ff27cf0 to get file information and parse file time\n5. Compare current file time with reference file time using CompareFileTime\n6. If file times match (equal):\n   a. Check if flag 0x02 is set for file time update mode\n   b. If update mode enabled, open file handle with write access\n   c. Update file time stamps (creation, access, write) to reference time\n   d. Close file handle after update\n7. Call recursive file processor (FUN_6ff22bd0) with current parameters\n8. Clean up file parsing result with FUN_6ff27430\n9. Return early if file time comparison or processing succeeded\n10. If comparison failed or no file info, allocate thread parameter structure (560 bytes)\n11. Initialize structure with zero fill (140 DWORDs)\n12. Calculate and store source path length plus 0x20 offset\n13. Set structure magic values: 0x49583836 and 0x44324456 (ASCII: \"68XI\" and \"VD2D\")\n14. Copy source and destination paths to structure buffers (260 bytes each)\n15. Store all parameters in structure for thread context\n16. Increment global thread counter at offset 0xf4\n17. Create new thread with entry point 0x6ff22f10 and parameter structure\n18. Close thread handle if creation successful\n\nParameters:\npContext - File processing context structure pointer for operation tracking\ndwFlags - Processing flags (bit 0x02 = enable file time update mode)\ndwSourceId - Source operation identifier for tracking and logging\ndwDestId - Destination operation identifier for tracking and logging  \npFileTime - Reference file time structure for comparison operations\npbSourcePath - Source file path buffer (null-terminated byte string)\nlpszDestPath - Destination path string (null uses global default path)\n\nReturns:\nvoid - No return value (asynchronous operation with thread creation)\n\nSpecial Cases:\n- If pbSourcePath is null or empty, function returns immediately without processing\n- If lpszDestPath is null, uses global default path at g_lpszDefaultDestPath\n- If file times match exactly, calls recursive handler instead of creating thread\n- Thread creation failure is ignored (handle checked but no error propagation)\n- Structure allocation failure causes silent function exit\n\nMagic Numbers Reference:\n0x230 - Thread parameter structure size (560 bytes decimal)\n0x8c - DWORD count for structure initialization (140 DWORDs = 560 bytes)\n0x02 - File time update flag bit in dwFlags parameter\n0x20 - Offset value added to calculated source path length\n0x104 - Individual path buffer size (260 bytes decimal for MAX_PATH)\n0x49583836 - Structure magic signature field (\"68XI\" in little-endian ASCII)\n0x44324456 - Structure magic signature field (\"VD2D\" in little-endian ASCII)\n0x6ff22f10 - Thread entry point function address for async processing\n0xf4 - Offset to global thread counter for InterlockedIncrement operation\n\nStructure Layout (FileProcessThreadParams):\nOffset | Size | Field Name      | Type      | Description\n-------|------|-----------------|-----------|------------------------------------------\n0x00   | 2    | wSize          | ushort    | Total structure size (path length + 0x20)\n0x02   | 1    | bPadding       | byte      | Padding byte (initialized to 0)\n0x03   | 1    | bFlags         | byte      | Processing flags (set to 0x01)\n0x04   | 4    | dwMagic        | uint      | Magic signature 0x49583836 (\"68XI\")\n0x08   | 4    | dwMagic2       | uint      | Magic signature 0x44324456 (\"VD2D\")\n0x0c   | 4    | dwSourceId     | uint      | Source operation identifier\n0x10   | 4    | dwDestId       | uint      | Destination operation identifier\n0x14   | 4    | dwUnused1      | uint      | Reserved field (initialized to 0)\n0x18   | 8    | fileTime       | FILETIME  | Reference file time structure\n0x20   | 260  | szSourcePath   | char[260] | Source file path buffer (MAX_PATH)\n0x124  | 260  | szDestPath     | char[260] | Destination path buffer (MAX_PATH)\n0x228  | 4    | pContext       | void*     | Original context pointer parameter\n0x22c  | 4    | dwFlags        | uint      | Original flags parameter",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:130e02e774bf6beb69c095236b00babd"
    },
    "Bnclient_API_13c45e6cfee2": {
      "addresses": {
        "LoD/1.11": "0x6FF337D0",
        "LoD/1.11b": "0x6FF2E6A0",
        "LoD/1.12a": "0x6FF2EB30",
        "LoD/1.13c": "0x6FF34B60",
        "LoD/1.13d": "0x6FF362D0"
      },
      "rvas": {
        "LoD/1.11": "0x137D0",
        "LoD/1.11b": "0xE6A0",
        "LoD/1.12a": "0xEB30",
        "LoD/1.13c": "0x14B60",
        "LoD/1.13d": "0x162D0"
      },
      "name": "GetBattlenetRealmsList",
      "signature": "void GetBattlenetRealmsList(BNGatewayAccess * this)",
      "comment": "private: void __thiscall BNGatewayAccess::GetBattlenetRealmsList(void)",
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:13c45e6cfee2ba8a5b7b01ad2478c8aa"
    },
    "Bnclient_API_154e5b552b20": {
      "addresses": {
        "LoD/1.07": "0x6FF24F30",
        "LoD/1.08": "0x6FF24F50",
        "LoD/1.09": "0x6FF058B0",
        "LoD/1.09b": "0x6FF058B0",
        "LoD/1.09d": "0x6FF05B20",
        "LoD/1.10": "0x6FF05A90",
        "LoD/1.11": "0x6FF343E0",
        "LoD/1.11b": "0x6FF31110",
        "LoD/1.12a": "0x6FF2F750",
        "LoD/1.13c": "0x6FF373A0",
        "LoD/1.13d": "0x6FF36650"
      },
      "rvas": {
        "LoD/1.07": "0x4F30",
        "LoD/1.08": "0x4F50",
        "LoD/1.09": "0x58B0",
        "LoD/1.09b": "0x58B0",
        "LoD/1.09d": "0x5B20",
        "LoD/1.10": "0x5A90",
        "LoD/1.11": "0x143E0",
        "LoD/1.11b": "0x11110",
        "LoD/1.12a": "0xF750",
        "LoD/1.13c": "0x173A0",
        "LoD/1.13d": "0x16650"
      },
      "name": "WriteDefaultGatewayList",
      "signature": "void WriteDefaultGatewayList(BNGatewayAccess * this)",
      "comment": "Write default gateway list from configuration file and update internal gateway state\n\nAlgorithm:\n1. Log diagnostic message \"Writing default gateway list\" to system log\n2. Initialize file handle (dwFileHandle) and data pointer (lpszData) to zero\n3. Attempt to open/read \"gateways.txt\" configuration file using Ordinal_279\n4. If file operation fails (return value 0):\n   - Log error message indicating file load failure at line 440\n   - Terminate process immediately with exit code -1 (non-recoverable error)\n5. If file operation succeeds and data pointer is non-null:\n   - Call UpdateGatewaysFromIni to process gateway configuration data\n   - Pass this object as context for gateway state updates\n6. Clean up and return to caller\n\nParameters:\n- this: BNGatewayAccess * - Gateway access object containing internal gateway state\n\nReturns:\n- void - No return value (function terminates process on critical errors)\n\nSpecial Cases:\n- File access failure triggers immediate process termination (0xffffffff exit code)\n- Empty or null configuration data is silently ignored (no gateway updates)\n- File handle and data buffer are automatically managed by Ordinal_279\n\nMagic Numbers Reference:\n- 0x1b8 (440): Source line number for error reporting in log system\n- 0xffffffff (-1): Process termination exit code indicating critical failure",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:154e5b552b20cfabdcc9499dbdc0b863"
    },
    "Bnclient_API_165d46eec034": {
      "addresses": {
        "LoD/1.11": "0x6FF365B0",
        "LoD/1.11b": "0x6FF30870"
      },
      "rvas": {
        "LoD/1.11": "0x165B0",
        "LoD/1.11b": "0x10870"
      },
      "method": "API",
      "index": "API:165d46eec0349fe4508398b8ce6c64d1"
    },
    "Bnclient_API_16c953fb8010": {
      "addresses": {
        "LoD/1.11": "0x6FF2C5F0",
        "LoD/1.11b": "0x6FF34890",
        "LoD/1.12a": "0x6FF34560",
        "LoD/1.13c": "0x6FF2CC10",
        "LoD/1.13d": "0x6FF33A00"
      },
      "rvas": {
        "LoD/1.11": "0xC5F0",
        "LoD/1.11b": "0x14890",
        "LoD/1.12a": "0x14560",
        "LoD/1.13c": "0xCC10",
        "LoD/1.13d": "0x13A00"
      },
      "method": "API",
      "index": "API:16c953fb8010ceba21d061c6f5b1d4b1"
    },
    "Bnclient_API_1de1ebd36697": {
      "addresses": {
        "LoD/1.11": "0x6FF2C850",
        "LoD/1.11b": "0x6FF35070",
        "LoD/1.12a": "0x6FF2B650",
        "LoD/1.13c": "0x6FF328C0",
        "LoD/1.13d": "0x6FF345F0"
      },
      "rvas": {
        "LoD/1.11": "0xC850",
        "LoD/1.11b": "0x15070",
        "LoD/1.12a": "0xB650",
        "LoD/1.13c": "0x128C0",
        "LoD/1.13d": "0x145F0"
      },
      "method": "API",
      "index": "API:1de1ebd36697e25d3c439a514264dfe1"
    },
    "Bnclient_API_2069644e2e2b": {
      "addresses": {
        "LoD/1.11": "0x6FF2A3C0",
        "LoD/1.11b": "0x6FF2A3C0",
        "LoD/1.12a": "0x6FF2A9F0",
        "LoD/1.13c": "0x6FF2A9D0",
        "LoD/1.13d": "0x6FF2A9E0"
      },
      "rvas": {
        "LoD/1.11": "0xA3C0",
        "LoD/1.11b": "0xA3C0",
        "LoD/1.12a": "0xA9F0",
        "LoD/1.13c": "0xA9D0",
        "LoD/1.13d": "0xA9E0"
      },
      "method": "API",
      "index": "API:2069644e2e2b34cf74f21971aa0cf67d",
      "candidates": {
        "LoD/1.09b": {
          "address": "0x6FF07820",
          "rva": "0x7820",
          "confidence": 0.42,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09": {
          "address": "0x6FF07820",
          "rva": "0x7820",
          "confidence": 0.34,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_API_226b4b45fc7d": {
      "addresses": {
        "LoD/1.07": "0x6FF24EA0",
        "LoD/1.08": "0x6FF24EC0",
        "LoD/1.09": "0x6FF05820",
        "LoD/1.09b": "0x6FF05820",
        "LoD/1.09d": "0x6FF05A90",
        "LoD/1.10": "0x6FF05A00",
        "LoD/1.11": "0x6FF33B50",
        "LoD/1.11b": "0x6FF2EA20",
        "LoD/1.12a": "0x6FF2EEB0",
        "LoD/1.13c": "0x6FF34EE0",
        "LoD/1.13d": "0x6FF366C0"
      },
      "rvas": {
        "LoD/1.07": "0x4EA0",
        "LoD/1.08": "0x4EC0",
        "LoD/1.09": "0x5820",
        "LoD/1.09b": "0x5820",
        "LoD/1.09d": "0x5A90",
        "LoD/1.10": "0x5A00",
        "LoD/1.11": "0x13B50",
        "LoD/1.11b": "0xEA20",
        "LoD/1.12a": "0xEEB0",
        "LoD/1.13c": "0x14EE0",
        "LoD/1.13d": "0x166C0"
      },
      "name": "GetBattlenetGatewayList",
      "signature": "void GetBattlenetGatewayList(BNGatewayAccess * this)",
      "comment": "Initialize Battle.net gateway list with fallback mechanism.\n\nAlgorithm:\n1. Clear override mode flag (fOverrideMode = 0) to reset state\n2. Attempt to load override gateway list using \"Override Battle.net gateways\" configuration\n3. Call GetGatewayList with override gateway configuration string\n4. Check if buffer was populated (pBuffer != NULL) after override attempt\n5. If override gateways loaded successfully, set override mode flag (fOverrideMode = 1) and return\n6. If override failed (pBuffer still NULL), attempt fallback to default gateways\n7. Call GetGatewayList with \"Diablo II Battle.net gateways\" default configuration string\n8. Return with either override or default gateways loaded\n\nParameters:\nthis - Instance of BNGatewayAccess class containing gateway configuration and buffer state\n\nReturns:\nvoid - Function modifies object state directly through this pointer\nSuccess indicated by populated pBuffer and appropriate fOverrideMode setting\nFailure results in empty pBuffer state\n\nSpecial Cases:\n- Override gateway configuration takes priority over default configuration\n- Default gateway configuration used only when override configuration fails or unavailable\n- fOverrideMode flag tracks which configuration source was successfully used (0=default, 1=override)\n\nMagic Numbers Reference:\n0x1c - Offset to fOverrideMode field in BNGatewayAccess structure  \n0x10 - Offset to pBuffer field in BNGatewayAccess structure\n0x0 - Reset value for fOverrideMode (default mode)\n0x1 - Set value for fOverrideMode (override mode active)\n0x6ff35a94 - String address for \"Override Battle.net gateways\" configuration\n0x6ff35a74 - String address for \"Diablo II Battle.net gateways\" configuration",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:226b4b45fc7db39c7af749fa1d34697f"
    },
    "Bnclient_API_246ad536e3e6": {
      "addresses": {
        "LoD/1.11": "0x6FF33C30",
        "LoD/1.11b": "0x6FF2EB00",
        "LoD/1.12a": "0x6FF2EF90",
        "LoD/1.13c": "0x6FF34FC0",
        "LoD/1.13d": "0x6FF36E60"
      },
      "rvas": {
        "LoD/1.11": "0x13C30",
        "LoD/1.11b": "0xEB00",
        "LoD/1.12a": "0xEF90",
        "LoD/1.13c": "0x14FC0",
        "LoD/1.13d": "0x16E60"
      },
      "name": "Realm",
      "signature": "char * Realm(int param_1)",
      "comment": "public: char * __stdcall BNGatewayAccess::Realm(int)",
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:246ad536e3e6ba5a83f79745ede8e932"
    },
    "Bnclient_API_2785a35175c0": {
      "addresses": {
        "LoD/1.09": "0x6FF07A80",
        "LoD/1.09b": "0x6FF07A80",
        "LoD/1.09d": "0x6FF07CE0",
        "LoD/1.10": "0x6FF086C0",
        "LoD/1.11": "0x6FF303E0",
        "LoD/1.11b": "0x6FF32DE0",
        "LoD/1.12a": "0x6FF36310",
        "LoD/1.13c": "0x6FF31E60",
        "LoD/1.13d": "0x6FF2E650"
      },
      "rvas": {
        "LoD/1.09": "0x7A80",
        "LoD/1.09b": "0x7A80",
        "LoD/1.09d": "0x7CE0",
        "LoD/1.10": "0x86C0",
        "LoD/1.11": "0x103E0",
        "LoD/1.11b": "0x12DE0",
        "LoD/1.12a": "0x16310",
        "LoD/1.13c": "0x11E60",
        "LoD/1.13d": "0xE650"
      },
      "method": "API",
      "index": "API:2785a35175c04d6e30e6b72c3991e78e",
      "candidates": {
        "LoD/1.08": {
          "address": "0x6FF26800",
          "rva": "0x6800",
          "confidence": 0.471,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.09"
        },
        "LoD/1.07": {
          "address": "0x6FF267E0",
          "rva": "0x67E0",
          "confidence": 0.343,
          "method": "unique_api",
          "direction": "reverse",
          "source": "LoD/1.08"
        }
      }
    },
    "Bnclient_API_27b2e27c9374": {
      "addresses": {
        "LoD/1.07": "0x6FF25B50",
        "LoD/1.08": "0x6FF25B70"
      },
      "rvas": {
        "LoD/1.07": "0x5B50",
        "LoD/1.08": "0x5B70"
      },
      "name": "CreateAndSendAuthenticationPackets",
      "signature": "int CreateAndSendAuthenticationPackets(void)",
      "comment": "Creates and sends authentication packets for network communication based on global connection state.\n\nAlgorithm:\n1. Initialize network subsystem and obtain session token from system\n2. Generate two data inputs (0x00 and 0x01) for key derivation process\n3. Obtain session ID and accumulate random entropy into global buffer\n4. Get tick count and add to entropy pool for randomness enhancement\n5. Check global connection state to determine authentication packet strategy\n6. If state == 0: Execute single packet mode with packet type 1\n7. If state != 0: Execute dual packet mode with packet types 1 and 2\n8. Extract 4-byte client ID from global buffer at offset 0x158-0x15B\n9. Generate triple hash keys using input data and populate output parameters\n10. Create packet data arrays with 24-byte structure copy from client ID\n11. Encrypt 128-byte buffer with session token using Ordinal_501 encryption\n12. Send packets via network validation system with error checking\n13. Clean up network subsystem resources on completion\n14. Set global process ID to 3 on authentication failure for error tracking\n\nParameters:\nNone (void function - operates on global state)\n\nIMPLICIT:\nNone (function uses only global variables and system calls)\n\nReturns:\n0 - Authentication failed, unable to send packets or hash generation failed\n1 - Authentication successful, packets created and sent successfully\n\nSpecial Cases:\nGlobal state == 0: Single packet authentication mode using type 1 only\nGlobal state != 0: Dual packet authentication mode using types 1 and 2\nHash key generation failure: Early return with 0 (failure)\nNetwork send failure: Return 1 (success indicates packet was properly created)\nClient ID extraction: Always reads 4 bytes from fixed offset 0x158\n\nMagic Numbers Reference:\n0x00 - First input data value for key generation (single packet mode)\n0x01 - Second input data value for key generation (dual packet mode)\n0x158 - Offset in global buffer for 4-byte client ID extraction (0x158-0x15B)\n0x18 - Size in bytes (24) for packet data structure memory copy operation\n0x80 - Size in bytes (128) for encrypted buffer passed to Ordinal_501\n1 - Packet type identifier for initial/primary authentication packet\n2 - Packet type identifier for secondary authentication packet (dual mode)\n3 - Process ID value set globally on authentication failure\n\nError Handling:\nNetwork subsystem initialization: Continues execution if initialization fails\nTriple hash key generation: Returns 0 immediately if hash generation fails\nNetwork packet transmission: Returns 1 on success, 0 on transmission failure\nResource cleanup: Always executed via FUN_6ff2a100 regardless of success/failure state",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:27b2e27c9374eea689aded8afd41e00d"
    },
    "Bnclient_API_2c07962e3f71": {
      "addresses": {
        "LoD/1.11": "0x6FF2A800",
        "LoD/1.11b": "0x6FF2A800",
        "LoD/1.12a": "0x6FF2AE30",
        "LoD/1.13c": "0x6FF2AE10",
        "LoD/1.13d": "0x6FF2AE20"
      },
      "rvas": {
        "LoD/1.11": "0xA800",
        "LoD/1.11b": "0xA800",
        "LoD/1.12a": "0xAE30",
        "LoD/1.13c": "0xAE10",
        "LoD/1.13d": "0xAE20"
      },
      "method": "API",
      "index": "API:2c07962e3f713d78e002fa5cca49c4a3"
    },
    "Bnclient_API_371349f30914": {
      "addresses": {
        "LoD/1.11": "0x6FF33400",
        "LoD/1.11b": "0x6FF2FFB0",
        "LoD/1.12a": "0x6FF35A70",
        "LoD/1.13c": "0x6FF315B0",
        "LoD/1.13d": "0x6FF2CB00"
      },
      "rvas": {
        "LoD/1.11": "0x13400",
        "LoD/1.11b": "0xFFB0",
        "LoD/1.12a": "0x15A70",
        "LoD/1.13c": "0x115B0",
        "LoD/1.13d": "0xCB00"
      },
      "method": "API",
      "index": "API:371349f30914e339f2e4ca9123ae028e",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF071C0",
          "rva": "0x71C0",
          "confidence": 0.57,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF06A80",
          "rva": "0x6A80",
          "confidence": 0.461,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.10"
        },
        "LoD/1.09b": {
          "address": "0x6FF06810",
          "rva": "0x6810",
          "confidence": 0.336,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.09d"
        },
        "LoD/1.09": {
          "address": "0x6FF06810",
          "rva": "0x6810",
          "confidence": 0.374,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_API_39593535e860": {
      "addresses": {
        "LoD/1.09": "0x6FF07920",
        "LoD/1.09b": "0x6FF07920",
        "LoD/1.09d": "0x6FF07B80",
        "LoD/1.10": "0x6FF08560"
      },
      "rvas": {
        "LoD/1.09": "0x7920",
        "LoD/1.09b": "0x7920",
        "LoD/1.09d": "0x7B80",
        "LoD/1.10": "0x8560"
      },
      "method": "API",
      "index": "API:39593535e8604e87167bff3fa0972720"
    },
    "Bnclient_API_3c3e6a654119": {
      "addresses": {
        "LoD/1.09": "0x6FF07C10",
        "LoD/1.09b": "0x6FF07C10",
        "LoD/1.09d": "0x6FF07E70",
        "LoD/1.10": "0x6FF08850",
        "LoD/1.11": "0x6FF30340",
        "LoD/1.11b": "0x6FF32D40",
        "LoD/1.12a": "0x6FF36270",
        "LoD/1.13c": "0x6FF31DC0",
        "LoD/1.13d": "0x6FF2E5B0"
      },
      "rvas": {
        "LoD/1.09": "0x7C10",
        "LoD/1.09b": "0x7C10",
        "LoD/1.09d": "0x7E70",
        "LoD/1.10": "0x8850",
        "LoD/1.11": "0x10340",
        "LoD/1.11b": "0x12D40",
        "LoD/1.12a": "0x16270",
        "LoD/1.13c": "0x11DC0",
        "LoD/1.13d": "0xE5B0"
      },
      "method": "API",
      "index": "API:3c3e6a654119e5a711661a3a21530095",
      "candidates": {
        "LoD/1.08": {
          "address": "0x6FF260D0",
          "rva": "0x60D0",
          "confidence": 0.548,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.09"
        },
        "LoD/1.07": {
          "address": "0x6FF260B0",
          "rva": "0x60B0",
          "confidence": 0.444,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.08"
        }
      }
    },
    "Bnclient_API_3e42cd412070": {
      "addresses": {
        "LoD/1.11": "0x6FF29A80",
        "LoD/1.11b": "0x6FF29A80",
        "LoD/1.12a": "0x6FF2A0B0",
        "LoD/1.13c": "0x6FF2A090",
        "LoD/1.13d": "0x6FF2A0A0"
      },
      "rvas": {
        "LoD/1.11": "0x9A80",
        "LoD/1.11b": "0x9A80",
        "LoD/1.12a": "0xA0B0",
        "LoD/1.13c": "0xA090",
        "LoD/1.13d": "0xA0A0"
      },
      "method": "API",
      "index": "API:3e42cd412070ec65401f99c780a37ec5"
    },
    "Bnclient_API_3ed03f754c55": {
      "addresses": {
        "LoD/1.11": "0x6FF29ED0",
        "LoD/1.11b": "0x6FF29ED0",
        "LoD/1.12a": "0x6FF2A500",
        "LoD/1.13c": "0x6FF2A4E0",
        "LoD/1.13d": "0x6FF2A4F0"
      },
      "rvas": {
        "LoD/1.11": "0x9ED0",
        "LoD/1.11b": "0x9ED0",
        "LoD/1.12a": "0xA500",
        "LoD/1.13c": "0xA4E0",
        "LoD/1.13d": "0xA4F0"
      },
      "method": "API",
      "index": "API:3ed03f754c557e31ed29279ffb487e71"
    },
    "Bnclient_API_417cf96483b9": {
      "addresses": {
        "LoD/1.11": "0x6FF2A6C0",
        "LoD/1.11b": "0x6FF2A6C0",
        "LoD/1.12a": "0x6FF2ACF0",
        "LoD/1.13c": "0x6FF2ACD0",
        "LoD/1.13d": "0x6FF2ACE0"
      },
      "rvas": {
        "LoD/1.11": "0xA6C0",
        "LoD/1.11b": "0xA6C0",
        "LoD/1.12a": "0xACF0",
        "LoD/1.13c": "0xACD0",
        "LoD/1.13d": "0xACE0"
      },
      "method": "API",
      "index": "API:417cf96483b9e4e785f13c7f5122063d"
    },
    "Bnclient_API_451e4d87b9a6": {
      "addresses": {
        "LoD/1.11": "0x6FF2C1A0",
        "LoD/1.11b": "0x6FF34440",
        "LoD/1.12a": "0x6FF33E70",
        "LoD/1.13c": "0x6FF2C7C0",
        "LoD/1.13d": "0x6FF334E0"
      },
      "rvas": {
        "LoD/1.11": "0xC1A0",
        "LoD/1.11b": "0x14440",
        "LoD/1.12a": "0x13E70",
        "LoD/1.13c": "0xC7C0",
        "LoD/1.13d": "0x134E0"
      },
      "method": "API",
      "index": "API:451e4d87b9a613e8671336fd375f016a",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF13D70",
          "rva": "0x13D70",
          "confidence": 0.33,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF13770",
          "rva": "0x13770",
          "confidence": 0.195,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_API_46e4263294a5": {
      "addresses": {
        "LoD/1.11": "0x6FF2B3E0",
        "LoD/1.11b": "0x6FF33570",
        "LoD/1.12a": "0x6FF33230",
        "LoD/1.13c": "0x6FF2BA00",
        "LoD/1.13d": "0x6FF32680"
      },
      "rvas": {
        "LoD/1.11": "0xB3E0",
        "LoD/1.11b": "0x13570",
        "LoD/1.12a": "0x13230",
        "LoD/1.13c": "0xBA00",
        "LoD/1.13d": "0x12680"
      },
      "method": "API",
      "index": "API:46e4263294a5c4407ab564e51555a7cf"
    },
    "Bnclient_API_519554149bff": {
      "addresses": {
        "LoD/1.10": "0x6FF07E90",
        "LoD/1.11": "0x6FF2B640",
        "LoD/1.11b": "0x6FF33860",
        "LoD/1.12a": "0x6FF33530",
        "LoD/1.13c": "0x6FF2BC70",
        "LoD/1.13d": "0x6FF328F0"
      },
      "rvas": {
        "LoD/1.10": "0x7E90",
        "LoD/1.11": "0xB640",
        "LoD/1.11b": "0x13860",
        "LoD/1.12a": "0x13530",
        "LoD/1.13c": "0xBC70",
        "LoD/1.13d": "0x128F0"
      },
      "method": "API",
      "index": "API:519554149bffe2d4f4e3b5a4a94362bc"
    },
    "Bnclient_API_5379980306a8": {
      "addresses": {
        "LoD/1.11": "0x6FF2AD90",
        "LoD/1.11b": "0x6FF2AD90",
        "LoD/1.12a": "0x6FF2B3C0",
        "LoD/1.13c": "0x6FF2B3A0",
        "LoD/1.13d": "0x6FF2B3B0"
      },
      "rvas": {
        "LoD/1.11": "0xAD90",
        "LoD/1.11b": "0xAD90",
        "LoD/1.12a": "0xB3C0",
        "LoD/1.13c": "0xB3A0",
        "LoD/1.13d": "0xB3B0"
      },
      "method": "API",
      "index": "API:5379980306a89ceee8b21df71be3824f"
    },
    "Bnclient_API_569168a5cfc1": {
      "addresses": {
        "LoD/1.11": "0x6FF33820",
        "LoD/1.11b": "0x6FF2E6F0",
        "LoD/1.12a": "0x6FF2EB80",
        "LoD/1.13c": "0x6FF34BB0",
        "LoD/1.13d": "0x6FF36320"
      },
      "rvas": {
        "LoD/1.11": "0x13820",
        "LoD/1.11b": "0xE6F0",
        "LoD/1.12a": "0xEB80",
        "LoD/1.13c": "0x14BB0",
        "LoD/1.13d": "0x16320"
      },
      "name": "GetGatewayList",
      "signature": "void GetGatewayList(BNGatewayAccess * this, char * param_1)",
      "comment": "private: void __thiscall BNGatewayAccess::GetGatewayList(char const *)",
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:569168a5cfc1aef933e6414ee7196cfa"
    },
    "Bnclient_API_57419d6c30af": {
      "addresses": {
        "LoD/1.11": "0x6FF346F0",
        "LoD/1.11b": "0x6FF2C790",
        "LoD/1.12a": "0x6FF2BDF0",
        "LoD/1.13c": "0x6FF2CF10",
        "LoD/1.13d": "0x6FF30C30"
      },
      "rvas": {
        "LoD/1.11": "0x146F0",
        "LoD/1.11b": "0xC790",
        "LoD/1.12a": "0xBDF0",
        "LoD/1.13c": "0xCF10",
        "LoD/1.13d": "0x10C30"
      },
      "method": "API",
      "index": "API:57419d6c30afd73cd65c5e9185be6eea"
    },
    "Bnclient_API_586f87cbb0d2": {
      "addresses": {
        "LoD/1.07": "0x6FF27370",
        "LoD/1.08": "0x6FF27390",
        "LoD/1.09": "0x6FF07FA0",
        "LoD/1.09b": "0x6FF07FA0",
        "LoD/1.09d": "0x6FF08200",
        "LoD/1.10": "0x6FF08BE0",
        "LoD/1.11": "0x6FF31020",
        "LoD/1.11b": "0x6FF31690",
        "LoD/1.12a": "0x6FF30110",
        "LoD/1.13c": "0x6FF332D0",
        "LoD/1.13d": "0x6FF2F290"
      },
      "rvas": {
        "LoD/1.07": "0x7370",
        "LoD/1.08": "0x7390",
        "LoD/1.09": "0x7FA0",
        "LoD/1.09b": "0x7FA0",
        "LoD/1.09d": "0x8200",
        "LoD/1.10": "0x8BE0",
        "LoD/1.11": "0x11020",
        "LoD/1.11b": "0x11690",
        "LoD/1.12a": "0x10110",
        "LoD/1.13c": "0x132D0",
        "LoD/1.13d": "0xF290"
      },
      "name": "CleanupGlobalResources",
      "signature": "void CleanupGlobalResources(void)",
      "comment": "Cleanup and release all global resources and handles\n\nAlgorithm:\n1. Enter critical section to ensure thread-safe cleanup\n2. Clear global buffer state flags (4 bytes starting at offset 0x1b8)\n3. Check and cleanup first handle (offset 0x428) - log and clear buffer\n4. Check and cleanup second handle (offset 0x436) - log and clear buffer  \n5. Check and cleanup third handle (offset 0x424) - log and clear buffer\n6. Check global handle validity and close if not INVALID_HANDLE_VALUE\n7. Check and cleanup fourth handle (offset 0x432) - log and clear buffer\n8. Leave critical section to allow other threads access\n\nParameters:\nNone - void function for global resource cleanup\n\nReturns:\nvoid - No return value, cleanup operation always completes\n\nSpecial Cases:\nHandles are checked for validity before cleanup operations\nGlobal handle checked against INVALID_HANDLE_VALUE (0xffffffff) before closing\nEach handle cleanup includes debug logging via Ordinal_403\n\nMagic Numbers Reference:\n0x190 (400) - Critical section offset in global buffer\n0x1b8 (440) - Global state flags offset (4 bytes cleared)\n0x424 (1060) - Third handle storage offset\n0x428 (1064) - First handle storage offset  \n0x432 (1074) - Fourth handle storage offset\n0x436 (1078) - Second handle storage offset\n0x1a8-0x1ab (424-427) - Third handle buffer clear range\n0x1ac-0x1af (428-431) - First handle buffer clear range\n0x1b0-0x1b3 (432-435) - Fourth handle buffer clear range\n0x1b4-0x1b7 (436-439) - Second handle buffer clear range\n0x13e (318) - First handle debug log line number\n0x142 (322) - Second handle debug log line number  \n0x146 (326) - Third handle debug log line number\n0x14e (334) - Fourth handle debug log line number\n0xffffffff - INVALID_HANDLE_VALUE constant\n\nError Handling:\nNo explicit error handling - cleanup operations are unconditional\nCritical section ensures atomic cleanup operation\nInvalid handles are safely ignored by CloseHandle API",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:586f87cbb0d2f36af8b55ec5e8629f51"
    },
    "Bnclient_API_5ae1ea4446d8": {
      "addresses": {
        "LoD/1.11": "0x6FF323F0",
        "LoD/1.11b": "0x6FF2B190",
        "LoD/1.12a": "0x6FF314E0",
        "LoD/1.13c": "0x6FF2FE00",
        "LoD/1.13d": "0x6FF34FE0"
      },
      "rvas": {
        "LoD/1.11": "0x123F0",
        "LoD/1.11b": "0xB190",
        "LoD/1.12a": "0x114E0",
        "LoD/1.13c": "0xFE00",
        "LoD/1.13d": "0x14FE0"
      },
      "method": "API",
      "index": "API:5ae1ea4446d83d95724c54afcb7f02a1"
    },
    "Bnclient_API_60b3612940d4": {
      "addresses": {
        "LoD/1.09": "0x6FF07CB0",
        "LoD/1.09b": "0x6FF07CB0",
        "LoD/1.09d": "0x6FF07F10",
        "LoD/1.10": "0x6FF088F0",
        "LoD/1.11": "0x6FF30230",
        "LoD/1.11b": "0x6FF32C30",
        "LoD/1.12a": "0x6FF36160",
        "LoD/1.13c": "0x6FF31CB0",
        "LoD/1.13d": "0x6FF2E4A0"
      },
      "rvas": {
        "LoD/1.09": "0x7CB0",
        "LoD/1.09b": "0x7CB0",
        "LoD/1.09d": "0x7F10",
        "LoD/1.10": "0x88F0",
        "LoD/1.11": "0x10230",
        "LoD/1.11b": "0x12C30",
        "LoD/1.12a": "0x16160",
        "LoD/1.13c": "0x11CB0",
        "LoD/1.13d": "0xE4A0"
      },
      "method": "API",
      "index": "API:60b3612940d42dca79101ef9ed03abfa"
    },
    "Bnclient_API_62322eab4fda": {
      "addresses": {
        "LoD/1.11": "0x6FF324B0",
        "LoD/1.11b": "0x6FF2B250",
        "LoD/1.12a": "0x6FF315A0",
        "LoD/1.13c": "0x6FF2FEC0",
        "LoD/1.13d": "0x6FF350A0"
      },
      "rvas": {
        "LoD/1.11": "0x124B0",
        "LoD/1.11b": "0xB250",
        "LoD/1.12a": "0x115A0",
        "LoD/1.13c": "0xFEC0",
        "LoD/1.13d": "0x150A0"
      },
      "method": "API",
      "index": "API:62322eab4fdafa1b7151e6707ef8977f"
    },
    "Bnclient_API_632c316e50a5": {
      "addresses": {
        "LoD/1.11": "0x6FF2D710",
        "LoD/1.11b": "0x6FF2B6F0",
        "LoD/1.12a": "0x6FF2DB30",
        "LoD/1.13c": "0x6FF2EC50",
        "LoD/1.13d": "0x6FF2D060"
      },
      "rvas": {
        "LoD/1.11": "0xD710",
        "LoD/1.11b": "0xB6F0",
        "LoD/1.12a": "0xDB30",
        "LoD/1.13c": "0xEC50",
        "LoD/1.13d": "0xD060"
      },
      "method": "API",
      "index": "API:632c316e50a57bea6696b0c11ac22c24"
    },
    "Bnclient_API_682ee23fe6f6": {
      "addresses": {
        "LoD/1.09": "0x6FF07BB0",
        "LoD/1.09b": "0x6FF07BB0",
        "LoD/1.09d": "0x6FF07E10",
        "LoD/1.11": "0x6FF30580",
        "LoD/1.11b": "0x6FF32F80",
        "LoD/1.12a": "0x6FF364B0",
        "LoD/1.13c": "0x6FF32000",
        "LoD/1.13d": "0x6FF2E7F0"
      },
      "rvas": {
        "LoD/1.09": "0x7BB0",
        "LoD/1.09b": "0x7BB0",
        "LoD/1.09d": "0x7E10",
        "LoD/1.11": "0x10580",
        "LoD/1.11b": "0x12F80",
        "LoD/1.12a": "0x164B0",
        "LoD/1.13c": "0x12000",
        "LoD/1.13d": "0xE7F0"
      },
      "method": "API",
      "index": "API:682ee23fe6f64092cc813ed6b0ce4313"
    },
    "Bnclient_API_68d9a5c6913d": {
      "addresses": {
        "LoD/1.09d": "0x6FF03AF0",
        "LoD/1.10": "0x6FF03B00",
        "LoD/1.11": "0x6FF34940",
        "LoD/1.11b": "0x6FF2C9E0",
        "LoD/1.12a": "0x6FF2C040",
        "LoD/1.13c": "0x6FF2D160",
        "LoD/1.13d": "0x6FF30E80"
      },
      "rvas": {
        "LoD/1.09d": "0x3AF0",
        "LoD/1.10": "0x3B00",
        "LoD/1.11": "0x14940",
        "LoD/1.11b": "0xC9E0",
        "LoD/1.12a": "0xC040",
        "LoD/1.13c": "0xD160",
        "LoD/1.13d": "0x10E80"
      },
      "method": "API",
      "index": "API:68d9a5c6913dfcd97d3385c16e598151"
    },
    "Bnclient_API_6a597000ad36": {
      "addresses": {
        "LoD/1.11": "0x6FF2D8E0",
        "LoD/1.11b": "0x6FF2B880",
        "LoD/1.12a": "0x6FF2DD00",
        "LoD/1.13c": "0x6FF2EE20",
        "LoD/1.13d": "0x6FF2D420"
      },
      "rvas": {
        "LoD/1.11": "0xD8E0",
        "LoD/1.11b": "0xB880",
        "LoD/1.12a": "0xDD00",
        "LoD/1.13c": "0xEE20",
        "LoD/1.13d": "0xD420"
      },
      "method": "API",
      "index": "API:6a597000ad36dbe90196b5b0189ab75f"
    },
    "Bnclient_API_6d36d2683446": {
      "addresses": {
        "LoD/1.11": "0x6FF35F20",
        "LoD/1.11b": "0x6FF2DFC0",
        "LoD/1.12a": "0x6FF2D620",
        "LoD/1.13c": "0x6FF2E740",
        "LoD/1.13d": "0x6FF32460"
      },
      "rvas": {
        "LoD/1.11": "0x15F20",
        "LoD/1.11b": "0xDFC0",
        "LoD/1.12a": "0xD620",
        "LoD/1.13c": "0xE740",
        "LoD/1.13d": "0x12460"
      },
      "method": "API",
      "index": "API:6d36d26834464118c2dc6d8251d84814"
    },
    "Bnclient_API_6e7fa7cb7ea1": {
      "addresses": {
        "LoD/1.09": "0x6FF07E90",
        "LoD/1.09b": "0x6FF07E90",
        "LoD/1.09d": "0x6FF080F0",
        "LoD/1.10": "0x6FF08AD0",
        "LoD/1.11": "0x6FF30080",
        "LoD/1.11b": "0x6FF32890",
        "LoD/1.12a": "0x6FF35DC0",
        "LoD/1.13c": "0x6FF31B00",
        "LoD/1.13d": "0x6FF2E2F0"
      },
      "rvas": {
        "LoD/1.09": "0x7E90",
        "LoD/1.09b": "0x7E90",
        "LoD/1.09d": "0x80F0",
        "LoD/1.10": "0x8AD0",
        "LoD/1.11": "0x10080",
        "LoD/1.11b": "0x12890",
        "LoD/1.12a": "0x15DC0",
        "LoD/1.13c": "0x11B00",
        "LoD/1.13d": "0xE2F0"
      },
      "method": "API",
      "index": "API:6e7fa7cb7ea15693876bef87cf9df9cb",
      "candidates": {
        "LoD/1.08": {
          "address": "0x6FF260D0",
          "rva": "0x60D0",
          "confidence": 0.672,
          "method": "composite",
          "direction": "reverse",
          "source": "LoD/1.09"
        }
      }
    },
    "Bnclient_API_6fc9ed070965": {
      "addresses": {
        "LoD/1.07": "0x6FF24EE0",
        "LoD/1.08": "0x6FF24F00",
        "LoD/1.09": "0x6FF05860",
        "LoD/1.09b": "0x6FF05860",
        "LoD/1.09d": "0x6FF05AD0",
        "LoD/1.10": "0x6FF05A40",
        "LoD/1.11": "0x6FF32290",
        "LoD/1.11b": "0x6FF2B030",
        "LoD/1.12a": "0x6FF331E0",
        "LoD/1.13c": "0x6FF2FCA0",
        "LoD/1.13d": "0x6FF34E80"
      },
      "rvas": {
        "LoD/1.07": "0x4EE0",
        "LoD/1.08": "0x4F00",
        "LoD/1.09": "0x5860",
        "LoD/1.09b": "0x5860",
        "LoD/1.09d": "0x5AD0",
        "LoD/1.10": "0x5A40",
        "LoD/1.11": "0x12290",
        "LoD/1.11b": "0xB030",
        "LoD/1.12a": "0x131E0",
        "LoD/1.13c": "0xFCA0",
        "LoD/1.13d": "0x14E80"
      },
      "name": "GetBattlenetRealmsList",
      "signature": "void GetBattlenetRealmsList(BNGatewayAccess * this)",
      "comment": "Loads and parses the Battle.net realms list from a binary data file.\n\nAlgorithm:\n1. Initialize data size variable to zero\n2. Call Storm.dll function to read realms data from binary file\n3. If data loading fails (return value 0), trigger fatal error\n4. Return silently if data loading succeeds\n\nParameters:\nthis - Pointer to BNGatewayAccess object instance\n\nReturns:\nvoid - Function does not return a value\nOn failure: Calls fatal error handler and terminates process\n\nSpecial Cases:\nIf Ordinal_279 returns 0, the function triggers a fatal error message and terminates\nthe process via FUN_6ff2b29c with error code 0xffffffff\n\nMagic Numbers Reference:\n0x17a (378) - Error code passed to Ordinal_10023 for realm loading failure\n0xffffffff - Fatal error code passed to process termination function",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:6fc9ed070965aa87a8a48a7f66bd303e"
    },
    "Bnclient_API_7682baa14f17": {
      "addresses": {
        "LoD/1.07": "0x6FF25DB0",
        "LoD/1.08": "0x6FF25DD0",
        "LoD/1.09": "0x6FF064D0",
        "LoD/1.09b": "0x6FF064D0",
        "LoD/1.09d": "0x6FF06740",
        "LoD/1.10": "0x6FF06E80",
        "LoD/1.11": "0x6FF36240",
        "LoD/1.11b": "0x6FF30500",
        "LoD/1.12a": "0x6FF32910",
        "LoD/1.13c": "0x6FF30220",
        "LoD/1.13d": "0x6FF30520"
      },
      "rvas": {
        "LoD/1.07": "0x5DB0",
        "LoD/1.08": "0x5DD0",
        "LoD/1.09": "0x64D0",
        "LoD/1.09b": "0x64D0",
        "LoD/1.09d": "0x6740",
        "LoD/1.10": "0x6E80",
        "LoD/1.11": "0x16240",
        "LoD/1.11b": "0x10500",
        "LoD/1.12a": "0x12910",
        "LoD/1.13c": "0x10220",
        "LoD/1.13d": "0x10520"
      },
      "name": "GenerateTripleHashKeys",
      "signature": "BOOL GenerateTripleHashKeys(int nInputData, DWORD * pdwKey1, DWORD * pdwKey2, DWORD * pdwKey3)",
      "comment": "Generate three cryptographic hash keys from numeric input data with validation checksum.\n\nAlgorithm:\n1. Validate input parameters - return FALSE if nInputData is zero\n2. Convert input integer to 32-byte hex string using Ordinal_501 buffer function\n3. Process hex string through character conversion lookup table (g_abCharacterConversionLookup)\n   - For each byte pair: Calculate weighted value = first_char * 0x18 + second_char\n   - If calculated value > 0xFF: subtract 0x100 and set bit in checksum mask\n   - Convert high nibble to ASCII hex character (0-9: +0x30, A-F: +0x37)\n   - Convert low nibble to ASCII hex character using same logic\n4. Validate checksum by processing converted string with ConvertCharacterToLowerCase\n   - Accumulate hash using formula: hash = hash + (hash * 2 XOR converted_char + offset)\n   - Compare low byte of hash with checksum mask - return FALSE if mismatch\n5. Perform buffer shuffle algorithm to randomize byte positions\n   - Swap bytes using calculated index: (ptr + (0x16 - base_offset)) & 0xF\n6. Apply character case conversion and bit manipulation with seed 0x13AC9741\n   - Convert each character to uppercase using ConvertCharacterToUpperCase\n   - For chars < '8': XOR with (seed & 7), then shift seed right by 3 bits\n   - For chars >= '8' and < 'A': XOR with (index & 1)\n7. Generate three hash keys using StringToUnsignedLongWithBaseOne (base 16)\n   - Key 1: Convert 3 bytes starting from buffer (dwSeed area)\n   - Key 2: Convert 7 bytes starting from buffer + 2 (abKey1Buffer area)\n   - Key 3: Convert 9 bytes starting from buffer + 8 (abKey2Buffer area)\n\nParameters:\nnInputData     - Source integer value to convert to hash keys\npdwKey1        - Output pointer for first generated hash key\npdwKey2        - Output pointer for second generated hash key  \npdwKey3        - Output pointer for third generated hash key\n\nReturns:\nTRUE (1)  - Successfully generated three hash keys\nFALSE (0) - Input validation failed or checksum verification failed\n\nSpecial Cases:\nInput value 0 causes immediate return with all output keys set to zero.\nChecksum validation uses character conversion lookup table for weighted calculations.\nBuffer shuffle algorithm prevents predictable key generation from similar inputs.\n\nMagic Numbers Reference:\n0x20       - Hash buffer size (32 bytes)\n0x18       - Character weighting multiplier (24 decimal)\n0x100      - Overflow threshold (256 decimal)  \n0x30       - ASCII offset for digits 0-9\n0x37       - ASCII offset for hex A-F (0x41 - 0x0A)\n0x57       - ASCII offset for lowercase conversion (-87 decimal)\n0x13AC9741 - Bit manipulation seed value\n0x16       - Buffer shuffle offset calculation base",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:7682baa14f171062ab7bc6a9f1f265a1"
    },
    "Bnclient_API_76853cc34d93": {
      "addresses": {
        "LoD/1.07": "0x6FF28610",
        "LoD/1.08": "0x6FF28630",
        "LoD/1.09": "0x6FF09240",
        "LoD/1.09b": "0x6FF09240",
        "LoD/1.09d": "0x6FF094A0",
        "LoD/1.10": "0x6FF09DA0"
      },
      "rvas": {
        "LoD/1.07": "0x8610",
        "LoD/1.08": "0x8630",
        "LoD/1.09": "0x9240",
        "LoD/1.09b": "0x9240",
        "LoD/1.09d": "0x94A0",
        "LoD/1.10": "0x9DA0"
      },
      "name": "WriteCacheEntryWithTimestamp",
      "signature": "bool WriteCacheEntryWithTimestamp(char * lpszFilePath, byte * * ppDataBuffer, char * lpszDataLength, _FILETIME * pftTimestamps, byte byStartTick, byte byEndTick)",
      "comment": "Cache entry writer with timestamp validation and file integrity management.\n\nAlgorithm:\n1. Validate input parameters (file path, data buffer, length, timestamps, timing values)\n2. Enter critical section to protect cache data structures\n3. Clear any existing cache entries for the file path using hash lookup\n4. Search for available cache slot by checking data size requirements\n5. If no suitable slot found, scan existing entries for expired/invalid entries\n6. Calculate hash values for file path using three different hash algorithms\n7. Find empty hash table slot using linear probing collision resolution\n8. Create cache entry header with CRC32 validation and timestamp information\n9. Update system timestamps using GetSystemTime and SystemTimeToFileTime APIs\n10. Apply timing calculations for start/end tick conversion to file time format\n11. Generate CRC32 checksums for both data payload and cache header structures\n12. Write cache header (324 bytes) and data payload to cache file\n13. Update hash table and block table with encrypted/obfuscated entries\n14. Calculate and write final CRC32 checksums for hash and block tables\n15. Write updated cache file header with validation checksums\n16. Handle error conditions with specific error codes and cleanup operations\n\nParameters:\nlpszFilePath - File path string for cache key identification\nppDataBuffer - Double pointer to data buffer for cache storage\npbDataLength - Character pointer representing data length value\npftTimestamps - Pointer to FILETIME structures for timestamp validation\ndwStartTick - Start timing tick value for duration calculation\ndwEndTick - End timing tick value for duration calculation\n\nReturns:\ntrue - Cache entry successfully written and validated\nfalse - Operation failed due to invalid parameters, file errors, or cache corruption\n\nSpecial Cases:\nFile path validation rejects NULL pointers, empty strings, or paths exceeding 16MB limit\nCache corruption triggers cleanup of bncache.dat file and reinitialization\nHash table collisions resolved using linear probing with 1024-slot limit\nCRC32 validation failures cause error reporting and cache invalidation\n\nMagic Numbers Reference:\n0x144 (324 decimal) - Cache entry header size including CRC32 validation data\n0x400 (1024 decimal) - Maximum cache slots for hash table and block table\n0x10000000 (16MB decimal) - Maximum allowed file path data size limit\n0x7fed7fed - Initial hash seed value for primary hash algorithm calculation\n0xeeeeeeee - Initial hash seed for secondary hash algorithm calculation\n0xfffffffe (-2 decimal) - Marker value for deleted/invalid cache hash entries\n0xffffffff (-1 decimal) - Marker value for empty/unused cache hash entries\n\nError Handling:\nError code 0x0b - Cache slot table exhausted, no available entries\nError code 0x0c - Hash table slot collision, cannot find empty slot\nError code 0x0d - Cache header write failed, file system error\nError code 0x0e - Data payload write failed, insufficient disk space\nError code 0x0f - Hash table write failed, cache file corruption detected\nError code 0x10 - Block table write failed, cache structure damaged\nError code 0x11 - Cache file header write failed, critical file system error\n\nStructure Layout:\nCache Header (324 bytes total):\nOffset  Size  Field Name           Type    Description\n0x00    4     dwHeaderMagic        DWORD   Always 0x144 for validation\n0x04    320   abCacheData          BYTE[]  Encrypted cache entry data\n0x140   4     dwHeaderCrc32        DWORD   CRC32 checksum of entire header\n\nHash Table Entry (16 bytes per slot):\nOffset  Size  Field Name           Type    Description  \n0x00    4     dwPrimaryHash        DWORD   Primary file path hash value\n0x04    4     dwSecondaryHash      DWORD   Secondary file path hash value\n0x08    4     dwFlags              DWORD   Entry status and validation flags\n0x0c    4     dwSlotIndex          DWORD   Block table slot index reference\n\nFlag Bits:\n0xfffffffe - Deleted entry marker (entry was removed but slot occupied)\n0xffffffff - Empty slot marker (slot never used or properly cleared)\n0x00000000 to 0x000003ff - Valid slot index (0-1023 decimal range)",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:76853cc34d93dc688b28820d12f9d501"
    },
    "Bnclient_API_83311ac54b24": {
      "addresses": {
        "LoD/1.07": "0x6FF257D0",
        "LoD/1.08": "0x6FF257F0",
        "LoD/1.09": "0x6FF06150",
        "LoD/1.09b": "0x6FF06150",
        "LoD/1.09d": "0x6FF063C0",
        "LoD/1.10": "0x6FF06320"
      },
      "rvas": {
        "LoD/1.07": "0x57D0",
        "LoD/1.08": "0x57F0",
        "LoD/1.09": "0x6150",
        "LoD/1.09b": "0x6150",
        "LoD/1.09d": "0x63C0",
        "LoD/1.10": "0x6320"
      },
      "name": "QueueBattleNetMessage",
      "signature": "int QueueBattleNetMessage(int nMessageId, byte * pbData, int nDataSize)",
      "comment": "Queues a message for transmission to Battle.net servers with thread-safe packet management.\n\nAlgorithm:\n1. Allocate NetworkPacket structure via Ordinal_10042 (FOG memory allocator)\n2. Validate data size against maximum limit (0x120 = 288 bytes)\n3. If size exceeds limit, truncate to maximum allowed size\n4. Copy message data from source buffer using optimized 32-bit copy loops\n5. Handle remaining bytes with byte-by-byte copy for alignment\n6. Store message ID, data size, and initialize flags in packet structure\n7. Enter critical section for thread-safe queue manipulation\n8. Insert packet into linked list queue (g_abGlobalStringBuffer queue)\n9. Update queue head and tail pointers atomically\n10. Exit critical section and return success status\n11. If size validation fails, trigger fatal error via Ordinal_10023\n\nParameters:\nnMessageId - Battle.net message type identifier stored in packet header\npbData - Source buffer containing message payload data to transmit  \nnDataSize - Size in bytes of data to copy (validated against 0x120 limit)\n\nReturns:\n1 (TRUE) - Message successfully queued for transmission\nDOES NOT RETURN - Fatal error if size exceeds maximum after truncation\n\nSpecial Cases:\nEmpty messages (nDataSize = 0) are handled by null-terminating data buffer\nSize limit enforcement prevents buffer overflow attacks\nCritical section prevents race conditions in multi-threaded environment\nFatal error path indicates programming error, not runtime exception\n\nMagic Numbers Reference:\n0x39 - Allocation units for NetworkPacket structure (57 * 4 = 228 bytes minimum)\n0x120 - Maximum message data payload size (288 bytes)\n0x121 - Size limit boundary check (289 bytes) \n0x124 - Offset to dwDataSize field in NetworkPacket (offset 0x49 * 4)\n0x128 - Offset to dwFlags field in NetworkPacket (offset 0x4A * 4)\n0x130 - Offset to critical section in g_abGlobalStringBuffer\n0x336 - Offset to queue head pointer in g_abGlobalStringBuffer  \n0x340 - Offset to queue tail pointer in g_abGlobalStringBuffer\n\nError Handling:\nSize validation failure triggers Ordinal_10023 fatal error handler\nMemory allocation failure would cause access violation (no null check)\nCritical section protects against queue corruption in threaded environment\n\nStructure Layout:\nNetworkPacket (304 bytes total):\nOffset | Size | Field Name | Type        | Description\n0x00   | 4    | dwMessageId| uint        | Message type identifier  \n0x04   | 288  | abData     | byte[288]   | Message payload buffer\n0x124  | 4    | dwDataSize | uint        | Actual payload size\n0x128  | 4    | dwFlags    | uint        | Processing flags (unused = 0)\n0x12C  | 4    | pNext      | void*       | Next packet in queue",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:83311ac54b246d6943903bb686f0e640"
    },
    "Bnclient_API_8351e794ae97": {
      "addresses": {
        "LoD/1.09": "0x6FF15030",
        "LoD/1.09b": "0x6FF15030",
        "LoD/1.09d": "0x6FF15350",
        "LoD/1.10": "0x6FF158E0"
      },
      "rvas": {
        "LoD/1.09": "0x15030",
        "LoD/1.09b": "0x15030",
        "LoD/1.09d": "0x15350",
        "LoD/1.10": "0x158E0"
      },
      "method": "API",
      "index": "API:8351e794ae978939ec419b90712afc39"
    },
    "Bnclient_API_842d48b28050": {
      "addresses": {
        "LoD/1.11": "0x6FF33060",
        "LoD/1.11b": "0x6FF34350",
        "LoD/1.12a": "0x6FF360A0",
        "LoD/1.13c": "0x6FF31BF0",
        "LoD/1.13d": "0x6FF33920"
      },
      "rvas": {
        "LoD/1.11": "0x13060",
        "LoD/1.11b": "0x14350",
        "LoD/1.12a": "0x160A0",
        "LoD/1.13c": "0x11BF0",
        "LoD/1.13d": "0x13920"
      },
      "method": "API",
      "index": "API:842d48b28050bd89864d7bb1674e62f7"
    },
    "Bnclient_API_8a6e4f8594c0": {
      "addresses": {
        "LoD/1.11": "0x6FF30FA0",
        "LoD/1.11b": "0x6FF35AE0",
        "LoD/1.12a": "0x6FF31B30",
        "LoD/1.13c": "0x6FF35C10",
        "LoD/1.13d": "0x6FF35670"
      },
      "rvas": {
        "LoD/1.11": "0x10FA0",
        "LoD/1.11b": "0x15AE0",
        "LoD/1.12a": "0x11B30",
        "LoD/1.13c": "0x15C10",
        "LoD/1.13d": "0x15670"
      },
      "method": "API",
      "index": "API:8a6e4f8594c00b4cb9efa909dc55bb3e"
    },
    "Bnclient_API_9899166e0e53": {
      "addresses": {
        "LoD/1.11": "0x6FF35D50",
        "LoD/1.11b": "0x6FF2D9A0",
        "LoD/1.12a": "0x6FF2D000",
        "LoD/1.13c": "0x6FF2E120",
        "LoD/1.13d": "0x6FF32290"
      },
      "rvas": {
        "LoD/1.11": "0x15D50",
        "LoD/1.11b": "0xD9A0",
        "LoD/1.12a": "0xD000",
        "LoD/1.13c": "0xE120",
        "LoD/1.13d": "0x12290"
      },
      "method": "API",
      "index": "API:9899166e0e53eefd94403b4742255ea2"
    },
    "Bnclient_API_a0d5134936a6": {
      "addresses": {
        "LoD/1.11": "0x6FF34780",
        "LoD/1.11b": "0x6FF2C820",
        "LoD/1.12a": "0x6FF2BE80",
        "LoD/1.13c": "0x6FF2CFA0",
        "LoD/1.13d": "0x6FF30CC0"
      },
      "rvas": {
        "LoD/1.11": "0x14780",
        "LoD/1.11b": "0xC820",
        "LoD/1.12a": "0xBE80",
        "LoD/1.13c": "0xCFA0",
        "LoD/1.13d": "0x10CC0"
      },
      "method": "API",
      "index": "API:a0d5134936a623001790ecda7c268540"
    },
    "Bnclient_API_a4d956281286": {
      "addresses": {
        "LoD/1.11": "0x6FF305E0",
        "LoD/1.11b": "0x6FF32FE0",
        "LoD/1.12a": "0x6FF36510",
        "LoD/1.13c": "0x6FF32060",
        "LoD/1.13d": "0x6FF2E850"
      },
      "rvas": {
        "LoD/1.11": "0x105E0",
        "LoD/1.11b": "0x12FE0",
        "LoD/1.12a": "0x16510",
        "LoD/1.13c": "0x12060",
        "LoD/1.13d": "0xE850"
      },
      "method": "API",
      "index": "API:a4d956281286f0d6c8c9092f9365f899"
    },
    "Bnclient_API_a8077b8ba5ca": {
      "addresses": {
        "LoD/1.11": "0x6FF2AAB0",
        "LoD/1.11b": "0x6FF2AAB0",
        "LoD/1.12a": "0x6FF2B0E0",
        "LoD/1.13c": "0x6FF2B0C0",
        "LoD/1.13d": "0x6FF2B0D0"
      },
      "rvas": {
        "LoD/1.11": "0xAAB0",
        "LoD/1.11b": "0xAAB0",
        "LoD/1.12a": "0xB0E0",
        "LoD/1.13c": "0xB0C0",
        "LoD/1.13d": "0xB0D0"
      },
      "method": "API",
      "index": "API:a8077b8ba5cab84532a27f1cd035bf5a"
    },
    "Bnclient_API_af32ec05c83d": {
      "addresses": {
        "LoD/1.11": "0x6FF2B710",
        "LoD/1.11b": "0x6FF33930",
        "LoD/1.12a": "0x6FF33600",
        "LoD/1.13c": "0x6FF2BD40",
        "LoD/1.13d": "0x6FF32A20"
      },
      "rvas": {
        "LoD/1.11": "0xB710",
        "LoD/1.11b": "0x13930",
        "LoD/1.12a": "0x13600",
        "LoD/1.13c": "0xBD40",
        "LoD/1.13d": "0x12A20"
      },
      "method": "API",
      "index": "API:af32ec05c83d41c1d48a0e836007b63c"
    },
    "Bnclient_API_b224d7889c50": {
      "addresses": {
        "LoD/1.10": "0x6FF06D50",
        "LoD/1.11": "0x6FF2CA00",
        "LoD/1.11b": "0x6FF35220",
        "LoD/1.12a": "0x6FF2B800",
        "LoD/1.13c": "0x6FF32A70",
        "LoD/1.13d": "0x6FF347A0"
      },
      "rvas": {
        "LoD/1.10": "0x6D50",
        "LoD/1.11": "0xCA00",
        "LoD/1.11b": "0x15220",
        "LoD/1.12a": "0xB800",
        "LoD/1.13c": "0x12A70",
        "LoD/1.13d": "0x147A0"
      },
      "method": "API",
      "index": "API:b224d7889c5087907e18d1e1ec5c86f7"
    },
    "Bnclient_API_b8a70fdeafe7": {
      "addresses": {
        "LoD/1.11": "0x6FF2BEF0",
        "LoD/1.11b": "0x6FF34190",
        "LoD/1.12a": "0x6FF33D00",
        "LoD/1.13c": "0x6FF2C520",
        "LoD/1.13d": "0x6FF33170"
      },
      "rvas": {
        "LoD/1.11": "0xBEF0",
        "LoD/1.11b": "0x14190",
        "LoD/1.12a": "0x13D00",
        "LoD/1.13c": "0xC520",
        "LoD/1.13d": "0x13170"
      },
      "method": "API",
      "index": "API:b8a70fdeafe78bc6b7f4f1407cba9631",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF076D0",
          "rva": "0x76D0",
          "confidence": 0.366,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF06FE0",
          "rva": "0x6FE0",
          "confidence": 0.296,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.10"
        },
        "LoD/1.09b": {
          "address": "0x6FF06D70",
          "rva": "0x6D70",
          "confidence": 0.194,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09": {
          "address": "0x6FF06D70",
          "rva": "0x6D70",
          "confidence": 0.142,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.09b"
        }
      }
    },
    "Bnclient_API_b97b99733404": {
      "addresses": {
        "LoD/1.11": "0x6FF2F720",
        "LoD/1.11b": "0x6FF35FB0",
        "LoD/1.12a": "0x6FF32000",
        "LoD/1.13c": "0x6FF360E0",
        "LoD/1.13d": "0x6FF35B40"
      },
      "rvas": {
        "LoD/1.11": "0xF720",
        "LoD/1.11b": "0x15FB0",
        "LoD/1.12a": "0x12000",
        "LoD/1.13c": "0x160E0",
        "LoD/1.13d": "0x15B40"
      },
      "method": "API",
      "index": "API:b97b997334049372b023b34396f9b7df"
    },
    "Bnclient_API_c2ef67340766": {
      "addresses": {
        "LoD/1.09": "0x6FF15110",
        "LoD/1.09b": "0x6FF15110",
        "LoD/1.09d": "0x6FF15430",
        "LoD/1.10": "0x6FF159C0",
        "LoD/1.11": "0x6FF29B70",
        "LoD/1.11b": "0x6FF29B70",
        "LoD/1.12a": "0x6FF2A1A0",
        "LoD/1.13c": "0x6FF2A180",
        "LoD/1.13d": "0x6FF2A190"
      },
      "rvas": {
        "LoD/1.09": "0x15110",
        "LoD/1.09b": "0x15110",
        "LoD/1.09d": "0x15430",
        "LoD/1.10": "0x159C0",
        "LoD/1.11": "0x9B70",
        "LoD/1.11b": "0x9B70",
        "LoD/1.12a": "0xA1A0",
        "LoD/1.13c": "0xA180",
        "LoD/1.13d": "0xA190"
      },
      "method": "API",
      "index": "API:c2ef67340766ee73c492be41229a7df3"
    },
    "Bnclient_API_c62e9ff05049": {
      "addresses": {
        "LoD/1.07": "0x6FF258A0",
        "LoD/1.08": "0x6FF258C0",
        "LoD/1.09": "0x6FF06220",
        "LoD/1.09b": "0x6FF06220",
        "LoD/1.09d": "0x6FF06490",
        "LoD/1.10": "0x6FF063F0"
      },
      "rvas": {
        "LoD/1.07": "0x58A0",
        "LoD/1.08": "0x58C0",
        "LoD/1.09": "0x6220",
        "LoD/1.09b": "0x6220",
        "LoD/1.09d": "0x6490",
        "LoD/1.10": "0x63F0"
      },
      "name": "CreateAndEnqueueMessageNode",
      "signature": "bool CreateAndEnqueueMessageNode(int nMessageId, char * lpszMessage)",
      "comment": "Creates a new message node and enqueues it to the global message queue.\nThis function allocates memory for a message structure, copies the input string,\ncalculates its length, and adds the node to a thread-safe global linked list queue.\nUsed for asynchronous message processing in the Battle.net client subsystem.\nCritical for maintaining message ordering and preventing data races during\nconcurrent access to the global message queue infrastructure.\n\nAlgorithm:\n1. Allocate memory for new MessageNode structure (94 bytes) using Ordinal_10042\n2. Copy input message string to node's szMessage buffer (max 288 bytes) using Ordinal_501\n3. Calculate string length using manual SCAS loop with 0xFFFFFFFF counter\n4. Initialize node fields: nMessageId, dwMessageLength, dwUnused (set to 0)\n5. Validate message length is within bounds (< 0x121 = 289 bytes)\n6. Enter critical section to protect global queue modification\n7. Add node to linked list queue using head/tail pointers\n8. Update global queue head and tail pointers atomically\n9. Exit critical section and return success (true)\n10. If message too long: call error handler and terminate process\n\nParameters:\nnMessageId: Unique identifier for the message type or source\nlpszMessage: Null-terminated string message to enqueue (max 288 chars)\n\nReturns:\ntrue: Message successfully enqueued to global queue\nfalse: Never returned (function terminates process on error)\n\nSpecial Cases:\nIf message length >= 289 bytes: Triggers fatal error via Ordinal_10023 and FUN_6ff2b29c\n\nStructure Layout:\nMessageNode (304 bytes total):\nOffset  Size  Field Name        Type     Description\n0x00    4     nMessageId        int      Message identifier\n0x04    288   szMessage         char[288] Message text buffer  \n0x124   4     dwMessageLength   uint     Length of message string\n0x128   4     dwUnused          uint     Reserved field (always 0)\n0x12C   4     pNextNode         void*    Pointer to next node in queue\n\nMagic Numbers Reference:\n0x5E (94): Allocation size for MessageNode structure\n0x120 (288): Maximum message buffer size in bytes\n0x121 (289): Maximum allowed message length threshold\n0xFFFFFFFF: String length calculation counter initial value",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:c62e9ff0504902836ea0f1bbca368c3e"
    },
    "Bnclient_API_c73b9eda445b": {
      "addresses": {
        "LoD/1.11": "0x6FF345B0",
        "LoD/1.11b": "0x6FF2C650",
        "LoD/1.12a": "0x6FF2BCB0",
        "LoD/1.13c": "0x6FF2CDD0",
        "LoD/1.13d": "0x6FF30AF0"
      },
      "rvas": {
        "LoD/1.11": "0x145B0",
        "LoD/1.11b": "0xC650",
        "LoD/1.12a": "0xBCB0",
        "LoD/1.13c": "0xCDD0",
        "LoD/1.13d": "0x10AF0"
      },
      "method": "API",
      "index": "API:c73b9eda445b44a62efc66b008bbda48"
    },
    "Bnclient_API_cf4576ce8f50": {
      "addresses": {
        "LoD/1.07": "0x6FF261F0",
        "LoD/1.08": "0x6FF26210",
        "LoD/1.09": "0x6FF06950",
        "LoD/1.09b": "0x6FF06950",
        "LoD/1.09d": "0x6FF06BC0",
        "LoD/1.10": "0x6FF07300",
        "LoD/1.11": "0x6FF2C240",
        "LoD/1.11b": "0x6FF344E0",
        "LoD/1.12a": "0x6FF33F10",
        "LoD/1.13c": "0x6FF2C860",
        "LoD/1.13d": "0x6FF33B60"
      },
      "rvas": {
        "LoD/1.07": "0x61F0",
        "LoD/1.08": "0x6210",
        "LoD/1.09": "0x6950",
        "LoD/1.09b": "0x6950",
        "LoD/1.09d": "0x6BC0",
        "LoD/1.10": "0x7300",
        "LoD/1.11": "0xC240",
        "LoD/1.11b": "0x144E0",
        "LoD/1.12a": "0x13F10",
        "LoD/1.13c": "0xC860",
        "LoD/1.13d": "0x13B60"
      },
      "name": "CreateAuthenticationPacket",
      "signature": "int CreateAuthenticationPacket(char * lpszChannelKey, char * lpszUsername, char * lpszPassword)",
      "comment": "Creates authentication packet by computing cryptographic hashes of credentials with timestamp and salt.\n\nAlgorithm:\n1. Copy username to buffer and compute length using Ordinal_501/506\n2. Convert username to lowercase using CharLowerBuffA\n3. Capture current timestamp using GetTickCount for packet uniqueness\n4. Extract 4-byte salt from global buffer at offset 0x15c-0x15f\n5. Compute hash of lowercase username using FUN_6ff2acd0\n6. Copy password to buffer and compute length using Ordinal_501/506\n7. Convert password to lowercase using CharLowerBuffA\n8. Create timestamped data structure with salt bytes\n9. Compute hash of timestamp and salt data (28 bytes) using FUN_6ff2acd0\n10. Compute hash of lowercase password using FUN_6ff2acd0\n11. Copy channel key to buffer using Ordinal_501\n12. Send complete authentication packet with SendNetworkPacketWithValidation\n\nParameters:\n  lpszChannelKey (char*) - Channel/realm identifier string for authentication\n  lpszUsername (char*) - User account name to authenticate\n  lpszPassword (char*) - User password for authentication\n\nReturns:\n  1 (int) - Always returns success after packet construction\n\nSpecial Cases:\n  Buffer sizes fixed at 128 bytes for credentials via 0x80 parameter\n  Timestamp provides replay protection via GetTickCount\n  Global salt buffer provides additional cryptographic entropy\n  All credentials converted to lowercase for case-insensitive comparison\n\nMagic Numbers Reference:\n  0x80 (128 bytes) - Maximum buffer size for credential strings\n  0x15c-0x15f - Global salt buffer offsets in g_abGlobalStringBuffer\n  0x1c (28 bytes) - Size of timestamp + salt structure for hashing",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:cf4576ce8f501f10c5955906f805a02a"
    },
    "Bnclient_API_d02d77d7e571": {
      "addresses": {
        "LoD/1.11": "0x6FF35890",
        "LoD/1.11b": "0x6FF2D4D0",
        "LoD/1.12a": "0x6FF2CB30",
        "LoD/1.13c": "0x6FF2DC50",
        "LoD/1.13d": "0x6FF31DD0"
      },
      "rvas": {
        "LoD/1.11": "0x15890",
        "LoD/1.11b": "0xD4D0",
        "LoD/1.12a": "0xCB30",
        "LoD/1.13c": "0xDC50",
        "LoD/1.13d": "0x11DD0"
      },
      "method": "API",
      "index": "API:d02d77d7e57115979a630ed7cd81f12c"
    },
    "Bnclient_API_d6c7cf90cfd8": {
      "addresses": {
        "LoD/1.07": "0x6FF24BF0",
        "LoD/1.08": "0x6FF24C10",
        "LoD/1.09": "0x6FF05570",
        "LoD/1.09b": "0x6FF05570",
        "LoD/1.09d": "0x6FF057E0",
        "LoD/1.10": "0x6FF05740",
        "LoD/1.11": "0x6FF363D0",
        "LoD/1.11b": "0x6FF30690"
      },
      "rvas": {
        "LoD/1.07": "0x4BF0",
        "LoD/1.08": "0x4C10",
        "LoD/1.09": "0x5570",
        "LoD/1.09b": "0x5570",
        "LoD/1.09d": "0x57E0",
        "LoD/1.10": "0x5740",
        "LoD/1.11": "0x163D0",
        "LoD/1.11b": "0x10690"
      },
      "name": "GMT",
      "signature": "int GMT(byte * pThis, int nStringCount)",
      "comment": "Process string collection from BNGateway data structure and convert to integer format.\n\nAlgorithm:\n1. Validate input parameters: check pThis is non-null and nStringCount is positive\n2. Verify nStringCount is within bounds of the buffer (offset +0x8)\n3. Extract buffer pointer from pThis structure (offset +0x10)\n4. Calculate total processing count as nStringCount * 3\n5. Initialize loop variables: nCurrentIndex=1, nBufferOffset=0\n6. Loop through string processing while nCurrentIndex < total count:\n   a. Check buffer bounds against structure limit (offset +0x14)\n   b. Exit loop if buffer would overflow\n   c. Call Ordinal_506 (string length function) on current buffer position\n   d. Advance buffer pointer by string length + 1 (null terminator)\n   e. Update buffer offset and increment current index\n7. Perform final buffer bounds validation\n8. Skip to buffer start if bounds check fails\n9. Process null-terminated string at final buffer position\n10. Call FUN_6ff2b921 with processed buffer and conversion parameter 0xa\n\nParameters:\npThis - Pointer to BNGatewayAccess structure containing buffer info\n  +0x8: Buffer size limit (int)\n  +0x10: Buffer data pointer (byte *)\n  +0x14: Buffer bounds check value (int)\nnStringCount - Number of strings to process from buffer\n\nReturns:\nResult from FUN_6ff2b921 conversion function\nSuccess: Converted integer value from processed strings\nError: Function-specific error code from conversion routine\n\nSpecial Cases:\nInvalid parameters (null pThis, count <= 0, count > buffer size) - Uses pThis as fallback buffer\nBuffer overflow during string processing - Exits loop early and uses accumulated position\nEmpty or null-terminated strings - Skips final string processing step\n\nMagic Numbers Reference:\n0x3 (3) - String processing multiplier for total count calculation\n0xa (10) - Decimal base parameter for final conversion call\n0x8 (8) - Offset to buffer size field in structure\n0x10 (16) - Offset to buffer pointer field in structure  \n0x14 (20) - Offset to buffer bounds field in structure",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:d6c7cf90cfd8e1f1153f8bd6ad14c372"
    },
    "Bnclient_API_d91bd47149d2": {
      "addresses": {
        "LoD/1.11": "0x6FF35350",
        "LoD/1.11b": "0x6FF2D3F0",
        "LoD/1.12a": "0x6FF2CA50",
        "LoD/1.13c": "0x6FF2DB70",
        "LoD/1.13d": "0x6FF31890"
      },
      "rvas": {
        "LoD/1.11": "0x15350",
        "LoD/1.11b": "0xD3F0",
        "LoD/1.12a": "0xCA50",
        "LoD/1.13c": "0xDB70",
        "LoD/1.13d": "0x11890"
      },
      "method": "API",
      "index": "API:d91bd47149d2daa3dde44e74cb438e6c"
    },
    "Bnclient_API_dd114cd9df6f": {
      "addresses": {
        "LoD/1.11": "0x6FF33B90",
        "LoD/1.11b": "0x6FF2EA60",
        "LoD/1.12a": "0x6FF2EEF0",
        "LoD/1.13c": "0x6FF34F20",
        "LoD/1.13d": "0x6FF36700"
      },
      "rvas": {
        "LoD/1.11": "0x13B90",
        "LoD/1.11b": "0xEA60",
        "LoD/1.12a": "0xEEF0",
        "LoD/1.13c": "0x14F20",
        "LoD/1.13d": "0x16700"
      },
      "name": "Name",
      "signature": "char * Name(int param_1)",
      "comment": "public: char * __stdcall BNGatewayAccess::Name(int)",
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:dd114cd9df6f79abe6a190e421d48bc6"
    },
    "Bnclient_API_e1a240c7f621": {
      "addresses": {
        "LoD/1.07": "0x6FF26170",
        "LoD/1.08": "0x6FF26190",
        "LoD/1.09": "0x6FF068D0",
        "LoD/1.09b": "0x6FF068D0",
        "LoD/1.09d": "0x6FF06B40",
        "LoD/1.10": "0x6FF07280",
        "LoD/1.11": "0x6FF2C3C0",
        "LoD/1.11b": "0x6FF34660",
        "LoD/1.12a": "0x6FF34090",
        "LoD/1.13c": "0x6FF2C9E0",
        "LoD/1.13d": "0x6FF33CE0"
      },
      "rvas": {
        "LoD/1.07": "0x6170",
        "LoD/1.08": "0x6190",
        "LoD/1.09": "0x68D0",
        "LoD/1.09b": "0x68D0",
        "LoD/1.09d": "0x6B40",
        "LoD/1.10": "0x7280",
        "LoD/1.11": "0xC3C0",
        "LoD/1.11b": "0x14660",
        "LoD/1.12a": "0x14090",
        "LoD/1.13c": "0xC9E0",
        "LoD/1.13d": "0x13CE0"
      },
      "name": "ProcessNetworkAuthenticationRequest",
      "signature": "int ProcessNetworkAuthenticationRequest(char * lpszDestBuffer, char * lpszSourceData)",
      "comment": "Processes network authentication request by preparing hashed data packets for validation.\n\nAlgorithm:\n1. Clear index table entry using colon prefix (0x3a) extracted from destination buffer\n2. Copy source authentication data to local processing buffer (128 bytes max)\n3. Calculate string length and convert to lowercase for case-insensitive processing\n4. Capture current tick count timestamp for packet timing validation\n5. Copy 4-byte global string buffer segment (indices 0x15c-0x15f) as authentication salt\n6. Generate first hash using processed string data and calculated length\n7. Duplicate timestamp and salt data for second hash computation\n8. Generate second hash using timestamp and salt data (28 bytes total)\n9. Copy destination buffer data to final output buffer (128 bytes max)\n10. Send combined authentication packet with validation hashes\n11. Return success status (1)\n\nParameters:\n- lpszDestBuffer (char*): Destination buffer containing colon prefix and target data\n- lpszSourceData (char*): Source authentication data to be processed and validated\n\nReturns:\n- int: Always returns 1 (success) - no error conditions handled\n\nSpecial Cases:\n- Function always succeeds - no validation of buffer sizes or null pointers\n- Global string buffer access at fixed indices (0x15c-0x15f) provides authentication salt\n- Both string operations limited to 128 bytes (0x80) to prevent buffer overflow\n\nMagic Numbers Reference:\n- 0x3a: Colon character (:) used as command prefix delimiter\n- 0x80: 128-byte buffer size limit for string operations\n- 0x15c-0x15f: Global string buffer indices for authentication salt (4 bytes)\n- 0x1c: 28 bytes of timestamp + salt data for second hash computation\n\nError Handling:\n- No error checking - assumes valid input buffers and successful API calls\n- Relies on called functions for buffer overflow protection\n- Network packet transmission assumed to succeed",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:e1a240c7f6210dc881fb0336483a53ff"
    },
    "Bnclient_API_e955ea152214": {
      "addresses": {
        "LoD/1.07": "0x6FF21EF0",
        "LoD/1.08": "0x6FF21F10",
        "LoD/1.09": "0x6FF01FD0",
        "LoD/1.09b": "0x6FF01FD0",
        "LoD/1.09d": "0x6FF01FA0",
        "LoD/1.10": "0x6FF01F70",
        "LoD/1.11": "0x6FF2D5C0",
        "LoD/1.11b": "0x6FF2B5A0",
        "LoD/1.12a": "0x6FF2D9E0",
        "LoD/1.13c": "0x6FF2EB00",
        "LoD/1.13d": "0x6FF2CEF0"
      },
      "rvas": {
        "LoD/1.07": "0x1EF0",
        "LoD/1.08": "0x1F10",
        "LoD/1.09": "0x1FD0",
        "LoD/1.09b": "0x1FD0",
        "LoD/1.09d": "0x1FA0",
        "LoD/1.10": "0x1F70",
        "LoD/1.11": "0xD5C0",
        "LoD/1.11b": "0xB5A0",
        "LoD/1.12a": "0xD9E0",
        "LoD/1.13c": "0xEB00",
        "LoD/1.13d": "0xCEF0"
      },
      "name": "SendNetworkPacketWithValidation",
      "signature": "dword SendNetworkPacketWithValidation(void)",
      "comment": "Validates network connection state and sends packet data to server.\n\nAlgorithm:\n1. Call FUN_6ff2b240() for initialization/setup\n2. Check if active server connection exists (g_pActiveServerConnection != 0)\n3. Check if connection abort is not requested (g_dwAbortConnection == 0)\n4. If either check fails, call FUN_6ff22200() for cleanup and return 0\n5. If extraout_EDX is 0, set in_stack_00002008 to 0 (reset packet size)\n6. Call Ordinal_491() to prepare initial 4-byte packet header\n7. If extraout_EDX contains data and total size < 0x2000, call Ordinal_491() again for packet body\n8. Call Ordinal_10007() with total packet size to send data\n9. Return result from packet send operation\n\nParameters:\nNone (void function)\nIMPLICIT extraout_EDX: Packet data size or buffer pointer from previous call\nIMPLICIT in_stack_00002008: Current packet buffer size on stack\n\nReturns:\ndword dwResult: 0 on failure/no connection, non-zero on successful packet send\n  0x00000000 - No active connection or connection aborted\n  Other values - Success status from Ordinal_10007 packet send operation\n\nSpecial Cases:\n- Maximum packet size limit of 0x2000 bytes enforced\n- Function allocates 0x2004 bytes of stack space for packet buffer\n- Handles both header-only packets (4 bytes) and packets with body data\n- Early return with cleanup if connection validation fails\n\nMagic Numbers Reference:\n0x2004 - Stack allocation size (8196 bytes)\n0x2000 - Maximum packet size limit (8192 bytes)  \n0x4 - Minimum packet header size (4 bytes)",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:e955ea1522144f47fcc1913322a47574"
    },
    "Bnclient_API_e978514103fa": {
      "addresses": {
        "LoD/1.07": "0x6FF24CF0",
        "LoD/1.08": "0x6FF24D10",
        "LoD/1.09": "0x6FF05670",
        "LoD/1.09b": "0x6FF05670",
        "LoD/1.09d": "0x6FF058E0",
        "LoD/1.10": "0x6FF05850"
      },
      "rvas": {
        "LoD/1.07": "0x4CF0",
        "LoD/1.08": "0x4D10",
        "LoD/1.09": "0x5670",
        "LoD/1.09b": "0x5670",
        "LoD/1.09d": "0x58E0",
        "LoD/1.10": "0x5850"
      },
      "name": "Realm",
      "signature": "char * Realm(int * pRealmListContext, int nRealmIndex)",
      "comment": "Retrieves the realm name string for a specific realm index from Battle.net gateway realm list.\n\nAlgorithm:\n1. Validate realm context pointer and verify realm index bounds (0 < index <= realm count)\n2. Calculate realm data offset by multiplying index by 3 (each realm has 3 string entries)  \n3. Iterate through realm data structure, advancing string pointers using strlen operations\n4. Track current position in realm list until reaching target index\n5. Verify calculated offset doesn't exceed buffer bounds to prevent overflow\n6. Search through realm string entries using strncmp to match target realm\n7. Skip realm entries by advancing pointer past each null-terminated string\n8. Return pointer to realm name string if found, or default path if not found\n\nParameters:\npRealmListContext - Pointer to realm list context structure containing:\n  +0x08: Total realm count (int)\n  +0x10: Realm data buffer pointer (char*)\n  +0x14: Buffer size limit (int) \n  +0x20: Realm string data pointer (char*)\nIMPLICIT nRealmIndex - Realm index to search for (1-based indexing)\n\nReturns:\nchar* - Pointer to realm name string if valid index found\nchar* - Pointer to default destination path (g_lpszDefaultDestPath) if invalid index\n\nSpecial Cases:\n- Returns default path if realm context is NULL\n- Returns default path if realm index <= 0 or > realm count\n- Returns default path if buffer offset calculation would overflow\n- Returns default path if realm string data is empty or NULL\n\nStructure Layout:\nOffset  Size  Field Name       Type    Description\n+0x08   4     nRealmCount      int     Total number of realms available\n+0x10   4     pRealmData       char*   Pointer to realm data buffer  \n+0x14   4     nBufferSize      int     Maximum buffer size limit\n+0x20   4     pRealmStrings    char*   Pointer to realm string data\n\nMagic Numbers Reference:\n0x08 - Offset to realm count field\n0x10 - Offset to realm data pointer field  \n0x14 - Offset to buffer size field\n0x20 - Offset to realm strings pointer field\n0x7fffffff - Maximum string comparison length for strncmp",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:e978514103fa178222b211f15ba2992f"
    },
    "Bnclient_API_eb10ff843512": {
      "addresses": {
        "LoD/1.11": "0x6FF321C0",
        "LoD/1.11b": "0x6FF35D40",
        "LoD/1.12a": "0x6FF31D90",
        "LoD/1.13c": "0x6FF35E70",
        "LoD/1.13d": "0x6FF358D0"
      },
      "rvas": {
        "LoD/1.11": "0x121C0",
        "LoD/1.11b": "0x15D40",
        "LoD/1.12a": "0x11D90",
        "LoD/1.13c": "0x15E70",
        "LoD/1.13d": "0x158D0"
      },
      "method": "API",
      "index": "API:eb10ff8435120b3c720eabae1a6eb481"
    },
    "Bnclient_API_ee9fa014ce67": {
      "addresses": {
        "LoD/1.07": "0x6FF21920",
        "LoD/1.08": "0x6FF21940",
        "LoD/1.09": "0x6FF01920",
        "LoD/1.09b": "0x6FF01920",
        "LoD/1.09d": "0x6FF018F0",
        "LoD/1.10": "0x6FF018C0",
        "LoD/1.11": "0x6FF2DE80",
        "LoD/1.11b": "0x6FF2BE20",
        "LoD/1.12a": "0x6FF2E2A0",
        "LoD/1.13c": "0x6FF2F3C0",
        "LoD/1.13d": "0x6FF2D570"
      },
      "rvas": {
        "LoD/1.07": "0x1920",
        "LoD/1.08": "0x1940",
        "LoD/1.09": "0x1920",
        "LoD/1.09b": "0x1920",
        "LoD/1.09d": "0x18F0",
        "LoD/1.10": "0x18C0",
        "LoD/1.11": "0xDE80",
        "LoD/1.11b": "0xBE20",
        "LoD/1.12a": "0xE2A0",
        "LoD/1.13c": "0xF3C0",
        "LoD/1.13d": "0xD570"
      },
      "name": "InitializeBNetGatewayConnection",
      "signature": "void InitializeBNetGatewayConnection(byte * pOutputBuffer, uint dwConnectionFlags)",
      "comment": "Initialize Battle.net connection and resolve gateway address\n\nAlgorithm:\n1. Zero-initialize the output connection buffer to prepare for address storage\n2. Load Battle.net gateway access system via BNGatewayAccess::Load()\n3. Resolve primary gateway DNS address using configured gateway hostname\n4. Attempt primary connection using resolved DNS address and connection flags\n5. Query Windows registry for backup \"BNETIP\" override address in \"Diablo II\" key\n6. If registry query succeeds (non-zero return), attempt fallback connection using registry IP\n7. Return after connection attempts complete\n\nParameters:\npOutputBuffer (byte *): Output buffer for storing resolved IP address string\ndwConnectionFlags (uint): Connection configuration flags and options\n\nReturns:\nvoid - Function performs initialization only, connection status determined by callees\n\nSpecial Cases:\nRegistry fallback only activates if Ordinal_422 returns non-zero success code\nUses 0x100 (256) byte buffer size for IP address string storage\nPrimary DNS resolution uses hardcoded gateway configuration at 0x6ff39af8\nRegistry query targets \"Diablo II\" application key and \"BNETIP\" value name\n\nMagic Numbers Reference:\n0x6ff39af8 - Pointer to Battle.net gateway hostname configuration\n0x6ff35288 - Pointer to \"Diablo II\" registry key name string\n0x6ff35294 - Pointer to \"BNETIP\" registry value name string  \n0x100 (256) - Buffer size for IP address string storage",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:ee9fa014ce67a62f7995858fb3d3d722"
    },
    "Bnclient_API_f0a06a107d78": {
      "addresses": {
        "LoD/1.13d": "0x6FF32DF0"
      },
      "rvas": {
        "LoD/1.13d": "0x12DF0"
      },
      "method": "API",
      "index": "API:f0a06a107d789a5ba4b1502d9b91f5b4",
      "candidates": {
        "LoD/1.13c": {
          "address": "0x6FF2C220",
          "rva": "0xC220",
          "confidence": 0.696,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.13d"
        },
        "LoD/1.12a": {
          "address": "0x6FF33990",
          "rva": "0x13990",
          "confidence": 0.564,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.13c"
        },
        "LoD/1.11b": {
          "address": "0x6FF33E20",
          "rva": "0x13E20",
          "confidence": 0.411,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.12a"
        },
        "LoD/1.11": {
          "address": "0x6FF2BBF0",
          "rva": "0xBBF0",
          "confidence": 0.27,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11b"
        }
      }
    },
    "Bnclient_API_f227016f3ca0": {
      "addresses": {
        "LoD/1.07": "0x6FF27180",
        "LoD/1.08": "0x6FF271A0",
        "LoD/1.09": "0x6FF075E0",
        "LoD/1.09b": "0x6FF075E0",
        "LoD/1.09d": "0x6FF07810",
        "LoD/1.10": "0x6FF07E40",
        "LoD/1.11": "0x6FF32610",
        "LoD/1.11b": "0x6FF33490",
        "LoD/1.12a": "0x6FF34C80",
        "LoD/1.13c": "0x6FF307D0",
        "LoD/1.13d": "0x6FF33480"
      },
      "rvas": {
        "LoD/1.07": "0x7180",
        "LoD/1.08": "0x71A0",
        "LoD/1.09": "0x75E0",
        "LoD/1.09b": "0x75E0",
        "LoD/1.09d": "0x7810",
        "LoD/1.10": "0x7E40",
        "LoD/1.11": "0x12610",
        "LoD/1.11b": "0x13490",
        "LoD/1.12a": "0x14C80",
        "LoD/1.13c": "0x107D0",
        "LoD/1.13d": "0x13480"
      },
      "name": "CopyDataToGlobalBuffer",
      "signature": "void CopyDataToGlobalBuffer(void * pSourceData, uint dwByteCount)",
      "comment": "Copies data from source buffer to global string buffer with allocation management.\n\nAlgorithm:\n1. Check if global buffer is already allocated - if so, free it with Ordinal_10043\n2. Clear 4 bytes of buffer header at offset 0x164-0x167 to reset state\n3. Allocate new buffer space using Ordinal_10042 with parameters (0x1cb, 0)\n4. Store allocation pointer in global buffer field at offset 0x356\n5. Perform optimized memory copy: first copy 4-byte chunks (DWORD aligned)\n6. Handle remaining 1-3 bytes with byte-wise copy for partial DWORD at end\n\nParameters:\npSourceData (void *): Source buffer to copy data from\ndwByteCount (uint): Number of bytes to copy from source to global buffer\n\nReturns:\nvoid: No return value, operation success indicated by global buffer state\n\nSpecial Cases:\n- Zero byte count: Function completes without error but no data copied\n- Unaligned byte counts: Handled by separate byte-wise loop for remainder\n- Prior allocation: Automatically freed before new allocation to prevent leaks\n\nMagic Numbers Reference:\n0x1d4 (468): Ordinal parameter for buffer deallocation function\n0x1cb (459): Ordinal parameter for buffer allocation function  \n0x164 (356): Offset to buffer header start for state reset\n0x356 (854): Offset to allocation pointer storage in global buffer",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:f227016f3ca055ed4282069acb9176e8"
    },
    "Bnclient_API_f23b3308f647": {
      "addresses": {
        "LoD/1.11": "0x6FF33A80",
        "LoD/1.11b": "0x6FF2E950",
        "LoD/1.12a": "0x6FF2EDE0",
        "LoD/1.13c": "0x6FF34E10",
        "LoD/1.13d": "0x6FF36580"
      },
      "rvas": {
        "LoD/1.11": "0x13A80",
        "LoD/1.11b": "0xE950",
        "LoD/1.12a": "0xEDE0",
        "LoD/1.13c": "0x14E10",
        "LoD/1.13d": "0x16580"
      },
      "name": "FindSection",
      "signature": "char * FindSection(BNGatewayAccess * this, char * param_1, char * param_2)",
      "comment": "private: char * __thiscall BNGatewayAccess::FindSection(char *,char *)",
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:f23b3308f6472a53e3242f4dfd3ea732"
    },
    "Bnclient_API_f308b19fec30": {
      "addresses": {
        "LoD/1.11": "0x6FF2A070",
        "LoD/1.11b": "0x6FF2A070",
        "LoD/1.12a": "0x6FF2A6A0",
        "LoD/1.13c": "0x6FF2A680",
        "LoD/1.13d": "0x6FF2A690"
      },
      "rvas": {
        "LoD/1.11": "0xA070",
        "LoD/1.11b": "0xA070",
        "LoD/1.12a": "0xA6A0",
        "LoD/1.13c": "0xA680",
        "LoD/1.13d": "0xA690"
      },
      "method": "API",
      "index": "API:f308b19fec30e94fec0d966782461c09"
    },
    "Bnclient_API_f4c47addc5a0": {
      "addresses": {
        "LoD/1.11": "0x6FF2AC10",
        "LoD/1.11b": "0x6FF2AC10",
        "LoD/1.12a": "0x6FF2B240",
        "LoD/1.13c": "0x6FF2B220",
        "LoD/1.13d": "0x6FF2B230"
      },
      "rvas": {
        "LoD/1.11": "0xAC10",
        "LoD/1.11b": "0xAC10",
        "LoD/1.12a": "0xB240",
        "LoD/1.13c": "0xB220",
        "LoD/1.13d": "0xB230"
      },
      "method": "API",
      "index": "API:f4c47addc5a02dd788c8cde1db15e2e0"
    },
    "Bnclient_API_f55a67251dc4": {
      "addresses": {
        "LoD/1.09": "0x6FF07DC0",
        "LoD/1.09b": "0x6FF07DC0",
        "LoD/1.09d": "0x6FF08020",
        "LoD/1.11": "0x6FF30500",
        "LoD/1.11b": "0x6FF32F00",
        "LoD/1.12a": "0x6FF36430",
        "LoD/1.13c": "0x6FF31F80",
        "LoD/1.13d": "0x6FF2E770"
      },
      "rvas": {
        "LoD/1.09": "0x7DC0",
        "LoD/1.09b": "0x7DC0",
        "LoD/1.09d": "0x8020",
        "LoD/1.11": "0x10500",
        "LoD/1.11b": "0x12F00",
        "LoD/1.12a": "0x16430",
        "LoD/1.13c": "0x11F80",
        "LoD/1.13d": "0xE770"
      },
      "method": "API",
      "index": "API:f55a67251dc44f9a1f8626ecc34632dc"
    },
    "Bnclient_API_f5b5b42d2d1f": {
      "addresses": {
        "LoD/1.10": "0x6FF06D90",
        "LoD/1.11": "0x6FF211C0",
        "LoD/1.11b": "0x6FF21170",
        "LoD/1.12a": "0x6FF21220",
        "LoD/1.13c": "0x6FF211C0",
        "LoD/1.13d": "0x6FF211C0"
      },
      "rvas": {
        "LoD/1.10": "0x6D90",
        "LoD/1.11": "0x11C0",
        "LoD/1.11b": "0x1170",
        "LoD/1.12a": "0x1220",
        "LoD/1.13c": "0x11C0",
        "LoD/1.13d": "0x11C0"
      },
      "method": "API",
      "index": "API:f5b5b42d2d1fed227d4fa043a66edba4"
    },
    "Bnclient_API_f6065b591951": {
      "addresses": {
        "LoD/1.12a": "0x6FF32BD0",
        "LoD/1.13c": "0x6FF30620",
        "LoD/1.13d": "0x6FF30920"
      },
      "rvas": {
        "LoD/1.12a": "0x12BD0",
        "LoD/1.13c": "0x10620",
        "LoD/1.13d": "0x10920"
      },
      "method": "API",
      "index": "API:f6065b5919516f6116f7f60d4631d3e6"
    },
    "Bnclient_API_f9b74334df81": {
      "addresses": {
        "LoD/1.09": "0x6FF15060",
        "LoD/1.09b": "0x6FF15060",
        "LoD/1.09d": "0x6FF15380",
        "LoD/1.10": "0x6FF15910",
        "LoD/1.11": "0x6FF2A300",
        "LoD/1.11b": "0x6FF2A300",
        "LoD/1.12a": "0x6FF2A930",
        "LoD/1.13c": "0x6FF2A910",
        "LoD/1.13d": "0x6FF2A920"
      },
      "rvas": {
        "LoD/1.09": "0x15060",
        "LoD/1.09b": "0x15060",
        "LoD/1.09d": "0x15380",
        "LoD/1.10": "0x15910",
        "LoD/1.11": "0xA300",
        "LoD/1.11b": "0xA300",
        "LoD/1.12a": "0xA930",
        "LoD/1.13c": "0xA910",
        "LoD/1.13d": "0xA920"
      },
      "method": "API",
      "index": "API:f9b74334df815e1422deaf893b2f5fca"
    },
    "Bnclient_API_fec99b7d337c": {
      "addresses": {
        "LoD/1.11": "0x6FF2A960",
        "LoD/1.11b": "0x6FF2A960",
        "LoD/1.12a": "0x6FF2AF90",
        "LoD/1.13c": "0x6FF2AF70",
        "LoD/1.13d": "0x6FF2AF80"
      },
      "rvas": {
        "LoD/1.11": "0xA960",
        "LoD/1.11b": "0xA960",
        "LoD/1.12a": "0xAF90",
        "LoD/1.13c": "0xAF70",
        "LoD/1.13d": "0xAF80"
      },
      "method": "API",
      "index": "API:fec99b7d337cf79e7c2bda9f3fa7e801"
    },
    "Bnclient_MNE_0002c858ef39": {
      "addresses": {
        "LoD/1.07": "0x6FF2EF29",
        "LoD/1.08": "0x6FF2EF49",
        "LoD/1.09": "0x6FF0FB74",
        "LoD/1.09b": "0x6FF0FB74",
        "LoD/1.09d": "0x6FF0FE59",
        "LoD/1.10": "0x6FF10447"
      },
      "rvas": {
        "LoD/1.07": "0xEF29",
        "LoD/1.08": "0xEF49",
        "LoD/1.09": "0xFB74",
        "LoD/1.09b": "0xFB74",
        "LoD/1.09d": "0xFE59",
        "LoD/1.10": "0x10447"
      },
      "name": "AllocateMemoryPool",
      "signature": "int AllocateMemoryPool(MemoryAllocation * pMemoryDescriptor)",
      "comment": "Allocates a new memory pool by creating a 32KB virtual memory page with linked list structure\n\nAlgorithm:\n1. Calculate pool index by bit-shifting the allocation bitmask to find first available slot\n2. Calculate pool structure address using formula: poolIndex * 0x204 + 0x144 + structBase\n3. Initialize 64 free list heads (0x3f + 1) as self-referencing circular linked lists\n4. Calculate virtual memory address: poolIndex * 0x8000 + baseAddress (32KB aligned)\n5. Allocate 32KB virtual memory page using VirtualAlloc with MEM_COMMIT and PAGE_READWRITE\n6. If allocation fails, return -1 to indicate failure\n7. Initialize memory page by creating linked list structures every 4KB (0x1000 bytes)\n8. Set up doubly-linked free block structures with sentinel values (-1) and size markers (0xff0)\n9. Link pool structure to memory page by storing pointers at calculated offsets\n10. Update pool management arrays: clear busy flag, set allocation count to 1\n11. Increment pool counter and set overflow flag if counter wraps from 0\n12. Clear pool availability bit in allocation bitmask using bit shift and mask operation\n\nParameters:\npMemoryDescriptor: Pointer to MemoryAllocation structure containing pool management data\n- +0x4: Pool availability flags (uint)\n- +0x8: Pool allocation bitmask (uint) \n- +0xc: Base virtual address for memory pools (uint)\n- +0x10: Pointer to pool management structure (MemoryPool*)\n\nReturns:\nPool index (0-31) on successful allocation\n-1 on allocation failure\n\nMagic Numbers:\n0x204 (516): Size of pool descriptor structure in bytes\n0x144 (324): Base offset in pool management structure  \n0x8000 (32768): Size of each memory pool page in bytes\n0x1000 (4096): Memory commit granularity and block stride\n0x3f (63): Maximum free list index (64 total lists: 0-63)\n0xff0 (4080): Block size marker for 4KB - 16 byte header\n0x1fc (508): Offset to first pool link pointer\n0x200 (512): Offset to second pool link pointer  \n0x44 (68): Offset to pool busy flags array\n0xc4 (196): Offset to pool allocation count array\n0x43 (67): Offset to pool counter byte\n0x80000000: Bit mask for pool availability (MSB)\n\nStructure Layout:\nMemoryAllocation (20 bytes):\nOffset  Size  Field                   Type    Description\n0x0     4     dwReserved1            uint    Reserved field 1\n0x4     4     dwPoolFlags            uint    Pool availability flags  \n0x8     4     dwPoolBitmask          uint    Pool allocation bitmask\n0xc     4     pBaseAddress           uint    Virtual memory base address\n0x10    4     pPoolStruct            uint    Pointer to MemoryPool structure\n\nSpecial Cases:\nPool counter overflow sets bit 0 in pool flags when wrapping from 255 to 0\nPool index calculation uses bit scanning to find first available slot\nMemory page initialization creates 7 linked list blocks (0x1c00 / 0x400 = 7)\nEach block has forward/backward pointers and size markers for memory management",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0002c858ef3942a0b403454c72674bfe"
    },
    "Bnclient_MNE_015e27c7d17f": {
      "addresses": {
        "LoD/1.11": "0x6FF2CE70",
        "LoD/1.11b": "0x6FF34A10",
        "LoD/1.12a": "0x6FF346E0",
        "LoD/1.13c": "0x6FF32260",
        "LoD/1.13d": "0x6FF36EF0"
      },
      "rvas": {
        "LoD/1.11": "0xCE70",
        "LoD/1.11b": "0x14A10",
        "LoD/1.12a": "0x146E0",
        "LoD/1.13c": "0x12260",
        "LoD/1.13d": "0x16EF0"
      },
      "method": "MNE",
      "index": "MNE:015e27c7d17f6b96e8539dcc4559e114"
    },
    "Bnclient_MNE_02783607761b": {
      "addresses": {
        "LoD/1.11": "0x6FF24669",
        "LoD/1.11b": "0x6FF2465B",
        "LoD/1.12a": "0x6FF246C9",
        "LoD/1.13c": "0x6FF246CE",
        "LoD/1.13d": "0x6FF246D4"
      },
      "rvas": {
        "LoD/1.11": "0x4669",
        "LoD/1.11b": "0x465B",
        "LoD/1.12a": "0x46C9",
        "LoD/1.13c": "0x46CE",
        "LoD/1.13d": "0x46D4"
      },
      "name": "___heap_select",
      "signature": "undefined4 ___heap_select(void)",
      "comment": "Library Function - Single Match\n ___heap_select\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:02783607761bb7b7f3ed068e856f0ca2"
    },
    "Bnclient_MNE_02f63f79ce8d": {
      "addresses": {
        "LoD/1.07": "0x6FF2B3CD",
        "LoD/1.08": "0x6FF2B3EE",
        "LoD/1.09": "0x6FF0BFEE",
        "LoD/1.09b": "0x6FF0BFEE",
        "LoD/1.09d": "0x6FF0C24D",
        "LoD/1.10": "0x6FF0C7AD",
        "LoD/1.11": "0x6FF21A1F",
        "LoD/1.11b": "0x6FF2152E",
        "LoD/1.12a": "0x6FF214D4",
        "LoD/1.13c": "0x6FF2131A",
        "LoD/1.13d": "0x6FF217FE"
      },
      "rvas": {
        "LoD/1.07": "0xB3CD",
        "LoD/1.08": "0xB3EE",
        "LoD/1.09": "0xBFEE",
        "LoD/1.09b": "0xBFEE",
        "LoD/1.09d": "0xC24D",
        "LoD/1.10": "0xC7AD",
        "LoD/1.11": "0x1A1F",
        "LoD/1.11b": "0x152E",
        "LoD/1.12a": "0x14D4",
        "LoD/1.13c": "0x131A",
        "LoD/1.13d": "0x17FE"
      },
      "name": "IsCharacterAttributeSet",
      "signature": "uint IsCharacterAttributeSet(void * this, int nCharacterCode)",
      "comment": "Tests whether a character has a specific attribute bit set (bit 4, value 0x4).\n\nAlgorithm:\n1. Check if character processing level exceeds basic mode (g_dwCharacterProcessingMode > 1)\n2. If advanced mode: Call FUN_6ff2c474 for full character attribute processing with bit mask 4\n3. If basic mode: Directly access character attribute table at g_pCharacterAttributeTable\n4. Calculate table offset using character code * 2 (16-bit entries)\n5. Read byte from attribute table and mask with 0x4 to test bit 4\n6. Return masked result (0 if bit clear, 4 if bit set)\n\nParameters:\nthis - Character object pointer (auto-parameter in ECX register)\nIMPLICIT: ECX contains character object pointer for __thiscall convention\nnCharacterCode - Character code or index for attribute lookup (0-255 range)\n\nReturns:\nNon-zero (4) if character attribute bit 4 is set\nZero (0) if character attribute bit 4 is clear\nReturn type: uint (32-bit unsigned integer)\n\nSpecial Cases:\nAdvanced character processing: When g_dwCharacterProcessingMode > 1, delegates to FUN_6ff2c474\nBasic character processing: Direct table lookup for simple cases\nCharacter codes are used as indices into 16-bit attribute table\nOut-of-bounds character codes may cause undefined behavior\n\nMagic Numbers Reference:\n0x4 (4) - Attribute bit mask for testing bit 4 (specific character attribute flag)\n0x1 - Threshold value for basic vs advanced processing mode comparison\n0x2 - Stride multiplier for 16-bit table entries (character_code * 2)\n\nError Handling:\nNo explicit error handling for invalid character codes\nRelies on bounds checking in advanced processing mode\nBasic mode performs direct memory access without validation",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:02f63f79ce8db59bc61e8411ac4120cf"
    },
    "Bnclient_MNE_03493a37c07d": {
      "addresses": {
        "LoD/1.07": "0x6FF31843",
        "LoD/1.08": "0x6FF31863",
        "LoD/1.09": "0x6FF12483",
        "LoD/1.09b": "0x6FF12483",
        "LoD/1.09d": "0x6FF12773",
        "LoD/1.10": "0x6FF12CC3"
      },
      "rvas": {
        "LoD/1.07": "0x11843",
        "LoD/1.08": "0x11863",
        "LoD/1.09": "0x12483",
        "LoD/1.09b": "0x12483",
        "LoD/1.09d": "0x12773",
        "LoD/1.10": "0x12CC3"
      },
      "name": "GetEnvironmentVariableValue",
      "signature": "char * GetEnvironmentVariableValue(char * lpszVariableName)",
      "comment": "Searches environment variable array for a variable by name and returns pointer to its value.\n\nAlgorithm:\n1. Validate global processing state flags (g_dwProcessingCompleteFlag must be set)\n2. Verify parsed environment array is available (g_pdwParsedStringArray not NULL)\n3. Call initialization helper if required (DAT_6ff39e6c flag check)\n4. Validate input parameter (lpszVariableName not NULL)\n5. Calculate search name length using CalculateStringLength()\n6. Iterate through environment array until NULL terminator found\n7. For each environment string:\n   a. Calculate current string length\n   b. Check if search name fits within current string\n   c. Verify '=' character exists at expected position (lpszVariableName[dwSearchNameLen])\n   d. Perform case-insensitive comparison using __mbsnbicoll()\n8. If match found, return pointer to value portion (after '=' character)\n9. If no match found, return NULL\n\nParameters:\nlpszVariableName - Pointer to null-terminated string containing environment variable name to search for\n\nReturns:\nPointer to environment variable value (char after '=' in matched string) on success\nNULL (0) if variable not found, invalid parameters, or system not initialized\n\nSpecial Cases:\n- Returns NULL if global processing flag not set (system not initialized)\n- Returns NULL if environment array not available\n- Returns NULL if initialization helper fails when required\n- Returns NULL if input parameter is NULL\n- Skips empty environment strings (NULL pointers in array)\n- Uses case-insensitive string comparison for variable names\n\nMagic Numbers Reference:\n0x3d (61) - ASCII '=' character used as name/value separator in environment strings",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:03493a37c07d984fa34a394ba093ba8b"
    },
    "Bnclient_MNE_03ce6e557a60": {
      "addresses": {
        "LoD/1.11": "0x6FF2281D",
        "LoD/1.11b": "0x6FF22BA0",
        "LoD/1.12a": "0x6FF22F41",
        "LoD/1.13c": "0x6FF2321C",
        "LoD/1.13d": "0x6FF22E4D"
      },
      "rvas": {
        "LoD/1.11": "0x281D",
        "LoD/1.11b": "0x2BA0",
        "LoD/1.12a": "0x2F41",
        "LoD/1.13c": "0x321C",
        "LoD/1.13d": "0x2E4D"
      },
      "method": "MNE",
      "index": "MNE:03ce6e557a60cad10c5f167fdc7f4b70",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF0C752",
          "rva": "0xC752",
          "confidence": 0.405,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF0C1F2",
          "rva": "0xC1F2",
          "confidence": 0.328,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF0BEB7",
          "rva": "0xBEB7",
          "confidence": 0.215,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_0432b5507696": {
      "addresses": {
        "LoD/1.07": "0x6FF31703",
        "LoD/1.08": "0x6FF31723",
        "LoD/1.09": "0x6FF12343",
        "LoD/1.09b": "0x6FF12343",
        "LoD/1.09d": "0x6FF12633",
        "LoD/1.10": "0x6FF12B83",
        "LoD/1.11b": "0x6FF27793",
        "LoD/1.13c": "0x6FF27B4A",
        "LoD/1.13d": "0x6FF277F5"
      },
      "rvas": {
        "LoD/1.07": "0x11703",
        "LoD/1.08": "0x11723",
        "LoD/1.09": "0x12343",
        "LoD/1.09b": "0x12343",
        "LoD/1.09d": "0x12633",
        "LoD/1.10": "0x12B83",
        "LoD/1.11b": "0x7793",
        "LoD/1.13c": "0x7B4A",
        "LoD/1.13d": "0x77F5"
      },
      "name": "EnsureTimestampSystemInitialized",
      "signature": "void EnsureTimestampSystemInitialized(void)",
      "comment": "Ensures the timestamp system is initialized exactly once using double-checked locking.\n\nAlgorithm:\n1. Check if timestamp system already initialized (g_dwTimestampSystemInitialized != 0)\n2. If already initialized, return immediately\n3. Acquire critical section 0xB for thread safety\n4. Double-check initialization flag inside critical section\n5. If still uninitialized, call FUN_6ff306e3() to perform initialization\n6. Increment initialization flag to mark system as initialized\n7. Release critical section 0xB\n8. Return\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Uses double-checked locking pattern to avoid critical section overhead on subsequent calls\n- Critical section index 0xB provides thread-safe initialization\n- Initialization flag prevents redundant initialization calls\n\nMagic Numbers Reference:\n0xB (11) - Critical section index for timestamp system initialization",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0432b550769644da846baf2a836117f2"
    },
    "Bnclient_MNE_048fa86b16ba": {
      "addresses": {
        "LoD/1.11": "0x6FF373E4",
        "LoD/1.11b": "0x6FF373B4",
        "LoD/1.12a": "0x6FF38264",
        "LoD/1.13c": "0x6FF38244",
        "LoD/1.13d": "0x6FF38184"
      },
      "rvas": {
        "LoD/1.11": "0x173E4",
        "LoD/1.11b": "0x173B4",
        "LoD/1.12a": "0x18264",
        "LoD/1.13c": "0x18244",
        "LoD/1.13d": "0x18184"
      },
      "name": "terminate",
      "signature": "void terminate(void)",
      "comment": "Library Function - Single Match\n void __cdecl terminate(void)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:048fa86b16ba3f4924242f25b953c745",
      "candidates": {
        "LoD/1.09d": {
          "address": "0x6FF11391",
          "rva": "0x11391",
          "confidence": 0.324,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF110A1",
          "rva": "0x110A1",
          "confidence": 0.212,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_04f1e6f173a4": {
      "addresses": {
        "LoD/1.11": "0x6FF22856",
        "LoD/1.11b": "0x6FF22BD9",
        "LoD/1.12a": "0x6FF22F7A",
        "LoD/1.13c": "0x6FF23255",
        "LoD/1.13d": "0x6FF22E86"
      },
      "rvas": {
        "LoD/1.11": "0x2856",
        "LoD/1.11b": "0x2BD9",
        "LoD/1.12a": "0x2F7A",
        "LoD/1.13c": "0x3255",
        "LoD/1.13d": "0x2E86"
      },
      "name": "__getptd",
      "signature": "_ptiddata __getptd(void)",
      "comment": "Library Function - Single Match\n __getptd\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:04f1e6f173a4f00f5247db68bf412e5b"
    },
    "Bnclient_MNE_057b2070bbbd": {
      "addresses": {
        "LoD/1.11": "0x6FF24683",
        "LoD/1.11b": "0x6FF24675",
        "LoD/1.12a": "0x6FF246E3",
        "LoD/1.13c": "0x6FF246E8",
        "LoD/1.13d": "0x6FF246EE"
      },
      "rvas": {
        "LoD/1.11": "0x4683",
        "LoD/1.11b": "0x4675",
        "LoD/1.12a": "0x46E3",
        "LoD/1.13c": "0x46E8",
        "LoD/1.13d": "0x46EE"
      },
      "name": "__heap_init",
      "signature": "int __heap_init(void)",
      "comment": "Library Function - Single Match\n __heap_init\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:057b2070bbbdb5455d8d4d9018467770"
    },
    "Bnclient_MNE_059e9bb2efc1": {
      "addresses": {
        "LoD/1.07": "0x6FF2CE64",
        "LoD/1.08": "0x6FF2CE84",
        "LoD/1.09": "0x6FF0DA84",
        "LoD/1.09b": "0x6FF0DA84",
        "LoD/1.09d": "0x6FF0DD94",
        "LoD/1.10": "0x6FF0E2FC",
        "LoD/1.11": "0x6FF25790",
        "LoD/1.11b": "0x6FF255E4",
        "LoD/1.12a": "0x6FF24A4C",
        "LoD/1.13c": "0x6FF25830",
        "LoD/1.13d": "0x6FF25B90"
      },
      "rvas": {
        "LoD/1.07": "0xCE64",
        "LoD/1.08": "0xCE84",
        "LoD/1.09": "0xDA84",
        "LoD/1.09b": "0xDA84",
        "LoD/1.09d": "0xDD94",
        "LoD/1.10": "0xE2FC",
        "LoD/1.11": "0x5790",
        "LoD/1.11b": "0x55E4",
        "LoD/1.12a": "0x4A4C",
        "LoD/1.13c": "0x5830",
        "LoD/1.13d": "0x5B90"
      },
      "name": "__global_unwind2",
      "signature": "undefined __global_unwind2(PVOID param_1)",
      "comment": "Library Function - Single Match\n __global_unwind2\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:059e9bb2efc1de93bfe21089d0ad96d3"
    },
    "Bnclient_MNE_05d3556ba26e": {
      "addresses": {
        "LoD/1.07": "0x6FF30EA1",
        "LoD/1.08": "0x6FF30EC1",
        "LoD/1.09": "0x6FF11AE1",
        "LoD/1.09b": "0x6FF11AE1",
        "LoD/1.09d": "0x6FF11DD1",
        "LoD/1.10": "0x6FF12321"
      },
      "rvas": {
        "LoD/1.07": "0x10EA1",
        "LoD/1.08": "0x10EC1",
        "LoD/1.09": "0x11AE1",
        "LoD/1.09b": "0x11AE1",
        "LoD/1.09d": "0x11DD1",
        "LoD/1.10": "0x12321"
      },
      "name": "InitializeCharacterTypeConfiguration",
      "signature": "void InitializeCharacterTypeConfiguration(void)",
      "comment": "Initializes character type table and code page configuration to default state.\n\nAlgorithm:\n1. Clear 256-byte character type table using optimized 4-byte operations\n2. Zero the final byte after the loop to handle remainder\n3. Reset code page configuration globals to zero state\n4. Set current code page identifier to 0 (invalid/uninitialized)\n5. Clear multibyte code page flag to false\n6. Reset code page properties and character type configurations\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nvoid - no return value, operates on global state only\n\nSpecial Cases:\n- Uses REP STOSD for efficient 4-byte clearing (0x40 iterations = 256 bytes)\n- Final STOSB handles the last byte alignment\n- Resets all character classification configuration to known state\n\nMagic Numbers Reference:\n- 0x40 (64 decimal): Loop count for 4-byte operations (64 * 4 = 256 bytes)\n- 0x6ff3a2e0: Base address of g_abCharacterTypeTable (256-byte array)\n\nError Handling:\nNone - this is an initialization function that cannot fail",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:05d3556ba26e52c51954a1255d97c525"
    },
    "Bnclient_MNE_07ed516e62d4": {
      "addresses": {
        "LoD/1.11": "0x6FF2A4C0",
        "LoD/1.11b": "0x6FF2A4C0",
        "LoD/1.12a": "0x6FF2AAF0",
        "LoD/1.13c": "0x6FF2AAD0",
        "LoD/1.13d": "0x6FF2AAE0"
      },
      "rvas": {
        "LoD/1.11": "0xA4C0",
        "LoD/1.11b": "0xA4C0",
        "LoD/1.12a": "0xAAF0",
        "LoD/1.13c": "0xAAD0",
        "LoD/1.13d": "0xAAE0"
      },
      "method": "MNE",
      "index": "MNE:07ed516e62d486112195861acf22fc26"
    },
    "Bnclient_MNE_0aa5002025f9": {
      "addresses": {
        "LoD/1.11": "0x6FF21914",
        "LoD/1.11b": "0x6FF21DBB",
        "LoD/1.12a": "0x6FF21EC2",
        "LoD/1.13c": "0x6FF21F1F",
        "LoD/1.13d": "0x6FF21C54"
      },
      "rvas": {
        "LoD/1.11": "0x1914",
        "LoD/1.11b": "0x1DBB",
        "LoD/1.12a": "0x1EC2",
        "LoD/1.13c": "0x1F1F",
        "LoD/1.13d": "0x1C54"
      },
      "name": "__beginthreadex",
      "signature": "uintptr_t __beginthreadex(void * _Security, uint _StackSize, _StartAddress * _StartAddress, void * _ArgList, uint _InitFlag, uint * _ThrdAddr)",
      "comment": "Library Function - Single Match\n __beginthreadex\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:0aa5002025f9107e388717e294e9f257"
    },
    "Bnclient_MNE_0af4c6ac3306": {
      "addresses": {
        "LoD/1.07": "0x6FF21D80",
        "LoD/1.08": "0x6FF21DA0"
      },
      "rvas": {
        "LoD/1.07": "0x1D80",
        "LoD/1.08": "0x1DA0"
      },
      "name": "GetValueAndNotify",
      "signature": "void GetValueAndNotify(uint * pOutputValue)",
      "comment": "Retrieves a value and stores it through pointer, then sends notification.\n\nAlgorithm:\n1. Call FUN_6ff22220() to retrieve a 32-bit value\n2. Store the retrieved value through the provided output pointer\n3. Call FUN_6ff22300() with hardcoded notification parameter (0x3d)\n4. Return to caller\n\nParameters:\npOutputValue (uint *) - Pointer to storage location for retrieved value\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nMagic Numbers Reference:\n0x3d (61 decimal) - Hardcoded notification parameter passed to FUN_6ff22300",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0af4c6ac330673e4fa1df52de80b4db2"
    },
    "Bnclient_MNE_0c1b1eb893ed": {
      "addresses": {
        "LoD/1.11": "0x6FF21411",
        "LoD/1.11b": "0x6FF212BD",
        "LoD/1.12a": "0x6FF21546",
        "LoD/1.13c": "0x6FF21621",
        "LoD/1.13d": "0x6FF21745"
      },
      "rvas": {
        "LoD/1.11": "0x1411",
        "LoD/1.11b": "0x12BD",
        "LoD/1.12a": "0x1546",
        "LoD/1.13c": "0x1621",
        "LoD/1.13d": "0x1745"
      },
      "name": "FID_conflict:__time32",
      "signature": "__time32_t FID_conflict:__time32(__time32_t * _Time)",
      "comment": "Library Function - Multiple Matches With Different Base Names\n __time32\n _time\n\nLibraries: Visual Studio 2003 Release, Visual Studio 2005 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:0c1b1eb893ed76911dc810ba960af5cf"
    },
    "Bnclient_MNE_0c44e947b1ea": {
      "addresses": {
        "LoD/1.11": "0x6FF258D6",
        "LoD/1.11b": "0x6FF250BD",
        "LoD/1.13d": "0x6FF25CD6"
      },
      "rvas": {
        "LoD/1.11": "0x58D6",
        "LoD/1.11b": "0x50BD",
        "LoD/1.13d": "0x5CD6"
      },
      "name": "setSBUpLow",
      "signature": "undefined setSBUpLow(void)",
      "comment": "Library Function - Single Match\n _setSBUpLow\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:0c44e947b1ea344017d45b0d6df8c6c5"
    },
    "Bnclient_MNE_0cd6117ad6e3": {
      "addresses": {
        "LoD/1.09": "0x6FF12F70",
        "LoD/1.09b": "0x6FF12F70",
        "LoD/1.09d": "0x6FF13290",
        "LoD/1.10": "0x6FF13890"
      },
      "rvas": {
        "LoD/1.09": "0x12F70",
        "LoD/1.09b": "0x12F70",
        "LoD/1.09d": "0x13290",
        "LoD/1.10": "0x13890"
      },
      "method": "MNE",
      "index": "MNE:0cd6117ad6e34588cb82d9be6153a34b"
    },
    "Bnclient_MNE_0cd6dc09c874": {
      "addresses": {
        "LoD/1.11": "0x6FF36CD9",
        "LoD/1.11b": "0x6FF36CA9",
        "LoD/1.12a": "0x6FF37B59",
        "LoD/1.13c": "0x6FF37B39",
        "LoD/1.13d": "0x6FF37A79"
      },
      "rvas": {
        "LoD/1.11": "0x16CD9",
        "LoD/1.11b": "0x16CA9",
        "LoD/1.12a": "0x17B59",
        "LoD/1.13c": "0x17B39",
        "LoD/1.13d": "0x17A79"
      },
      "name": "CallCatchBlock",
      "signature": "void * CallCatchBlock(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, _s_FuncInfo * param_4, void * param_5, int param_6, ulong param_7)",
      "comment": "Library Function - Single Match\n void * __cdecl CallCatchBlock(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,struct _s_FuncInfo const *,void *,int,unsigned long)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:0cd6dc09c8745218b08aa07ad6229378"
    },
    "Bnclient_MNE_0e5fe8f035f6": {
      "addresses": {
        "LoD/1.11": "0x6FF36BA7",
        "LoD/1.11b": "0x6FF36B77",
        "LoD/1.12a": "0x6FF37A27",
        "LoD/1.13c": "0x6FF37A07",
        "LoD/1.13d": "0x6FF37947"
      },
      "rvas": {
        "LoD/1.11": "0x16BA7",
        "LoD/1.11b": "0x16B77",
        "LoD/1.12a": "0x17A27",
        "LoD/1.13c": "0x17A07",
        "LoD/1.13d": "0x17947"
      },
      "name": "___FrameUnwindToState",
      "signature": "undefined ___FrameUnwindToState(int param_1, undefined4 param_2, int param_3, int param_4)",
      "comment": "Library Function - Single Match\n ___FrameUnwindToState\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:0e5fe8f035f67d55ee839a615aebb8b3"
    },
    "Bnclient_MNE_0f2d1d788102": {
      "addresses": {
        "LoD/1.07": "0x6FF24210",
        "LoD/1.08": "0x6FF24230"
      },
      "rvas": {
        "LoD/1.07": "0x4210",
        "LoD/1.08": "0x4230"
      },
      "name": "ClearPacketHandlerState",
      "signature": "void ClearPacketHandlerState(void)",
      "comment": "Clears packet handler state by resetting flags and nulling the active packet handler.\n\nAlgorithm:\n1. Enter critical section for thread-safe packet handler access\n2. Clear first packet flag at g_apfnPacketHandlers[0xf5] byte 0\n3. Clear second packet flag at g_apfnPacketHandlers[0xf5] byte 1  \n4. Set packet handler pointer at g_apfnPacketHandlers[0xac] to NULL\n5. Leave critical section to release synchronization lock\n\nParameters:\n  None\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  Thread synchronization handled via critical section g_PacketCriticalSection\n\nMagic Numbers Reference:\n  0xf5 (245) - Index into packet handlers array for flag storage\n  0xac (172) - Index into packet handlers array for active handler pointer\n  0xad (173) - Offset to critical section structure (g_apfnPacketHandlers + 0xad)\n\nError Handling:\n  No explicit error handling - critical section operations assumed to succeed\n\nStructure Layout:\n  g_apfnPacketHandlers array layout (relevant offsets):\n  Offset   Size  Field Name              Type      Description\n  0xac*4   4     ActiveHandler          uint*     Currently active packet handler pointer\n  0xf5*4   1     PacketFlag1            byte      First packet processing flag  \n  0xf5*4+1 1     PacketFlag2            byte      Second packet processing flag\n  0xad*4   24    CriticalSection        CRITICAL_SECTION  Thread synchronization",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0f2d1d788102ace00be009753e73f6d0"
    },
    "Bnclient_MNE_103d33fd6c90": {
      "addresses": {
        "LoD/1.11": "0x6FF297B0",
        "LoD/1.11b": "0x6FF297B0",
        "LoD/1.12a": "0x6FF29DE0",
        "LoD/1.13c": "0x6FF29DC0",
        "LoD/1.13d": "0x6FF29DD0"
      },
      "rvas": {
        "LoD/1.11": "0x97B0",
        "LoD/1.11b": "0x97B0",
        "LoD/1.12a": "0x9DE0",
        "LoD/1.13c": "0x9DC0",
        "LoD/1.13d": "0x9DD0"
      },
      "method": "MNE",
      "index": "MNE:103d33fd6c90e2e890e0f9f65a342c76"
    },
    "Bnclient_MNE_124a050f7896": {
      "addresses": {
        "LoD/1.11": "0x6FF24028",
        "LoD/1.11b": "0x6FF2401A",
        "LoD/1.12a": "0x6FF24088",
        "LoD/1.13c": "0x6FF2408D",
        "LoD/1.13d": "0x6FF24093"
      },
      "rvas": {
        "LoD/1.11": "0x4028",
        "LoD/1.11b": "0x401A",
        "LoD/1.12a": "0x4088",
        "LoD/1.13c": "0x408D",
        "LoD/1.13d": "0x4093"
      },
      "name": "__ioinit",
      "signature": "int __ioinit(void)",
      "comment": "Library Function - Single Match\n __ioinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:124a050f7896343631e89fc5722f0cb0"
    },
    "Bnclient_MNE_12dead7d93dd": {
      "addresses": {
        "LoD/1.07": "0x6FF3055E",
        "LoD/1.08": "0x6FF3057E",
        "LoD/1.09": "0x6FF1119E",
        "LoD/1.09b": "0x6FF1119E",
        "LoD/1.09d": "0x6FF1148E",
        "LoD/1.10": "0x6FF119DE",
        "LoD/1.11": "0x6FF21637",
        "LoD/1.11b": "0x6FF21726",
        "LoD/1.12a": "0x6FF21AED",
        "LoD/1.13c": "0x6FF218C6",
        "LoD/1.13d": "0x6FF21A56"
      },
      "rvas": {
        "LoD/1.07": "0x1055E",
        "LoD/1.08": "0x1057E",
        "LoD/1.09": "0x1119E",
        "LoD/1.09b": "0x1119E",
        "LoD/1.09d": "0x1148E",
        "LoD/1.10": "0x119DE",
        "LoD/1.11": "0x1637",
        "LoD/1.11b": "0x1726",
        "LoD/1.12a": "0x1AED",
        "LoD/1.13c": "0x18C6",
        "LoD/1.13d": "0x1A56"
      },
      "name": "ConvertWideCharToMultiByte",
      "signature": "char * ConvertWideCharToMultiByte(char * lpszBuffer, wchar_t wcChar)",
      "comment": "Converts a wide character to a multibyte character with locale-aware processing.\n\nAlgorithm:\n1. Validate input buffer pointer for null\n2. If locale processing unavailable, perform simple cast conversion for ASCII range\n3. If locale available, use WideCharToMultiByte API with default code page\n4. Check conversion result and flags parameter modification\n5. On any failure, set thread error context to 0x2a and return -1\n\nParameters:\nlpszBuffer (char *): Output buffer to receive converted multibyte character\nwcChar (wchar_t): Input wide character to convert\n\nReturns:\nchar *: Pointer to conversion result on success\n        (char *)0x1 for simple conversion success  \n        (char *)0xffffffff (-1) on failure with error code 0x2a set\n\nSpecial Cases:\n- Null buffer returns immediately without processing\n- Characters >= 0x100 require locale conversion when locale unavailable\n- API failure or flag modification triggers error path\n\nMagic Numbers Reference:\n0x220 (544): WideCharToMultiByte flags (WC_NO_BEST_FIT_CHARS | WC_DEFAULTCHAR)\n0x100 (256): ASCII character range threshold\n0x2a (42): Error code for character conversion failure\n0xffffffff (-1): Failure return value",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:12dead7d93dd2763acf5540fd9895c41"
    },
    "Bnclient_MNE_130d350cf3d6": {
      "addresses": {
        "LoD/1.10": "0x6FF0B880"
      },
      "rvas": {
        "LoD/1.10": "0xB880"
      },
      "method": "MNE",
      "index": "MNE:130d350cf3d6d79207a679cbd53204df"
    },
    "Bnclient_MNE_1352fc0555ea": {
      "addresses": {
        "LoD/1.07": "0x6FF2DC3C",
        "LoD/1.08": "0x6FF2DC5C",
        "LoD/1.09": "0x6FF0E887",
        "LoD/1.09b": "0x6FF0E887",
        "LoD/1.09d": "0x6FF0EB6C",
        "LoD/1.10": "0x6FF0F15A"
      },
      "rvas": {
        "LoD/1.07": "0xDC3C",
        "LoD/1.08": "0xDC5C",
        "LoD/1.09": "0xE887",
        "LoD/1.09b": "0xE887",
        "LoD/1.09d": "0xEB6C",
        "LoD/1.10": "0xF15A"
      },
      "name": "InitializeStdIoStreams",
      "signature": "void InitializeStdIoStreams(void)",
      "comment": "Initializes C runtime standard I/O stream descriptors for stdin/stdout/stderr\n\nAlgorithm:\n1. Allocate 0x480 bytes for initial StreamIO descriptor block (32 streams)\n2. Initialize all 32 stream descriptors with default state (closed, flags 0x0A)\n3. Call GetStartupInfoA to retrieve process startup information\n4. If startup info contains inherited handles (cbReserved2 != 0):\n   a. Parse handle table from lpReserved2 pointer\n   b. Limit handle count to 0x800 maximum for memory safety\n   c. Allocate additional StreamIO blocks if needed (32 streams per block)\n   d. For each inherited handle: validate handle and flags, set stream descriptor\n5. For streams 0, 1, 2 (stdin/stdout/stderr): if not inherited, get standard handles\n6. Set handle type flags based on GetFileType: 0x08 for pipes, 0x40 for character devices\n7. Call SetHandleCount with total allocated handle count\n\nParameters:\nNone\n\nReturns:\nNone (void function)\n\nSpecial Cases:\n- Memory allocation failure triggers AmsgExit(0x1B) - fatal error\n- Invalid handles (0xFFFFFFFF) are marked with 0x81 flags  \n- Handle count clamped to 0x800 maximum to prevent excessive memory allocation\n- Stream indices use bit operations: bucket = index >> 5, offset = index & 0x1F\n\nMagic Numbers:\n0x480 = 1152 bytes = 32 * 36 byte StreamIO structures per allocation block\n0x20 = 32 streams per descriptor block  \n0x24 = 36 bytes = size of StreamIO structure\n0x800 = 2048 maximum inherited handles supported\n0x1B = 27 decimal = exit code for memory allocation failure\n0xFFFFFFF6 = STD_INPUT_HANDLE (-10)\n0xFFFFFFF5 = STD_OUTPUT_HANDLE (-11) \n0xFFFFFFF4 = STD_ERROR_HANDLE (-12)\n0x81 = stream flags for standard handles (binary mode + allocated)\n0x80 = STREAM_ALLOCATED flag\n0x40 = STREAM_CHARACTER_DEVICE flag (console)\n0x08 = STREAM_PIPE flag\n0x01 = inherited handle valid flag in startup info\n0x0A = 10 decimal = default stream flags (line buffered)\n\nStructure Layout:\nOffset | Size | Field Name | Type | Description\n-------|------|------------|------|------------\n0x00   | 4    | pBase      | void*| File handle or buffer pointer  \n0x04   | 1    | nPosition  | byte | Stream status flags\n0x05   | 1    | (padding)  | byte | Line buffer mode (0x0A = LF)\n0x08   | 4    | pCurrent   | void*| Current position in buffer\n0x0C   | 24   | (other)    | -    | Additional StreamIO fields\n\nFlag Bits:\n0x01 = STREAM_VALID (handle inherited and valid)\n0x08 = STREAM_PIPE (pipe handle type)  \n0x40 = STREAM_CHARACTER (character device - console)\n0x80 = STREAM_ALLOCATED (descriptor allocated and active)\n0x81 = STREAM_STANDARD (standard handle - stdin/stdout/stderr)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:1352fc0555ea3629db2c9325fd0e6c42"
    },
    "Bnclient_MNE_137dd1f09c34": {
      "addresses": {
        "LoD/1.11": "0x6FF249B0",
        "LoD/1.11b": "0x6FF26F00",
        "LoD/1.13d": "0x6FF27110"
      },
      "rvas": {
        "LoD/1.11": "0x49B0",
        "LoD/1.11b": "0x6F00",
        "LoD/1.13d": "0x7110"
      },
      "name": "___ansicp",
      "signature": "undefined ___ansicp(LCID param_1)",
      "comment": "Library Function - Single Match\n ___ansicp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:137dd1f09c34b57b162936229329b15b"
    },
    "Bnclient_MNE_138cb9be9d7c": {
      "addresses": {
        "LoD/1.12a": "0x6FF25C50",
        "LoD/1.13c": "0x6FF26F60"
      },
      "rvas": {
        "LoD/1.12a": "0x5C50",
        "LoD/1.13c": "0x6F60"
      },
      "method": "MNE",
      "index": "MNE:138cb9be9d7caeaaa6cff721ddf1f5fa"
    },
    "Bnclient_MNE_13d93ac20184": {
      "addresses": {
        "LoD/1.07": "0x6FF31ADA",
        "LoD/1.08": "0x6FF31AFA",
        "LoD/1.09": "0x6FF1271A",
        "LoD/1.09b": "0x6FF1271A",
        "LoD/1.09d": "0x6FF12A0A",
        "LoD/1.10": "0x6FF12F8E",
        "LoD/1.11b": "0x6FF27E04",
        "LoD/1.13c": "0x6FF27E74",
        "LoD/1.13d": "0x6FF27E74"
      },
      "rvas": {
        "LoD/1.07": "0x11ADA",
        "LoD/1.08": "0x11AFA",
        "LoD/1.09": "0x1271A",
        "LoD/1.09b": "0x1271A",
        "LoD/1.09d": "0x12A0A",
        "LoD/1.10": "0x12F8E",
        "LoD/1.11b": "0x7E04",
        "LoD/1.13c": "0x7E74",
        "LoD/1.13d": "0x7E74"
      },
      "name": "CloseStreamHandle",
      "signature": "int CloseStreamHandle(uint dwStreamIndex)",
      "comment": "Closes a stream handle and cleans up its descriptor entry.\n\nAlgorithm:\n1. Validate stream by calling GetStreamBasePointer to check if stream exists\n2. Special handling for console streams (index 1 and 2):\n   - Get handles for both stdout (index 1) and stderr (index 2) \n   - Skip handle closure if both point to same underlying handle\n3. Get actual stream handle via GetStreamBasePointer\n4. Close the Windows handle using CloseHandle\n5. Capture any error code from GetLastError if closure fails\n6. Clean up stream descriptor by calling CloseStreamByIndex\n7. Clear the nPosition field in the StreamIO descriptor array\n8. Translate error code if handle closure failed\n9. Return success (0) or error (-1)\n\nParameters:\ndwStreamIndex (uint): Zero-based index into stream descriptor array\n\nReturns:\n0 on successful stream closure and cleanup\n-1 if CloseHandle fails or other error occurs\n\nSpecial Cases:\nConsole streams (indices 1 and 2) receive special handling to prevent\ndouble-closure when stdout and stderr point to the same handle.\n\nStructure Layout:\nStreamIO descriptor accessed via bucket array:\nbucket = dwStreamIndex >> 5 (divide by 32)\nslot = dwStreamIndex & 0x1F (modulo 32)  \nnPosition field cleared at offset +4 in descriptor\n\nMagic Numbers Reference:\n0x1F (31): Bit mask for modulo 32 operation (slot within bucket)\n0x5: Right shift count for divide by 32 (bucket calculation)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:13d93ac20184bc58361cf8520dc0da42"
    },
    "Bnclient_MNE_14b13ed976e9": {
      "addresses": {
        "LoD/1.09": "0x6FF07F30",
        "LoD/1.09b": "0x6FF07F30",
        "LoD/1.09d": "0x6FF08190",
        "LoD/1.10": "0x6FF08B70"
      },
      "rvas": {
        "LoD/1.09": "0x7F30",
        "LoD/1.09b": "0x7F30",
        "LoD/1.09d": "0x8190",
        "LoD/1.10": "0x8B70"
      },
      "method": "MNE",
      "index": "MNE:14b13ed976e9fe94acaa123138d5fb4f",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF21D04",
          "rva": "0x1D04",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.11b": {
          "address": "0x6FF2147D",
          "rva": "0x147D",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.12a": {
          "address": "0x6FF21423",
          "rva": "0x1423",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF21569",
          "rva": "0x1569",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_1563254ce315": {
      "addresses": {
        "LoD/1.07": "0x6FF2C1DD",
        "LoD/1.08": "0x6FF2C308",
        "LoD/1.09": "0x6FF0CF08",
        "LoD/1.09b": "0x6FF0CF08",
        "LoD/1.09d": "0x6FF0D10D",
        "LoD/1.10": "0x6FF0D673"
      },
      "rvas": {
        "LoD/1.07": "0xC1DD",
        "LoD/1.08": "0xC308",
        "LoD/1.09": "0xCF08",
        "LoD/1.09b": "0xCF08",
        "LoD/1.09d": "0xD10D",
        "LoD/1.10": "0xD673"
      },
      "name": "InitializeThreadLocalStorage",
      "signature": "bool InitializeThreadLocalStorage(void)",
      "comment": "Initialize thread-local storage for per-thread context management\n\nAlgorithm:\n1. Call cleanup routine to prepare for TLS initialization\n2. Allocate TLS slot using TlsAlloc(), store in global g_dwTlsSlotIndex  \n3. Check if TLS allocation succeeded (index != 0xFFFFFFFF)\n4. Allocate ThreadContext structure memory (116 bytes) via custom allocator\n5. Verify ThreadContext allocation succeeded (pointer not NULL)\n6. Associate ThreadContext with TLS slot using TlsSetValue()\n7. Verify TLS value was set successfully\n8. Initialize ThreadContext structure with InitializeThreadContext()\n9. Get current thread ID and store in context structure\n10. Set context flags field to 0xFFFFFFFF (all flags enabled)\n11. Store thread ID in first field of context structure\n12. Return success status\n\nParameters:\nNone\n\nReturns:\nbool: true (1) on successful TLS initialization, false (0) on any failure\n\nSpecial Cases:\nIf TLS allocation fails (returns 0xFFFFFFFF), function exits immediately with failure\nIf memory allocation fails, function exits with failure  \nIf TLS value cannot be set, function exits with failure\nEach failure condition branches to common exit_failure label\n\nMagic Numbers Reference:\n0x74 (116 decimal): Size of ThreadContext structure allocation\n0xFFFFFFFF: Invalid TLS index return value indicating allocation failure\n0xFFFFFFFF: Flag mask for enabling all context flags\n\nError Handling:\nTLS allocation failure: return 0\nMemory allocation failure: return 0  \nTLS value set failure: return 0\nAll errors result in immediate function exit with false return value",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:1563254ce315644019ac4e0b71caac74"
    },
    "Bnclient_MNE_15aa81e73603": {
      "addresses": {
        "LoD/1.07": "0x6FF2E3F9",
        "LoD/1.08": "0x6FF2E419",
        "LoD/1.09": "0x6FF0F044",
        "LoD/1.09b": "0x6FF0F044",
        "LoD/1.09d": "0x6FF0F329",
        "LoD/1.10": "0x6FF0F917",
        "LoD/1.11b": "0x6FF27736",
        "LoD/1.13c": "0x6FF27AED",
        "LoD/1.13d": "0x6FF27798"
      },
      "rvas": {
        "LoD/1.07": "0xE3F9",
        "LoD/1.08": "0xE419",
        "LoD/1.09": "0xF044",
        "LoD/1.09b": "0xF044",
        "LoD/1.09d": "0xF329",
        "LoD/1.10": "0xF917",
        "LoD/1.11b": "0x7736",
        "LoD/1.13c": "0x7AED",
        "LoD/1.13d": "0x7798"
      },
      "name": "InitializeHeapAndAllocator",
      "signature": "int InitializeHeapAndAllocator(int nReason)",
      "comment": "Initialize heap and allocator subsystem during DLL initialization.\n\nAlgorithm:\n1. Create heap with HEAP_NO_SERIALIZE flag based on DLL attachment reason\n2. Store heap handle in global variable g_hHeapHandle\n3. Retrieve allocation strategy from allocator subsystem (FUN_6ff2e2b1)\n4. Store allocation strategy in global variable g_dwAllocationStrategy\n5. Initialize allocator based on strategy value:\n   - Strategy 3: Call FUN_6ff2e7d3(0x3f8) for 1016-byte allocation pool\n   - Strategy 2: Call FUN_6ff2f31a() for default allocation pool\n   - Other strategies: Return success immediately (no allocator needed)\n6. Verify allocator initialization succeeded (non-NULL return)\n7. Return success if all initialization completed\n8. Clean up heap and return failure if allocator initialization failed\n\nParameters:\nnReason (int): DLL attachment reason from DllMain (DLL_PROCESS_ATTACH, etc.)\n               Used to determine heap serialization policy\n\nReturns:\n1 - Successful initialization of heap and allocator subsystem\n0 - Initialization failed (heap creation failed or allocator init failed)\n\nSpecial Cases:\n- If nReason is 0 (DLL_PROCESS_DETACH), heap created with HEAP_NO_SERIALIZE\n- Strategy values other than 2 or 3 skip allocator initialization\n- NULL heap handle causes immediate failure return\n\nMagic Numbers Reference:\n0x1000 - Initial heap commit size (4096 bytes)\n0x3f8 - Allocation pool size for strategy 3 (1016 bytes)\n2 - Default allocation strategy requiring FUN_6ff2f31a initialization  \n3 - Pool allocation strategy requiring FUN_6ff2e7d3 initialization\n\nError Handling:\n- HeapCreate failure returns NULL handle, function returns 0\n- Allocator initialization failure triggers HeapDestroy cleanup before return 0\n- Invalid strategy values (not 2 or 3) treated as success case",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:15aa81e73603ef0f9aff675af9b3ec8c"
    },
    "Bnclient_MNE_15c1391d599a": {
      "addresses": {
        "LoD/1.07": "0x6FF2C7C2",
        "LoD/1.08": "0x6FF2C7E2",
        "LoD/1.09": "0x6FF0D3E2",
        "LoD/1.09b": "0x6FF0D3E2",
        "LoD/1.09d": "0x6FF0D6F2",
        "LoD/1.10": "0x6FF0DC58"
      },
      "rvas": {
        "LoD/1.07": "0xC7C2",
        "LoD/1.08": "0xC7E2",
        "LoD/1.09": "0xD3E2",
        "LoD/1.09b": "0xD3E2",
        "LoD/1.09d": "0xD6F2",
        "LoD/1.10": "0xDC58"
      },
      "name": "ReleaseCriticalSection9",
      "signature": "void ReleaseCriticalSection9(void)",
      "comment": "Release critical section 9 and clear EDI register\n\nAlgorithm:\n1. Release critical section with index 9 via ReleaseCriticalSectionByIndex\n2. Clear EDI register to zero\n3. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nNone - Simple wrapper function with no conditional logic",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:15c1391d599afb321981e8dd71ecc926"
    },
    "Bnclient_MNE_17d5e4a2ea8e": {
      "addresses": {
        "LoD/1.07": "0x6FF2C2C9",
        "LoD/1.08": "0x6FF2C3F4",
        "LoD/1.09": "0x6FF0CFF4",
        "LoD/1.09b": "0x6FF0CFF4",
        "LoD/1.09d": "0x6FF0D1F9",
        "LoD/1.10": "0x6FF0D75F"
      },
      "rvas": {
        "LoD/1.07": "0xC2C9",
        "LoD/1.08": "0xC3F4",
        "LoD/1.09": "0xCFF4",
        "LoD/1.09b": "0xCFF4",
        "LoD/1.09d": "0xD1F9",
        "LoD/1.10": "0xD75F"
      },
      "name": "CleanupThreadContext",
      "signature": "void CleanupThreadContext(ThreadContext * pThreadContext)",
      "comment": "Cleanup thread context structure by deallocating all associated memory buffers.\n\nAlgorithm:\n1. Validate TLS slot index is initialized (not 0xffffffff)\n2. Determine thread context pointer from parameter or TLS storage\n3. Deallocate memory pointers in reserved1 field at offsets 0x1c, 0x20, 0x28, 0x30, 0x38, 0x3c\n4. Check if reserved2 field points to non-default error code array\n5. Deallocate custom error code array if not using global default\n6. Deallocate the thread context structure itself\n7. Clear TLS slot by setting to NULL\n\nParameters:\npThreadContext: Pointer to ThreadContext structure to cleanup, or NULL to retrieve from TLS\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nIf pThreadContext is NULL, retrieves current thread context from TLS storage\nIf TLS slot is invalid (0xffffffff), function returns immediately\nDefault error codes array (g_adwSehErrorCodes) at 0x6ff36908 is not deallocated\n\nMagic Numbers Reference:\n0xffffffff - Invalid TLS slot index indicating uninitialized TLS\n0x1c, 0x20, 0x28, 0x30, 0x38, 0x3c - Offsets to memory buffer pointers in reserved1\n0x6ff36908 - Address of global default SEH error codes array (g_adwSehErrorCodes)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:17d5e4a2ea8eca0808e1116fecc65876"
    },
    "Bnclient_MNE_18c434a84227": {
      "addresses": {
        "LoD/1.07": "0x6FF228D0",
        "LoD/1.08": "0x6FF228F0",
        "LoD/1.09": "0x6FF03240",
        "LoD/1.09b": "0x6FF03240",
        "LoD/1.09d": "0x6FF03250",
        "LoD/1.10": "0x6FF032A0"
      },
      "rvas": {
        "LoD/1.07": "0x28D0",
        "LoD/1.08": "0x28F0",
        "LoD/1.09": "0x3240",
        "LoD/1.09b": "0x3240",
        "LoD/1.09d": "0x3250",
        "LoD/1.10": "0x32A0"
      },
      "name": "DispatchPacketHandler",
      "signature": "DWORD DispatchPacketHandler(byte byCommandId)",
      "comment": "Dispatch packet handler function based on command ID\n\nAlgorithm:\n1. Initialize result value to 0 (success/no-op state)\n2. Validate command ID is within valid range (< 0x43 = 67)\n3. If invalid command ID, skip to cleanup and return 0\n4. Lookup function pointer from handler table at PTR_LAB_6ff35344[byCommandId]\n5. If handler function exists (not NULL), call it and store result\n6. Set corresponding flag in g_apfnPacketHandlers[byCommandId + 0x45] to 0x1 (mark as executed)\n7. Return handler result or 0 if no handler found\n\nParameters:\nbyCommandId (byte) - Packet/command identifier (0-66 valid range)\n\nReturns:\nDWORD - Handler execution result (0 for success/no-op, handler-specific values for errors)\n\nSpecial Cases:\nCommand IDs >= 0x43 (67) are invalid and result in early return with 0\nNULL function pointers in handler table are valid (no-op handlers)\n\nMagic Numbers Reference:\n0x43 (67) - Maximum valid command ID (exclusive upper bound)\n0x45 (69) - Offset added to command ID for flag array indexing\n0x1 - Flag value indicating handler has been executed\n0x6ff35344 - Base address of function pointer table (PTR_LAB_6ff35344)\n0x6ff39630 - Base address of handler execution flags (g_apfnPacketHandlers)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:18c434a84227d4ac99307880ad57caad"
    },
    "Bnclient_MNE_1bacf15d4212": {
      "addresses": {
        "LoD/1.11": "0x6FF24BBC",
        "LoD/1.11b": "0x6FF2710C",
        "LoD/1.12a": "0x6FF25E71",
        "LoD/1.13c": "0x6FF27181",
        "LoD/1.13d": "0x6FF2731C"
      },
      "rvas": {
        "LoD/1.11": "0x4BBC",
        "LoD/1.11b": "0x710C",
        "LoD/1.12a": "0x5E71",
        "LoD/1.13c": "0x7181",
        "LoD/1.13d": "0x731C"
      },
      "name": "__resetstkoflw",
      "signature": "int __resetstkoflw(void)",
      "comment": "Library Function - Single Match\n __resetstkoflw\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:1bacf15d421243740ab5a96b430ce3dc"
    },
    "Bnclient_MNE_1bc390d8ff20": {
      "addresses": {
        "LoD/1.11": "0x6FF21790",
        "LoD/1.11b": "0x6FF217A0",
        "LoD/1.12a": "0x6FF21B70",
        "LoD/1.13c": "0x6FF21940",
        "LoD/1.13d": "0x6FF21AD0"
      },
      "rvas": {
        "LoD/1.11": "0x1790",
        "LoD/1.11b": "0x17A0",
        "LoD/1.12a": "0x1B70",
        "LoD/1.13c": "0x1940",
        "LoD/1.13d": "0x1AD0"
      },
      "name": "_strchr",
      "signature": "char * _strchr(char * _Str, int _Val)",
      "comment": "Library Function - Single Match\n _strchr\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:1bc390d8ff201cb7e4949aa7242ab695"
    },
    "Bnclient_MNE_1bfe45c9047f": {
      "addresses": {
        "LoD/1.11": "0x6FF33990",
        "LoD/1.11b": "0x6FF2E860",
        "LoD/1.12a": "0x6FF2ECF0",
        "LoD/1.13c": "0x6FF34D20",
        "LoD/1.13d": "0x6FF36490"
      },
      "rvas": {
        "LoD/1.11": "0x13990",
        "LoD/1.11b": "0xE860",
        "LoD/1.12a": "0xECF0",
        "LoD/1.13c": "0x14D20",
        "LoD/1.13d": "0x16490"
      },
      "name": "GetSystemTimeZone",
      "signature": "int GetSystemTimeZone(BNGatewayAccess * this)",
      "comment": "private: int __thiscall BNGatewayAccess::GetSystemTimeZone(void)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:1bfe45c9047f668aa56e5014f3f5d921"
    },
    "Bnclient_MNE_1c48859ddf90": {
      "addresses": {
        "LoD/1.11": "0x6FF21F86",
        "LoD/1.11b": "0x6FF21F67",
        "LoD/1.12a": "0x6FF21FDF",
        "LoD/1.13c": "0x6FF21FDD",
        "LoD/1.13d": "0x6FF21FDC"
      },
      "rvas": {
        "LoD/1.11": "0x1F86",
        "LoD/1.11b": "0x1F67",
        "LoD/1.12a": "0x1FDF",
        "LoD/1.13c": "0x1FDD",
        "LoD/1.13d": "0x1FDC"
      },
      "name": "__CRT_INIT@12",
      "signature": "undefined4 __CRT_INIT@12(undefined4 param_1, int param_2)",
      "comment": "Library Function - Single Match\n __CRT_INIT@12\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:1c48859ddf90d08dbf4d9d03c0c2a56a"
    },
    "Bnclient_MNE_1c8e05375765": {
      "addresses": {
        "LoD/1.11": "0x6FF22651",
        "LoD/1.11b": "0x6FF236AE",
        "LoD/1.12a": "0x6FF22D75",
        "LoD/1.13c": "0x6FF23601",
        "LoD/1.13d": "0x6FF22C81"
      },
      "rvas": {
        "LoD/1.11": "0x2651",
        "LoD/1.11b": "0x36AE",
        "LoD/1.12a": "0x2D75",
        "LoD/1.13c": "0x3601",
        "LoD/1.13d": "0x2C81"
      },
      "name": "___freetlocinfo",
      "signature": "undefined ___freetlocinfo(void * param_1)",
      "comment": "Library Function - Single Match\n ___freetlocinfo\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:1c8e05375765f5055ce29f9161a94626"
    },
    "Bnclient_MNE_1ca444181aa4": {
      "addresses": {
        "LoD/1.11": "0x6FF25710",
        "LoD/1.11b": "0x6FF26E80",
        "LoD/1.12a": "0x6FF26680",
        "LoD/1.13c": "0x6FF26EE0",
        "LoD/1.13d": "0x6FF25B10"
      },
      "rvas": {
        "LoD/1.11": "0x5710",
        "LoD/1.11b": "0x6E80",
        "LoD/1.12a": "0x6680",
        "LoD/1.13c": "0x6EE0",
        "LoD/1.13d": "0x5B10"
      },
      "name": "_strncmp",
      "signature": "int _strncmp(char * _Str1, char * _Str2, size_t _MaxCount)",
      "comment": "Library Function - Single Match\n _strncmp\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:1ca444181aa479bff1f1eb748b3a2663"
    },
    "Bnclient_MNE_1d77126aaa02": {
      "addresses": {
        "LoD/1.11": "0x6FF30E00",
        "LoD/1.11b": "0x6FF31470",
        "LoD/1.12a": "0x6FF2FEF0",
        "LoD/1.13c": "0x6FF330B0",
        "LoD/1.13d": "0x6FF2F070"
      },
      "rvas": {
        "LoD/1.11": "0x10E00",
        "LoD/1.11b": "0x11470",
        "LoD/1.12a": "0xFEF0",
        "LoD/1.13c": "0x130B0",
        "LoD/1.13d": "0xF070"
      },
      "method": "MNE",
      "index": "MNE:1d77126aaa024ab162e4a02c067f90bd"
    },
    "Bnclient_MNE_1d9f75f652aa": {
      "addresses": {
        "LoD/1.07": "0x6FF244B0",
        "LoD/1.08": "0x6FF244D0",
        "LoD/1.09": "0x6FF04E30",
        "LoD/1.09b": "0x6FF04E30",
        "LoD/1.09d": "0x6FF050B0",
        "LoD/1.10": "0x6FF05040"
      },
      "rvas": {
        "LoD/1.07": "0x44B0",
        "LoD/1.08": "0x44D0",
        "LoD/1.09": "0x4E30",
        "LoD/1.09b": "0x4E30",
        "LoD/1.09d": "0x50B0",
        "LoD/1.10": "0x5040"
      },
      "name": "IsPacketHandler179Registered",
      "signature": "bool IsPacketHandler179Registered(void)",
      "comment": "Checks if packet handler 179 (0xb3) is registered in the global packet handler table.\n\nAlgorithm:\n1. Load packet handler function pointer from g_apfnPacketHandlers[0xb3] array slot\n2. Test if the loaded byte value is non-zero (function pointer is registered)\n3. Return true if packet handler is registered, false if slot is empty\n\nParameters:\nNone\n\nReturns:\ntrue - Packet handler 179 is registered in the handler table\nfalse - Packet handler slot 179 is empty or null\n\nMagic Numbers Reference:\n0xb3 (179) - Packet type identifier for handler lookup in function pointer array\n0x6ff397e8 - Memory address of g_apfnPacketHandlers[0xb3] array element",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:1d9f75f652aa66096514a71847c72cd6"
    },
    "Bnclient_MNE_1e2c15b5d4ca": {
      "addresses": {
        "LoD/1.07": "0x6FF26960",
        "LoD/1.08": "0x6FF26980",
        "LoD/1.09": "0x6FF06EF0",
        "LoD/1.09b": "0x6FF06EF0",
        "LoD/1.09d": "0x6FF07160",
        "LoD/1.10": "0x6FF078B0"
      },
      "rvas": {
        "LoD/1.07": "0x6960",
        "LoD/1.08": "0x6980",
        "LoD/1.09": "0x6EF0",
        "LoD/1.09b": "0x6EF0",
        "LoD/1.09d": "0x7160",
        "LoD/1.10": "0x78B0"
      },
      "name": "SendBattleNetGatewayHeartbeat",
      "signature": "dword SendBattleNetGatewayHeartbeat(void)",
      "comment": "Sends a heartbeat packet to Battle.net gateway to maintain connection status.\n\nAlgorithm:\n1. Retrieve current global state value to determine connection status\n2. Convert state result to boolean condition using NEG/SBB operation\n3. Calculate conditional offset based on state (0x13fa if disconnected, 0 if connected)\n4. Add base magic value 0x44324456 to create packet identifier\n5. Load gateway configuration from global address 0x6ff397c0\n6. Initialize packet buffer with header magic 0x49583836\n7. Set packet type to 0xe (heartbeat command)\n8. Configure packet data fields with calculated values\n9. Initialize status flags to zero (bytes at offsets 0x10-0x11)\n10. Send packet via SendNetworkPacketWithValidation with prepared buffer\n11. Return success status (1) regardless of transmission result\n\nParameters:\nNone\n\nReturns:\ndword - Always returns 1 indicating heartbeat was sent (success)\n\nMagic Numbers Reference:\n0x49583836 - Battle.net packet header magic (connection validation)\n0x44324456 - Base packet identifier for heartbeat messages\n0x13fa - Disconnected state offset modifier (5114 decimal)\n0xe - Heartbeat packet type identifier\n0x50c - Stack buffer size (1292 bytes for packet construction)\n0x6ff397c0 - Global gateway configuration data address",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:1e2c15b5d4cad069d06678d4bf693f39"
    },
    "Bnclient_MNE_1f1ea39570d7": {
      "addresses": {
        "LoD/1.07": "0x6FF2CA40",
        "LoD/1.08": "0x6FF2CA60",
        "LoD/1.09": "0x6FF0D660",
        "LoD/1.09b": "0x6FF0D660",
        "LoD/1.09d": "0x6FF0D970",
        "LoD/1.10": "0x6FF0DED6",
        "LoD/1.11": "0x6FF22BAA",
        "LoD/1.11b": "0x6FF23CBF",
        "LoD/1.12a": "0x6FF23262",
        "LoD/1.13c": "0x6FF237DF",
        "LoD/1.13d": "0x6FF2316E"
      },
      "rvas": {
        "LoD/1.07": "0xCA40",
        "LoD/1.08": "0xCA60",
        "LoD/1.09": "0xD660",
        "LoD/1.09b": "0xD660",
        "LoD/1.09d": "0xD970",
        "LoD/1.10": "0xDED6",
        "LoD/1.11": "0x2BAA",
        "LoD/1.11b": "0x3CBF",
        "LoD/1.12a": "0x3262",
        "LoD/1.13c": "0x37DF",
        "LoD/1.13d": "0x316E"
      },
      "name": "TranslateErrorCode",
      "signature": "void TranslateErrorCode(dword dwErrorCode)",
      "comment": "Translates system/Windows error codes to standardized internal error codes.\n\nAlgorithm:\n1. Store input error code via FUN_6ff2cabc() for thread context\n2. Initialize table index to 0, set pointer to g_aErrorCodeMappings array base\n3. Search through error code mapping table (22 entries of 8 bytes each)\n4. For each entry, compare input code with table entry's dwInputErrorCode\n5. If match found, retrieve corresponding dwOutputErrorCode and store via FUN_6ff2cab3()\n6. If no match in table, check special ranges:\n   - Range 0x13-0x24 (19-36): Map to 0xD (INVALID_DATA)\n   - Range 0xBC-0xCA (188-202): Map to 0x8 (NOT_ENOUGH_MEMORY)\n7. If no range match, default to 0x16 (GENERIC_ERROR)\n\nParameters:\ndwErrorCode (dword) - System or Windows error code to translate\n\nReturns:\nvoid - Result stored via internal function calls (FUN_6ff2cab3)\n\nSpecial Cases:\n- Error codes 0x13-0x24 map to INVALID_DATA (0xD)\n- Error codes 0xBC-0xCA map to NOT_ENOUGH_MEMORY (0x8)  \n- All other unmapped codes default to GENERIC_ERROR (0x16)\n\nMagic Numbers Reference:\n0xD (13) - INVALID_DATA error code for range 19-36\n0x8 (8) - NOT_ENOUGH_MEMORY error code for range 188-202\n0x16 (22) - GENERIC_ERROR default fallback code\n0x13 (19) - Lower bound for INVALID_DATA range\n0x24 (36) - Upper bound for INVALID_DATA range  \n0xBC (188) - Lower bound for NOT_ENOUGH_MEMORY range\n0xCA (202) - Upper bound for NOT_ENOUGH_MEMORY range\n\nStructure Layout:\nErrorCodeMapping table at g_aErrorCodeMappings (22 entries):\nOffset | Size | Field Name        | Type  | Description\n0x00   | 4    | dwInputErrorCode  | dword | System error code to match\n0x04   | 4    | dwOutputErrorCode | dword | Internal error code to return",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:1f1ea39570d78b40a761876432663560"
    },
    "Bnclient_MNE_1ffe42f00d5a": {
      "addresses": {
        "LoD/1.07": "0x6FF24B30",
        "LoD/1.08": "0x6FF24B50",
        "LoD/1.09": "0x6FF054B0",
        "LoD/1.09b": "0x6FF054B0",
        "LoD/1.09d": "0x6FF05720",
        "LoD/1.10": "0x6FF05680",
        "LoD/1.11": "0x6FF33930",
        "LoD/1.11b": "0x6FF2E800",
        "LoD/1.12a": "0x6FF2EC90",
        "LoD/1.13c": "0x6FF34CC0",
        "LoD/1.13d": "0x6FF36430"
      },
      "rvas": {
        "LoD/1.07": "0x4B30",
        "LoD/1.08": "0x4B50",
        "LoD/1.09": "0x54B0",
        "LoD/1.09b": "0x54B0",
        "LoD/1.09d": "0x5720",
        "LoD/1.10": "0x5680",
        "LoD/1.11": "0x13930",
        "LoD/1.11b": "0xE800",
        "LoD/1.12a": "0xEC90",
        "LoD/1.13c": "0x14CC0",
        "LoD/1.13d": "0x16430"
      },
      "name": "Nth",
      "signature": "char * Nth(BNGatewayAccess * this, int nIndex)",
      "comment": "Retrieves the Nth element from a BNGatewayAccess collection by traversing variable-length records.\n\nAlgorithm:\n1. Validate input parameters: check if node pointer is not NULL and index is in valid range (1 to collection count)\n2. Return NULL pointer cast to this if validation fails\n3. Initialize traversal: set counter to 1, target position to index * 3, current offset to 0\n4. Loop through elements: for each iteration less than target position\n   a. Check bounds: if current offset >= limit from offset 0x14, exit loop\n   b. Get current element length using Ordinal_506 (likely string length function)\n   c. Advance pointer: move to next element (current + length + 1)\n   d. Update current offset and increment counter\n5. Perform final bounds check with overflow detection using SBORROW4 macro\n6. Return current node pointer if within bounds, otherwise return this pointer\n\nParameters:\nthis (BNGatewayAccess *): Pointer to BNGatewayAccess object containing collection data\n  - Offset 0x8: Collection count (maximum valid index)\n  - Offset 0x10: Pointer to first element in collection\n  - Offset 0x14: Buffer size limit for bounds checking\nnIndex (int): 1-based index of desired element in collection\n\nReturns:\nchar *: Pointer to the Nth element in the collection, or NULL equivalent if index is invalid or out of bounds\n\nSpecial Cases:\nIf index is less than 1 or greater than collection count, returns NULL equivalent\nIf traversal exceeds buffer bounds during navigation, returns this pointer (fallback)\nIndex is 1-based, not 0-based (typical for user-facing APIs)\n\nMagic Numbers Reference:\n0x3: Multiplier applied to index for position calculation (target = index * 3)\n0x8: Offset to collection count field in BNGatewayAccess structure  \n0x10: Offset to first element pointer in BNGatewayAccess structure\n0x14: Offset to buffer limit field for bounds checking\n0x1: Size increment added after each string element (null terminator or separator)\n\nError Handling:\nReturns NULL equivalent (this pointer cast) for invalid indices\nUses overflow detection (SBORROW4) to prevent buffer overruns\nGraceful fallback to this pointer if bounds checking fails during traversal",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:1ffe42f00d5a61a1299a9030af0ba315"
    },
    "Bnclient_MNE_202d2c66c8a5": {
      "addresses": {
        "LoD/1.11": "0x6FF227E2",
        "LoD/1.11b": "0x6FF2383F",
        "LoD/1.12a": "0x6FF22F06",
        "LoD/1.13c": "0x6FF23792",
        "LoD/1.13d": "0x6FF22E12"
      },
      "rvas": {
        "LoD/1.11": "0x27E2",
        "LoD/1.11b": "0x383F",
        "LoD/1.12a": "0x2F06",
        "LoD/1.13c": "0x3792",
        "LoD/1.13d": "0x2E12"
      },
      "name": "___updatetlocinfo",
      "signature": "pthreadlocinfo ___updatetlocinfo(void)",
      "comment": "Library Function - Single Match\n ___updatetlocinfo\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:202d2c66c8a5b404ad3bf64c94b499c1"
    },
    "Bnclient_MNE_2221715ad392": {
      "addresses": {
        "LoD/1.07": "0x6FF304E2",
        "LoD/1.08": "0x6FF30502",
        "LoD/1.09": "0x6FF11122",
        "LoD/1.09b": "0x6FF11122",
        "LoD/1.09d": "0x6FF11412",
        "LoD/1.10": "0x6FF11962"
      },
      "rvas": {
        "LoD/1.07": "0x104E2",
        "LoD/1.08": "0x10502",
        "LoD/1.09": "0x11122",
        "LoD/1.09b": "0x11122",
        "LoD/1.09d": "0x11412",
        "LoD/1.10": "0x11962"
      },
      "name": "AcquireCriticalSectionConditional",
      "signature": "void AcquireCriticalSectionConditional(int nLockIndex, LockContext * pLockContext)",
      "comment": "Acquire critical section using index-based or direct method based on threshold\n\nAlgorithm:\n\n1. Load lock index parameter from stack\n2. Compare lock index against threshold value 0x14 (20)\n3. If index below threshold: branch to indexed acquisition method\n4. If index at/above threshold: use direct critical section method\n5. For indexed method: add offset 0x1c (28) to index\n6. For indexed method: call AcquireCriticalSectionByIndex with adjusted index\n7. For direct method: calculate CRITICAL_SECTION address (pLockContext + 0x20)\n8. For direct method: call Windows EnterCriticalSection API\n9. Return to caller\n\nParameters:\n\n- nLockIndex: Zero-based index of critical section to acquire\n- pLockContext: Pointer to LockContext structure containing synchronization objects\n\nReturns:\n\n- void (no return value)\n- Function modifies global synchronization state\n\nSpecial Cases:\n\n- Threshold 0x14 (20) determines which acquisition method to use\n- Index adjustment +0x1c (28) applied for indexed acquisition only\n- Offset +0x20 (32) locates CRITICAL_SECTION within LockContext structure\n\nStructure Layout:\n\nLockContext structure:\nOffset  Size  Field Name        Type                 Description\n+0x00   32    data              byte[32]            Reserved data area\n+0x20   24    criticalSection   _RTL_CRITICAL_SECTION Windows sync object\n\nMagic Numbers Reference:\n\n- 0x14 (20): Threshold separating indexed vs direct acquisition methods\n- 0x1c (28): Index offset applied before calling AcquireCriticalSectionByIndex  \n- 0x20 (32): Byte offset to criticalSection field in LockContext structure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2221715ad392d22929a667a9021e3f90",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF21304",
          "rva": "0x1304",
          "confidence": 0.29,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.11b": {
          "address": "0x6FF21927",
          "rva": "0x1927",
          "confidence": 0.29,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.12a": {
          "address": "0x6FF2176C",
          "rva": "0x176C",
          "confidence": 0.29,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF21AC7",
          "rva": "0x1AC7",
          "confidence": 0.29,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_229a1516150c": {
      "addresses": {
        "LoD/1.11": "0x6FF339E0",
        "LoD/1.11b": "0x6FF2E8B0",
        "LoD/1.12a": "0x6FF2ED40",
        "LoD/1.13c": "0x6FF34D70",
        "LoD/1.13d": "0x6FF364E0"
      },
      "rvas": {
        "LoD/1.11": "0x139E0",
        "LoD/1.11b": "0xE8B0",
        "LoD/1.12a": "0xED40",
        "LoD/1.13c": "0x14D70",
        "LoD/1.13d": "0x164E0"
      },
      "name": "FindKey",
      "signature": "char * FindKey(BNGatewayAccess * this, char * param_1, char * param_2)",
      "comment": "private: char * __thiscall BNGatewayAccess::FindKey(char *,char *)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:229a1516150cb863f4ec8fa73ca96d14"
    },
    "Bnclient_MNE_23133f974a4f": {
      "addresses": {
        "LoD/1.07": "0x6FF2B240",
        "LoD/1.08": "0x6FF2B390",
        "LoD/1.09": "0x6FF132D0",
        "LoD/1.09b": "0x6FF132D0",
        "LoD/1.09d": "0x6FF135F0",
        "LoD/1.10": "0x6FF13BF0"
      },
      "rvas": {
        "LoD/1.07": "0xB240",
        "LoD/1.08": "0xB390",
        "LoD/1.09": "0x132D0",
        "LoD/1.09b": "0x132D0",
        "LoD/1.09d": "0x135F0",
        "LoD/1.10": "0x13BF0"
      },
      "name": "SetGlobalProcessIdSafe",
      "signature": "uint SetGlobalProcessIdSafe(uint dwProcessId)",
      "comment": "Thread-safe initialization of global process ID with one-time assignment semantics.\n\nAlgorithm:\n\n1. Enter critical section to ensure thread-safe access to global data\n2. Check if global process ID field is currently uninitialized (zero)\n3. If uninitialized, assign the provided process ID to the global field\n4. Leave critical section to release thread synchronization lock\n5. Return success indicator (always 1)\n\nParameters:\n\ndwProcessId (uint) - Process identifier to store globally if not already set\n\nReturns:\n\n1 (uint) - Always returns 1 indicating successful completion\n\nSpecial Cases:\n\nIf global process ID is already set (non-zero), the function performs no assignment\nbut still executes the full critical section protocol for consistency.\n\nStructure Layout:\n\nThe function accesses g_abGlobalStringBuffer structure:\nOffset | Size | Field Name         | Type | Description\n0x130  | 24   | criticalSection    | CRITICAL_SECTION | Thread synchronization object  \n0x14c  | 4    | globalProcessId    | uint | Protected process identifier storage",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:23133f974a4f1affb8dde84d92eb4221"
    },
    "Bnclient_MNE_2427cd9c654a": {
      "addresses": {
        "LoD/1.07": "0x6FF2C944",
        "LoD/1.08": "0x6FF2C964",
        "LoD/1.09": "0x6FF0D564",
        "LoD/1.09b": "0x6FF0D564",
        "LoD/1.09d": "0x6FF0D874",
        "LoD/1.10": "0x6FF0DDDA"
      },
      "rvas": {
        "LoD/1.07": "0xC944",
        "LoD/1.08": "0xC964",
        "LoD/1.09": "0xD564",
        "LoD/1.09b": "0xD564",
        "LoD/1.09d": "0xD874",
        "LoD/1.10": "0xDDDA"
      },
      "name": "AllocateMemoryByStrategy",
      "signature": "void * AllocateMemoryByStrategy(ulong dwSize)",
      "comment": "Allocate memory using strategy-based allocation system with fallback to heap\n\nAlgorithm:\n1. Initialize structured exception handling (SEH) with error state 0xFFFFFFFF\n2. Check global allocation strategy value (g_dwAllocationStrategy)\n3. Strategy 3 (Pool allocation):\n   - Verify requested size <= pool limit (g_dwPoolSizeLimit)\n   - Acquire critical section lock (index 9)\n   - Call pool allocator (FUN_6ff2eb6f) with raw size\n   - Release critical section lock\n   - Return allocated pointer if successful, otherwise fall to heap\n4. Strategy 2 (Block allocation):\n   - Calculate aligned size: (size + 15) & 0xFFFFFFF0 (16-byte alignment)\n   - Use minimum 16 bytes if size is 0\n   - Verify aligned size <= block threshold (g_dwBlockSizeThreshold)\n   - Acquire critical section lock (index 9)\n   - Call block allocator (FUN_6ff2f612) with size >> 4 (divided by 16)\n   - Release critical section lock\n   - Return allocated pointer if successful, otherwise fall to heap\n5. Fallback allocation:\n   - Use minimum 1 byte if size is 0\n   - Calculate aligned size: (size + 15) & 0xFFFFFFF0\n   - Call HeapAlloc with global heap handle (g_hHeapHandle)\n   - Return allocated pointer (or NULL on failure)\n6. Restore exception handling and return\n\nParameters:\ndwSize (ulong): Requested allocation size in bytes\n\nReturns:\nvoid *: Pointer to allocated memory block, or NULL if allocation fails\n\nSpecial Cases:\nZero size allocation converts to minimum allocation (1 byte for heap, 16 for blocks)\nAll allocations are 16-byte aligned for optimal performance\nCritical sections provide thread safety for pool and block strategies\n\nMagic Numbers Reference:\n0xFFFFFFFF - SEH error state marker\n0x10 (16) - Minimum block size and alignment boundary\n0xF (15) - Alignment mask for 16-byte boundary calculation\n0xFFFFFFF0 - Alignment mask (inverted 15) for clearing low 4 bits\n9 - Critical section index for allocation subsystem\n\nError Handling:\nSEH protects against access violations during allocation\nFailed pool/block allocations automatically fall back to heap allocation\nNULL return indicates complete allocation failure (out of memory)\n\nState Machine:\nState 1: Check strategy 3 \u2192 Pool allocation attempt \u2192 Success/Fall to heap\nState 2: Check strategy 2 \u2192 Block allocation attempt \u2192 Success/Fall to heap  \nState 3: Fallback allocation \u2192 HeapAlloc \u2192 Return result\nState 4: Cleanup SEH and return allocated pointer",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2427cd9c654afc2c511ea083018810d8"
    },
    "Bnclient_MNE_2544af1d7a07": {
      "addresses": {
        "LoD/1.11": "0x6FF21A7F",
        "LoD/1.11b": "0x6FF2158E",
        "LoD/1.12a": "0x6FF21534",
        "LoD/1.13c": "0x6FF2137A",
        "LoD/1.13d": "0x6FF2185E"
      },
      "rvas": {
        "LoD/1.11": "0x1A7F",
        "LoD/1.11b": "0x158E",
        "LoD/1.12a": "0x1534",
        "LoD/1.13c": "0x137A",
        "LoD/1.13d": "0x185E"
      },
      "name": "_atexit",
      "signature": "int _atexit(_func_4879 * param_1)",
      "comment": "Library Function - Single Match\n _atexit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:2544af1d7a0712444106eb929de8e62d"
    },
    "Bnclient_MNE_259e69de0e65": {
      "addresses": {
        "LoD/1.09": "0x6FF15170",
        "LoD/1.09b": "0x6FF15170",
        "LoD/1.09d": "0x6FF15490",
        "LoD/1.10": "0x6FF15A20"
      },
      "rvas": {
        "LoD/1.09": "0x15170",
        "LoD/1.09b": "0x15170",
        "LoD/1.09d": "0x15490",
        "LoD/1.10": "0x15A20"
      },
      "method": "MNE",
      "index": "MNE:259e69de0e65044867c468a378151c1d"
    },
    "Bnclient_MNE_262b55d4b1f2": {
      "addresses": {
        "LoD/1.11": "0x6FF25750",
        "LoD/1.11b": "0x6FF26EC0",
        "LoD/1.12a": "0x6FF266C0",
        "LoD/1.13c": "0x6FF26F20",
        "LoD/1.13d": "0x6FF25B50"
      },
      "rvas": {
        "LoD/1.11": "0x5750",
        "LoD/1.11b": "0x6EC0",
        "LoD/1.12a": "0x66C0",
        "LoD/1.13c": "0x6F20",
        "LoD/1.13d": "0x5B50"
      },
      "name": "_strpbrk",
      "signature": "char * _strpbrk(char * _Str, char * _Control)",
      "comment": "Library Function - Single Match\n _strpbrk\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:262b55d4b1f21fd166621d0ca2135ed8"
    },
    "Bnclient_MNE_28393cf54a38": {
      "addresses": {
        "LoD/1.07": "0x6FF2D034",
        "LoD/1.08": "0x6FF2D054",
        "LoD/1.09": "0x6FF0DC54",
        "LoD/1.09b": "0x6FF0DC54",
        "LoD/1.09d": "0x6FF0DF64",
        "LoD/1.10": "0x6FF0E4CC"
      },
      "rvas": {
        "LoD/1.07": "0xD034",
        "LoD/1.08": "0xD054",
        "LoD/1.09": "0xDC54",
        "LoD/1.09b": "0xDC54",
        "LoD/1.09d": "0xDF64",
        "LoD/1.10": "0xE4CC"
      },
      "name": "StreamPutChar",
      "signature": "dword StreamPutChar(dword nCharacter, StreamIO * pStream)",
      "comment": "Writes a single character to a stream with buffering and error handling support.\n\nAlgorithm:\n1. Validate stream flags - check for invalid flag combinations (0x82 clear OR 0x40 set)\n2. Handle buffering reset - if 0x01 flag set, reset position and optionally restore buffer base\n3. Setup output mode - clear position, set backup pointer, configure output flags (clear 0x10, set 0x02)\n4. Validate special streams - check if stream matches standard descriptors and validate with FUN_6ff3037c\n5. Perform stream cleanup - call FUN_6ff30338 if validation passes\n6. Choose output path - buffered (flags & 0x108 != 0) or unbuffered output\n7. Buffered output - calculate available space, write directly to buffer or call write function\n8. Handle buffer exhaustion - get stream descriptor from table and check error flags\n9. Error handling - call FUN_6ff30070 if error flag 0x20 is set\n10. Unbuffered output - call FUN_6ff30148 with character address and size 1\n11. Verify write result - compare returned bytes with expected count\n12. Set error state - set flag 0x20 on write failure, return character on success\n\nParameters:\nnCharacter: Character to write (only low 8 bits used)\npStream: Pointer to stream descriptor structure\n\nReturns:\nCharacter value (0x00-0xFF) on successful write\n0xFFFFFFFF on error or invalid stream state\n\nMagic Numbers Reference:\n0x01: Buffer reset flag\n0x02: Output mode flag  \n0x10: Buffer restore flag\n0x20: Error state flag\n0x40: Read-only flag\n0x82: Combined invalid flags\n0x108: Buffering mode flags\n0x24: Stream descriptor stride (36 bytes)\n0xFF: Character mask for return value\n0xFFFFFFFF: Error return value\n\nStructure Layout:\nOffset  Size  Field Name    Type      Description\n0x00    4     pBase         void*     Base buffer pointer\n0x04    4     nPosition     int       Current position offset  \n0x08    4     pCurrent      void*     Current buffer pointer\n0x0C    4     dwFlags       dword     Primary stream flags\n0x10    4     dwFlags2      dword     Stream identifier/handle\n0x14    4     reserved      dword     Reserved field\n0x18    4     nAvailable    int       Available buffer space\n0x1C    4     reserved2     dword     Reserved field  \n0x20    4     reserved3     dword     Reserved field\n\nError Handling:\nInvalid flags (0x82 clear OR 0x40 set): Set error flag 0x20 and return 0xFFFFFFFF\nBuffer exhaustion with error flag: Call error handler FUN_6ff30070\nWrite operation failure: Set flag 0x20 and return 0xFFFFFFFF  \nStandard stream validation failure: Proceed with cleanup and normal flow",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:28393cf54a38bf1465f92d01d5d4df21"
    },
    "Bnclient_MNE_287f56bbdd21": {
      "addresses": {
        "LoD/1.09": "0x6FF13270",
        "LoD/1.09b": "0x6FF13270",
        "LoD/1.09d": "0x6FF13590",
        "LoD/1.10": "0x6FF13B90"
      },
      "rvas": {
        "LoD/1.09": "0x13270",
        "LoD/1.09b": "0x13270",
        "LoD/1.09d": "0x13590",
        "LoD/1.10": "0x13B90"
      },
      "method": "MNE",
      "index": "MNE:287f56bbdd2164f990dde4e20bd8c66a"
    },
    "Bnclient_MNE_28a1cba9ddfd": {
      "addresses": {
        "LoD/1.11": "0x6FF21BD7",
        "LoD/1.11b": "0x6FF21350",
        "LoD/1.12a": "0x6FF212F6",
        "LoD/1.13c": "0x6FF2143C",
        "LoD/1.13d": "0x6FF215B8"
      },
      "rvas": {
        "LoD/1.11": "0x1BD7",
        "LoD/1.11b": "0x1350",
        "LoD/1.12a": "0x12F6",
        "LoD/1.13c": "0x143C",
        "LoD/1.13d": "0x15B8"
      },
      "name": "__cinit",
      "signature": "int __cinit(int param_1)",
      "comment": "Library Function - Single Match\n __cinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:28a1cba9ddfd9945ee3fec59104d67a8"
    },
    "Bnclient_MNE_2a0dd1f395da": {
      "addresses": {
        "LoD/1.07": "0x6FF31E05",
        "LoD/1.08": "0x6FF31E25",
        "LoD/1.09": "0x6FF0F466",
        "LoD/1.09b": "0x6FF0F466",
        "LoD/1.09d": "0x6FF12D35",
        "LoD/1.10": "0x6FF132B9",
        "LoD/1.11": "0x6FF2642D",
        "LoD/1.11b": "0x6FF2595E",
        "LoD/1.12a": "0x6FF24DC6",
        "LoD/1.13c": "0x6FF24A11",
        "LoD/1.13d": "0x6FF26487"
      },
      "rvas": {
        "LoD/1.07": "0x11E05",
        "LoD/1.08": "0x11E25",
        "LoD/1.09": "0xF466",
        "LoD/1.09b": "0xF466",
        "LoD/1.09d": "0x12D35",
        "LoD/1.10": "0x132B9",
        "LoD/1.11": "0x642D",
        "LoD/1.11b": "0x595E",
        "LoD/1.12a": "0x4DC6",
        "LoD/1.13c": "0x4A11",
        "LoD/1.13d": "0x6487"
      },
      "name": "FindMemoryAllocationByAddress",
      "signature": "MemoryAllocation * FindMemoryAllocationByAddress(byte * pVirtualAddress)",
      "comment": "Searches the global allocation table to find the MemoryAllocation record containing a given virtual address.\n\nAlgorithm:\n1. Initialize pAllocationEntry to point to start of g_pAllocationTable\n2. Check if pAllocationEntry has reached end of allocation table (g_pAllocationTable + g_dwAllocationCount)\n3. If at end of table, return NULL (allocation not found)\n4. Calculate address difference: pVirtualAddress - pAllocationEntry->pVirtualMemory\n5. Check if difference is within allocation size boundary (< 0x100000)\n6. If within boundary, allocation found - return pointer to MemoryAllocation record\n7. If not within boundary, advance to next allocation entry (+20 bytes)\n8. Loop back to step 2 to check next entry\n\nParameters:\npVirtualAddress - Virtual memory address to search for in allocation table\n\nReturns:\nMemoryAllocation * - Pointer to allocation record containing the address, or NULL if not found\n\nSpecial Cases:\nNULL return when address not found in any allocation record\nAddress range check uses 0x100000 boundary for allocation size validation\n\nMagic Numbers Reference:\n0x100000 (1,048,576) - Maximum allocation size boundary in bytes\n0x14 (20) - Size of MemoryAllocation structure for pointer advancement\n0xc (12) - Offset to pVirtualMemory field in MemoryAllocation structure\n\nStructure Layout:\nMemoryAllocation (20 bytes):\nOffset | Size | Field Name      | Type    | Description\n+0x00  | 4    | dwFlags         | uint    | Allocation flags and status\n+0x04  | 4    | dwSize          | uint    | Size of allocated memory block  \n+0x08  | 4    | pNextEntry      | void *  | Next allocation in linked list\n+0x0c  | 4    | pVirtualMemory  | void *  | Base address of allocated memory\n+0x10  | 4    | dwChecksum      | uint    | Integrity checksum for validation",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2a0dd1f395da0f8e13609d337843c676"
    },
    "Bnclient_MNE_2af2421e9adb": {
      "addresses": {
        "LoD/1.11": "0x6FF37572",
        "LoD/1.11b": "0x6FF37542",
        "LoD/1.12a": "0x6FF383F2",
        "LoD/1.13c": "0x6FF383D2",
        "LoD/1.13d": "0x6FF38312"
      },
      "rvas": {
        "LoD/1.11": "0x17572",
        "LoD/1.11b": "0x17542",
        "LoD/1.12a": "0x183F2",
        "LoD/1.13c": "0x183D2",
        "LoD/1.13d": "0x18312"
      },
      "name": "siglookup",
      "signature": "undefined siglookup(void)",
      "comment": "Library Function - Single Match\n _siglookup\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:2af2421e9adbd50e4220f87768729b8e"
    },
    "Bnclient_MNE_2b72785c7d09": {
      "addresses": {
        "LoD/1.11": "0x6FF255C0",
        "LoD/1.11b": "0x6FF24EB0",
        "LoD/1.12a": "0x6FF26530",
        "LoD/1.13c": "0x6FF260A0",
        "LoD/1.13d": "0x6FF24F20"
      },
      "rvas": {
        "LoD/1.11": "0x55C0",
        "LoD/1.11b": "0x4EB0",
        "LoD/1.12a": "0x6530",
        "LoD/1.13c": "0x60A0",
        "LoD/1.13d": "0x4F20"
      },
      "name": "_strlen",
      "signature": "size_t _strlen(char * _Str)",
      "comment": "Library Function - Single Match\n _strlen\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:2b72785c7d09e5484d16dae5407e64ce"
    },
    "Bnclient_MNE_2db85971dc36": {
      "addresses": {
        "LoD/1.11": "0x6FF249F3",
        "LoD/1.11b": "0x6FF26F43",
        "LoD/1.13d": "0x6FF27153"
      },
      "rvas": {
        "LoD/1.11": "0x49F3",
        "LoD/1.11b": "0x6F43",
        "LoD/1.13d": "0x7153"
      },
      "name": "___convertcp",
      "signature": "undefined ___convertcp(UINT param_1, UINT param_2, char * param_3, size_t * param_4, LPSTR param_5, int param_6)",
      "comment": "Library Function - Single Match\n ___convertcp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:2db85971dc36836255f9e9bf407d84c7"
    },
    "Bnclient_MNE_2e762c1c6c45": {
      "addresses": {
        "LoD/1.07": "0x6FF2FE80",
        "LoD/1.08": "0x6FF2FEA0",
        "LoD/1.09": "0x6FF10AC0",
        "LoD/1.09b": "0x6FF10AC0",
        "LoD/1.09d": "0x6FF10DB0",
        "LoD/1.10": "0x6FF11300"
      },
      "rvas": {
        "LoD/1.07": "0xFE80",
        "LoD/1.08": "0xFEA0",
        "LoD/1.09": "0x10AC0",
        "LoD/1.09b": "0x10AC0",
        "LoD/1.09d": "0x10DB0",
        "LoD/1.10": "0x11300"
      },
      "name": "CalculateStringLength",
      "signature": "size_t CalculateStringLength(char * lpszStr)",
      "comment": "Calculates the length of a null-terminated string using optimized 4-byte chunk processing.\n\nAlgorithm:\n1. Check if input pointer is 4-byte aligned using mask operation (lpszStr & 3)\n2. If unaligned, process bytes one-by-one until reaching 4-byte boundary or null terminator\n3. For aligned processing, load 4-byte chunks and use bit manipulation to detect zero bytes in parallel\n4. Apply magic constant 0x7efefeff to detect null bytes: ((chunk ^ 0xffffffff) ^ (chunk + 0x7efefeff)) & 0x81010100\n5. When zero byte detected, examine each byte position to find exact null terminator location\n6. Calculate final length by subtracting original pointer from null terminator position\n\nParameters:\nlpszStr (char *): Null-terminated input string to measure\n\nReturns:\nsize_t: Length of string in bytes (excluding null terminator)\nReturns 0 for empty string or single null character\n\nSpecial Cases:\nUses optimized bit manipulation for parallel null byte detection in 4-byte chunks\nHandles unaligned string pointers by processing leading bytes individually\nMagic number 0x7efefeff enables simultaneous zero detection across all 4 bytes\n\nMagic Numbers Reference:\n0x3 (0x00000003): Alignment mask to check if pointer is 4-byte aligned\n0x7efefeff: Magic constant for parallel zero byte detection in 32-bit words\n0xffffffff: XOR mask to invert all bits for zero detection algorithm  \n0x81010100: Test mask to isolate zero byte detection results",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2e762c1c6c457f4a0349d0f895009434"
    },
    "Bnclient_MNE_2eb702b4edd9": {
      "addresses": {
        "LoD/1.09": "0x6FF13010",
        "LoD/1.09b": "0x6FF13010",
        "LoD/1.09d": "0x6FF13330"
      },
      "rvas": {
        "LoD/1.09": "0x13010",
        "LoD/1.09b": "0x13010",
        "LoD/1.09d": "0x13330"
      },
      "method": "MNE",
      "index": "MNE:2eb702b4edd9f0140ab5f3ab0711b670"
    },
    "Bnclient_MNE_2f17f14e3f70": {
      "addresses": {
        "LoD/1.11": "0x6FF33740",
        "LoD/1.11b": "0x6FF2E610",
        "LoD/1.12a": "0x6FF2EAA0",
        "LoD/1.13c": "0x6FF34AD0",
        "LoD/1.13d": "0x6FF36240"
      },
      "rvas": {
        "LoD/1.11": "0x13740",
        "LoD/1.11b": "0xE610",
        "LoD/1.12a": "0xEAA0",
        "LoD/1.13c": "0x14AD0",
        "LoD/1.13d": "0x16240"
      },
      "name": "SkipEOL",
      "signature": "char * SkipEOL(BNGatewayAccess * this, char * param_1, char * param_2)",
      "comment": "private: char * __thiscall BNGatewayAccess::SkipEOL(char *,char *)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:2f17f14e3f70cc985dc81c835053b4b7",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF0FD39",
          "rva": "0xFD39",
          "confidence": 0.365,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF0F74B",
          "rva": "0xF74B",
          "confidence": 0.296,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF0E85C",
          "rva": "0xE85C",
          "confidence": 0.194,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_30121dcb0e48": {
      "addresses": {
        "LoD/1.07": "0x6FF2B473",
        "LoD/1.08": "0x6FF2B494",
        "LoD/1.09": "0x6FF0C094",
        "LoD/1.09b": "0x6FF0C094",
        "LoD/1.09d": "0x6FF0C2F3",
        "LoD/1.10": "0x6FF0C853"
      },
      "rvas": {
        "LoD/1.07": "0xB473",
        "LoD/1.08": "0xB494",
        "LoD/1.09": "0xC094",
        "LoD/1.09b": "0xC094",
        "LoD/1.09d": "0xC2F3",
        "LoD/1.10": "0xC853"
      },
      "name": "AddToDynamicBufferWithErrorCode",
      "signature": "int AddToDynamicBufferWithErrorCode(uint dwValue)",
      "comment": "Wrapper function that adds a value to dynamic buffer and converts result to standard error code format.\n\nAlgorithm:\n1. Call AddToDynamicBuffer with the input value\n2. Convert boolean result to error code: 0 (success) becomes 0, non-zero (failure) becomes -1\n3. Return the converted error code\n\nParameters:\n- dwValue (uint): Value to add to the dynamic buffer\n\nReturns:\n- 0: Success (AddToDynamicBuffer returned non-zero indicating success)\n- -1: Failure (AddToDynamicBuffer returned 0 indicating failure)\n\nSpecial Cases:\n- Function performs boolean-to-error-code conversion using the pattern: (result != 0) - 1\n- This converts: true \u2192 0 (success), false \u2192 -1 (error)\n\nError Handling:\n- Propagates AddToDynamicBuffer failure as -1 error code\n- No direct error checking, relies on called function's return value",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:30121dcb0e48ab1814aec1130583025a"
    },
    "Bnclient_MNE_301bd5440f60": {
      "addresses": {
        "LoD/1.07": "0x6FF2C906",
        "LoD/1.08": "0x6FF2C926",
        "LoD/1.09": "0x6FF0D526",
        "LoD/1.09b": "0x6FF0D526",
        "LoD/1.09d": "0x6FF0D836",
        "LoD/1.10": "0x6FF0DD9C",
        "LoD/1.11": "0x6FF23D3E",
        "LoD/1.11b": "0x6FF23543",
        "LoD/1.12a": "0x6FF228A8",
        "LoD/1.13c": "0x6FF22544",
        "LoD/1.13d": "0x6FF238F2"
      },
      "rvas": {
        "LoD/1.07": "0xC906",
        "LoD/1.08": "0xC926",
        "LoD/1.09": "0xD526",
        "LoD/1.09b": "0xD526",
        "LoD/1.09d": "0xD836",
        "LoD/1.10": "0xDD9C",
        "LoD/1.11": "0x3D3E",
        "LoD/1.11b": "0x3543",
        "LoD/1.12a": "0x28A8",
        "LoD/1.13c": "0x2544",
        "LoD/1.13d": "0x38F2"
      },
      "name": "_malloc",
      "signature": "void * _malloc(size_t _Size)",
      "comment": "Library Function - Single Match\n _malloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:301bd5440f60703ca7a24a8fb30f1e56"
    },
    "Bnclient_MNE_305c32d33191": {
      "addresses": {
        "LoD/1.07": "0x6FF26090",
        "LoD/1.08": "0x6FF260B0",
        "LoD/1.09": "0x6FF067F0",
        "LoD/1.09b": "0x6FF067F0",
        "LoD/1.09d": "0x6FF06A60",
        "LoD/1.10": "0x6FF071A0"
      },
      "rvas": {
        "LoD/1.07": "0x6090",
        "LoD/1.08": "0x60B0",
        "LoD/1.09": "0x67F0",
        "LoD/1.09b": "0x67F0",
        "LoD/1.09d": "0x6A60",
        "LoD/1.10": "0x71A0"
      },
      "name": "SetGlobalStringBufferField",
      "signature": "void SetGlobalStringBufferField(uint dwValue)",
      "comment": "Sets a 32-bit value in the global string buffer at offset 348.\n\nAlgorithm:\n1. Store the provided 32-bit value directly into g_abGlobalStringBuffer at offset 348\n2. Return to caller without additional processing\n\nParameters:\n  dwValue (uint) - 32-bit value to store in the global buffer field\n\nReturns:\n  void - Function performs store operation and returns\n\nSpecial Cases:\n  - No validation performed on input value\n  - Direct memory write at fixed offset 0x15C (348 decimal)\n  - Function assumes g_abGlobalStringBuffer is properly initialized\n\nMagic Numbers Reference:\n  0x15C (348) - Fixed offset into global string buffer for this field",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:305c32d33191c1b22ce2562362c5fa24"
    },
    "Bnclient_MNE_305f98c2994b": {
      "addresses": {
        "LoD/1.11": "0x6FF36A29",
        "LoD/1.11b": "0x6FF369FA",
        "LoD/1.12a": "0x6FF378A9",
        "LoD/1.13c": "0x6FF3788F",
        "LoD/1.13d": "0x6FF377C8"
      },
      "rvas": {
        "LoD/1.11": "0x16A29",
        "LoD/1.11b": "0x169FA",
        "LoD/1.12a": "0x178A9",
        "LoD/1.13c": "0x1788F",
        "LoD/1.13d": "0x177C8"
      },
      "name": "_CallCatchBlock2",
      "signature": "void * _CallCatchBlock2(EHRegistrationNode * param_1, _s_FuncInfo * param_2, void * param_3, int param_4, ulong param_5)",
      "comment": "Library Function - Single Match\n void * __cdecl _CallCatchBlock2(struct EHRegistrationNode *,struct _s_FuncInfo const *,void *,int,unsigned long)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:305f98c2994b523fe4a005bfb539afe0"
    },
    "Bnclient_MNE_30f0fd08cad9": {
      "addresses": {
        "LoD/1.07": "0x6FF2FE40",
        "LoD/1.08": "0x6FF2FE60",
        "LoD/1.09": "0x6FF10A80",
        "LoD/1.09b": "0x6FF10A80",
        "LoD/1.09d": "0x6FF10D70",
        "LoD/1.10": "0x6FF112C0"
      },
      "rvas": {
        "LoD/1.07": "0xFE40",
        "LoD/1.08": "0xFE60",
        "LoD/1.09": "0x10A80",
        "LoD/1.09b": "0x10A80",
        "LoD/1.09d": "0x10D70",
        "LoD/1.10": "0x112C0"
      },
      "name": "CountCharsUntilFilterMatch",
      "signature": "int CountCharsUntilFilterMatch(byte * pbInput, byte * pbFilterChars)",
      "comment": "Counts characters in input string until encountering a character present in the filter string.\n\nAlgorithm:\n1. Initialize 256-bit character bitmap (32 bytes) to zero on stack\n2. Build bitmap from filter string: for each character, set corresponding bit using BTS instruction\n3. Initialize character counter to -1\n4. Loop through input string:\n   a. Increment counter\n   b. Read current character from input\n   c. If character is null terminator, return counter (end of string reached)\n   d. Test if character bit is set in bitmap using BT instruction\n   e. If bit is clear (character not in filter), continue loop\n   f. If bit is set (character matches filter), return counter\n\nParameters:\npbInput (byte *): Input string to scan for characters\npbFilterChars (byte *): String containing characters to filter against\n\nReturns:\nint: Number of characters processed before encountering a filtered character\n     Returns total string length if no filtered characters found\n\nSpecial Cases:\nEmpty input string: Returns 0\nEmpty filter string: Returns length of entire input string (no characters filtered)\nNull terminator handling: Proper termination on null bytes\n\nMagic Numbers Reference:\n0x01: Bit mask for setting individual bits in bitmap (1 << (char & 7))\n0x20: Stack space allocated for 32-byte character bitmap (256 bits)\n0x07: Bit position mask (char & 7) for bit operations within byte\n0x03: Right shift count (char >> 3) to convert character to byte index\n\nAlgorithm Implementation:\nBitmap indexing: abCharBitmap[char >> 3] accesses byte containing char's bit\nBit positioning: (char & 7) gets bit position (0-7) within that byte\nBit setting: Uses BTS (bit test and set) for atomic bit setting\nBit testing: Uses BT (bit test) for efficient character lookup",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:30f0fd08cad97c1e8bd24ed371c4d8a2"
    },
    "Bnclient_MNE_312b4ad2d1d8": {
      "addresses": {
        "LoD/1.11": "0x6FF21160",
        "LoD/1.11b": "0x6FF21110",
        "LoD/1.12a": "0x6FF211C0",
        "LoD/1.13c": "0x6FF21160",
        "LoD/1.13d": "0x6FF21160"
      },
      "rvas": {
        "LoD/1.11": "0x1160",
        "LoD/1.11b": "0x1110",
        "LoD/1.12a": "0x11C0",
        "LoD/1.13c": "0x1160",
        "LoD/1.13d": "0x1160"
      },
      "method": "MNE",
      "index": "MNE:312b4ad2d1d805e200c10b6d0fbe02ac"
    },
    "Bnclient_MNE_3178e58c7793": {
      "addresses": {
        "LoD/1.10": "0x6FF13930"
      },
      "rvas": {
        "LoD/1.10": "0x13930"
      },
      "method": "MNE",
      "index": "MNE:3178e58c779350a3b36dadcbbe52268e"
    },
    "Bnclient_MNE_328852572d3a": {
      "addresses": {
        "LoD/1.11": "0x6FF32260",
        "LoD/1.11b": "0x6FF2B000",
        "LoD/1.12a": "0x6FF31350",
        "LoD/1.13c": "0x6FF2FC70",
        "LoD/1.13d": "0x6FF34E50"
      },
      "rvas": {
        "LoD/1.11": "0x12260",
        "LoD/1.11b": "0xB000",
        "LoD/1.12a": "0x11350",
        "LoD/1.13c": "0xFC70",
        "LoD/1.13d": "0x14E50"
      },
      "method": "MNE",
      "index": "MNE:328852572d3a9f0ab8de60cdc5daa0aa",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF065B0",
          "rva": "0x65B0",
          "confidence": 0.399,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF063E0",
          "rva": "0x63E0",
          "confidence": 0.212,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_334e7114a534": {
      "addresses": {
        "LoD/1.09": "0x6FF12F90",
        "LoD/1.09b": "0x6FF12F90",
        "LoD/1.09d": "0x6FF132B0",
        "LoD/1.10": "0x6FF138B0"
      },
      "rvas": {
        "LoD/1.09": "0x12F90",
        "LoD/1.09b": "0x12F90",
        "LoD/1.09d": "0x132B0",
        "LoD/1.10": "0x138B0"
      },
      "method": "MNE",
      "index": "MNE:334e7114a534a7eb51a020a2b3dceeed",
      "candidates": {
        "LoD/1.12a": {
          "address": "0x6FF34010",
          "rva": "0x14010",
          "confidence": 0.294,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF2C960",
          "rva": "0xC960",
          "confidence": 0.294,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13d": {
          "address": "0x6FF33C60",
          "rva": "0x13C60",
          "confidence": 0.174,
          "method": "minhash",
          "direction": "forward",
          "source": "LoD/1.13c"
        }
      }
    },
    "Bnclient_MNE_34dfd362d301": {
      "addresses": {
        "LoD/1.07": "0x6FF2ADD0",
        "LoD/1.08": "0x6FF2ADF0",
        "LoD/1.09": "0x6FF0B9F0",
        "LoD/1.09b": "0x6FF0B9F0",
        "LoD/1.09d": "0x6FF0BC40",
        "LoD/1.10": "0x6FF0C250"
      },
      "rvas": {
        "LoD/1.07": "0xADD0",
        "LoD/1.08": "0xADF0",
        "LoD/1.09": "0xB9F0",
        "LoD/1.09b": "0xB9F0",
        "LoD/1.09d": "0xBC40",
        "LoD/1.10": "0xC250"
      },
      "name": "UpdateCryptoContextWithData",
      "signature": "void UpdateCryptoContextWithData(int nContextIndex, dword * pdwInputData, dword * pdwOutputHash)",
      "comment": "Updates cryptographic context with 64 bytes of input data and optionally returns hash state.\n\nAlgorithm:\n1. Calculate context structure offset using nContextIndex * 0x5c + 0x340\n2. Read current counter value and add 0x200 (512 bytes)\n3. Check for counter overflow and increment overflow counter if needed\n4. Update counter value in context structure\n5. Copy 64 bytes of input data (16 dwords) into context buffer at offset +0x1c\n6. Call cryptographic processing function on updated context\n7. If output buffer provided, copy 5 dwords (20 bytes) of hash state to output\n\nParameters:\nnContextIndex - Index into global cryptographic context array\npdwInputData - Pointer to 64 bytes (16 dwords) of input data to process\npdwOutputHash - Optional output buffer for 20 bytes of hash state (NULL to skip)\n\nReturns:\nvoid\n\nSpecial Cases:\n- Counter overflow detection at step 3 increments overflow counter\n- Output copying skipped if pdwOutputHash is NULL\n- Input data always copied regardless of output buffer presence\n\nMagic Numbers Reference:\n0x5c (92) - Size of each cryptographic context structure\n0x200 (512) - Block size increment for counter update\n0x340 (832) - Base offset to cryptographic context array in global buffer\n0x354 (852) - Offset to counter field within context structure\n0x358 (856) - Offset to overflow counter field\n0x35c (860) - Offset to 64-byte data buffer within context\n0x10 (16) - Number of dwords to copy from input (64 bytes total)\n0x5 (5) - Number of dwords to copy to output (20 bytes total)\n\nStructure Layout:\nOffset | Size | Field Name    | Type  | Description\n+0x00  | 4    | dwState       | dword | First state dword\n+0x04  | 4    | dwCounter     | dword | Block counter (offset +0x14 relative to +0x340)\n+0x08  | 4    | dwOverflow    | dword | Overflow counter (offset +0x18 relative to +0x340)\n+0x0C  | 4    | reserved      | dword | Reserved field\n+0x10  | 64   | abBuffer      | byte  | Input data buffer (offset +0x1c relative to +0x340)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:34dfd362d301581ce07fc8eec35c408b"
    },
    "Bnclient_MNE_3545eb0c48f8": {
      "addresses": {
        "LoD/1.07": "0x6FF25A90",
        "LoD/1.08": "0x6FF25AB0",
        "LoD/1.09": "0x6FF06410",
        "LoD/1.09b": "0x6FF06410",
        "LoD/1.09d": "0x6FF06680"
      },
      "rvas": {
        "LoD/1.07": "0x5A90",
        "LoD/1.08": "0x5AB0",
        "LoD/1.09": "0x6410",
        "LoD/1.09b": "0x6410",
        "LoD/1.09d": "0x6680"
      },
      "name": "SetGlobalProcessIdForced",
      "signature": "DWORD SetGlobalProcessIdForced(DWORD dwProcessId)",
      "comment": "Thread-safe global process ID setter that unconditionally overwrites stored value.\n\nAlgorithm:\n1. Enter critical section to ensure thread safety during global state modification\n2. Store the provided process ID value unconditionally to global storage location  \n3. Leave critical section to release lock for other threads\n4. Return success code to indicate operation completed\n\nParameters:\n- dwProcessId (DWORD): Process ID value to store in global state\n\nReturns:\n- DWORD: Always returns 1 indicating successful storage operation\n\nSpecial Cases:\n- Unlike SetGlobalProcessIdSafe which only sets if value is 0, this function always overwrites the stored value\n- Function uses __fastcall convention with dwProcessId passed in ECX register\n\nMagic Numbers Reference:\n- 0x130: Offset to critical section structure within g_abGlobalStringBuffer\n- 0x14C: Offset to process ID storage location (g_abGlobalStringBuffer._332_4_)  \n- 0x1: Success return value indicating operation completed",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:3545eb0c48f8a1e83d4b209d9e2fc0b1",
      "candidates": {
        "LoD/1.11b": {
          "address": "0x6FF2AFD0",
          "rva": "0xAFD0",
          "confidence": 0.291,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.09d"
        },
        "LoD/1.12a": {
          "address": "0x6FF31320",
          "rva": "0x11320",
          "confidence": 0.291,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.09d"
        }
      }
    },
    "Bnclient_MNE_3586df3e31dd": {
      "addresses": {
        "LoD/1.11": "0x6FF258AD",
        "LoD/1.11b": "0x6FF25094",
        "LoD/1.12a": "0x6FF2672F",
        "LoD/1.13c": "0x6FF2631F",
        "LoD/1.13d": "0x6FF25CAD"
      },
      "rvas": {
        "LoD/1.11": "0x58AD",
        "LoD/1.11b": "0x5094",
        "LoD/1.12a": "0x672F",
        "LoD/1.13c": "0x631F",
        "LoD/1.13d": "0x5CAD"
      },
      "name": "setSBCS",
      "signature": "undefined setSBCS(void)",
      "comment": "Library Function - Single Match\n _setSBCS\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:3586df3e31dd0bc0a688e61a43024ab7"
    },
    "Bnclient_MNE_371cf2604575": {
      "addresses": {
        "LoD/1.07": "0x6FF2CBAE",
        "LoD/1.08": "0x6FF2CBCE",
        "LoD/1.09": "0x6FF0D7CE",
        "LoD/1.09b": "0x6FF0D7CE",
        "LoD/1.09d": "0x6FF0DADE",
        "LoD/1.10": "0x6FF0E044"
      },
      "rvas": {
        "LoD/1.07": "0xCBAE",
        "LoD/1.08": "0xCBCE",
        "LoD/1.09": "0xD7CE",
        "LoD/1.09b": "0xD7CE",
        "LoD/1.09d": "0xDADE",
        "LoD/1.10": "0xE044"
      },
      "name": "AllocateMemoryWithRetry",
      "signature": "void * AllocateMemoryWithRetry(uint dwWidth, uint dwHeight)",
      "comment": "Allocates memory using a multi-tiered allocation strategy with automatic retry handling.\n\nAlgorithm:\n1. Multiply dwWidth * dwHeight to calculate total size requirement\n2. Apply size validation - reject requests larger than 0xFFFFFFE0 bytes  \n3. Apply 16-byte alignment padding for small allocations (add 0xF, mask 0xFFFFFFF0)\n4. Set up structured exception handling (SEH) frame with handler at 0x6ff2cf5c\n5. Enter retry loop with multiple allocation strategies:\n   a. If g_dwAllocationStrategy == 3 (pool mode):\n      - Check size against g_dwPoolSizeLimit threshold\n      - Acquire critical section 9 for thread safety\n      - Call FUN_6ff2eb6f(size) for pool allocation\n      - Release critical section and zero allocated block\n   b. If g_dwAllocationStrategy == 2 (block mode):\n      - Check size against g_dwBlockSizeThreshold  \n      - Acquire critical section 9 for thread safety\n      - Call FUN_6ff2f612(size >> 4) for 16-byte block allocation\n      - Release critical section and zero allocated block\n   c. Fallback to HeapAlloc with HEAP_ZERO_MEMORY (0x8) flag\n6. If allocation fails and g_pfnRetryHandler exists:\n   - Call FUN_6ff2f9e7(size) retry handler\n   - If retry succeeds, restart allocation loop\n   - If retry fails, return NULL\n7. Zero allocated memory using _memset before returning\n8. Restore SEH frame and return pointer or NULL\n\nParameters:\n- dwWidth (uint): Width dimension for allocation size calculation\n- dwHeight (uint): Height dimension for allocation size calculation\n\nReturns:\n- Success: Non-NULL pointer to zeroed memory block of size (dwWidth * dwHeight)\n- Failure: NULL if allocation fails or size exceeds limits\n\nSpecial Cases:\n- Size 0 is normalized to size 1 to prevent zero-byte allocations\n- Sizes > 0xFFFFFFE0 immediately return NULL (integer overflow protection)\n- Small allocations get 16-byte alignment padding for performance\n- Uses structured exception handling for robust error recovery\n\nMagic Numbers Reference:\n- 0xFFFFFFE0 (4294967264): Maximum allocation size limit\n- 0xF (15): Alignment padding mask\n- 0xFFFFFFF0 (4294967280): 16-byte alignment mask  \n- 0x8 (8): HEAP_ZERO_MEMORY flag for HeapAlloc\n- 9: Critical section index for allocation synchronization\n\nError Handling:\n- Integer overflow: Sizes > 0xFFFFFFE0 rejected immediately\n- Pool allocation failure: Falls through to block allocation\n- Block allocation failure: Falls through to heap allocation  \n- Heap allocation failure: Calls retry handler if available\n- Retry handler failure: Returns NULL to caller\n- SEH exceptions: Handled by registered exception handler",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:371cf2604575a233020cd5d20fe5277c"
    },
    "Bnclient_MNE_378e464c3884": {
      "addresses": {
        "LoD/1.11": "0x6FF27930",
        "LoD/1.11b": "0x6FF278B0",
        "LoD/1.12a": "0x6FF27520",
        "LoD/1.13c": "0x6FF27510",
        "LoD/1.13d": "0x6FF279A0"
      },
      "rvas": {
        "LoD/1.11": "0x7930",
        "LoD/1.11b": "0x78B0",
        "LoD/1.12a": "0x7520",
        "LoD/1.13c": "0x7510",
        "LoD/1.13d": "0x79A0"
      },
      "name": "_memcpy",
      "signature": "void * _memcpy(void * _Dst, void * _Src, size_t _Size)",
      "comment": "Library Function - Single Match\n _memcpy\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:378e464c38840f3332fec8fa0fd86d30",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF10F20",
          "rva": "0x10F20",
          "confidence": 0.402,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF10940",
          "rva": "0x10940",
          "confidence": 0.326,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF10650",
          "rva": "0x10650",
          "confidence": 0.214,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_37d7c6a4c251": {
      "addresses": {
        "LoD/1.07": "0x6FF2FF40",
        "LoD/1.08": "0x6FF2FF60",
        "LoD/1.09": "0x6FF10B80",
        "LoD/1.09b": "0x6FF10B80",
        "LoD/1.09d": "0x6FF10E70",
        "LoD/1.10": "0x6FF113C0"
      },
      "rvas": {
        "LoD/1.07": "0xFF40",
        "LoD/1.08": "0xFF60",
        "LoD/1.09": "0x10B80",
        "LoD/1.09b": "0x10B80",
        "LoD/1.09d": "0x10E70",
        "LoD/1.10": "0x113C0"
      },
      "name": "FindExceptionMapping",
      "signature": "int * FindExceptionMapping(int nExceptionCode, int * pMappingArray)",
      "comment": "Searches array of exception mappings for matching exception code.\n\nAlgorithm:\n1. Initialize search pointer to start of mapping array\n2. Check if first mapping matches exception code, if so skip loop\n3. Iterate through array with 12-byte stride (3 integers per mapping)\n4. Compare first integer of each mapping against exception code\n5. Break if pointer exceeds array bounds (base + size * 3 entries)\n6. Continue until match found or end reached\n7. Validate final result is within bounds and matches code\n8. Return pointer to matching mapping or NULL if not found\n\nParameters:\nnExceptionCode - Exception code value to search for in mapping table\npMappingArray - Pointer to array of 3-integer exception mapping structures\n\nReturns:\nPointer to matching exception mapping entry on success\nNULL if exception code not found in mapping table\n\nSpecial Cases:\nArray size determined by global g_nMappingArraySize (currently 10 entries)\nEach mapping entry contains 3 integers: exception code, mapped value, flags\n\nMagic Numbers Reference:\n0xC (12) - Size in bytes of each mapping structure (3 * sizeof(int))\n0x3 - Number of integers per mapping entry\n\nStructure Layout:\nOffset | Size | Field Name      | Type | Description\n0x00   | 4    | nExceptionCode  | int  | Exception code to match against\n0x04   | 4    | nMappedValue    | int  | Mapped/converted exception value\n0x08   | 4    | nFlags          | int  | Additional flags for mapping",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:37d7c6a4c251088612ebbc596a4d3ae9"
    },
    "Bnclient_MNE_3830360e7eb4": {
      "addresses": {
        "LoD/1.11": "0x6FF28170",
        "LoD/1.11b": "0x6FF28170",
        "LoD/1.12a": "0x6FF287A0",
        "LoD/1.13c": "0x6FF28780",
        "LoD/1.13d": "0x6FF28790"
      },
      "rvas": {
        "LoD/1.11": "0x8170",
        "LoD/1.11b": "0x8170",
        "LoD/1.12a": "0x87A0",
        "LoD/1.13c": "0x8780",
        "LoD/1.13d": "0x8790"
      },
      "method": "MNE",
      "index": "MNE:3830360e7eb43508366054fd869e6192"
    },
    "Bnclient_MNE_38a52ad8d912": {
      "addresses": {
        "LoD/1.07": "0x6FF2CAC5",
        "LoD/1.08": "0x6FF2CAE5",
        "LoD/1.09": "0x6FF0D6E5",
        "LoD/1.09b": "0x6FF0D6E5",
        "LoD/1.09d": "0x6FF0D9F5",
        "LoD/1.10": "0x6FF0DF5B"
      },
      "rvas": {
        "LoD/1.07": "0xCAC5",
        "LoD/1.08": "0xCAE5",
        "LoD/1.09": "0xD6E5",
        "LoD/1.09b": "0xD6E5",
        "LoD/1.09d": "0xD9F5",
        "LoD/1.10": "0xDF5B"
      },
      "name": "DeallocateMemory",
      "signature": "void DeallocateMemory(void * pMemory)",
      "comment": "Strategy-based memory deallocation with custom memory management and exception handling.\n\nAlgorithm:\n\n1. Validate memory pointer parameter - return early if NULL\n2. Set up structured exception handling frame with global exception data\n3. Check allocation strategy from g_dwAllocationStrategy global variable\n4. Strategy 3: Acquire critical section 9, locate memory block, remove from custom pool\n5. Strategy 2: Acquire critical section 9, find block metadata, deallocate from custom allocator  \n6. Fallback: Use standard HeapFree with global heap handle for all other strategies\n7. Release critical sections and restore exception context before return\n8. Handle allocation failures by falling back to standard heap operations\n\nParameters:\n\npMemory (void *): Pointer to memory block to deallocate. NULL check performed early.\n\nReturns:\n\nvoid: Function does not return a value. Memory is deallocated through side effects.\n\nSpecial Cases:\n\n- NULL pointer: Function returns immediately without error\n- Strategy 3 (0x03): Custom pool allocation with block tracking and removal\n- Strategy 2 (0x02): Metadata-based allocation with size and location tracking  \n- All other strategies: Standard Win32 HeapFree fallback using g_hHeapHandle\n- Exception handling: SEH frame protects against access violations during deallocation\n\nMagic Numbers Reference:\n\n0x03: Custom pool allocation strategy requiring block location and removal\n0x02: Metadata-tracked allocation strategy with size/location info\n0x09: Critical section index for memory allocation synchronization\n0xFFFFFFFF: Exception handler state reset value (-1)\n0x00: Exception handler active state value\n0x01: Exception handler secondary state value\n\nError Handling:\n\n- Access violations caught by SEH frame during block location/removal\n- Critical sections always released via exception unwinding or normal exit\n- Failed custom deallocation falls back to standard HeapFree operation\n- Memory corruption protection through structured exception handling\n\nState Machine:\n\nState 1: Initial validation - NULL check and exception frame setup\nState 2: Strategy analysis - Read g_dwAllocationStrategy and branch accordingly  \nState 3a: Strategy 3 path - Critical section, block location, custom removal\nState 3b: Strategy 2 path - Critical section, metadata lookup, allocator cleanup\nState 4: Fallback path - Standard HeapFree with global heap handle\nState 5: Cleanup - Critical section release and exception context restoration",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:38a52ad8d9123a0ed65e4de10b1cf943"
    },
    "Bnclient_MNE_38e59a246232": {
      "addresses": {
        "LoD/1.09": "0x6FF06730",
        "LoD/1.09b": "0x6FF06730",
        "LoD/1.09d": "0x6FF069A0",
        "LoD/1.10": "0x6FF070E0"
      },
      "rvas": {
        "LoD/1.09": "0x6730",
        "LoD/1.09b": "0x6730",
        "LoD/1.09d": "0x69A0",
        "LoD/1.10": "0x70E0"
      },
      "method": "MNE",
      "index": "MNE:38e59a2462325983f58d187793af5f85",
      "candidates": {
        "LoD/1.08": {
          "address": "0x6FF24C90",
          "rva": "0x4C90",
          "confidence": 0.748,
          "method": "composite",
          "direction": "reverse",
          "source": "LoD/1.09"
        },
        "LoD/1.07": {
          "address": "0x6FF24C70",
          "rva": "0x4C70",
          "confidence": 0.545,
          "method": "unique_api",
          "direction": "reverse",
          "source": "LoD/1.08"
        }
      }
    },
    "Bnclient_MNE_3946237a610d": {
      "addresses": {
        "LoD/1.07": "0x6FF2ACD0",
        "LoD/1.08": "0x6FF2ACF0",
        "LoD/1.09": "0x6FF0B8F0",
        "LoD/1.09b": "0x6FF0B8F0",
        "LoD/1.09d": "0x6FF0BB40",
        "LoD/1.10": "0x6FF0C150"
      },
      "rvas": {
        "LoD/1.07": "0xACD0",
        "LoD/1.08": "0xACF0",
        "LoD/1.09": "0xB8F0",
        "LoD/1.09b": "0xB8F0",
        "LoD/1.09d": "0xBB40",
        "LoD/1.10": "0xC150"
      },
      "name": "ComputeSha1Hash",
      "signature": "void ComputeSha1Hash(dword * pHashOutput, dword * pInputData, dword cbDataLength)",
      "comment": "Computes SHA-1 hash digest for input data buffer using standard algorithm\n\nAlgorithm:\n1. Initialize SHA-1 state buffer with standard constants (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)\n2. Process input data in 64-byte (0x40) chunks until all data consumed\n3. For each chunk: copy remaining bytes from input buffer to state buffer at offset +20 (0x14)\n4. Copy data using 4-byte DWORD moves (MOVSD.REP) followed by byte moves (MOVSB.REP) for alignment\n5. If chunk < 64 bytes, zero-fill remaining buffer space using 4-byte stores (STOSD.REP) + byte stores (STOSB.REP)\n6. Call SHA-1 compression function (FUN_6ff2aa80) to process 64-byte block and update state\n7. Advance processing offset by 64 bytes and repeat until all input consumed\n8. Copy final 20-byte hash state (5 DWORDs) to output buffer using MOVSD.REP\n\nParameters:\npdwHashOut - Pointer to 20-byte output buffer for SHA-1 digest (5 DWORDs)\npdwDataIn - Pointer to input data buffer to hash\ncbLength - Length of input data in bytes\n\nReturns:\nvoid - Hash digest written to pdwHashOut buffer\n\nSpecial Cases:\nZero-length input (cbLength=0) produces hash of empty buffer\nInput not multiple of 64 bytes gets zero-padding in final chunk\nBuffer overflow protection: chunk size clamped to 64 bytes maximum (0x40)\n\nMagic Numbers:\n0x40 (64) - SHA-1 block size in bytes\n0x14 (20) - Offset to data area in state buffer (after 5-DWORD state)\n0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 - SHA-1 initial state constants\n\nStructure Layout:\nSHA-1 State Buffer (84 bytes total):\nOffset  Size  Field Name       Type     Description\n0x00    4     state[0]         DWORD    SHA-1 state word A (0x67452301)\n0x04    4     state[1]         DWORD    SHA-1 state word B (0xefcdab89) \n0x08    4     state[2]         DWORD    SHA-1 state word C (0x98badcfe)\n0x0C    4     state[3]         DWORD    SHA-1 state word D (0x10325476)\n0x10    4     state[4]         DWORD    SHA-1 state word E (0xc3d2e1f0)\n0x14    64    data[16]         DWORD    Input data block for compression (64 bytes)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:3946237a610de0db24ef69e4763f6b6a"
    },
    "Bnclient_MNE_39efaf0fc20e": {
      "addresses": {
        "LoD/1.11": "0x6FF34DB0",
        "LoD/1.11b": "0x6FF2CE50",
        "LoD/1.12a": "0x6FF2C460",
        "LoD/1.13c": "0x6FF2D580",
        "LoD/1.13d": "0x6FF312F0"
      },
      "rvas": {
        "LoD/1.11": "0x14DB0",
        "LoD/1.11b": "0xCE50",
        "LoD/1.12a": "0xC460",
        "LoD/1.13c": "0xD580",
        "LoD/1.13d": "0x112F0"
      },
      "method": "MNE",
      "index": "MNE:39efaf0fc20e69c224fcea291f1d7879"
    },
    "Bnclient_MNE_3b30ad0b0652": {
      "addresses": {
        "LoD/1.11": "0x6FF2B860",
        "LoD/1.11b": "0x6FF33A80",
        "LoD/1.12a": "0x6FF33750",
        "LoD/1.13c": "0x6FF2BE90",
        "LoD/1.13d": "0x6FF32B70"
      },
      "rvas": {
        "LoD/1.11": "0xB860",
        "LoD/1.11b": "0x13A80",
        "LoD/1.12a": "0x13750",
        "LoD/1.13c": "0xBE90",
        "LoD/1.13d": "0x12B70"
      },
      "method": "MNE",
      "index": "MNE:3b30ad0b0652cde4519818bc3ce0b3f5"
    },
    "Bnclient_MNE_3b6c3d2f2421": {
      "addresses": {
        "LoD/1.07": "0x6FF31A0F",
        "LoD/1.08": "0x6FF31A2F",
        "LoD/1.09": "0x6FF1264F",
        "LoD/1.09b": "0x6FF1264F",
        "LoD/1.09d": "0x6FF1293F",
        "LoD/1.10": "0x6FF12EC3"
      },
      "rvas": {
        "LoD/1.07": "0x11A0F",
        "LoD/1.08": "0x11A2F",
        "LoD/1.09": "0x1264F",
        "LoD/1.09b": "0x1264F",
        "LoD/1.09d": "0x1293F",
        "LoD/1.10": "0x12EC3"
      },
      "name": "ProcessEnvironmentStringTable",
      "signature": "int ProcessEnvironmentStringTable(void)",
      "comment": "Process all environment variable strings from global string table.\n\nAlgorithm:\n1. Load pointer to global environment string table (g_dwEnvironmentInitFlag)\n2. Initialize table pointer for iteration through string array\n3. While current string pointer is not NULL:\n   a. Get required buffer size for wide-to-multibyte conversion\n   b. Allocate buffer for converted string using malloc\n   c. Convert wide character string to multibyte using WideCharToMultiByte\n   d. Process converted string by calling FUN_6ff31e30\n   e. Advance to next string in table (ppwszStringTablePtr[1])\n   f. Update table pointer to next position\n4. Return success (0) when all strings processed or error (-1) on failure\n\nParameters:\n  (none) - Function takes no parameters\n\nReturns:\n  int - 0 on successful processing of all strings\n       -1 (0xffffffff) on allocation failure or conversion error\n\nSpecial Cases:\n  - Empty string table (first pointer is NULL) returns success (0)\n  - Malloc failure during buffer allocation triggers error return\n  - WideCharToMultiByte failure during conversion triggers error return\n  - Uses Windows CP_ACP (1) for multibyte conversion\n\nMagic Numbers:\n  0x1 - Code page CP_ACP for default ANSI conversion\n  -1 - Null-terminated string length indicator\n  0xffffffff - Error return code indicating failure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:3b6c3d2f2421ca1228631708357a8aa1",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF23C97",
          "rva": "0x3C97",
          "confidence": 0.294,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.11b": {
          "address": "0x6FF2349C",
          "rva": "0x349C",
          "confidence": 0.294,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.12a": {
          "address": "0x6FF22801",
          "rva": "0x2801",
          "confidence": 0.294,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF2249D",
          "rva": "0x249D",
          "confidence": 0.294,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_3b865c2f933c": {
      "addresses": {
        "LoD/1.12a": "0x6FF268F3",
        "LoD/1.13c": "0x6FF264E3"
      },
      "rvas": {
        "LoD/1.12a": "0x68F3",
        "LoD/1.13c": "0x64E3"
      },
      "method": "MNE",
      "index": "MNE:3b865c2f933cac7b684f56d2d74a981a"
    },
    "Bnclient_MNE_3bbf25cccab8": {
      "addresses": {
        "LoD/1.10": "0x6FF0B820"
      },
      "rvas": {
        "LoD/1.10": "0xB820"
      },
      "method": "MNE",
      "index": "MNE:3bbf25cccab88f617762d600e01532b7"
    },
    "Bnclient_MNE_3c09a404c09b": {
      "addresses": {
        "LoD/1.11": "0x6FF21E00",
        "LoD/1.11b": "0x6FF215A0",
        "LoD/1.12a": "0x6FF21580",
        "LoD/1.13c": "0x6FF21AF0",
        "LoD/1.13d": "0x6FF218D0"
      },
      "rvas": {
        "LoD/1.11": "0x1E00",
        "LoD/1.11b": "0x15A0",
        "LoD/1.12a": "0x1580",
        "LoD/1.13c": "0x1AF0",
        "LoD/1.13d": "0x18D0"
      },
      "name": "_strncpy",
      "signature": "char * _strncpy(char * _Dest, char * _Source, size_t _Count)",
      "comment": "Library Function - Single Match\n _strncpy\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:3c09a404c09b60148d7501f511aba84d"
    },
    "Bnclient_MNE_3c60546d8cfb": {
      "addresses": {
        "LoD/1.07": "0x6FF31070",
        "LoD/1.08": "0x6FF31090",
        "LoD/1.09": "0x6FF11CB0",
        "LoD/1.09b": "0x6FF11CB0",
        "LoD/1.09d": "0x6FF11FA0",
        "LoD/1.10": "0x6FF124F0"
      },
      "rvas": {
        "LoD/1.07": "0x11070",
        "LoD/1.08": "0x11090",
        "LoD/1.09": "0x11CB0",
        "LoD/1.09b": "0x11CB0",
        "LoD/1.09d": "0x11FA0",
        "LoD/1.10": "0x124F0"
      },
      "name": "FindSubstringInString",
      "signature": "char * FindSubstringInString(char * lpszString, char * lpszSubstring)",
      "comment": "Searches for the first occurrence of a substring within a string using optimized character comparison.\n\nAlgorithm:\n1. Check if substring is empty - return original string pointer if so\n2. Extract first character of substring for initial matching\n3. Check if substring is single character - use optimized single-char search if so\n4. For single character: align string pointer to 4-byte boundary for faster access\n5. Use word-level operations with null-terminator detection masks (0x7efefeff)\n6. For multi-character substring: scan string for first character match\n7. When first character matches, compare remaining characters sequentially\n8. If complete substring matches, return pointer to start of match\n9. If mismatch occurs, continue searching from next position in string\n10. Return NULL if substring not found or string ends before complete match\n\nParameters:\nlpszString (char*): Null-terminated source string to search within\nlpszSubstring (char*): Null-terminated substring to find in source string\n\nReturns:\nchar*: Pointer to first occurrence of substring in string\nNULL: If substring not found or lpszString is shorter than lpszSubstring\n\nSpecial Cases:\nEmpty substring (lpszSubstring[0] == '\\0'): Returns lpszString pointer\nSingle character substring: Uses optimized word-level scanning with bit masks\nString alignment: Handles unaligned access by processing bytes until 4-byte boundary\nEnd of string: Returns NULL when null terminator reached before finding match\n\nMagic Numbers Reference:\n0x7efefeff: Null detection mask for word-level string scanning\n0x81010100: Bit pattern mask for detecting null bytes in 32-bit words\n0xffffffff: XOR mask for bitwise null detection algorithm",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:3c60546d8cfb6e92d20e0cc9dd281ae9"
    },
    "Bnclient_MNE_3d673ff0fb62": {
      "addresses": {
        "LoD/1.11": "0x6FF23DD8",
        "LoD/1.11b": "0x6FF22F61",
        "LoD/1.12a": "0x6FF222C0",
        "LoD/1.13c": "0x6FF23059",
        "LoD/1.13d": "0x6FF232A1"
      },
      "rvas": {
        "LoD/1.11": "0x3DD8",
        "LoD/1.11b": "0x2F61",
        "LoD/1.12a": "0x22C0",
        "LoD/1.13c": "0x3059",
        "LoD/1.13d": "0x32A1"
      },
      "name": "__mtdeletelocks",
      "signature": "void __mtdeletelocks(void)",
      "comment": "Library Function - Single Match\n __mtdeletelocks\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:3d673ff0fb622876ea58c1a43b2af6a0"
    },
    "Bnclient_MNE_3d9593887473": {
      "addresses": {
        "LoD/1.11": "0x6FF25BF2",
        "LoD/1.11b": "0x6FF253D9",
        "LoD/1.12a": "0x6FF26A87",
        "LoD/1.13c": "0x6FF26677",
        "LoD/1.13d": "0x6FF25FF2"
      },
      "rvas": {
        "LoD/1.11": "0x5BF2",
        "LoD/1.11b": "0x53D9",
        "LoD/1.12a": "0x6A87",
        "LoD/1.13c": "0x6677",
        "LoD/1.13d": "0x5FF2"
      },
      "name": "__setmbcp",
      "signature": "int __setmbcp(int _CodePage)",
      "comment": "Library Function - Single Match\n __setmbcp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:3d95938874732b844e73905e6c952bdf"
    },
    "Bnclient_MNE_3e05470f02af": {
      "addresses": {
        "LoD/1.11": "0x6FF2583A",
        "LoD/1.11b": "0x6FF2568E",
        "LoD/1.12a": "0x6FF24AF6",
        "LoD/1.13c": "0x6FF258DA",
        "LoD/1.13d": "0x6FF25C3A"
      },
      "rvas": {
        "LoD/1.11": "0x583A",
        "LoD/1.11b": "0x568E",
        "LoD/1.12a": "0x4AF6",
        "LoD/1.13c": "0x58DA",
        "LoD/1.13d": "0x5C3A"
      },
      "name": "__abnormal_termination",
      "signature": "int __abnormal_termination(void)",
      "comment": "Library Function - Single Match\n __abnormal_termination\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:3e05470f02af6f6fdd7e67f07762fb3b"
    },
    "Bnclient_MNE_3ecdb5e459e2": {
      "addresses": {
        "LoD/1.07": "0x6FF2B750"
      },
      "rvas": {
        "LoD/1.07": "0xB750"
      },
      "name": "DecrementValue",
      "signature": "int DecrementValue(int nUnused, int nValue)",
      "comment": "Decrements an integer value by 1 and returns the result.\n\nAlgorithm:\n1. Ignore the first parameter (unused placeholder for fastcall convention)\n2. Load the second parameter value into a register\n3. Subtract 1 from the value using LEA instruction\n4. Return the decremented result\n\nParameters:\nnUnused - int: Unused parameter (fastcall ECX register placeholder)\nnValue - int: The integer value to decrement\n\nReturns:\nint: The input value decreased by 1\n\nSpecial Cases:\n- Function ignores the first parameter completely\n- Uses LEA instruction for efficient decrement: LEA EAX,[EDX + -0x1]\n- Contains orphaned POP EBX instruction from compiler optimization\n\nError Handling:\nNone - this is a simple arithmetic helper function",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:3ecdb5e459e29b4117490dc114e98574",
      "candidates": {
        "LoD/1.08": {
          "address": "0x6FF22230",
          "rva": "0x2230",
          "confidence": 0.365,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.07"
        }
      }
    },
    "Bnclient_MNE_3ed9d2d0aadf": {
      "addresses": {
        "LoD/1.07": "0x6FF259E0",
        "LoD/1.08": "0x6FF25A00",
        "LoD/1.09": "0x6FF06360",
        "LoD/1.09b": "0x6FF06360",
        "LoD/1.09d": "0x6FF065D0",
        "LoD/1.10": "0x6FF06530",
        "LoD/1.11": "0x6FF34A60",
        "LoD/1.11b": "0x6FF2CB00",
        "LoD/1.12a": "0x6FF2C160",
        "LoD/1.13c": "0x6FF2D280",
        "LoD/1.13d": "0x6FF30FA0"
      },
      "rvas": {
        "LoD/1.07": "0x59E0",
        "LoD/1.08": "0x5A00",
        "LoD/1.09": "0x6360",
        "LoD/1.09b": "0x6360",
        "LoD/1.09d": "0x65D0",
        "LoD/1.10": "0x6530",
        "LoD/1.11": "0x14A60",
        "LoD/1.11b": "0xCB00",
        "LoD/1.12a": "0xC160",
        "LoD/1.13c": "0xD280",
        "LoD/1.13d": "0x10FA0"
      },
      "name": "ProcessPendingItems",
      "signature": "dword ProcessPendingItems(void)",
      "comment": "Processes all items in the global pending item queue\n\nAlgorithm:\n1. Enter critical section to protect global queue access\n2. Loop while queue head pointer is non-null\n3. For each item: read next pointer from offset 0x128\n4. Call Ordinal_10043 with parameters (0xa1, 0)\n5. Advance to next item in linked list\n6. Continue until queue is empty\n7. Exit critical section\n8. Return success status (1)\n\nParameters:\n   None\n\nReturns:\n   dword - Always returns 1 (success)\n\nSpecial Cases:\n   - Empty queue: exits immediately after acquiring/releasing lock\n   - Thread-safe: protected by critical section at offset 0x130\n\nMagic Numbers Reference:\n   0x130 - Offset to CRITICAL_SECTION in global structure\n   0x150 - Offset to queue head pointer (g_abGlobalStringBuffer._336_4_)\n   0x128 - Offset to next pointer in queued item structure\n   0xa1 - First parameter to Ordinal_10043 (operation code)\n   0x0 - Second parameter to Ordinal_10043",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:3ed9d2d0aadf29a1c949528bd5e10fcd"
    },
    "Bnclient_MNE_3f585ab7136a": {
      "addresses": {
        "LoD/1.11": "0x6FF2730A",
        "LoD/1.11b": "0x6FF25557",
        "LoD/1.12a": "0x6FF249BE",
        "LoD/1.13c": "0x6FF26265",
        "LoD/1.13d": "0x6FF26170"
      },
      "rvas": {
        "LoD/1.11": "0x730A",
        "LoD/1.11b": "0x5557",
        "LoD/1.12a": "0x49BE",
        "LoD/1.13c": "0x6265",
        "LoD/1.13d": "0x6170"
      },
      "name": "___crtInitCritSecAndSpinCount",
      "signature": "undefined ___crtInitCritSecAndSpinCount(undefined4 param_1, undefined4 param_2)",
      "comment": "Library Function - Single Match\n ___crtInitCritSecAndSpinCount\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:3f585ab7136accb11659a7703e402a24"
    },
    "Bnclient_MNE_404bd6d84719": {
      "addresses": {
        "LoD/1.10": "0x6FF13D00"
      },
      "rvas": {
        "LoD/1.10": "0x13D00"
      },
      "method": "MNE",
      "index": "MNE:404bd6d847190fb4b6be2cb594a60136"
    },
    "Bnclient_MNE_40605ad9ba51": {
      "addresses": {
        "LoD/1.11": "0x6FF21A91",
        "LoD/1.11b": "0x6FF21E46",
        "LoD/1.13d": "0x6FF21CDF"
      },
      "rvas": {
        "LoD/1.11": "0x1A91",
        "LoD/1.11b": "0x1E46",
        "LoD/1.13d": "0x1CDF"
      },
      "name": "_strtok",
      "signature": "char * _strtok(char * _Str, char * _Delim)",
      "comment": "Library Function - Single Match\n _strtok\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:40605ad9ba515a87cec9a5320307a1b3"
    },
    "Bnclient_MNE_40903556bc57": {
      "addresses": {
        "LoD/1.11": "0x6FF37780",
        "LoD/1.11b": "0x6FF37750",
        "LoD/1.12a": "0x6FF38600",
        "LoD/1.13c": "0x6FF385E0",
        "LoD/1.13d": "0x6FF38520"
      },
      "rvas": {
        "LoD/1.11": "0x17780",
        "LoD/1.11b": "0x17750",
        "LoD/1.12a": "0x18600",
        "LoD/1.13c": "0x185E0",
        "LoD/1.13d": "0x18520"
      },
      "name": "Unwind@6ff37740",
      "signature": "undefined Unwind@6ff37740(void)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:40903556bc57a4df1722c0a365e78b81"
    },
    "Bnclient_MNE_40ace89e5da5": {
      "addresses": {
        "LoD/1.11": "0x6FF2221E",
        "LoD/1.11b": "0x6FF2387A",
        "LoD/1.13d": "0x6FF23CD7"
      },
      "rvas": {
        "LoD/1.11": "0x221E",
        "LoD/1.11b": "0x387A",
        "LoD/1.13d": "0x3CD7"
      },
      "name": "___crtLCMapStringA",
      "signature": "int ___crtLCMapStringA(_locale_t _Plocinfo, LPCWSTR _LocaleName, DWORD _DwMapFlag, LPCSTR _LpSrcStr, int _CchSrc, LPSTR _LpDestStr, int _CchDest, int _Code_page, BOOL _BError)",
      "comment": "Library Function - Single Match\n ___crtLCMapStringA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:40ace89e5da5d434e25a5d26402f71e1"
    },
    "Bnclient_MNE_40add3a6c7a7": {
      "addresses": {
        "LoD/1.07": "0x6FF22310",
        "LoD/1.08": "0x6FF22330",
        "LoD/1.09": "0x6FF023F0",
        "LoD/1.09b": "0x6FF023F0",
        "LoD/1.09d": "0x6FF023C0",
        "LoD/1.10": "0x6FF023E0"
      },
      "rvas": {
        "LoD/1.07": "0x2310",
        "LoD/1.08": "0x2330",
        "LoD/1.09": "0x23F0",
        "LoD/1.09b": "0x23F0",
        "LoD/1.09d": "0x23C0",
        "LoD/1.10": "0x23E0"
      },
      "name": "ClearIndexTableEntry",
      "signature": "void ClearIndexTableEntry(uint dwIndex)",
      "comment": "Clears entries in both primary and secondary index lookup tables\n\nAlgorithm:\n1. Mask input index to 8-bit range (dwIndex & 0xFF) for array bounds safety\n2. Calculate DWORD array offset by shifting masked index left by 2 bits\n3. Clear entry in primary index table (g_adwPrimaryIndexTable) at calculated offset\n4. Clear entry in secondary index table (g_adwSecondaryIndexTable) at calculated offset\n\nParameters:\n  dwIndex (uint): Index value where only the low byte (0-255) is used for table access\n\nReturns:\n  void: Function performs side effects only, no return value\n\nSpecial Cases:\n  - Input values beyond 255 are masked down using dwIndex & 0xFF operation\n  - Both tables are always cleared together at the same index\n  - Tables support 256 entries each (indices 0-255)\n\nMagic Numbers Reference:\n  0xFF - Bitmask to extract low byte for array indexing (0-255 range)\n  0x2 - Left shift amount to convert byte index to DWORD offset (* 4)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:40add3a6c7a7b4d727973e49970f81ed"
    },
    "Bnclient_MNE_4256cd0b09fe": {
      "addresses": {
        "LoD/1.09": "0x6FF077D0",
        "LoD/1.09b": "0x6FF077D0",
        "LoD/1.09d": "0x6FF07A00",
        "LoD/1.10": "0x6FF08380"
      },
      "rvas": {
        "LoD/1.09": "0x77D0",
        "LoD/1.09b": "0x77D0",
        "LoD/1.09d": "0x7A00",
        "LoD/1.10": "0x8380"
      },
      "method": "MNE",
      "index": "MNE:4256cd0b09fe2f739a7fa96d3a146140"
    },
    "Bnclient_MNE_42dbe7ade19c": {
      "addresses": {
        "LoD/1.07": "0x6FF2D948",
        "LoD/1.08": "0x6FF2D968",
        "LoD/1.09": "0x6FF0E568",
        "LoD/1.09b": "0x6FF0E568",
        "LoD/1.09d": "0x6FF0E878",
        "LoD/1.10": "0x6FF0EDE0"
      },
      "rvas": {
        "LoD/1.07": "0xD948",
        "LoD/1.08": "0xD968",
        "LoD/1.09": "0xE568",
        "LoD/1.09b": "0xE568",
        "LoD/1.09d": "0xE878",
        "LoD/1.10": "0xEDE0"
      },
      "name": "ReadShortAndAdvancePointer",
      "signature": "uint ReadShortAndAdvancePointer(uint * * ppnArgsPtr)",
      "comment": "Reads a 16-bit value from variadic arguments and advances pointer\n\nAlgorithm:\n1. Advance the arguments pointer by 4 bytes to next argument position\n2. Read 16-bit value from previous argument position (offset -4)\n3. Combine with high 16 bits of current pointer value\n4. Return composite 32-bit value\n\nParameters:\n  ppnArgsPtr (uint **) - pointer to variadic arguments pointer array\n\nReturns:\n  uint - composite value with previous 16-bit argument in low bits\n\nSpecial Cases:\n  - Advances pointer before reading value from previous position\n  - Combines current high bits with previous low 16 bits using CONCAT22\n\nMagic Numbers Reference:\n  0x4 - argument stride (4 bytes per 32-bit argument)\n  -0x4 - offset to read previous argument position",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:42dbe7ade19c5b9c81e427c9077693e7"
    },
    "Bnclient_MNE_4356a93c484f": {
      "addresses": {
        "LoD/1.07": "0x6FF2F4B4",
        "LoD/1.08": "0x6FF2F4D4",
        "LoD/1.09": "0x6FF100FF",
        "LoD/1.09b": "0x6FF100FF",
        "LoD/1.09d": "0x6FF103E4",
        "LoD/1.10": "0x6FF109D2"
      },
      "rvas": {
        "LoD/1.07": "0xF4B4",
        "LoD/1.08": "0xF4D4",
        "LoD/1.09": "0x100FF",
        "LoD/1.09b": "0x100FF",
        "LoD/1.09d": "0x103E4",
        "LoD/1.10": "0x109D2"
      },
      "name": "FreeMemoryPoolPages",
      "signature": "void FreeMemoryPoolPages(int nPageCount)",
      "comment": "Frees virtual memory pages from managed memory pools\n\nAlgorithm:\n1. Initialize pool traversal from global pool head pointer g_aErrorTable[0x12].lpszMessage\n2. Skip pools with invalid virtual memory base (ppuVar4[4] == 0xffffffff)\n3. Initialize page offset to 0x3ff000 (4MB - 4KB) and scan backwards through bitmap\n4. For each bitmap entry marked as allocated (0xf0), attempt VirtualFree\n5. Call VirtualFree with MEM_DECOMMIT (0x4000) to release 4KB page\n6. Mark bitmap slot as freed (0xffffffff) and decrement global page counter\n7. Update minimum free slot pointer if current slot is lower\n8. Decrement target page count and exit early if quota reached\n9. Continue scanning until beginning of pool (offset 0) reached\n10. Check if all bitmap entries are free (0x400 consecutive 0xffffffff entries)\n11. If pool is completely empty, call cleanup function FUN_6ff2f45e\n12. Advance to next pool in linked list and repeat until quota met\n\nParameters:\nnPageCount (int): Maximum number of 4KB pages to free from all pools\n\nReturns:\nvoid: No return value, modifies global pool state and memory allocation\n\nSpecial Cases:\n- Early exit when requested page count reached\n- Skip pools with no virtual memory allocated\n- Only update minimum free slot if current is lower than existing\n- Pool cleanup only triggered when all 1024 bitmap entries are free\n- Global page counter DAT_6ff3a058 decremented for each freed page\n\nMagic Numbers:\n0x3ff000 - Starting offset (4MB - 4KB) for backward bitmap scan\n0x1000 - Page size (4KB) for VirtualFree operations  \n0x4000 - MEM_DECOMMIT flag for VirtualFree\n0xf0 - Bitmap entry indicating allocated page\n0xffffffff - Bitmap entry indicating freed page\n0x400 - Total bitmap entries per pool (1024 slots)\n0x804 - Offset to bitmap data array (2052 bytes)\n\nStructure Layout (MemoryPoolDescriptor):\nOffset | Size | Field Name    | Type  | Description\n-------|------|---------------|-------|----------------------------------\n   0   |  4   | pHead         | void* | Head of pool list  \n   4   |  4   | pNext         | void* | Next pool in linked list\n   8   |  4   | dwReserved1   | uint  | Reserved field\n  12   |  4   | pMinFreeSlot  | void* | Pointer to lowest free slot\n  16   |  4   | pVirtualBase  | void* | Virtual memory base address\n  20   |  4   | dwReserved2   | uint  | Reserved field  \n  24   |  4   | dwPoolStatus  | uint  | Pool status flags\n  28   |  4   | dwReserved3   | uint  | Reserved field\n  32   | 8192 | aBitmapData   |uint[] | Page allocation bitmap (1024 entries)\n\nFlag Bits:\n0xf0 - Page allocated and committed\n0xffffffff - Page freed and available",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4356a93c484fa354f7841c9d1d714a19"
    },
    "Bnclient_MNE_43c0a0116a01": {
      "addresses": {
        "LoD/1.11": "0x6FF246D4",
        "LoD/1.11b": "0x6FF246C6",
        "LoD/1.12a": "0x6FF24734",
        "LoD/1.13c": "0x6FF24739",
        "LoD/1.13d": "0x6FF2473F"
      },
      "rvas": {
        "LoD/1.11": "0x46D4",
        "LoD/1.11b": "0x46C6",
        "LoD/1.12a": "0x4734",
        "LoD/1.13c": "0x4739",
        "LoD/1.13d": "0x473F"
      },
      "name": "__heap_term",
      "signature": "void __heap_term(void)",
      "comment": "Library Function - Single Match\n __heap_term\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:43c0a0116a0179cd961980d35fb0c190"
    },
    "Bnclient_MNE_457ecf3d8055": {
      "addresses": {
        "LoD/1.11": "0x6FF244A5",
        "LoD/1.11b": "0x6FF24497",
        "LoD/1.12a": "0x6FF24505",
        "LoD/1.13c": "0x6FF2450A",
        "LoD/1.13d": "0x6FF24510"
      },
      "rvas": {
        "LoD/1.11": "0x44A5",
        "LoD/1.11b": "0x4497",
        "LoD/1.12a": "0x4505",
        "LoD/1.13c": "0x450A",
        "LoD/1.13d": "0x4510"
      },
      "name": "__setargv",
      "signature": "int __setargv(void)",
      "comment": "Library Function - Single Match\n __setargv\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:457ecf3d8055d8e00a172b3d901a03ca"
    },
    "Bnclient_MNE_45f1b1208150": {
      "addresses": {
        "LoD/1.12a": "0x6FF21D03",
        "LoD/1.13c": "0x6FF21D60"
      },
      "rvas": {
        "LoD/1.12a": "0x1D03",
        "LoD/1.13c": "0x1D60"
      },
      "method": "MNE",
      "index": "MNE:45f1b1208150949511b38e3742040d6e"
    },
    "Bnclient_MNE_470047ed1f92": {
      "addresses": {
        "LoD/1.11": "0x6FF25048",
        "LoD/1.11b": "0x6FF2696C",
        "LoD/1.12a": "0x6FF262FD",
        "LoD/1.13c": "0x6FF269D4",
        "LoD/1.13d": "0x6FF252C4"
      },
      "rvas": {
        "LoD/1.11": "0x5048",
        "LoD/1.11b": "0x696C",
        "LoD/1.12a": "0x62FD",
        "LoD/1.13c": "0x69D4",
        "LoD/1.13d": "0x52C4"
      },
      "name": "___free_lconv_mon",
      "signature": "undefined ___free_lconv_mon(int param_1)",
      "comment": "Library Function - Single Match\n ___free_lconv_mon\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:470047ed1f9244aa874a163facc5cee5"
    },
    "Bnclient_MNE_478855be1acc": {
      "addresses": {
        "LoD/1.12a": "0x6FF26D14",
        "LoD/1.13c": "0x6FF25C66"
      },
      "rvas": {
        "LoD/1.12a": "0x6D14",
        "LoD/1.13c": "0x5C66"
      },
      "method": "MNE",
      "index": "MNE:478855be1acc46abf6139addf3589574"
    },
    "Bnclient_MNE_479669a133b1": {
      "addresses": {
        "LoD/1.10": "0x6FF13E00"
      },
      "rvas": {
        "LoD/1.10": "0x13E00"
      },
      "method": "MNE",
      "index": "MNE:479669a133b1fede3de040105c460670"
    },
    "Bnclient_MNE_47bdfc874694": {
      "addresses": {
        "LoD/1.11": "0x6FF37080",
        "LoD/1.11b": "0x6FF37050",
        "LoD/1.12a": "0x6FF37F00",
        "LoD/1.13c": "0x6FF37EE0",
        "LoD/1.13d": "0x6FF37E20"
      },
      "rvas": {
        "LoD/1.11": "0x17080",
        "LoD/1.11b": "0x17050",
        "LoD/1.12a": "0x17F00",
        "LoD/1.13c": "0x17EE0",
        "LoD/1.13d": "0x17E20"
      },
      "name": "FindHandlerForForeignException",
      "signature": "void FindHandlerForForeignException(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4, _s_FuncInfo * param_5, int param_6, int param_7, EHRegistrationNode * param_8)",
      "comment": "Library Function - Single Match\n void __cdecl FindHandlerForForeignException(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,int,int,struct EHRegistrationNode *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:47bdfc874694667f1fbbded06fa6a242"
    },
    "Bnclient_MNE_47eec8a2d9bd": {
      "addresses": {
        "LoD/1.09": "0x6FF133E0",
        "LoD/1.09b": "0x6FF133E0",
        "LoD/1.09d": "0x6FF13700"
      },
      "rvas": {
        "LoD/1.09": "0x133E0",
        "LoD/1.09b": "0x133E0",
        "LoD/1.09d": "0x13700"
      },
      "method": "MNE",
      "index": "MNE:47eec8a2d9bddf2c2f4c4b6ebc17b608"
    },
    "Bnclient_MNE_484d64e5757a": {
      "addresses": {
        "LoD/1.11": "0x6FF2DD00",
        "LoD/1.11b": "0x6FF2BCA0",
        "LoD/1.12a": "0x6FF2E120",
        "LoD/1.13c": "0x6FF2F240",
        "LoD/1.13d": "0x6FF2D780"
      },
      "rvas": {
        "LoD/1.11": "0xDD00",
        "LoD/1.11b": "0xBCA0",
        "LoD/1.12a": "0xE120",
        "LoD/1.13c": "0xF240",
        "LoD/1.13d": "0xD780"
      },
      "method": "MNE",
      "index": "MNE:484d64e5757a0826bcc143ef93fd3ec0"
    },
    "Bnclient_MNE_489067da1a2c": {
      "addresses": {
        "LoD/1.11": "0x6FF366A7",
        "LoD/1.11b": "0x6FF36678",
        "LoD/1.12a": "0x6FF37527",
        "LoD/1.13c": "0x6FF3750D",
        "LoD/1.13d": "0x6FF37446"
      },
      "rvas": {
        "LoD/1.11": "0x166A7",
        "LoD/1.11b": "0x16678",
        "LoD/1.12a": "0x17527",
        "LoD/1.13c": "0x1750D",
        "LoD/1.13d": "0x17446"
      },
      "name": "_JumpToContinuation",
      "signature": "void _JumpToContinuation(void * param_1, EHRegistrationNode * param_2)",
      "comment": "Library Function - Single Match\n void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:489067da1a2c8cee5a3d2d9b9de565b4"
    },
    "Bnclient_MNE_48de6fa61a4b": {
      "addresses": {
        "LoD/1.07": "0x6FF2D88D",
        "LoD/1.08": "0x6FF2D8AD",
        "LoD/1.09": "0x6FF0E4AD",
        "LoD/1.09b": "0x6FF0E4AD",
        "LoD/1.09d": "0x6FF0E7BD",
        "LoD/1.10": "0x6FF0ED25"
      },
      "rvas": {
        "LoD/1.07": "0xD88D",
        "LoD/1.08": "0xD8AD",
        "LoD/1.09": "0xE4AD",
        "LoD/1.09b": "0xE4AD",
        "LoD/1.09d": "0xE7BD",
        "LoD/1.10": "0xED25"
      },
      "name": "BufferedPutChar",
      "signature": "int BufferedPutChar(byte bCharacter, FileBuffer * pBuffer, int * pnCharsWritten)",
      "comment": "Writes a single character to a buffered output stream with automatic flushing.\n\nAlgorithm:\n1. Decrement the buffer's remaining byte count\n2. If buffer has space (count >= 0):\n   a. Store character at current buffer position\n   b. Increment buffer pointer\n   c. Return character value (masked to 8 bits)\n3. If buffer is full (count < 0):\n   a. Call flush/refill function FUN_6ff2d034\n   b. Use its return value as result\n4. Check for error condition (-1 return value):\n   a. If error: set chars written counter to -1\n   b. If success: increment chars written counter\n\nParameters:\nchCharacter (byte) - Character to write to buffer (0-255)\npBuffer (FileBuffer *) - Pointer to buffer structure containing:\n  - pbCurrent: Current write position in buffer\n  - dwBytesRemaining: Number of bytes left in buffer\npnCharsWritten (int *) - Pointer to character count/status tracker\n\nReturns:\nCharacter value (0-255) on success\n-1 (0xFFFFFFFF) on error or buffer flush failure\n\nSpecial Cases:\nIf buffer flush operation fails, error state is propagated to caller\nCharacters are masked to 8 bits (param_1 & 0xff) for return value\nNegative buffer count triggers automatic flush/refill operation\n\nMagic Numbers Reference:\n0xFFFFFFFF (-1) - Error indicator for failed operations\n\nStructure Layout:\nFileBuffer (8 bytes):\nOffset  Size  Field Name         Type    Description\n0x00    4     pbCurrent          byte*   Current write position\n0x04    4     dwBytesRemaining   uint    Bytes remaining in buffer",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:48de6fa61a4bf40c36c288aa452eb3ad"
    },
    "Bnclient_MNE_4a7687a1c80b": {
      "addresses": {
        "LoD/1.11": "0x6FF21C41",
        "LoD/1.11b": "0x6FF213BA",
        "LoD/1.12a": "0x6FF21360",
        "LoD/1.13c": "0x6FF214A6",
        "LoD/1.13d": "0x6FF21622"
      },
      "rvas": {
        "LoD/1.11": "0x1C41",
        "LoD/1.11b": "0x13BA",
        "LoD/1.12a": "0x1360",
        "LoD/1.13c": "0x14A6",
        "LoD/1.13d": "0x1622"
      },
      "name": "doexit",
      "signature": "undefined doexit(UINT param_1, int param_2, int param_3)",
      "comment": "Library Function - Single Match\n _doexit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:4a7687a1c80b4268254de38c80b8b1f6"
    },
    "Bnclient_MNE_4a81966979e4": {
      "addresses": {
        "LoD/1.09": "0x6FF07810",
        "LoD/1.09b": "0x6FF07810",
        "LoD/1.09d": "0x6FF07A40",
        "LoD/1.10": "0x6FF083C0"
      },
      "rvas": {
        "LoD/1.09": "0x7810",
        "LoD/1.09b": "0x7810",
        "LoD/1.09d": "0x7A40",
        "LoD/1.10": "0x83C0"
      },
      "method": "MNE",
      "index": "MNE:4a81966979e45325610a190ba9a761b5",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF21030",
          "rva": "0x1030",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.08": {
          "address": "0x6FF244E0",
          "rva": "0x44E0",
          "confidence": 0.405,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.09"
        },
        "LoD/1.07": {
          "address": "0x6FF244C0",
          "rva": "0x44C0",
          "confidence": 0.328,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.09"
        },
        "LoD/1.11b": {
          "address": "0x6FF21200",
          "rva": "0x1200",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.12a": {
          "address": "0x6FF21090",
          "rva": "0x1090",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF21030",
          "rva": "0x1030",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_4acad21b2e55": {
      "addresses": {
        "LoD/1.07": "0x6FF306E3",
        "LoD/1.08": "0x6FF30703",
        "LoD/1.09": "0x6FF11323",
        "LoD/1.09b": "0x6FF11323",
        "LoD/1.09d": "0x6FF11613",
        "LoD/1.10": "0x6FF11B63"
      },
      "rvas": {
        "LoD/1.07": "0x106E3",
        "LoD/1.08": "0x10703",
        "LoD/1.09": "0x11323",
        "LoD/1.09b": "0x11323",
        "LoD/1.09d": "0x11613",
        "LoD/1.10": "0x11B63"
      },
      "name": "InitializeTimezoneConfiguration",
      "signature": "void InitializeTimezoneConfiguration(void)",
      "comment": "Initialize timezone configuration system using environment variable or system time zone information\n\nAlgorithm:\n1. Acquire critical section lock for timezone data (index 0xc)\n2. Reset timezone state variables to default values\n3. Attempt to read TZ environment variable via FUN_6ff31843\n4. If TZ variable not found:\n   a. Release lock and get system timezone info via GetTimeZoneInformation\n   b. Calculate timezone offset in seconds (bias * 60)\n   c. Set timezone initialization flag to 1\n   d. Apply daylight savings adjustment if available\n   e. Convert wide char timezone names to multibyte strings\n5. If TZ variable found and valid:\n   a. Parse custom timezone string format\n   b. Extract timezone abbreviation (first 3 characters)\n   c. Parse timezone offset (hours:minutes:seconds format)\n   d. Handle positive/negative timezone indicators (+ or -)\n   e. Extract daylight savings timezone name if present\n6. Update global timezone variables with parsed values\n\nParameters:\nNone\n\nReturns:\nvoid - Updates global timezone configuration variables\n\nSpecial Cases:\n- If TZ environment variable is empty or matches current cached value, exits early\n- Handles both positive (+) and negative (-) timezone offsets\n- Supports optional minutes and seconds in timezone offset format\n- Gracefully handles conversion failures by zeroing string buffers\n- Timezone offset stored in seconds for compatibility with system APIs\n\nMagic Numbers Reference:\n0xc - Critical section index for timezone data protection\n0xffffffff - Invalid/unset timezone state marker\n0x3c - Seconds per minute conversion factor (60)\n0xe10 - Seconds per hour conversion factor (3600)\n0x220 - WideCharToMultiByte flags (WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK)\n0x3f - Maximum timezone name buffer size (63 characters)\n0x2d - ASCII minus sign ('-') for negative timezone\n0x3a - ASCII colon (':') timezone format separator\n\nError Handling:\n- Memory allocation failure for timezone string cache handled gracefully\n- WideCharToMultiByte conversion errors result in empty string buffers\n- Invalid timezone information returns set global flags to safe defaults\n- Critical section properly released on all exit paths\n\nGlobal Variables Modified:\ng_dwTimezoneOffset - Timezone offset from UTC in seconds\ng_dwTimezoneFlag - Daylight savings time availability flag  \ng_dwDaylightAdjust - Daylight savings time adjustment in seconds\nDAT_6ff38ee8 - Timezone state cache flag\nDAT_6ff38ed8 - Secondary timezone state flag\nDAT_6ff3a0d0 - Timezone initialization completion flag\nDAT_6ff3a184 - Cached timezone string pointer\nPTR_DAT_6ff38ecc - Standard timezone name buffer (64 bytes)\nPTR_DAT_6ff38ed0 - Daylight timezone name buffer (64 bytes)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4acad21b2e553f5b1c0ed6f64429f34e"
    },
    "Bnclient_MNE_4af6f4d1378e": {
      "addresses": {
        "LoD/1.11": "0x6FF2714C",
        "LoD/1.11b": "0x6FF271EF",
        "LoD/1.12a": "0x6FF27275",
        "LoD/1.13c": "0x6FF27264",
        "LoD/1.13d": "0x6FF26F62"
      },
      "rvas": {
        "LoD/1.11": "0x714C",
        "LoD/1.11b": "0x71EF",
        "LoD/1.12a": "0x7275",
        "LoD/1.13c": "0x7264",
        "LoD/1.13d": "0x6F62"
      },
      "name": "___security_init_cookie",
      "signature": "void ___security_init_cookie(void)",
      "comment": "Library Function - Single Match\n ___security_init_cookie\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:4af6f4d1378e3b27617b296b4a2b16cc"
    },
    "Bnclient_MNE_4beef3b29c3b": {
      "addresses": {
        "LoD/1.07": "0x6FF2FF00",
        "LoD/1.08": "0x6FF2FF20",
        "LoD/1.09": "0x6FF10B40",
        "LoD/1.09b": "0x6FF10B40",
        "LoD/1.09d": "0x6FF10E30",
        "LoD/1.10": "0x6FF11380"
      },
      "rvas": {
        "LoD/1.07": "0xFF00",
        "LoD/1.08": "0xFF20",
        "LoD/1.09": "0x10B40",
        "LoD/1.09b": "0x10B40",
        "LoD/1.09d": "0x10E30",
        "LoD/1.10": "0x11380"
      },
      "name": "_strncmp",
      "signature": "int _strncmp(char * lpszStr1, char * lpszStr2, size_t _MaxCount)",
      "comment": "Compares two null-terminated strings up to a specified maximum length.\n\nAlgorithm:\n1. Check if maximum count is zero, return 0 if so\n2. Find the actual length to compare by scanning first string for null terminator\n3. Limit comparison to minimum of max count and first string length \n4. Compare strings character by character until difference found or end reached\n5. Return comparison result: 0 if equal, positive if first > second, negative if first < second\n\nParameters:\n_Str1 (char *): Pointer to first null-terminated string to compare\n_Str2 (char *): Pointer to second null-terminated string to compare  \n_MaxCount (size_t): Maximum number of characters to compare\n\nReturns:\n0: Strings are equal within the comparison length\nPositive: First string is lexicographically greater than second\nNegative: First string is lexicographically less than second\n\nSpecial Cases:\n- If _MaxCount is 0, returns 0 without comparing any characters\n- Comparison stops at first null terminator encountered in either string\n- Uses unsigned byte comparison for character ordering\n\nMagic Numbers Reference:\n0xfffffffe (4294967294): Used to construct negative result when first < second\n0x0: Equal comparison result",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4beef3b29c3b4b805408e60c6861211a"
    },
    "Bnclient_MNE_4bfb4adc00fc": {
      "addresses": {
        "LoD/1.07": "0x6FF2A700",
        "LoD/1.08": "0x6FF2A720",
        "LoD/1.09": "0x6FF0B320",
        "LoD/1.09b": "0x6FF0B320",
        "LoD/1.09d": "0x6FF0B570",
        "LoD/1.10": "0x6FF0BBF0"
      },
      "rvas": {
        "LoD/1.07": "0xA700",
        "LoD/1.08": "0xA720",
        "LoD/1.09": "0xB320",
        "LoD/1.09b": "0xB320",
        "LoD/1.09d": "0xB570",
        "LoD/1.10": "0xBBF0"
      },
      "name": "ProcessEncryptionRounds",
      "signature": "void ProcessEncryptionRounds(ushort * pwKey, short * psOutput, ushort * pwSubKeys)",
      "comment": "Process 8 rounds of encryption algorithm using 16-bit block cipher with subkey array.\n\nAlgorithm:\n1. Load 4 key words (16-bit each) from input key array into working variables\n2. Initialize round counter to 8 for main encryption loop\n3. For each round (8 iterations total):\n   a. Load 6 subkeys from current position in subkey array (48 bytes per round)\n   b. Apply complex multiplication with zero-check and carry propagation\n   c. Perform XOR operations between intermediate values and key data\n   d. Calculate modular arithmetic with bit masking and overflow handling\n   e. Advance subkey pointer by 6 words (12 bytes) for next round\n4. After 8 rounds, process final 4 subkeys for output transformation\n5. Store 4 computed result words into output array\n\nParameters:\npwKey - Pointer to input key array (4 x 16-bit words = 8 bytes)\npsOutput - Pointer to output buffer for encrypted data (4 x 16-bit words = 8 bytes)\npwSubKeys - Pointer to subkey array (52 x 16-bit words = 104 bytes total)\n\nReturns:\nvoid (results written directly to psOutput array)\n\nSpecial Cases:\nZero multiplication values default to (1 - other_operand) to avoid null operations\nOverflow detection using bit masking with 0xffff for 16-bit boundaries\nCarry propagation implemented with comparison and conditional subtraction\n\nMagic Numbers Reference:\n0x8 - Number of encryption rounds in main loop\n0xffff - 16-bit mask for overflow detection and value clamping\n0x10 - Right shift amount for extracting high word from 32-bit multiplication\n0x1 - Default value used when operand is zero to prevent null encryption\n0x6 - Subkey advancement per round (6 x 16-bit words = 12 bytes)\n\nStructure Layout:\nInput Key Array (8 bytes):\nOffset  Size  Field Name    Type      Description\n0x00    2     Key Word 0    ushort    First key component\n0x02    2     Key Word 1    ushort    Second key component  \n0x04    2     Key Word 2    ushort    Third key component\n0x06    2     Key Word 3    ushort    Fourth key component\n\nOutput Array (8 bytes):\nOffset  Size  Field Name    Type      Description\n0x00    2     Result 0      short     First encrypted word\n0x02    2     Result 1      short     Second encrypted word\n0x04    2     Result 2      short     Third encrypted word\n0x06    2     Result 3      short     Fourth encrypted word\n\nSubkey Array (104 bytes):\nEach round uses 6 sequential 16-bit subkeys\nRound 0: offsets 0x00-0x0A (6 words)\nRound 1: offsets 0x0C-0x16 (6 words)\n...\nRound 7: offsets 0x54-0x5E (6 words)\nFinal: offsets 0x60-0x68 (4 words)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4bfb4adc00fcd8e128d9f826138da6f4",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF2F250",
          "rva": "0xF250",
          "confidence": 0.288,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_4c053343a65b": {
      "addresses": {
        "LoD/1.07": "0x6FF31731",
        "LoD/1.08": "0x6FF31751",
        "LoD/1.09": "0x6FF12371",
        "LoD/1.09b": "0x6FF12371",
        "LoD/1.09d": "0x6FF12661",
        "LoD/1.10": "0x6FF12BB1"
      },
      "rvas": {
        "LoD/1.07": "0x11731",
        "LoD/1.08": "0x11751",
        "LoD/1.09": "0x12371",
        "LoD/1.09b": "0x12371",
        "LoD/1.09d": "0x12661",
        "LoD/1.10": "0x12BB1"
      },
      "name": "FlushOutputBuffer",
      "signature": "int FlushOutputBuffer(FILE * pFileStream)",
      "comment": "Flushes pending write data from output buffer to underlying stream handle\n\nAlgorithm:\n1. Check if stream is in write mode (flags & 0x3 == 0x2) and buffered output enabled (flags & 0x108)\n2. Calculate pending bytes as current_pointer - base_pointer\n3. If pending bytes > 0, call WriteToValidatedStream with file handle, base pointer, and byte count\n4. If write successful (bytes written equals pending bytes):\n   - Clear dirty flag (flags & 0xfffffffd) if buffering flag (0x80) is set\n5. If write failed, set error flag (flags | 0x20) and return -1\n6. Reset buffer state: set count to 0 and current pointer to base pointer\n7. Return 0 on success, -1 on write failure\n\nParameters:\npFileStream (FILE*): Pointer to FILE structure containing buffer state and flags\n\nReturns:\n0 on success (buffer flushed successfully or no pending data)\n-1 on write failure (WriteToValidatedStream returned different byte count)\n\nSpecial Cases:\nStream not in write mode or buffering disabled - no operation performed, returns 0\n\nMagic Numbers Reference:\n0x2 - Write mode flag (bits 1-0 = 10 binary)\n0x3 - Mode mask for extracting write/read mode bits\n0x108 - Buffered output enabled flags (0x100 | 0x8)\n0x80 - Buffer dirty flag indicating pending writes\n0x20 - Error flag set when write operations fail\n0xfffffffd - Mask to clear dirty flag (inverts 0x2)\n0xffffffff - Error return value (-1)\n\nStructure Layout:\nFILE structure (_iobuf) accessed at these offsets:\nOffset | Size | Field Name | Type | Description\n   0   |  4   | _ptr       | char* | Current position in buffer\n   4   |  4   | _cnt       | int   | Characters remaining in buffer\n   8   |  4   | _base      | char* | Base address of buffer\n  12   |  4   | _flag      | uint  | File status flags\n  16   |  4   | _file      | int   | File handle/descriptor\n\nFlag Bits:\n0x01 - Read mode\n0x02 - Write mode / Dirty flag\n0x08 - Line buffering enabled\n0x20 - Error condition occurred\n0x80 - Buffer requires flushing\n0x100 - Full buffering enabled",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4c053343a65baac58fac65c0d3534b2b"
    },
    "Bnclient_MNE_4d2bfe3d487a": {
      "addresses": {
        "LoD/1.07": "0x6FF2A980",
        "LoD/1.08": "0x6FF2A9A0",
        "LoD/1.09": "0x6FF0B5A0",
        "LoD/1.09b": "0x6FF0B5A0",
        "LoD/1.09d": "0x6FF0B7F0",
        "LoD/1.10": "0x6FF0BE70"
      },
      "rvas": {
        "LoD/1.07": "0xA980",
        "LoD/1.08": "0xA9A0",
        "LoD/1.09": "0xB5A0",
        "LoD/1.09b": "0xB5A0",
        "LoD/1.09d": "0xB7F0",
        "LoD/1.10": "0xBE70"
      },
      "name": "ProcessEncryptionData",
      "signature": "void ProcessEncryptionData(int nBlockIndex, ushort * pInputBuffer, short * pOutputBuffer)",
      "comment": "Processes encryption data transformation during block cipher decryption\n\nAlgorithm:\n1. Calculate offset into global encryption lookup table using block index\n2. Multiply block index by 0x68 (104-byte stride) for structure access\n3. Add base offset 0x208 to reach encryption data within structure\n4. Call ProcessEncryptionRounds with input buffer, output buffer, and derived lookup pointer\n5. Return without value (void function)\n\nParameters:\nnBlockIndex - Block index for encryption table lookup (0-based counter)\npInputBuffer - Pointer to input data buffer containing encrypted bytes\npOutputBuffer - Pointer to output buffer for transformed encryption data\n\nReturns:\nvoid - Function performs transformation in-place via ProcessEncryptionRounds call\n\nSpecial Cases:\nCalled only when (dwBlockIndex & 7) == 0 in DecryptDataBlocks main loop\nProcesses data in 8-byte chunks within 64-byte block boundaries\nGlobal lookup table g_abGlobalStringBuffer accessed with 104-byte stride\n\nMagic Numbers Reference:\n0x68 - Structure stride size (104 bytes) for encryption lookup table\n0x208 - Base offset within structure to encryption data section",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4d2bfe3d487aed565cb18395cee52f15"
    },
    "Bnclient_MNE_4d563aa2d88f": {
      "addresses": {
        "LoD/1.09": "0x6FF12DE0",
        "LoD/1.09b": "0x6FF12DE0",
        "LoD/1.09d": "0x6FF13100",
        "LoD/1.10": "0x6FF13700"
      },
      "rvas": {
        "LoD/1.09": "0x12DE0",
        "LoD/1.09b": "0x12DE0",
        "LoD/1.09d": "0x13100",
        "LoD/1.10": "0x13700"
      },
      "method": "MNE",
      "index": "MNE:4d563aa2d88fb963927552e411c575c0"
    },
    "Bnclient_MNE_4ebd25a652d4": {
      "addresses": {
        "LoD/1.07": "0x6FF31660",
        "LoD/1.08": "0x6FF31680",
        "LoD/1.09": "0x6FF122A0",
        "LoD/1.09b": "0x6FF122A0",
        "LoD/1.09d": "0x6FF12590",
        "LoD/1.10": "0x6FF12AE0"
      },
      "rvas": {
        "LoD/1.07": "0x11660",
        "LoD/1.08": "0x11680",
        "LoD/1.09": "0x122A0",
        "LoD/1.09b": "0x122A0",
        "LoD/1.09d": "0x12590",
        "LoD/1.10": "0x12AE0"
      },
      "name": "UnlockStreamDescriptor",
      "signature": "void UnlockStreamDescriptor(uint dwStreamIndex)",
      "comment": "Unlocks the critical section for a stream descriptor using bucket-based indexing.\n\nAlgorithm:\n1. Extract bucket index from stream index using right shift by 5 bits (divide by 32)\n2. Extract offset within bucket using bitwise AND with 0x1F (modulo 32)\n3. Calculate descriptor address using bucket array and 36-byte stride\n4. Access dwFlags field at offset +12 within StreamIO structure\n5. Call LeaveCriticalSection to release the critical section lock\n\nParameters:\ndwStreamIndex (uint) - Zero-based stream identifier used for bucket/offset calculation\n\nReturns:\nvoid - No return value, unlocks critical section synchronously\n\nSpecial Cases:\nStream indexing uses bucket system: bucket = index >> 5, offset = index & 0x1F\nEach bucket contains 32 StreamIO descriptors at 36-byte stride\nCritical section is embedded at offset +12 (dwFlags) within StreamIO structure\n\nStructure Layout:\nStreamIO structure (36 bytes):\nOffset  Size  Field Name    Type                Description\n0x00    ?     ?             ?                   Unknown fields\n0x0C    24    dwFlags       CRITICAL_SECTION    Synchronization lock\n\nMagic Numbers Reference:\n0x1F (31) - Mask for extracting offset within 32-entry bucket\n0x5 (5) - Right shift count for bucket calculation (log2(32))\n0xC (12) - Offset to dwFlags/CRITICAL_SECTION within StreamIO\n0x24 (36) - Size of StreamIO structure for stride calculation",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4ebd25a652d48fc0c3275eab0a712286"
    },
    "Bnclient_MNE_4f3543287939": {
      "addresses": {
        "LoD/1.07": "0x6FF2F81A",
        "LoD/1.08": "0x6FF2F83A",
        "LoD/1.09": "0x6FF10465",
        "LoD/1.09b": "0x6FF10465",
        "LoD/1.09d": "0x6FF1074A",
        "LoD/1.10": "0x6FF10D38"
      },
      "rvas": {
        "LoD/1.07": "0xF81A",
        "LoD/1.08": "0xF83A",
        "LoD/1.09": "0x10465",
        "LoD/1.09b": "0x10465",
        "LoD/1.09d": "0x1074A",
        "LoD/1.10": "0x10D38"
      },
      "name": "AllocateBufferSpace",
      "signature": "int AllocateBufferSpace(BufferManager * pBufferMgr, uint dwAvailableBytes, uint dwRequestedBytes)",
      "comment": "Allocates buffer space in managed buffer with chunk-based allocation\n\nAlgorithm:\n1. Extract buffer boundary (pBufferMgr + 0xF8) and current position \n2. Check if remaining space (pBufferMgr->dwRemaining) is sufficient for request\n3. If sufficient space available at current position, allocate directly\n4. Otherwise, scan buffer starting from current position for available chunks\n5. For each chunk, if first byte is 0, count consecutive zeros to find free space\n6. If first byte is non-zero, advance by that value (skip allocated chunk)\n7. When suitable free space found, mark first byte with marker value\n8. Update buffer manager pointers: pCurrent advances by dwRequestedBytes\n9. Calculate return value: (allocated_pointer * 16 - pBufferMgr * 15)\n\nParameters:\npBufferMgr: Pointer to BufferManager structure with allocation state\ndwAvailableBytes: Total bytes available for allocation operations\ndwRequestedBytes: Number of bytes to allocate from buffer\n\nReturns:\nint: Calculated handle/offset for allocated space, 0 on failure\n\nSpecial Cases:\n- Returns 0 if insufficient space available\n- Returns 0 if buffer boundary would be exceeded\n- Handles buffer wraparound by resetting to base pointer (offset 8)\n- Marker value placed at allocation start for tracking\n\nStructure Layout:\nOffset | Size | Field Name  | Type     | Description\n-------|------|-------------|----------|----------------------------------\n0x00   | 4    | pCurrent    | void*    | Current allocation position\n0x04   | 4    | dwRemaining | uint     | Bytes remaining at current pos\n0x08   | 4    | pBase       | void*    | Base buffer pointer for reset\n...    | 236  | padding     | byte[236]| Reserved space\n0xF8   | 4    | pEnd        | void*    | End boundary pointer",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4f3543287939943021eaf1632a1582f1"
    },
    "Bnclient_MNE_4f4efd8121d4": {
      "addresses": {
        "LoD/1.07": "0x6FF300D5",
        "LoD/1.08": "0x6FF300F5",
        "LoD/1.09": "0x6FF10D15",
        "LoD/1.09b": "0x6FF10D15",
        "LoD/1.09d": "0x6FF11005",
        "LoD/1.10": "0x6FF11555"
      },
      "rvas": {
        "LoD/1.07": "0x100D5",
        "LoD/1.08": "0x100F5",
        "LoD/1.09": "0x10D15",
        "LoD/1.09b": "0x10D15",
        "LoD/1.09d": "0x11005",
        "LoD/1.10": "0x11555"
      },
      "name": "SeekStreamPosition",
      "signature": "DWORD SeekStreamPosition(DWORD dwStreamId, int nOffset, DWORD dwOrigin)",
      "comment": "Sets the file pointer position for a stream and updates stream state.\n\nAlgorithm:\n1. Convert stream ID to Windows file handle using internal conversion function\n2. If handle conversion fails (returns 0xFFFFFFFF), set thread error field to 9 and return error\n3. Call SetFilePointer with handle, offset, and origin to set new file position\n4. If SetFilePointer fails (returns 0xFFFFFFFF), capture last error using GetLastError\n5. If successful, clear flag bit 0x02 in stream descriptor position state field\n6. Return new file position on success, or 0xFFFFFFFF on error\n7. If error occurred, translate error code using internal error translation function\n\nParameters:\n- dwStreamId: Stream identifier used for bucket-based lookup in descriptor array\n- nOffset: Signed offset value for file seek operation\n- dwOrigin: Seek origin method (FILE_BEGIN=0, FILE_CURRENT=1, FILE_END=2)\n\nReturns:\n- Success: New file pointer position as DWORD value\n- Failure: 0xFFFFFFFF (INVALID_SET_FILE_POINTER)\n\nSpecial Cases:\n- Invalid stream ID results in failed handle conversion and error 9\n- SetFilePointer failure triggers error code translation and cleanup\n- Success path clears stream descriptor position flag bit 0x02\n\nMagic Numbers Reference:\n- 0xFFFFFFFF: INVALID_HANDLE_VALUE and INVALID_SET_FILE_POINTER constant\n- 0x9: Thread context error code for invalid stream handle\n- 0x02: Position state flag bit cleared on successful seek\n- 0x1F: Bit mask for within-bucket index (31 entries per bucket)\n- 0x5: Right shift for bucket calculation (divide by 32)\n\nStructure Layout:\nOffset  Size  Field Name    Type      Description\n------  ----  ----------    ----      -----------\n+0x00   4     (unknown)     DWORD     Stream descriptor field 0\n+0x04   1     nPosition     BYTE      Position state flags (bit 1 = position dirty)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4f4efd8121d403a870aeab94c4a12f4c"
    },
    "Bnclient_MNE_50505d6d0bc0": {
      "addresses": {
        "LoD/1.07": "0x6FF244E0",
        "LoD/1.08": "0x6FF24500",
        "LoD/1.09": "0x6FF04E60",
        "LoD/1.09b": "0x6FF04E60",
        "LoD/1.09d": "0x6FF050E0",
        "LoD/1.10": "0x6FF05070"
      },
      "rvas": {
        "LoD/1.07": "0x44E0",
        "LoD/1.08": "0x4500",
        "LoD/1.09": "0x4E60",
        "LoD/1.09b": "0x4E60",
        "LoD/1.09d": "0x50E0",
        "LoD/1.10": "0x5070"
      },
      "name": "AssignmentOperator",
      "signature": "BNGatewayAccess * AssignmentOperator(BNGatewayAccess * this, BNGatewayAccess * pSource)",
      "comment": "Assignment operator for BNGatewayAccess class that performs member-wise copy.\n\nAlgorithm:\n1. Initialize destination pointer to this object\n2. Set copy counter to 9 DWORDs (36 bytes total)\n3. Copy each DWORD from source to destination in sequence\n4. Advance both source and destination pointers by 4 bytes per iteration\n5. Decrement counter and continue until all members copied\n6. Return reference to this object for chaining\n\nParameters:\n- this: BNGatewayAccess * - Target object for assignment (cannot be renamed - auto-parameter)\n- pSource: BNGatewayAccess * - Source object to copy from (const reference in C++)\n\nReturns:\n- BNGatewayAccess * - Reference to this object for assignment chaining\n\nSpecial Cases:\n- Function assumes source and destination are valid non-null pointers\n- No self-assignment check - copying object to itself would work but is inefficient\n- Fixed 36-byte copy size indicates BNGatewayAccess is exactly 36 bytes\n\nMagic Numbers Reference:\n- 0x9 (9): Number of DWORDs to copy, equals 36 bytes total size\n- 0x4 (4): DWORD size in bytes for pointer arithmetic",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:50505d6d0bc0b2e52f1768ee0af8f940"
    },
    "Bnclient_MNE_505272b5b61e": {
      "addresses": {
        "LoD/1.11": "0x6FF30B40",
        "LoD/1.11b": "0x6FF2E510",
        "LoD/1.12a": "0x6FF2FC30",
        "LoD/1.13c": "0x6FF372C0",
        "LoD/1.13d": "0x6FF2EDB0"
      },
      "rvas": {
        "LoD/1.11": "0x10B40",
        "LoD/1.11b": "0xE510",
        "LoD/1.12a": "0xFC30",
        "LoD/1.13c": "0x172C0",
        "LoD/1.13d": "0xEDB0"
      },
      "method": "MNE",
      "index": "MNE:505272b5b61e54ed0d27aa893db5519d"
    },
    "Bnclient_MNE_50cd6b6fd69b": {
      "addresses": {
        "LoD/1.07": "0x6FF2DF9E",
        "LoD/1.08": "0x6FF2DFBE",
        "LoD/1.09": "0x6FF0EBE9",
        "LoD/1.09b": "0x6FF0EBE9",
        "LoD/1.09d": "0x6FF0EECE",
        "LoD/1.10": "0x6FF0F4BC"
      },
      "rvas": {
        "LoD/1.07": "0xDF9E",
        "LoD/1.08": "0xDFBE",
        "LoD/1.09": "0xEBE9",
        "LoD/1.09b": "0xEBE9",
        "LoD/1.09d": "0xEECE",
        "LoD/1.10": "0xF4BC"
      },
      "name": "ParseCommandLineArguments",
      "signature": "void ParseCommandLineArguments(char * lpszCommandLine, char * * pplpszArgv, char * lpszBuffer, int * pnArgc, int * pnTotalLength)",
      "comment": "Parses command line string into argc/argv format with quote and escape handling\n\nAlgorithm:\n1. Initialize output counters: set argc=1, total_length=0\n2. Set first argv entry to buffer start if argv array provided\n3. Check if command line starts with quote (0x22)\n4. If quoted: Parse quoted string with escape sequence handling\n   a. Advance through characters until closing quote or null terminator\n   b. Check character type using lookup table at g_abCharacterTypeTable (& 4 mask)\n   c. Copy valid characters to buffer, increment length counter\n   d. Handle escape sequences within quotes\n   e. Null-terminate parsed argument in buffer\n5. If unquoted: Parse until whitespace delimiter\n   a. Copy characters until space (0x20), tab (0x09), or null terminator\n   b. Handle escape sequences using same lookup table logic\n   c. Null-terminate argument in buffer\n6. Skip whitespace between arguments (spaces and tabs)\n7. For each subsequent argument:\n   a. Set argv[argc] to current buffer position\n   b. Increment argc counter\n   c. Parse argument with quote/escape handling\n   d. Handle backslash escaping: count consecutive backslashes\n   e. Process quote state changes: toggle inside/outside quoted mode\n   f. Copy literal backslashes (half of consecutive count)\n   g. Copy argument characters to buffer with proper escaping\n   h. Null-terminate argument in buffer\n8. Set final argv[argc] = NULL to terminate array\n9. Increment argc for final count\n\nParameters:\nlpszCommandLine: Input command line string to parse\npplpszArgv: Optional argv array to populate with argument pointers (can be NULL for size calculation)\nlpszBuffer: Buffer for concatenated argument strings (can be NULL for size calculation)\npnArgc: Output pointer for argument count (includes program name as argv[0])\npnTotalLength: Output pointer for total buffer length needed\n\nReturns:\nvoid\n\nSpecial Cases:\n- If pplpszArgv is NULL, only calculates size requirements without populating array\n- If lpszBuffer is NULL, only calculates length without copying argument text\n- Handles Windows-style escape sequences: backslash-quote combinations\n- Processes both single and double quote delimiters with proper nesting\n- Empty command line results in argc=1 (program name only)\n\nMagic Numbers Reference:\n0x22 (34): Double quote character for argument grouping\n0x20 (32): Space character - primary argument delimiter\n0x09 (9): Tab character - secondary argument delimiter\n0x5c (92): Backslash character for escape sequences\n0x4 (4): Character type mask for escape sequence validation\n\nError Handling:\nFunction assumes valid input pointers for pnArgc and pnTotalLength\nNo validation performed on input command line string\nCaller responsible for allocating sufficient buffer space",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:50cd6b6fd69b78c0380659763fce7ea0"
    },
    "Bnclient_MNE_52cd7137b980": {
      "addresses": {
        "LoD/1.09": "0x6FF13600",
        "LoD/1.09b": "0x6FF13600",
        "LoD/1.09d": "0x6FF13920",
        "LoD/1.10": "0x6FF13F20"
      },
      "rvas": {
        "LoD/1.09": "0x13600",
        "LoD/1.09b": "0x13600",
        "LoD/1.09d": "0x13920",
        "LoD/1.10": "0x13F20"
      },
      "method": "MNE",
      "index": "MNE:52cd7137b9801df5683c0de27f5c9139"
    },
    "Bnclient_MNE_5309cc011f44": {
      "addresses": {
        "LoD/1.11": "0x6FF24339",
        "LoD/1.11b": "0x6FF2432B",
        "LoD/1.12a": "0x6FF24399",
        "LoD/1.13c": "0x6FF2439E",
        "LoD/1.13d": "0x6FF243A4"
      },
      "rvas": {
        "LoD/1.11": "0x4339",
        "LoD/1.11b": "0x432B",
        "LoD/1.12a": "0x4399",
        "LoD/1.13c": "0x439E",
        "LoD/1.13d": "0x43A4"
      },
      "name": "parse_cmdline",
      "signature": "undefined parse_cmdline(undefined4 * param_1, int * param_2)",
      "comment": "Library Function - Single Match\n _parse_cmdline\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5309cc011f4489e83a895a5a05ecc215"
    },
    "Bnclient_MNE_534e7e7fed8d": {
      "addresses": {
        "LoD/1.07": "0x6FF314B5",
        "LoD/1.08": "0x6FF314D5",
        "LoD/1.09": "0x6FF120F5",
        "LoD/1.09b": "0x6FF120F5",
        "LoD/1.09d": "0x6FF123E5",
        "LoD/1.10": "0x6FF12935"
      },
      "rvas": {
        "LoD/1.07": "0x114B5",
        "LoD/1.08": "0x114D5",
        "LoD/1.09": "0x120F5",
        "LoD/1.09b": "0x120F5",
        "LoD/1.09d": "0x123E5",
        "LoD/1.10": "0x12935"
      },
      "name": "ParseStringToInteger",
      "signature": "int ParseStringToInteger(LocaleContext * pLocaleContext, byte * pszInput)",
      "comment": "Parse a string to extract an integer value with locale support.\n\nAlgorithm:\n1. Skip leading whitespace by checking character attribute table for whitespace flag (0x08)\n2. Check for optional sign character ('+' = 0x2B or '-' = 0x2D) \n3. Read sign character if found and advance pointer\n4. Initialize result accumulator to zero\n5. Parse decimal digits by checking character attribute table for digit flag (0x04)\n6. For each digit: result = (result * 10) + (digit - 0x30)\n7. Continue until non-digit character encountered\n8. Apply negative sign to result if minus sign was found\n9. Return final integer value\n\nParameters:\npLocaleContext - LocaleContext pointer for character processing context\npszInput - Pointer to null-terminated string to parse\n\nReturns:\nParsed integer value from string\nPositive or negative based on sign character\nZero if no digits found\n\nSpecial Cases:\nLeading whitespace is skipped completely\nPlus sign (0x2B) is accepted but does not change result sign\nMinus sign (0x2D) negates the final result\nParsing stops at first non-digit character\n\nMagic Numbers Reference:\n0x08 - Whitespace character attribute flag\n0x04 - Digit character attribute flag  \n0x2B - ASCII plus sign (+)\n0x2D - ASCII minus sign (-)\n0x30 - ASCII zero digit offset for conversion\n0x6ff36794 - Global character processing mode flag\n0x6ff36588 - Global character attribute table pointer\n\nError Handling:\nNo explicit error checking for null pointers\nInvalid characters simply terminate parsing\nResult defaults to zero if no valid digits found",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:534e7e7fed8d48d41353dab6322de72f"
    },
    "Bnclient_MNE_534f9c9a7440": {
      "addresses": {
        "LoD/1.09": "0x6FF07E40",
        "LoD/1.09b": "0x6FF07E40",
        "LoD/1.09d": "0x6FF080A0",
        "LoD/1.10": "0x6FF08A80"
      },
      "rvas": {
        "LoD/1.09": "0x7E40",
        "LoD/1.09b": "0x7E40",
        "LoD/1.09d": "0x80A0",
        "LoD/1.10": "0x8A80"
      },
      "method": "MNE",
      "index": "MNE:534f9c9a7440090219a84887f29c4b71"
    },
    "Bnclient_MNE_53f680a9a170": {
      "addresses": {
        "LoD/1.07": "0x6FF22280",
        "LoD/1.08": "0x6FF222A0",
        "LoD/1.09": "0x6FF02360",
        "LoD/1.09b": "0x6FF02360",
        "LoD/1.09d": "0x6FF02330",
        "LoD/1.10": "0x6FF02350"
      },
      "rvas": {
        "LoD/1.07": "0x2280",
        "LoD/1.08": "0x22A0",
        "LoD/1.09": "0x2360",
        "LoD/1.09b": "0x2360",
        "LoD/1.09d": "0x2330",
        "LoD/1.10": "0x2350"
      },
      "name": "WaitForSlotActivation",
      "signature": "uint WaitForSlotActivation(uint dwSlotIndex)",
      "comment": "Waits for a specified packet handler slot to become active in the global handler array.\n\nAlgorithm:\n1. Get initial timestamp from GetTickCount API\n2. Calculate handler array index by masking input with 0xFF and adding 0x45 offset\n3. Read handler pointer from global array g_apfnPacketHandlers[index]\n4. If handler is active (non-null pointer), return success immediately\n5. Check global error handler at index 0xA8, if set then exit with error\n6. Get current timestamp and calculate elapsed time\n7. If elapsed time exceeds 45000ms (45 seconds), trigger timeout error 0xD\n8. Sleep for 10ms to prevent busy waiting\n9. Re-read handler pointer and repeat from step 4\n10. If error handler detected during wait, trigger network error 0xE\n\nParameters:\ndwSlotIndex - Handler slot index to monitor (masked to 0-255 range, offset by 0x45)\n\nReturns:\n1 - Handler slot became active within timeout period\n0 - Timeout expired (45 seconds) or error handler set\n\nSpecial Cases:\nSlot index is masked with 0xFF limiting valid range to 0-255\nBase offset of 0x45 (69) added to masked index for handler array access\nError handler checked at fixed index 0xA8 (168) for early termination\n10ms sleep prevents CPU spinning during wait period\n\nMagic Numbers Reference:\n0xFF (255) - Slot index mask, limits to 256 possible slots\n0x45 (69) - Base offset added to slot index for handler array access\n0xA8 (168) - Fixed index for error handler check in handler array\n0xAFC8 (45000) - Timeout in milliseconds (45 seconds)\n0xA (10) - Sleep interval in milliseconds\n0xD (13) - Timeout error code passed to FUN_6ff25a30\n0xE (14) - Network error code passed to FUN_6ff25a30\n\nError Handling:\nTimeout condition triggers error code 0xD via FUN_6ff25a30\nNetwork error condition triggers error code 0xE via FUN_6ff25a30\nBoth error conditions return 0 to indicate failure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:53f680a9a170d2e893cb5e23823dc185"
    },
    "Bnclient_MNE_544ea4e68964": {
      "addresses": {
        "LoD/1.11": "0x6FF36E9D",
        "LoD/1.11b": "0x6FF36E6D",
        "LoD/1.12a": "0x6FF37D1D",
        "LoD/1.13c": "0x6FF37CFD",
        "LoD/1.13d": "0x6FF37C3D"
      },
      "rvas": {
        "LoD/1.11": "0x16E9D",
        "LoD/1.11b": "0x16E6D",
        "LoD/1.12a": "0x17D1D",
        "LoD/1.13c": "0x17CFD",
        "LoD/1.13d": "0x17C3D"
      },
      "name": "BuildCatchObject",
      "signature": "void BuildCatchObject(EHExceptionRecord * param_1, void * param_2, _s_HandlerType * param_3, _s_CatchableType * param_4)",
      "comment": "Library Function - Single Match\n void __cdecl BuildCatchObject(struct EHExceptionRecord *,void *,struct _s_HandlerType const *,struct _s_CatchableType const *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:544ea4e68964a9fa10177d533eda6601"
    },
    "Bnclient_MNE_5499cdf34757": {
      "addresses": {
        "LoD/1.07": "0x6FF31FB7",
        "LoD/1.08": "0x6FF31FD7",
        "LoD/1.09": "0x6FF12BCC",
        "LoD/1.09b": "0x6FF12BCC",
        "LoD/1.09d": "0x6FF12EE7",
        "LoD/1.10": "0x6FF1346B"
      },
      "rvas": {
        "LoD/1.07": "0x11FB7",
        "LoD/1.08": "0x11FD7",
        "LoD/1.09": "0x12BCC",
        "LoD/1.09b": "0x12BCC",
        "LoD/1.09d": "0x12EE7",
        "LoD/1.10": "0x1346B"
      },
      "name": "FindEnvironmentVariableIndex",
      "signature": "int FindEnvironmentVariableIndex(uchar * pbVariableName, size_t cbNameLength)",
      "comment": "Searches for an environment variable name in the parsed string array and returns its index.\n\nAlgorithm:\n1. Initialize pointers to start of global parsed string array (g_pdwParsedStringArray)\n2. Loop through each string entry in the array\n3. Check if current string pointer is NULL (end of array reached)\n4. If NULL, return negative index indicating variable not found\n5. Perform case-insensitive comparison using __mbsnbicoll with specified length\n6. If comparison matches (result == 0), check character after matched portion\n7. Verify next character is '=' (assignment) or '\\0' (end of string)\n8. If valid match found, return positive index in array\n9. Otherwise, advance to next array entry and continue loop\n\nParameters:\npbVariableName - Pointer to environment variable name to search for\ncbNameLength - Length in bytes of the variable name to compare\n\nReturns:\nPositive integer: Zero-based index of matching environment variable in array\nNegative integer: Negative index indicating variable not found in array\n\nSpecial Cases:\nFunction performs partial string matching up to cbNameLength bytes\nOnly matches complete variable names (followed by '=' or string terminator)\nCase-insensitive comparison supports multi-byte character strings\n\nMagic Numbers Reference:\n0x3d (61 decimal) - ASCII '=' character for environment variable assignment\n0x0 - NULL pointer indicating end of string array\n0x2 - Shift amount for pointer arithmetic (divide by 4 for array indexing)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5499cdf3475748beb261c4a1639cc8a7"
    },
    "Bnclient_MNE_54a4c3410932": {
      "addresses": {
        "LoD/1.11": "0x6FF37450",
        "LoD/1.11b": "0x6FF37420",
        "LoD/1.12a": "0x6FF382D0",
        "LoD/1.13c": "0x6FF382B0",
        "LoD/1.13d": "0x6FF381F0"
      },
      "rvas": {
        "LoD/1.11": "0x17450",
        "LoD/1.11b": "0x17420",
        "LoD/1.12a": "0x182D0",
        "LoD/1.13c": "0x182B0",
        "LoD/1.13d": "0x181F0"
      },
      "name": "__CallSettingFrame@12",
      "signature": "undefined __CallSettingFrame@12(undefined4 param_1, undefined4 param_2, int param_3)",
      "comment": "Library Function - Single Match\n __CallSettingFrame@12\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:54a4c3410932c862e3fcae53288bc46f"
    },
    "Bnclient_MNE_54ffff5ceafb": {
      "addresses": {
        "LoD/1.07": "0x6FF2F45E",
        "LoD/1.08": "0x6FF2F47E",
        "LoD/1.09": "0x6FF100A9",
        "LoD/1.09b": "0x6FF100A9",
        "LoD/1.09d": "0x6FF1038E",
        "LoD/1.10": "0x6FF1097C",
        "LoD/1.11": "0x6FF21D35",
        "LoD/1.11b": "0x6FF21949",
        "LoD/1.12a": "0x6FF21C2E",
        "LoD/1.13c": "0x6FF2138C",
        "LoD/1.13d": "0x6FF21870"
      },
      "rvas": {
        "LoD/1.07": "0xF45E",
        "LoD/1.08": "0xF47E",
        "LoD/1.09": "0x100A9",
        "LoD/1.09b": "0x100A9",
        "LoD/1.09d": "0x1038E",
        "LoD/1.10": "0x1097C",
        "LoD/1.11": "0x1D35",
        "LoD/1.11b": "0x1949",
        "LoD/1.12a": "0x1C2E",
        "LoD/1.13c": "0x138C",
        "LoD/1.13d": "0x1870"
      },
      "name": "FreeErrorTableEntry",
      "signature": "void FreeErrorTableEntry(void * * pErrorEntry)",
      "comment": "Free an error table entry and unlink it from the doubly-linked error table list.\n\nAlgorithm:\n1. Free virtual memory region associated with error entry (VirtualFree at offset 0x10 with MEM_RELEASE flag 0x8000)\n2. Check if entry is the current head of global error table list (PTR_g_aErrorTable_18__dwErrorCode_6ff38b90)\n3. If head entry, update global head pointer to next entry (pNext at offset 0x4)\n4. Check if entry is the sentinel node (g_aErrorTable + 0x12 = offset 0x6ff36b70)\n5. If sentinel node, set DAT_6ff36b80 to 0xffffffff and return\n6. If regular node, unlink from doubly-linked list by updating next/prev pointers\n7. Free the error table entry structure memory using HeapFree with global heap handle\n\nParameters:\npErrorEntry: Pointer to ErrorTableEntry structure to deallocate\n\nReturns:\nvoid: No return value\n\nSpecial Cases:\nSentinel node (at 0x6ff36b70): Sets global flag DAT_6ff36b80 to 0xffffffff instead of freeing\nHead node: Updates global head pointer before unlinking from list\n\nMagic Numbers Reference:\n0x8000: MEM_RELEASE flag for VirtualFree (decimal 32768)\n0x10: Offset to virtual memory handle in ErrorTableEntry structure (decimal 16)\n0x4: Offset to pNext pointer in ErrorTableEntry structure (decimal 4)  \n0x0: Offset to pPrev pointer in ErrorTableEntry structure (decimal 0)\n0x6ff36b70: Address of sentinel error table node\n0x6ff38b90: Global pointer to error table head entry\n0x6ff36b80: Global flag modified when sentinel node is freed\n0xffffffff: Value set in global flag when sentinel freed (decimal 4294967295)\n\nError Handling:\nNo explicit error checking performed on VirtualFree or HeapFree calls\nAssumes valid ErrorTableEntry pointer passed as parameter\nRelies on linked list structure integrity for safe unlinking operations\n\nStructure Layout:\nOffset | Size | Field Name | Type | Description\n0x00   | 4    | pNext      | void* | Pointer to next error table entry\n0x04   | 4    | pPrev      | void* | Pointer to previous error table entry  \n0x08   | 4    | dwReserved1| uint  | Reserved field (purpose unknown)\n0x0C   | 4    | dwReserved2| uint  | Reserved field (purpose unknown)\n0x10   | 4    | pVirtualMem| void* | Virtual memory handle for VirtualFree",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:54ffff5ceafbb1247d2270b70dfe4f31"
    },
    "Bnclient_MNE_56d15f5378ab": {
      "addresses": {
        "LoD/1.11": "0x6FF30E60",
        "LoD/1.11b": "0x6FF314D0",
        "LoD/1.12a": "0x6FF2FF50",
        "LoD/1.13c": "0x6FF33110",
        "LoD/1.13d": "0x6FF2F0D0"
      },
      "rvas": {
        "LoD/1.11": "0x10E60",
        "LoD/1.11b": "0x114D0",
        "LoD/1.12a": "0xFF50",
        "LoD/1.13c": "0x13110",
        "LoD/1.13d": "0xF0D0"
      },
      "method": "MNE",
      "index": "MNE:56d15f5378ab41f81036ec6a3fdb3f53"
    },
    "Bnclient_MNE_56ef14539498": {
      "addresses": {
        "LoD/1.07": "0x6FF226D0",
        "LoD/1.08": "0x6FF226F0",
        "LoD/1.09": "0x6FF027B0",
        "LoD/1.09b": "0x6FF027B0",
        "LoD/1.09d": "0x6FF02770",
        "LoD/1.10": "0x6FF02740",
        "LoD/1.11": "0x6FF32730",
        "LoD/1.11b": "0x6FF2F380",
        "LoD/1.12a": "0x6FF34DA0",
        "LoD/1.13c": "0x6FF308F0",
        "LoD/1.13d": "0x6FF2C170"
      },
      "rvas": {
        "LoD/1.07": "0x26D0",
        "LoD/1.08": "0x26F0",
        "LoD/1.09": "0x27B0",
        "LoD/1.09b": "0x27B0",
        "LoD/1.09d": "0x2770",
        "LoD/1.10": "0x2740",
        "LoD/1.11": "0x12730",
        "LoD/1.11b": "0xF380",
        "LoD/1.12a": "0x14DA0",
        "LoD/1.13c": "0x108F0",
        "LoD/1.13d": "0xC170"
      },
      "name": "ProcessCommand",
      "signature": "uint ProcessCommand(uint * pCommandData)",
      "comment": "Processes command requests through a switch-based dispatcher.\n\nAlgorithm:\n1. Store command type from input parameter to global command storage (0x6ff39628)\n2. Initialize status flag (0x6ff3973c) to zero and state flag (0x6ff39624) to zero  \n3. Switch on command type (0-6) using jump table at 0x6ff22768\n4. Case 0: Set state flag to 1 and return success\n5. Case 3: Call handler function with parameter 3 and return success\n6. Case 4: Call handler function with parameter 6, copy 128 bytes from command data to buffer 0x6ff3973c, call processing function, continue to return success\n7. Case 5: Call handler function with parameter 4 and return success\n8. Case 6: Call handler function with parameter 5 and return success\n9. Default: Fall through to return success\n\nParameters:\n- pCommandData: Pointer to command data structure containing command type as first uint\n\nReturns:\n- 1: Always returns success regardless of command type\n\nSpecial Cases:\n- Command type 4 includes additional data processing (128-byte copy operation)\n- Invalid command types (> 6) fall through to default success return\n- Global state maintained in memory locations 0x6ff39624, 0x6ff39628, 0x6ff3973c\n\nMagic Numbers Reference:\n- 0x80 (128): Buffer size for command data copy in case 4\n- 0x6ff39624: Global state flag storage\n- 0x6ff39628: Global command type storage  \n- 0x6ff3973c: Global status buffer and processing target",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:56ef14539498a4435598846291596620"
    },
    "Bnclient_MNE_573e024f3ff9": {
      "addresses": {
        "LoD/1.07": "0x6FF21D10",
        "LoD/1.08": "0x6FF21D30"
      },
      "rvas": {
        "LoD/1.07": "0x1D10",
        "LoD/1.08": "0x1D30"
      },
      "name": "ProcessWithColonPrefix",
      "signature": "int ProcessWithColonPrefix(uint dwParam1, uint dwParam2)",
      "comment": "Process operation with colon prefix character.\n\nAlgorithm:\n1. Save registers ESI and EDI to preserve caller state\n2. Store first parameter (ECX) in EDI for preservation\n3. Store second parameter (EDX) in ESI for preservation  \n4. Load colon character constant 0x3a into CL register\n5. Call first function with colon character as parameter\n6. Restore original parameters from saved registers\n7. Call second processing function with original parameters\n8. Set return value to 1 indicating success\n9. Restore caller's ESI and EDI registers\n10. Return to caller\n\nParameters:\ndwParam1 (uint): First parameter passed through to processing function\ndwParam2 (uint): Second parameter passed through to processing function\n\nReturns:\n1: Always returns success status indicating operation completed\n\nSpecial Cases:\nThis function is a wrapper that always succeeds regardless of called function results.\n\nMagic Numbers Reference:\n0x3a (58): ASCII colon character ':' used as prefix parameter",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:573e024f3ff903ebdc76c26dc0b0be0a"
    },
    "Bnclient_MNE_57ac66118a20": {
      "addresses": {
        "LoD/1.07": "0x6FF2D92B",
        "LoD/1.08": "0x6FF2D94B",
        "LoD/1.09": "0x6FF0E54B",
        "LoD/1.09b": "0x6FF0E54B",
        "LoD/1.09d": "0x6FF0E85B",
        "LoD/1.10": "0x6FF0EDC3"
      },
      "rvas": {
        "LoD/1.07": "0xD92B",
        "LoD/1.08": "0xD94B",
        "LoD/1.09": "0xE54B",
        "LoD/1.09b": "0xE54B",
        "LoD/1.09d": "0xE85B",
        "LoD/1.10": "0xEDC3"
      },
      "name": "ReadAndAdvancePointer",
      "signature": "uint ReadAndAdvancePointer(uint * * ppuCursor)",
      "comment": "Reads a 32-bit value from current pointer position and advances the pointer by one element.\n\nAlgorithm:\n1. Read current value from the pointed-to pointer location\n2. Advance the pointed-to pointer by 4 bytes (one uint element)\n3. Return the value that was at the original position before advancement\n\nParameters:\nppuCursor - Pointer to pointer tracking current read position in data stream\n\nReturns:\nThe 32-bit unsigned integer value that was at the current position before advancement\n\nSpecial Cases:\nThis function implements a common \"read and advance\" pattern used in serialization \nand parsing operations. The caller maintains a cursor pointer that gets automatically\nadvanced after each read operation.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:57ac66118a20c90490ffe62af18c6499"
    },
    "Bnclient_MNE_57f9ec64af4b": {
      "addresses": {
        "LoD/1.07": "0x6FF2AD80",
        "LoD/1.08": "0x6FF2ADA0",
        "LoD/1.09": "0x6FF0B9A0",
        "LoD/1.09b": "0x6FF0B9A0",
        "LoD/1.09d": "0x6FF0BBF0",
        "LoD/1.10": "0x6FF0C200"
      },
      "rvas": {
        "LoD/1.07": "0xAD80",
        "LoD/1.08": "0xADA0",
        "LoD/1.09": "0xB9A0",
        "LoD/1.09b": "0xB9A0",
        "LoD/1.09d": "0xBBF0",
        "LoD/1.10": "0xC200"
      },
      "name": "ClearGlobalStringBuffer",
      "signature": "void ClearGlobalStringBuffer(void)",
      "comment": "Clears 312 bytes of the global string buffer starting at offset 0x208 for security cleanup.\n\nAlgorithm:\n1. Calculate pointer to buffer section (g_abGlobalStringBuffer + 0x208 = 0x6ff39bf8)\n2. Initialize loop counter to 0x4e (78 dwords = 312 bytes)\n3. Loop while counter is non-zero:\n   a. Write four zero bytes at current pointer position\n   b. Advance pointer by 4 bytes (one dword)\n   c. Decrement counter\n4. Return when entire buffer section is cleared\n\nParameters:\nNone (void function)\n\nReturns:\nNone (void return)\n\nSpecial Cases:\nUses efficient REP STOSD assembly instruction for fast memory clearing.\nBuffer section starts at offset 0x208 (520 bytes) into global string buffer.\nTotal cleared size is exactly 312 bytes (0x138 bytes).\n\nMagic Numbers Reference:\n0x4e (78) - Number of dwords to clear\n0x208 (520) - Offset into global string buffer where clearing begins\n312 (0x138) - Total bytes cleared (78 dwords \u00d7 4 bytes/dword)\n\nError Handling:\nNone - Function assumes valid global buffer pointer and performs unconditional clearing.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:57f9ec64af4be3e0ffbc2e88bab6837a"
    },
    "Bnclient_MNE_5812d1889440": {
      "addresses": {
        "LoD/1.11": "0x6FF213EF",
        "LoD/1.11b": "0x6FF21A67",
        "LoD/1.12a": "0x6FF21857",
        "LoD/1.13c": "0x6FF21D3E",
        "LoD/1.13d": "0x6FF21F80"
      },
      "rvas": {
        "LoD/1.11": "0x13EF",
        "LoD/1.11b": "0x1A67",
        "LoD/1.12a": "0x1857",
        "LoD/1.13c": "0x1D3E",
        "LoD/1.13d": "0x1F80"
      },
      "name": "_tolower",
      "signature": "int _tolower(int _C)",
      "comment": "Library Function - Single Match\n _tolower\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5812d18894407ef6889050a4bd31c359",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF11910",
          "rva": "0x11910",
          "confidence": 0.398,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF113C0",
          "rva": "0x113C0",
          "confidence": 0.322,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF110D0",
          "rva": "0x110D0",
          "confidence": 0.212,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_58ce22034100": {
      "addresses": {
        "LoD/1.09": "0x6FF12D60",
        "LoD/1.09b": "0x6FF12D60",
        "LoD/1.09d": "0x6FF13080"
      },
      "rvas": {
        "LoD/1.09": "0x12D60",
        "LoD/1.09b": "0x12D60",
        "LoD/1.09d": "0x13080"
      },
      "method": "MNE",
      "index": "MNE:58ce2203410037d3ec0fe80792264133",
      "candidates": {
        "LoD/1.11b": {
          "address": "0x6FF345E0",
          "rva": "0x145E0",
          "confidence": 0.322,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.09d"
        }
      }
    },
    "Bnclient_MNE_5918dc16e1bf": {
      "addresses": {
        "LoD/1.07": "0x6FF2BC9F",
        "LoD/1.08": "0x6FF2BCBF",
        "LoD/1.09": "0x6FF0C8BF",
        "LoD/1.09b": "0x6FF0C8BF",
        "LoD/1.09d": "0x6FF0CB1F",
        "LoD/1.10": "0x6FF0D1C9"
      },
      "rvas": {
        "LoD/1.07": "0xBC9F",
        "LoD/1.08": "0xBCBF",
        "LoD/1.09": "0xC8BF",
        "LoD/1.09b": "0xC8BF",
        "LoD/1.09d": "0xCB1F",
        "LoD/1.10": "0xD1C9"
      },
      "name": "ConvertCharacterToUpperCaseWithLocale",
      "signature": "dword ConvertCharacterToUpperCaseWithLocale(void * this, void * pLocaleContext, dword dwCharacterCode)",
      "comment": "Converts a character to uppercase with locale-aware processing support\n\nAlgorithm:\n1. Initialize result with input character code\n2. Check if locale processing is available via g_dwLocaleAvailableFlag\n3. If locale unavailable, perform simple ASCII conversion (a-z to A-Z range 0x61-0x7A to 0x41-0x5A)\n4. If locale available, validate character is within single-byte range (< 0x100)\n5. Check character attribute flags using g_pCharacterAttributeTable or FUN_6ff2c474\n6. Return original character if no case conversion attribute (flag 0x02) found\n7. Determine byte length based on character attribute table high-byte entry (0x80 flag)\n8. Set up character buffer for conversion: single-byte (1) or double-byte (2) mode\n9. Call FUN_6ff2da18 (Windows LCMapStringA/W equivalent) for locale-specific conversion\n10. Extract converted result from buffer: single-byte (0xFF mask) or double-byte (0xFFFF mask)\n\nParameters:\npLocaleContext: Locale context pointer for character processing operations\ndwCharacterCode: Input character code to convert to uppercase\n\nReturns:\nConverted uppercase character code, or original character if no conversion applicable\n\nSpecial Cases:\nSimple ASCII conversion when locale unavailable: subtracts 0x20 from lowercase letters\nMulti-byte character handling via byte reordering and CONCAT operations\nFlag 0x02 in attribute table indicates case-convertible character\nFlag 0x80 in high-byte table indicates double-byte character sequence\n\nMagic Numbers Reference:\n0x60: ASCII '`' character, lower bound check for lowercase range\n0x7B: ASCII '{' character, upper bound check for lowercase range  \n0x20: ASCII offset between lowercase and uppercase letters\n0x100: Single-byte character range limit\n0x02: Character attribute flag for case conversion capability\n0x80: High-byte attribute flag indicating double-byte character\n0x200: LCMapString conversion flag (LCMAP_UPPERCASE)\n0xFF: Single-byte character mask\n0xFFFF: Double-byte character mask",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5918dc16e1bf74054af7a7988b490678"
    },
    "Bnclient_MNE_5b31e816b547": {
      "addresses": {
        "LoD/1.11": "0x6FF2CEF0",
        "LoD/1.11b": "0x6FF34A90",
        "LoD/1.12a": "0x6FF34760",
        "LoD/1.13c": "0x6FF322E0",
        "LoD/1.13d": "0x6FF36F70"
      },
      "rvas": {
        "LoD/1.11": "0xCEF0",
        "LoD/1.11b": "0x14A90",
        "LoD/1.12a": "0x14760",
        "LoD/1.13c": "0x122E0",
        "LoD/1.13d": "0x16F70"
      },
      "method": "MNE",
      "index": "MNE:5b31e816b5478a9528b737f5d1628389"
    },
    "Bnclient_MNE_5ba7875cbad7": {
      "addresses": {
        "LoD/1.07": "0x6FF2C3FE",
        "LoD/1.08": "0x6FF2C292",
        "LoD/1.09": "0x6FF0CE92",
        "LoD/1.09b": "0x6FF0CE92",
        "LoD/1.09d": "0x6FF0D32E",
        "LoD/1.10": "0x6FF0D894"
      },
      "rvas": {
        "LoD/1.07": "0xC3FE",
        "LoD/1.08": "0xC292",
        "LoD/1.09": "0xCE92",
        "LoD/1.09b": "0xCE92",
        "LoD/1.09d": "0xD32E",
        "LoD/1.10": "0xD894"
      },
      "name": "AcquireCriticalSectionByIndex",
      "signature": "void AcquireCriticalSectionByIndex(int nCriticalSectionIndex)",
      "comment": "Thread-safe lazy initialization and acquisition of critical section by array index\n\nAlgorithm:\n1. Calculate pointer to critical section slot in global array g_ppCriticalSections\n2. Check if critical section at index is already initialized (non-null)\n3. If uninitialized, allocate 0x18 bytes for CRITICAL_SECTION structure\n4. If allocation fails, call AmsgExit(0x11) to terminate process\n5. Acquire global initialization lock via recursive call AcquireCriticalSectionByIndex(0x11)\n6. Double-check critical section is still null (race condition protection)\n7. If still null, initialize critical section with InitializeCriticalSection\n8. Store initialized critical section pointer in global array\n9. If another thread initialized it first, free duplicate allocation with DeallocateMemory\n10. Release global initialization lock via FUN_6ff2c45f(0x11)\n11. Enter the requested critical section with EnterCriticalSection\n\nParameters:\nnCriticalSectionIndex - Index into global critical section array g_ppCriticalSections\nIMPLICIT: Uses global initialization lock at index 0x11 for thread-safe lazy initialization\n\nReturns:\nvoid - Function does not return a value, critical section is held upon return\n\nSpecial Cases:\nLock index 0x11 (17) is reserved for the global initialization synchronization lock\nProcess terminates with AmsgExit(0x11) if critical section allocation fails\nDouble-checked locking pattern prevents race conditions during initialization\n\nMagic Numbers Reference:\n0x18 (24 decimal) - Size of Windows CRITICAL_SECTION structure in bytes\n0x11 (17 decimal) - Reserved index for global initialization lock",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5ba7875cbad7a3d5fce31ff25fd40455"
    },
    "Bnclient_MNE_5c73446e6da2": {
      "addresses": {
        "LoD/1.07": "0x6FF221F0",
        "LoD/1.08": "0x6FF22210",
        "LoD/1.09": "0x6FF022D0",
        "LoD/1.09b": "0x6FF022D0",
        "LoD/1.09d": "0x6FF022A0",
        "LoD/1.10": "0x6FF022C0",
        "LoD/1.11": "0x6FF21020",
        "LoD/1.11b": "0x6FF211F0",
        "LoD/1.12a": "0x6FF21080",
        "LoD/1.13c": "0x6FF21020",
        "LoD/1.13d": "0x6FF21060"
      },
      "rvas": {
        "LoD/1.07": "0x21F0",
        "LoD/1.08": "0x2210",
        "LoD/1.09": "0x22D0",
        "LoD/1.09b": "0x22D0",
        "LoD/1.09d": "0x22A0",
        "LoD/1.10": "0x22C0",
        "LoD/1.11": "0x1020",
        "LoD/1.11b": "0x11F0",
        "LoD/1.12a": "0x1080",
        "LoD/1.13c": "0x1020",
        "LoD/1.13d": "0x1060"
      },
      "name": "DoNothing",
      "signature": "void DoNothing(void)",
      "comment": "Placeholder function that performs no operation and returns immediately.\n\nAlgorithm:\n1. Return immediately without performing any operations\n\nParameters:\nNone\n\nReturns:\nNothing (void function)\n\nSpecial Cases:\nThis appears to be a stub function used throughout the codebase where\na function call is expected but no actual operation is required.\nCommon patterns include disabled debugging/logging code or \nconditional functionality that has been compiled out.\n\nCross-Reference Analysis:\nReferenced 32 times throughout the codebase, indicating this is\na widely-used placeholder for operations that may be:\n- Debugging functions disabled in release builds\n- Logging operations that have been stubbed out  \n- Placeholder for future functionality\n- Error handling that has been simplified to no-op",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5c73446e6da2bc552d6d981beccb1347"
    },
    "Bnclient_MNE_5c819fccbe8b": {
      "addresses": {
        "LoD/1.11": "0x6FF24226",
        "LoD/1.11b": "0x6FF24218",
        "LoD/1.12a": "0x6FF24286",
        "LoD/1.13c": "0x6FF2428B",
        "LoD/1.13d": "0x6FF24291"
      },
      "rvas": {
        "LoD/1.11": "0x4226",
        "LoD/1.11b": "0x4218",
        "LoD/1.12a": "0x4286",
        "LoD/1.13c": "0x428B",
        "LoD/1.13d": "0x4291"
      },
      "name": "__ioterm",
      "signature": "void __ioterm(void)",
      "comment": "Library Function - Single Match\n __ioterm\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5c819fccbe8be253acb13e92783cc438"
    },
    "Bnclient_MNE_5d1fe854962f": {
      "addresses": {
        "LoD/1.09": "0x6FF13320",
        "LoD/1.09b": "0x6FF13320",
        "LoD/1.09d": "0x6FF13640"
      },
      "rvas": {
        "LoD/1.09": "0x13320",
        "LoD/1.09b": "0x13320",
        "LoD/1.09d": "0x13640"
      },
      "method": "MNE",
      "index": "MNE:5d1fe854962fce87e1cf67d38ccd2ad7",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF0C8FF",
          "rva": "0xC8FF",
          "confidence": 0.325,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.09d"
        }
      }
    },
    "Bnclient_MNE_5d2d40297dfe": {
      "addresses": {
        "LoD/1.11": "0x6FF21A47",
        "LoD/1.11b": "0x6FF21556",
        "LoD/1.12a": "0x6FF214FC",
        "LoD/1.13c": "0x6FF21342",
        "LoD/1.13d": "0x6FF21826"
      },
      "rvas": {
        "LoD/1.11": "0x1A47",
        "LoD/1.11b": "0x1556",
        "LoD/1.12a": "0x14FC",
        "LoD/1.13c": "0x1342",
        "LoD/1.13d": "0x1826"
      },
      "name": "__onexit",
      "signature": "_onexit_t __onexit(_onexit_t _Func)",
      "comment": "Library Function - Single Match\n __onexit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5d2d40297dfe2be53beef9d63f51ef80"
    },
    "Bnclient_MNE_5d8be9030f81": {
      "addresses": {
        "LoD/1.11": "0x6FF21326",
        "LoD/1.11b": "0x6FF2185E",
        "LoD/1.12a": "0x6FF2178E",
        "LoD/1.13c": "0x6FF219FE",
        "LoD/1.13d": "0x6FF21EB7"
      },
      "rvas": {
        "LoD/1.11": "0x1326",
        "LoD/1.11b": "0x185E",
        "LoD/1.12a": "0x178E",
        "LoD/1.13c": "0x19FE",
        "LoD/1.13d": "0x1EB7"
      },
      "name": "___toupper_mt",
      "signature": "uint ___toupper_mt(void * this, int param_1, uint param_2)",
      "comment": "Library Function - Single Match\n ___toupper_mt\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5d8be9030f8141e25fd0bc4b51fae279"
    },
    "Bnclient_MNE_5df4f5163008": {
      "addresses": {
        "LoD/1.11": "0x6FF2D1F0",
        "LoD/1.11b": "0x6FF34D90",
        "LoD/1.12a": "0x6FF34A60",
        "LoD/1.13c": "0x6FF325E0",
        "LoD/1.13d": "0x6FF37270"
      },
      "rvas": {
        "LoD/1.11": "0xD1F0",
        "LoD/1.11b": "0x14D90",
        "LoD/1.12a": "0x14A60",
        "LoD/1.13c": "0x125E0",
        "LoD/1.13d": "0x17270"
      },
      "method": "MNE",
      "index": "MNE:5df4f5163008251eb5407862c11b1a5b"
    },
    "Bnclient_MNE_5df976bd114b": {
      "addresses": {
        "LoD/1.07": "0x6FF26F10",
        "LoD/1.08": "0x6FF26F30"
      },
      "rvas": {
        "LoD/1.07": "0x6F10",
        "LoD/1.08": "0x6F30"
      },
      "name": "SendLocaleAndTimeInfo",
      "signature": "void SendLocaleAndTimeInfo(void)",
      "comment": "Collects system locale and time zone information and sends it via network packet.\n\nAlgorithm:\n1. Initialize TIME_ZONE_INFORMATION structure by zeroing memory\n2. Get current time zone information from system\n3. Get system time (UTC) and local time\n4. Convert both time values to FILETIME format for storage\n5. Extract time zone bias for local/UTC time difference calculation\n6. Get system default and user default locale identifiers\n7. Get user default language identifier and cast to DWORD\n8. Initialize 128-byte locale info buffer with null terminator\n9. Get locale info string for LOCALE_SLANGUAGE (0x3) - language name\n10. Calculate string length using REPNE SCASB instruction\n11. Append locale info string for LOCALE_SCOUNTRY (0x5) - country name\n12. Calculate length again and append next locale string\n13. Append locale info string for LOCALE_SENGLANGUAGE (0x7) - English language name\n14. Calculate length and append final locale string for LOCALE_SENGCOUNTRY (0x1002) - English country name\n15. Calculate total locale string buffer size used\n16. Send collected locale and time information via SendNetworkPacketWithValidation\n\nParameters:\nNone - function operates on system state only\n\nReturns:\nvoid - function does not return values but sends data via network\n\nSpecial Cases:\nNetwork packet sending may fail silently - no error handling for SendNetworkPacketWithValidation\nLocale string buffer limited to 128 bytes total - overflow not checked\nMultiple REPNE SCASB operations use manual string length calculation\n\nMagic Numbers Reference:\n0x16c (364) - Total stack frame size for all local variables\n0x2b (43) - Initialization loop count for TIME_ZONE_INFORMATION structure (172 bytes / 4 = 43 DWORDs)\n0x400 (1024) - LOCALE_SYSTEM_DEFAULT constant for GetLocaleInfoA calls\n0x3 (3) - LOCALE_SLANGUAGE constant for language name\n0x5 (5) - LOCALE_SCOUNTRY constant for country name  \n0x7 (7) - LOCALE_SENGLANGUAGE constant for English language name\n0x1002 (4098) - LOCALE_SENGCOUNTRY constant for English country name\n0x40 (64) - Maximum buffer size per locale string\n0xffffffff - Initial value for string length calculation (will become 0 after NOT operation)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5df976bd114bce6fa59a1da83f460955"
    },
    "Bnclient_MNE_5ee5e91686b8": {
      "addresses": {
        "LoD/1.07": "0x6FF31E30",
        "LoD/1.08": "0x6FF31E50",
        "LoD/1.09": "0x6FF12A45",
        "LoD/1.09b": "0x6FF12A45",
        "LoD/1.09d": "0x6FF12D60",
        "LoD/1.10": "0x6FF132E4"
      },
      "rvas": {
        "LoD/1.07": "0x11E30",
        "LoD/1.08": "0x11E50",
        "LoD/1.09": "0x12A45",
        "LoD/1.09b": "0x12A45",
        "LoD/1.09d": "0x12D60",
        "LoD/1.10": "0x132E4"
      },
      "name": "ProcessEnvironmentVariableString",
      "signature": "int ProcessEnvironmentVariableString(char * lpszEnvString, int nSetOsVariable)",
      "comment": "Processes environment variable strings by parsing VAR=VALUE format and managing global environment array\n\nAlgorithm:\n1. Validate input string pointer is not NULL, return -1 if NULL\n2. Search for equals sign (=) using character search function (0x3d = '=' in ASCII)  \n3. Return -1 if no equals sign found or equals sign is at start of string\n4. Determine if value portion is empty by checking byte after equals sign\n5. Initialize global environment array if not already initialized or pointing to sentinel\n6. If array is NULL and either not setting OS variable or environment not initialized:\n   - Return 0 if value is empty (no-op for empty unset operations)\n   - Allocate 4-byte array and initialize with NULL terminator\n   - Initialize environment flag if not already done\n7. If array is NULL but should process environment, call ProcessEnvironmentStringTable\n8. Look up variable name in current array using binary search function\n9. Handle three cases based on lookup result and value status:\n   - Variable not found or array empty + non-empty value: Add new entry\n   - Variable found + non-empty value: Update existing entry  \n   - Variable found + empty value: Remove entry and compact array\n10. If setting OS environment variable flag is set:\n    - Calculate total string length and allocate temporary buffer\n    - Copy string and null-terminate at equals sign to separate name/value\n    - Call SetEnvironmentVariableA with separated name and value\n    - Deallocate temporary buffer\n\nParameters:\nlpszEnvString (char *): Environment string in \"NAME=VALUE\" format, must not be NULL\nnSetOsVariable (int): Flag controlling OS environment update (0=internal only, non-zero=update OS)\n\nReturns:\n0 on success\n-1 (0xffffffff) on error (NULL input, no equals sign, memory allocation failure)\n\nSpecial Cases:\nEmpty values (NAME=) trigger variable removal when found in array\nMissing equals sign or equals at position 0 returns immediate error\nMemory allocation failures return -1 and leave array in previous state\n\nMagic Numbers Reference:\n0x3d (61 decimal): ASCII code for equals sign character\n0xffffffff (-1): Standard error return value\n4: Size in bytes for pointer array entries and initial array allocation",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5ee5e91686b897ac407a66f5e26c5af0"
    },
    "Bnclient_MNE_5f58e07c3a5e": {
      "addresses": {
        "LoD/1.07": "0x6FF21D50",
        "LoD/1.08": "0x6FF21D70"
      },
      "rvas": {
        "LoD/1.07": "0x1D50",
        "LoD/1.08": "0x1D70"
      },
      "name": "ClearGlobalArrayEntryAndProcess",
      "signature": "uint ClearGlobalArrayEntryAndProcess(uint dwIndex, uint dwParam2, uint dwParam3)",
      "comment": "Clears global array entries and processes input parameters\n\nAlgorithm:\n1. Clear entry at index 0x31 in global array at 0x6ff39630 using low byte of dwIndex\n2. Clear entry at index 0x31 in global array at 0x6ff3951c using low byte of dwIndex  \n3. Forward all three parameters to processing function FUN_6ff261f0\n4. Return success code 1\n\nParameters:\n  dwIndex (uint): Index value where low byte is used for array clearing operations\n  dwParam2 (uint): Second parameter forwarded to processing function\n  dwParam3 (uint): Third parameter forwarded to processing function\n\nReturns:\n  uint: Always returns 1 (success)\n\nSpecial Cases:\n  - Only the low byte (dwIndex & 0xFF) is used for array indexing\n  - The constant 0x31 is OR'd with upper bits of dwIndex before array access\n  - Both global arrays are always cleared at the same calculated index\n\nMagic Numbers Reference:\n  0x31 - Constant OR'd with dwIndex upper bits for array clearing\n  0x1 - Success return value",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5f58e07c3a5eead131aab91e720aaafb"
    },
    "Bnclient_MNE_5f5a2dadfb6e": {
      "addresses": {
        "LoD/1.11": "0x6FF25230",
        "LoD/1.11b": "0x6FF26B50",
        "LoD/1.12a": "0x6FF264E0",
        "LoD/1.13c": "0x6FF26BB0",
        "LoD/1.13d": "0x6FF254A0"
      },
      "rvas": {
        "LoD/1.11": "0x5230",
        "LoD/1.11b": "0x6B50",
        "LoD/1.12a": "0x64E0",
        "LoD/1.13c": "0x6BB0",
        "LoD/1.13d": "0x54A0"
      },
      "name": "_strcspn",
      "signature": "size_t _strcspn(char * _Str, char * _Control)",
      "comment": "Library Function - Single Match\n _strcspn\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5f5a2dadfb6e3cd7b350f3b00225ebe0"
    },
    "Bnclient_MNE_5f91c25bb129": {
      "addresses": {
        "LoD/1.11": "0x6FF25D60",
        "LoD/1.11b": "0x6FF2493D",
        "LoD/1.12a": "0x6FF26BF5",
        "LoD/1.13c": "0x6FF25B47",
        "LoD/1.13d": "0x6FF249AD"
      },
      "rvas": {
        "LoD/1.11": "0x5D60",
        "LoD/1.11b": "0x493D",
        "LoD/1.12a": "0x6BF5",
        "LoD/1.13c": "0x5B47",
        "LoD/1.13d": "0x49AD"
      },
      "name": "__lseek_lk",
      "signature": "DWORD __lseek_lk(uint param_1, LONG param_2, DWORD param_3)",
      "comment": "Library Function - Single Match\n __lseek_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5f91c25bb1292543e16ed50f66b203fb"
    },
    "Bnclient_MNE_60fb4369558c": {
      "addresses": {
        "LoD/1.07": "0x6FF2BEB0",
        "LoD/1.08": "0x6FF2BED0",
        "LoD/1.09": "0x6FF0CAD0",
        "LoD/1.09b": "0x6FF0CAD0",
        "LoD/1.09d": "0x6FF0CD30",
        "LoD/1.10": "0x6FF0CF80"
      },
      "rvas": {
        "LoD/1.07": "0xBEB0",
        "LoD/1.08": "0xBED0",
        "LoD/1.09": "0xCAD0",
        "LoD/1.09b": "0xCAD0",
        "LoD/1.09d": "0xCD30",
        "LoD/1.10": "0xCF80"
      },
      "name": "CopyStringWithLimit",
      "signature": "char * CopyStringWithLimit(char * szDestBuffer, char * szSourceBuffer, size_t dwMaxBytes)",
      "comment": "Copies up to dwMaxBytes characters from source string to destination buffer with optimized algorithms.\n\nAlgorithm:\n1. Return immediately if dwMaxBytes is zero (no bytes to copy)\n2. Cast destination pointer to uint pointer for optimized 4-byte operations\n3. Check source pointer alignment - if not 4-byte aligned, use byte-by-byte copy\n4. In byte copy mode: copy bytes until null terminator, count exhausted, or source aligned\n5. Switch to dword copy mode when source becomes 4-byte aligned\n6. Calculate number of complete 4-byte chunks to process (dwMaxBytes >> 2)\n7. Use SWAR (SIMD Within A Register) null detection for fast string termination\n8. Apply magic constant 0x7efefeff to detect null bytes within dwords\n9. When null detected, identify exact byte position and copy partial dword\n10. Fill remaining destination bytes with nulls after string termination\n11. Process any remaining 1-3 bytes with byte-by-byte copy\n12. Return pointer to destination buffer\n\nParameters:\nszDestBuffer (char *): Destination buffer to receive copied string\nszSourceBuffer (char *): Source string to copy from (null-terminated)\ndwMaxBytes (size_t): Maximum number of bytes to copy (includes null terminator)\n\nReturns:\nchar *: Pointer to destination buffer (same as szDestBuffer parameter)\n\nSpecial Cases:\nIf dwMaxBytes is 0, returns destination pointer without copying anything\nIf source string is shorter than dwMaxBytes, fills remaining bytes with null characters\nDoes not guarantee null termination if source string length equals dwMaxBytes\n\nMagic Numbers Reference:\n0x7efefeff (0x7efefeff): SWAR magic constant for null byte detection in 32-bit words\n0x81010100 (0x81010100): Bit mask to isolate null detection results after SWAR operation\n0x3 (3): Alignment mask to check for 4-byte boundary alignment\n0xffffffff (4294967295): XOR mask used in SWAR null detection algorithm\n\nError Handling:\nNo validation of pointer parameters - assumes valid non-null pointers\nNo bounds checking beyond dwMaxBytes limit\nUndefined behavior if destination buffer smaller than dwMaxBytes\nUndefined behavior if source and destination buffers overlap",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:60fb4369558c571ee3e9892006835a82"
    },
    "Bnclient_MNE_630b0e4f3169": {
      "addresses": {
        "LoD/1.12a": "0x6FF225D9",
        "LoD/1.13c": "0x6FF22275"
      },
      "rvas": {
        "LoD/1.12a": "0x25D9",
        "LoD/1.13c": "0x2275"
      },
      "method": "MNE",
      "index": "MNE:630b0e4f3169af3d32abd2ac2d1bf3c9"
    },
    "Bnclient_MNE_636b1231cc48": {
      "addresses": {
        "LoD/1.09": "0x6FF133A0",
        "LoD/1.09b": "0x6FF133A0",
        "LoD/1.09d": "0x6FF136C0"
      },
      "rvas": {
        "LoD/1.09": "0x133A0",
        "LoD/1.09b": "0x133A0",
        "LoD/1.09d": "0x136C0"
      },
      "method": "MNE",
      "index": "MNE:636b1231cc48f82d99e89e3852049195"
    },
    "Bnclient_MNE_63906d1f35f7": {
      "addresses": {
        "LoD/1.07": "0x6FF30ECA",
        "LoD/1.08": "0x6FF30EEA",
        "LoD/1.09": "0x6FF11B0A",
        "LoD/1.09b": "0x6FF11B0A",
        "LoD/1.09d": "0x6FF11DFA",
        "LoD/1.10": "0x6FF1234A"
      },
      "rvas": {
        "LoD/1.07": "0x10ECA",
        "LoD/1.08": "0x10EEA",
        "LoD/1.09": "0x11B0A",
        "LoD/1.09b": "0x11B0A",
        "LoD/1.09d": "0x11DFA",
        "LoD/1.10": "0x1234A"
      },
      "name": "InitializeCharacterMappingTable",
      "signature": "void InitializeCharacterMappingTable(void)",
      "comment": "Initialize character type and case mapping tables for locale-specific operations.\n\nAlgorithm:\n1. Attempt to retrieve code page information using GetCPInfo for g_dwCurrentCodePage\n2. If successful, build complete ASCII character table (0x00-0xFF) with each byte value\n3. Set position 0 to space character (0x20) to handle null terminator mapping\n4. Process multi-byte lead byte ranges from cpinfo.LeadByte array\n5. For each lead byte range, fill character positions with spaces to mark invalid single-byte chars\n6. Call GetStringCharacterTypesCompat to populate character type flags (letter/digit/punctuation)\n7. Call LocaleMapStringWithFallback twice: first for lowercase mapping, second for uppercase\n8. Process each character position to set type flags and case mappings:\n   - If character type & 0x01 (letter): set 0x10 flag, store lowercase mapping\n   - If character type & 0x02 (digit): set 0x20 flag, store uppercase mapping  \n   - Otherwise: clear mapping entry to 0\n9. If GetCPInfo fails, use hardcoded ASCII fallback:\n   - Characters 0x41-0x5A (A-Z): set 0x10 flag, map to lowercase (+0x20 offset)\n   - Characters 0x61-0x7A (a-z): set 0x20 flag, map to uppercase (-0x20 offset)\n   - All other characters: clear mapping\n\nParameters:\nNone - operates on global code page variables\n\nReturns:\nvoid - updates global character type and mapping tables\n\nMagic Numbers Reference:\n0x100 - Character table size (256 bytes for full 8-bit range)\n0x01 - Character type flag: alphabetic letter\n0x02 - Character type flag: numeric digit  \n0x10 - Global flag: uppercase letter\n0x20 - Global flag: lowercase letter\n0x41-0x5A - ASCII uppercase letters A-Z\n0x61-0x7A - ASCII lowercase letters a-z\n\nGlobal Variables Modified:\ng_abCharacterTypeTable - 257-byte array for character classification flags\nDAT_6ff3a1e0 - 256-byte array for case conversion mappings\n\nStructure Layout:\n_cpinfo (20 bytes):\nOffset  Size  Field Name    Type    Description\n0x00    4     MaxCharSize   UINT    Maximum character size in bytes\n0x04    12    DefaultChar   BYTE[2] Default character for unmappable chars\n0x06    12    LeadByte      BYTE[12] Lead byte ranges for MBCS (null terminated pairs)\n\nError Handling:\nIf GetCPInfo fails, function falls back to basic ASCII-only character mapping\nNo error return - always completes with either full locale mapping or ASCII fallback",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:63906d1f35f7842042066a6643d2050c"
    },
    "Bnclient_MNE_65b7a85da46b": {
      "addresses": {
        "LoD/1.07": "0x6FF24B90",
        "LoD/1.08": "0x6FF24BB0",
        "LoD/1.09": "0x6FF05510",
        "LoD/1.09b": "0x6FF05510",
        "LoD/1.09d": "0x6FF05780",
        "LoD/1.10": "0x6FF056E0"
      },
      "rvas": {
        "LoD/1.07": "0x4B90",
        "LoD/1.08": "0x4BB0",
        "LoD/1.09": "0x5510",
        "LoD/1.09b": "0x5510",
        "LoD/1.09d": "0x5780",
        "LoD/1.10": "0x56E0"
      },
      "name": "DNS",
      "signature": "char * DNS(DnsContainer * pDnsContainer)",
      "comment": "Retrieves a pointer to a specific DNS name component from a DNS container structure.\n\nAlgorithm:\n1. Validate DNS container pointer is non-null (pDnsContainer + 0x10)\n2. Check component index is positive and within bounds (1 <= nComponentIndex <= container.maxCount)\n3. Calculate maximum iterations as nComponentIndex * 3 for DNS label traversal\n4. Initialize loop counter to 1 and current offset to 0\n5. Enter component parsing loop while counter < maxIterations\n6. Check current offset doesn't exceed buffer limit (container + 0x14)\n7. Call Ordinal_506 (string length function) on current position\n8. Advance pointer by string length + 1 (null terminator)\n9. Update current offset and increment counter\n10. Continue until target component reached or bounds exceeded\n11. Perform final bounds check before returning pointer\n12. Return pointer to target component or original parameter on failure\n\nParameters:\npDnsContainer - Pointer to DNS container structure with layout:\n                +0x08: Maximum component count (int)\n                +0x10: Pointer to DNS name data buffer (char *)\n                +0x14: Buffer size limit (int)\nIMPLICIT nComponentIndex - Component index to retrieve (1-based, via ESP+0x14)\n\nReturns:\nSuccess - Pointer to start of requested DNS component string\nFailure - Original pDnsContainer parameter (fallback value)\nNULL conditions: Never returns NULL, always returns valid pointer\n\nSpecial Cases:\n- Index out of bounds (< 1 or > maxCount): Returns pDnsContainer\n- Null container pointer: Returns pDnsContainer  \n- Buffer overflow during traversal: Returns pDnsContainer\n- Component parsing reaches buffer limit: Returns current position\n\nMagic Numbers Reference:\n0x08 - Offset to maximum count field\n0x10 - Offset to DNS data pointer field  \n0x14 - Offset to buffer size limit field\n0x1 - Component counter start value\n0x3 - Multiplier for DNS traversal iterations (nComponentIndex * 3)\n\nError Handling:\n- Input validation returns original parameter on invalid inputs\n- Bounds checking prevents buffer overruns during string traversal\n- SBORROW4 macro detects integer overflow in offset calculations\n- Multiple exit paths ensure function always returns valid pointer\n\nStructure Layout:\nOffset | Size | Field Name    | Type  | Description\n-------|------|---------------|-------|----------------------------------\n+0x08  |  4   | nMaxCount     | int   | Maximum number of components\n+0x10  |  4   | pDnsData      | char* | Pointer to DNS name buffer\n+0x14  |  4   | nBufferLimit  | int   | Size limit for DNS data buffer",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:65b7a85da46b184fa35b2ec6cd4699d5"
    },
    "Bnclient_MNE_662566ebcde3": {
      "addresses": {
        "LoD/1.07": "0x6FF2B820",
        "LoD/1.08": "0x6FF2B840",
        "LoD/1.09": "0x6FF0C440",
        "LoD/1.09b": "0x6FF0C440",
        "LoD/1.09d": "0x6FF0C6A0",
        "LoD/1.10": "0x6FF0CC00"
      },
      "rvas": {
        "LoD/1.07": "0xB820",
        "LoD/1.08": "0xB840",
        "LoD/1.09": "0xC440",
        "LoD/1.09b": "0xC440",
        "LoD/1.09d": "0xC6A0",
        "LoD/1.10": "0xCC00"
      },
      "name": "CompareStringsWithLocale",
      "signature": "int CompareStringsWithLocale(byte * pbString1, char * szString2, uint dwMaxLength)",
      "comment": "Compares two strings with optional locale-aware processing and case handling.\n\nAlgorithm:\n1. Validate that dwMaxLength is non-zero, return 0 if zero\n2. Check global locale availability flag (g_dwLocaleAvailableFlag)\n3a. If locale unavailable (flag == 0):\n    - Perform simple byte-by-byte comparison\n    - Apply ASCII case conversion (0x41-0x5A -> 0x61-0x7A) for uppercase letters\n    - Compare converted characters until null terminator or length exceeded\n    - Return comparison result: -1 (less), 0 (equal), 1 (greater)\n3b. If locale available (flag != 0):\n    - Enter critical section with thread-safe counter increment\n    - Check critical section limit and call error handler if exceeded\n    - Perform locale-aware character comparison using FUN_6ff2bdda helper\n    - Process characters through locale transformation before comparison\n    - Exit critical section when complete or call cleanup handler\n4. Return comparison result as signed integer\n\nParameters:\npbString1 (byte*): First string to compare, treated as byte array for case conversion\nszString2 (char*): Second string to compare, null-terminated character string\ndwMaxLength (uint): Maximum number of characters to compare, prevents buffer overrun\n\nReturns:\n0: Strings are equal within specified length\n-1 (0xFFFFFFFF): First string is lexicographically less than second\n1: First string is lexicographically greater than second\n\nSpecial Cases:\nCritical section handling prevents race conditions in multi-threaded locale operations\nCase conversion limited to ASCII range (0x41-0x5A) for performance\nLocale-aware path delegates character mapping to FUN_6ff2bdda helper function\n\nMagic Numbers Reference:\n0x40 (64): ASCII boundary before uppercase letters\n0x5B (91): ASCII boundary after uppercase letters  \n0x20 (32): ASCII case conversion offset (upper to lower)\n0x13 (19): Error code for critical section limit exceeded",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:662566ebcde3842108cf876001e2ae79"
    },
    "Bnclient_MNE_679e7391cc43": {
      "addresses": {
        "LoD/1.07": "0x6FF2B6C0",
        "LoD/1.08": "0x6FF2B6E0",
        "LoD/1.09": "0x6FF0C2E0",
        "LoD/1.09b": "0x6FF0C2E0",
        "LoD/1.09d": "0x6FF0C540",
        "LoD/1.10": "0x6FF0CAA0"
      },
      "rvas": {
        "LoD/1.07": "0xB6C0",
        "LoD/1.08": "0xB6E0",
        "LoD/1.09": "0xC2E0",
        "LoD/1.09b": "0xC2E0",
        "LoD/1.09d": "0xC540",
        "LoD/1.10": "0xCAA0"
      },
      "name": "SafeStringFormat",
      "signature": "int SafeStringFormat(char * lpszDestBuffer, byte * pbFormatData)",
      "comment": "Safely format string data with bounds checking and error handling\n\nAlgorithm:\n1. Initialize local buffer pointers to destination buffer\n2. Set buffer size limit to 0x42 (66 bytes) and safety counter to maximum integer\n3. Call formatting function FUN_6ff2d14c with buffer pointers and format data\n4. Decrement safety counter to check for overflow conditions\n5. If counter underflow detected (negative), call cleanup function FUN_6ff2d034\n6. Otherwise null-terminate the buffer at current position\n7. Return formatting function result code\n\nParameters:\nlpszDestBuffer - Destination buffer for formatted output\npbFormatData - Binary format data or format string\n\nReturns:\nInteger result code from formatting operation\n- Success: Number of characters written or formatting success code\n- Failure: Error code from formatting function\n\nSpecial Cases:\nSafety counter overflow triggers emergency cleanup to prevent buffer corruption\n\nMagic Numbers Reference:\n0x42 (66) - Buffer size limit for formatting operation\n0x7FFFFFFF (2147483647) - Maximum safety counter value for overflow detection\n\nError Handling:\nCounter underflow detection prevents buffer overflow attacks\nEmergency cleanup called on overflow condition to maintain system stability\nNull termination ensures safe string handling on success path",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:679e7391cc431bfbfb578a6a70c8d79c"
    },
    "Bnclient_MNE_69cc32b62a39": {
      "addresses": {
        "LoD/1.10": "0x6FF01E10",
        "LoD/1.11": "0x6FF31670",
        "LoD/1.11b": "0x6FF31CE0",
        "LoD/1.12a": "0x6FF30760",
        "LoD/1.13c": "0x6FF33920",
        "LoD/1.13d": "0x6FF2F8E0"
      },
      "rvas": {
        "LoD/1.10": "0x1E10",
        "LoD/1.11": "0x11670",
        "LoD/1.11b": "0x11CE0",
        "LoD/1.12a": "0x10760",
        "LoD/1.13c": "0x13920",
        "LoD/1.13d": "0xF8E0"
      },
      "method": "MNE",
      "index": "MNE:69cc32b62a392a52aa9dc7aa3ec38143"
    },
    "Bnclient_MNE_6b07f716ad39": {
      "addresses": {
        "LoD/1.11": "0x6FF26350",
        "LoD/1.11b": "0x6FF24FD0",
        "LoD/1.12a": "0x6FF271E0",
        "LoD/1.13c": "0x6FF261C0",
        "LoD/1.13d": "0x6FF25040"
      },
      "rvas": {
        "LoD/1.11": "0x6350",
        "LoD/1.11b": "0x4FD0",
        "LoD/1.12a": "0x71E0",
        "LoD/1.13c": "0x61C0",
        "LoD/1.13d": "0x5040"
      },
      "name": "__aulldvrm",
      "signature": "undefined8 __aulldvrm(uint param_1, uint param_2, uint param_3, uint param_4)",
      "comment": "Library Function - Single Match\n __aulldvrm\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6b07f716ad39855b07502ac9a8f75c79"
    },
    "Bnclient_MNE_6b4ad6d2941b": {
      "addresses": {
        "LoD/1.11": "0x6FF24E59",
        "LoD/1.11b": "0x6FF2677D",
        "LoD/1.12a": "0x6FF2610E",
        "LoD/1.13c": "0x6FF267E5",
        "LoD/1.13d": "0x6FF250D5"
      },
      "rvas": {
        "LoD/1.11": "0x4E59",
        "LoD/1.11b": "0x677D",
        "LoD/1.12a": "0x610E",
        "LoD/1.13c": "0x67E5",
        "LoD/1.13d": "0x50D5"
      },
      "name": "___free_lc_time",
      "signature": "undefined ___free_lc_time(undefined4 * param_1)",
      "comment": "Library Function - Single Match\n ___free_lc_time\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6b4ad6d2941b712fcff606229e9dd829"
    },
    "Bnclient_MNE_6bb86e2cc8be": {
      "addresses": {
        "LoD/1.07": "0x6FF3098B",
        "LoD/1.08": "0x6FF309AB",
        "LoD/1.09": "0x6FF115CB",
        "LoD/1.09b": "0x6FF115CB",
        "LoD/1.09d": "0x6FF118BB",
        "LoD/1.10": "0x6FF11E0B"
      },
      "rvas": {
        "LoD/1.07": "0x1098B",
        "LoD/1.08": "0x109AB",
        "LoD/1.09": "0x115CB",
        "LoD/1.09b": "0x115CB",
        "LoD/1.09d": "0x118BB",
        "LoD/1.10": "0x11E0B"
      },
      "name": "CheckDaylightSavingTransition",
      "signature": "bool CheckDaylightSavingTransition(int * pTimeInfo)",
      "comment": "Determines if a given date/time falls within daylight saving time transition periods.\n\nAlgorithm:\n1. Check if timezone processing is enabled (g_dwTimezoneFlag)\n2. If disabled, return false immediately\n3. Extract timezone offset from time info structure [offset 0x14]\n4. Compare timezone offset against standard values (DAT_6ff38ed8, DAT_6ff38ee8)\n5. If timezone values don't match expected, trigger transition calculations:\n   - If DAT_6ff3a0d0 is zero, call simple transition functions with hardcoded parameters\n   - Otherwise, call complex transition functions using configuration data arrays\n6. Extract year value from time info structure [offset 0x1c]\n7. Check if year falls within DST date range (DAT_6ff38edc to DAT_6ff38eec)\n8. If year is within range bounds, return true for dates between boundaries\n9. If year equals boundary values, perform detailed time-of-day comparison:\n   - Calculate total milliseconds: ((hours * 60 + minutes) * 60 + seconds) * 1000\n   - For start boundary (DAT_6ff38edc), check if time >= start threshold (DAT_6ff38ee0)\n   - For end boundary (DAT_6ff38eec), check if time < end threshold (DAT_6ff38ef0)\n\nParameters:\n- pTimeInfo: Pointer to time/date structure containing:\n  [0x0] seconds (0-59)\n  [0x4] minutes (0-59) \n  [0x8] hours (0-23)\n  [0x14] timezone offset value\n  [0x1c] year value\n\nReturns:\n- true: Date/time falls within daylight saving transition period\n- false: Date/time is outside DST transition period or timezone processing disabled\n\nSpecial Cases:\n- Returns false immediately if g_dwTimezoneFlag is 0\n- Handles wrap-around year ranges when start year > end year\n- Precise millisecond comparison at DST boundary dates\n\nMagic Numbers Reference:\n- 0x3c (60): Seconds per minute, minutes per hour conversion\n- 0x3e8 (1000): Milliseconds per second conversion\n- 0x14 (20): Offset to timezone field in time structure\n- 0x1c (28): Offset to year field in time structure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:6bb86e2cc8beb9a2c340a0df09e576f1"
    },
    "Bnclient_MNE_6d50544faaf6": {
      "addresses": {
        "LoD/1.07": "0x6FF30B37",
        "LoD/1.08": "0x6FF30B57",
        "LoD/1.09": "0x6FF11777",
        "LoD/1.09b": "0x6FF11777",
        "LoD/1.09d": "0x6FF11A67",
        "LoD/1.10": "0x6FF11FB7"
      },
      "rvas": {
        "LoD/1.07": "0x10B37",
        "LoD/1.08": "0x10B57",
        "LoD/1.09": "0x11777",
        "LoD/1.09b": "0x11777",
        "LoD/1.09d": "0x11A67",
        "LoD/1.10": "0x11FB7"
      },
      "name": "CalculateAndSetCalendarDateTime",
      "signature": "void CalculateAndSetCalendarDateTime(int nMode, int nCalculationMode, uint dwYear, int nMonth, int nWeek, int nDayOfWeek, int nDayOffset, int nHour, int nMinute, int nSecond, int nMillisecond)",
      "comment": "Calculates calendar day numbers and time values, setting global date/time state variables.\n\nAlgorithm:\n1. Check calculation mode (nCalculationMode) to determine calendar vs simple calculation \n2. For calendar mode (nCalculationMode == 1):\n   a. Determine if year is leap year using bitwise test (dwYear & 3 == 0)\n   b. Get days in month from appropriate array (leap year vs normal year)\n   c. Calculate day of week using formula: (dwYear * 0x16d - 0x63db + dwDaysInMonth + 1 + ((dwYear-1) >> 2)) % 7\n   d. Adjust calculated day based on week number (nWeek) and target day of week (nDayOfWeek)\n   e. Handle week 5 special case - if calculated day exceeds month length, subtract 7\n3. For simple mode (nCalculationMode != 1):\n   a. Get days in target month using same leap year logic\n   b. Add day offset (nDayOffset) directly to month days\n4. Convert time components to milliseconds: ((nHour * 60 + nMinute) * 60 + nSecond) * 1000 + nMillisecond  \n5. Check mode flag (nMode) to determine global variable assignment:\n   a. Mode 1: Store values in g_dwStoredYear, g_dwStoredMilliseconds, g_nStoredDay\n   b. Mode 0: Apply daylight adjustment and handle day rollover, store in g_dwAdjustedYear, g_dwAdjustedTimeMilliseconds, g_nAdjustedDay\n\nParameters:\nnMode - Mode flag determining which global variables to update (1=stored, 0=adjusted)\nnCalculationMode - Calculation type flag (1=calendar calculation, other=simple day offset)\ndwYear - Year for calendar calculations and leap year determination  \nnMonth - Zero-based month index for array lookups (0=January, 11=December)\nnWeek - Week number within month (0-4, where 4 is special case for month end)\nnDayOfWeek - Target day of week for calendar calculations (0-6)\nnDayOffset - Simple day offset added to month days in non-calendar mode\nnHour - Hour component (0-23) for time calculation\nnMinute - Minute component (0-59) for time calculation  \nnSecond - Second component (0-59) for time calculation\nnMillisecond - Millisecond component (0-999) for time calculation\n\nReturns:\nvoid - Function updates global state variables rather than returning values\n\nSpecial Cases:\nWeek 5 handling: If nWeek == 5 and calculated day exceeds month length, subtract 7 days\nDay rollover: In mode 0, if time with daylight adjustment goes negative or exceeds 86,399,999ms, adjust day accordingly\nLeap year detection: Uses bitwise AND with 3 (dwYear & 3 == 0) for simple leap year test\n\nMagic Numbers Reference:\n0x16d (365) - Days per year for day-of-week calculation\n0x63db (25,563) - Calendar epoch adjustment constant  \n0x3e8 (1,000) - Milliseconds per second conversion\n0x3c (60) - Seconds per minute / minutes per hour conversion\n0x5265c00 (86,400,000) - Milliseconds per day (24 * 60 * 60 * 1000)\n0x5265c01 (86,400,001) - Day overflow threshold (one millisecond past midnight)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:6d50544faaf636cd3d820cef87818a92"
    },
    "Bnclient_MNE_6d6cf4ba1895": {
      "addresses": {
        "LoD/1.11": "0x6FF369BC",
        "LoD/1.11b": "0x6FF3698D",
        "LoD/1.12a": "0x6FF3783C",
        "LoD/1.13c": "0x6FF37822",
        "LoD/1.13d": "0x6FF3775B"
      },
      "rvas": {
        "LoD/1.11": "0x169BC",
        "LoD/1.11b": "0x1698D",
        "LoD/1.12a": "0x1783C",
        "LoD/1.13c": "0x17822",
        "LoD/1.13d": "0x1775B"
      },
      "name": "IsExceptionObjectToBeDestroyed",
      "signature": "int IsExceptionObjectToBeDestroyed(void * param_1)",
      "comment": "Library Function - Single Match\n int __cdecl IsExceptionObjectToBeDestroyed(void *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6d6cf4ba189585a4cd2d487202ee7142",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF05B00",
          "rva": "0x5B00",
          "confidence": 0.385,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF05B90",
          "rva": "0x5B90",
          "confidence": 0.312,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF05920",
          "rva": "0x5920",
          "confidence": 0.204,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_6d6e85748e7c": {
      "addresses": {
        "LoD/1.11": "0x6FF30130",
        "LoD/1.11b": "0x6FF32B30",
        "LoD/1.12a": "0x6FF36060",
        "LoD/1.13c": "0x6FF31BB0",
        "LoD/1.13d": "0x6FF2E3A0"
      },
      "rvas": {
        "LoD/1.11": "0x10130",
        "LoD/1.11b": "0x12B30",
        "LoD/1.12a": "0x16060",
        "LoD/1.13c": "0x11BB0",
        "LoD/1.13d": "0xE3A0"
      },
      "method": "MNE",
      "index": "MNE:6d6e85748e7c62f71836c8bcb508b315",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF15960",
          "rva": "0x15960",
          "confidence": 0.405,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF153D0",
          "rva": "0x153D0",
          "confidence": 0.295,
          "method": "unique_api",
          "direction": "reverse",
          "source": "LoD/1.10"
        },
        "LoD/1.09b": {
          "address": "0x6FF150B0",
          "rva": "0x150B0",
          "confidence": 0.295,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09": {
          "address": "0x6FF150B0",
          "rva": "0x150B0",
          "confidence": 0.194,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_6dad5d067638": {
      "addresses": {
        "LoD/1.07": "0x6FF2C262",
        "LoD/1.08": "0x6FF2C38D",
        "LoD/1.09": "0x6FF0CF8D",
        "LoD/1.09b": "0x6FF0CF8D",
        "LoD/1.09d": "0x6FF0D192",
        "LoD/1.10": "0x6FF0D6F8"
      },
      "rvas": {
        "LoD/1.07": "0xC262",
        "LoD/1.08": "0xC38D",
        "LoD/1.09": "0xCF8D",
        "LoD/1.09b": "0xCF8D",
        "LoD/1.09d": "0xD192",
        "LoD/1.10": "0xD6F8"
      },
      "name": "GetOrCreateThreadContext",
      "signature": "DWORD * GetOrCreateThreadContext(void)",
      "comment": "Gets or creates the thread-specific context for the current thread.\n\nAlgorithm:\n1. Preserve current thread error state using GetLastError()\n2. Attempt to retrieve existing ThreadContext from TLS using g_dwTlsSlotIndex\n3. If no context exists (NULL pointer):\n   a. Allocate new ThreadContext structure (116 bytes) via FUN_6ff2cbae\n   b. If allocation successful, store context in TLS using TlsSetValue\n   c. If TLS storage successful:\n      - Initialize the context structure using InitializeThreadContext\n      - Get current thread ID and store in context->reserved0 (offset 0x0)\n      - Set context flags to 0xFFFFFFFF (offset 0x4)\n   d. If allocation or TLS storage fails, call AmsgExit(0x10) to terminate\n4. Restore original error state using SetLastError()\n5. Return pointer to ThreadContext structure\n\nParameters:\nNone\n\nReturns:\nThreadContext* - Pointer to thread-specific context structure\n                 Never returns NULL (terminates process on failure)\n\nSpecial Cases:\n- Process termination via AmsgExit(0x10) if memory allocation fails\n- Process termination if TLS storage assignment fails\n- Error code preservation ensures GetLastError() state is unchanged\n\nMagic Numbers Reference:\n0x74 (116 decimal) - Size of ThreadContext structure allocation\n0x10 (16 decimal) - Exit code for thread context allocation failure\n0xFFFFFFFF - Default flag value set in ThreadContext.dwFlags\n\nStructure Layout:\nOffset | Size | Field Name | Type  | Description\n-------|------|------------|-------|------------------------------------------\n0x0    | 4    | reserved0  | DWORD | Thread ID storage (misleading field name)\n0x4    | 4    | dwFlags    | DWORD | Thread context flags (set to 0xFFFFFFFF)\n...    | ...  | ...        | ...   | (Additional fields initialized by InitializeThreadContext)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:6dad5d06763847d66c3aa4a89105e250"
    },
    "Bnclient_MNE_6db4eec4529d": {
      "addresses": {
        "LoD/1.07": "0x6FF30338",
        "LoD/1.08": "0x6FF30358",
        "LoD/1.09": "0x6FF10F78",
        "LoD/1.09b": "0x6FF10F78",
        "LoD/1.09d": "0x6FF11268",
        "LoD/1.10": "0x6FF117B8",
        "LoD/1.11": "0x6FF260F8",
        "LoD/1.11b": "0x6FF24CD5",
        "LoD/1.12a": "0x6FF26F7B",
        "LoD/1.13c": "0x6FF25ECD",
        "LoD/1.13d": "0x6FF24D45"
      },
      "rvas": {
        "LoD/1.07": "0x10338",
        "LoD/1.08": "0x10358",
        "LoD/1.09": "0x10F78",
        "LoD/1.09b": "0x10F78",
        "LoD/1.09d": "0x11268",
        "LoD/1.10": "0x117B8",
        "LoD/1.11": "0x60F8",
        "LoD/1.11b": "0x4CD5",
        "LoD/1.12a": "0x6F7B",
        "LoD/1.13c": "0x5ECD",
        "LoD/1.13d": "0x4D45"
      },
      "name": "InitializeStreamBuffer",
      "signature": "void InitializeStreamBuffer(StreamIO * pStream)",
      "comment": "Initialize stream buffer with 4KB heap allocation and fallback handling.\n\nAlgorithm:\n1. Increment global stream allocation counter for tracking\n2. Attempt to allocate 4KB (0x1000 bytes) buffer using malloc\n3. Store allocated buffer pointer at stream offset +0x8 (pCurrent field)\n4. Check allocation success and branch to appropriate setup\n5. On allocation success: Set buffer flag 0x8, set available size to 0x1000\n6. On allocation failure: Set error flag 0x4, use internal 8-byte fallback buffer at offset +0x14, set available size to 2\n7. Initialize stream position to 0 at offset +0x4\n8. Set base pointer to current buffer pointer at offset +0x0\n\nParameters:\npStream: Pointer to StreamIO structure to initialize buffer for\n\nReturns:\nvoid (no return value)\n\nMagic Numbers Reference:\n0x1000: 4KB standard buffer allocation size (4096 bytes)\n0x4: Error flag indicating allocation failure and fallback buffer use\n0x8: Buffer flag indicating successful heap allocation\n0x2: Fallback buffer size in bytes when allocation fails\n0x14: Offset to internal fallback buffer within stream structure\n\nError Handling:\nAllocation failure: Sets flag 0x4, uses internal buffer at +0x14, limits size to 2 bytes\nNo error propagation: Function handles failure internally with fallback\n\nStructure Layout (Stream Buffer Fields):\nOffset  Size  Field Name    Type      Description\n0x00    4     pBase         void*     Base buffer pointer (set to current)\n0x04    4     nPosition     int       Current position (initialized to 0)\n0x08    4     pCurrent      void*     Current buffer pointer (heap or fallback)\n0x0C    4     dwFlags       uint      Stream flags (bit 2: error, bit 3: allocated)\n0x14    8     abFallback    byte[8]   Internal fallback buffer\n0x18    4     nAvailable    int       Available buffer space (0x1000 or 2)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:6db4eec4529d7320d9c182be8df08afa"
    },
    "Bnclient_MNE_6e538b3bbbee": {
      "addresses": {
        "LoD/1.07": "0x6FF2DE4C",
        "LoD/1.08": "0x6FF2DE6C",
        "LoD/1.09": "0x6FF0EA97",
        "LoD/1.09b": "0x6FF0EA97",
        "LoD/1.09d": "0x6FF0ED7C",
        "LoD/1.10": "0x6FF0F36A"
      },
      "rvas": {
        "LoD/1.07": "0xDE4C",
        "LoD/1.08": "0xDE6C",
        "LoD/1.09": "0xEA97",
        "LoD/1.09b": "0xEA97",
        "LoD/1.09d": "0xED7C",
        "LoD/1.10": "0xF36A"
      },
      "name": "ParseEnvironmentVariables",
      "signature": "void ParseEnvironmentVariables(void)",
      "comment": "Parses environment variables from global string buffer and creates dynamic string array.\n\nAlgorithm:\n\n1. Check initialization flag at g_dwInitializationFlag, call FUN_6ff3104f if uninitialized\n2. Count non-assignment strings (strings not containing '=') in g_dwModuleHandle buffer\n3. Allocate memory for string pointer array: (count * 4 + 4) bytes\n4. Store array pointer in g_pdwParsedStringArray, exit with code 9 if allocation fails\n5. Iterate through environment strings, skip assignment strings (containing '=')\n6. For each non-assignment string: allocate memory for copy, store pointer in array\n7. Copy string using FUN_6ff2ff80, advance to next array slot\n8. Deallocate original environment buffer via DeallocateMemory\n9. Clear g_dwModuleHandle, null-terminate string array, set completion flag\n\nParameters:\nNone (uses global g_dwModuleHandle as input source)\n\nReturns:\nvoid (stores results in g_pdwParsedStringArray global, sets g_dwProcessingCompleteFlag = 1)\n\nSpecial Cases:\n- Exit code 9: Memory allocation failure for string array or individual strings\n- Assignment strings (containing '=') are skipped entirely from output array\n- Original environment buffer is deallocated after processing\n\nError Handling:\n- Memory allocation failures trigger AmsgExit(9) for graceful termination\n- No validation of input buffer format or string encoding\n\nMagic Numbers Reference:\n0x9 (decimal 9) - Memory allocation failure exit code\n0x3d (decimal 61) - ASCII '=' character for assignment detection\n0x4 (decimal 4) - Pointer size for array allocation calculation",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:6e538b3bbbeec8f94bef058bdad701fe"
    },
    "Bnclient_MNE_6f1fe3e59c58": {
      "addresses": {
        "LoD/1.11": "0x6FF2144A",
        "LoD/1.11b": "0x6FF21A89",
        "LoD/1.12a": "0x6FF21879",
        "LoD/1.13c": "0x6FF216D9",
        "LoD/1.13d": "0x6FF21371"
      },
      "rvas": {
        "LoD/1.11": "0x144A",
        "LoD/1.11b": "0x1A89",
        "LoD/1.12a": "0x1879",
        "LoD/1.13c": "0x16D9",
        "LoD/1.13d": "0x1371"
      },
      "name": "strtoxl",
      "signature": "uint strtoxl(byte * param_1, undefined4 * param_2, uint param_3, uint param_4)",
      "comment": "Library Function - Single Match\n _strtoxl\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6f1fe3e59c584b1eac83c0b815ebd421"
    },
    "Bnclient_MNE_6fa76a3bca13": {
      "addresses": {
        "LoD/1.07": "0x6FF2C1AA",
        "LoD/1.08": "0x6FF2C1CA",
        "LoD/1.09": "0x6FF0CDCA",
        "LoD/1.09b": "0x6FF0CDCA",
        "LoD/1.09d": "0x6FF0D0DA",
        "LoD/1.10": "0x6FF0D640",
        "LoD/1.11": "0x6FF2184E",
        "LoD/1.11b": "0x6FF21CF5",
        "LoD/1.12a": "0x6FF21DFC",
        "LoD/1.13c": "0x6FF21E59",
        "LoD/1.13d": "0x6FF21B8E"
      },
      "rvas": {
        "LoD/1.07": "0xC1AA",
        "LoD/1.08": "0xC1CA",
        "LoD/1.09": "0xCDCA",
        "LoD/1.09b": "0xCDCA",
        "LoD/1.09d": "0xD0DA",
        "LoD/1.10": "0xD640",
        "LoD/1.11": "0x184E",
        "LoD/1.11b": "0x1CF5",
        "LoD/1.12a": "0x1DFC",
        "LoD/1.13c": "0x1E59",
        "LoD/1.13d": "0x1B8E"
      },
      "name": "CleanupAndExitThread",
      "signature": "void CleanupAndExitThread(uint dwExitCode)",
      "comment": "Performs thread cleanup operations and terminates the current thread.\n\nAlgorithm:\n1. Check if global cleanup callback is registered (g_pfnCleanupCallback != NULL)\n2. If callback exists, invoke it to perform application-specific cleanup\n3. Allocate or retrieve cleanup data structure via FUN_6ff2c262()\n4. Validate cleanup data pointer is not NULL\n5. If NULL, exit with error code 0x10 via __amsg_exit()\n6. Process cleanup data through FUN_6ff2c2c9()\n7. Terminate current thread with specified exit code via ExitThread()\n\nParameters:\ndwExitCode - Thread exit code passed to ExitThread() for process notification\n\nReturns:\nvoid - Function does not return (terminates thread execution)\n\nSpecial Cases:\n- If g_pfnCleanupCallback is NULL, skips callback invocation\n- If FUN_6ff2c262() returns NULL, terminates with error code 0x10\n- Function never returns normally due to ExitThread() call\n\nMagic Numbers Reference:\n0x10 (16) - Error code for cleanup data allocation failure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:6fa76a3bca136809edcc40368ceda5e5"
    },
    "Bnclient_MNE_70593f43ea0b": {
      "addresses": {
        "LoD/1.07": "0x6FF2FF80",
        "LoD/1.08": "0x6FF2FFA0",
        "LoD/1.09": "0x6FF10BC0",
        "LoD/1.09b": "0x6FF10BC0",
        "LoD/1.09d": "0x6FF10EB0",
        "LoD/1.10": "0x6FF11400",
        "LoD/1.11": "0x6FF25130",
        "LoD/1.11b": "0x6FF26A50",
        "LoD/1.12a": "0x6FF263E0",
        "LoD/1.13c": "0x6FF26AB0",
        "LoD/1.13d": "0x6FF253A0"
      },
      "rvas": {
        "LoD/1.07": "0xFF80",
        "LoD/1.08": "0xFFA0",
        "LoD/1.09": "0x10BC0",
        "LoD/1.09b": "0x10BC0",
        "LoD/1.09d": "0x10EB0",
        "LoD/1.10": "0x11400",
        "LoD/1.11": "0x5130",
        "LoD/1.11b": "0x6A50",
        "LoD/1.12a": "0x63E0",
        "LoD/1.13c": "0x6AB0",
        "LoD/1.13d": "0x53A0"
      },
      "name": "OptimizedStringCopy",
      "signature": "byte * OptimizedStringCopy(byte * pbDestination, byte * pbSource)",
      "comment": "High-performance optimized string copy function with byte-aligned and word-aligned operation modes.\n\nAlgorithm:\n1. Handle unaligned beginning by copying bytes one at a time until 4-byte aligned\n2. Check each byte for null terminator during unaligned phase, exit early if found\n3. Switch to 4-byte block copy mode for aligned portion using magic number detection\n4. Load 4-byte blocks and test for null bytes using bit manipulation (uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100\n5. When null byte detected in block, identify exact position and copy remaining bytes\n6. Handle partial blocks by extracting bytes individually: first byte, second byte, third byte, full 4-byte\n7. Write null terminator at appropriate position and return destination pointer\n\nParameters:\npbDestination: Destination buffer pointer for copied string\npbSource: Source string pointer to copy from\n\nReturns:\npbDestination: Pointer to start of destination buffer (same as input parameter)\n\nMagic Numbers Reference:\n0x7efefeff: Magic constant for null byte detection in 4-byte words\n0x81010100: Mask for identifying null bytes after magic arithmetic\n0xffffffff: XOR mask for bit manipulation in null detection\n0xff0000: Mask for testing third byte in 4-byte word (0x00XX0000)\n0xff000000: Mask for testing fourth byte in 4-byte word (0xXX000000)\n\nSpecial Cases:\nEmpty string (immediate null): Copies null terminator and returns immediately\nUnaligned source: Handles byte-by-byte until aligned, then switches to block mode\nNull in first byte of block: Copies single byte and exits\nNull in second byte: Copies as 16-bit word and exits\nNull in third byte: Copies 16-bit word plus one byte, adds null terminator\nNull in fourth byte: Copies full 32-bit word and exits",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:70593f43ea0b0d7692df2cd60ddf29e8"
    },
    "Bnclient_MNE_71996afe3d91": {
      "addresses": {
        "LoD/1.11": "0x6FF3713E",
        "LoD/1.11b": "0x6FF3710E",
        "LoD/1.12a": "0x6FF37FBE",
        "LoD/1.13c": "0x6FF37F9E",
        "LoD/1.13d": "0x6FF37EDE"
      },
      "rvas": {
        "LoD/1.11": "0x1713E",
        "LoD/1.11b": "0x1710E",
        "LoD/1.12a": "0x17FBE",
        "LoD/1.13c": "0x17F9E",
        "LoD/1.13d": "0x17EDE"
      },
      "name": "FindHandler",
      "signature": "void FindHandler(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4, _s_FuncInfo * param_5, uchar param_6, int param_7, EHRegistrationNode * param_8)",
      "comment": "Library Function - Single Match\n void __cdecl FindHandler(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,unsigned char,int,struct EHRegistrationNode *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:71996afe3d91ebc0635560132615f7bc"
    },
    "Bnclient_MNE_71e3adec8688": {
      "addresses": {
        "LoD/1.11": "0x6FF2692D",
        "LoD/1.11b": "0x6FF25E5E",
        "LoD/1.12a": "0x6FF252C6",
        "LoD/1.13c": "0x6FF24F11",
        "LoD/1.13d": "0x6FF26987"
      },
      "rvas": {
        "LoD/1.11": "0x692D",
        "LoD/1.11b": "0x5E5E",
        "LoD/1.12a": "0x52C6",
        "LoD/1.13c": "0x4F11",
        "LoD/1.13d": "0x6987"
      },
      "name": "___sbh_resize_block",
      "signature": "undefined4 ___sbh_resize_block(uint * param_1, int param_2, int param_3)",
      "comment": "Library Function - Single Match\n ___sbh_resize_block\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:71e3adec86883da683f0e423eb14e485"
    },
    "Bnclient_MNE_7407cb05915d": {
      "addresses": {
        "LoD/1.12a": "0x6FF284F0",
        "LoD/1.13c": "0x6FF284D0",
        "LoD/1.13d": "0x6FF284D0"
      },
      "rvas": {
        "LoD/1.12a": "0x84F0",
        "LoD/1.13c": "0x84D0",
        "LoD/1.13d": "0x84D0"
      },
      "method": "MNE",
      "index": "MNE:7407cb05915d2fbf01236cdef927209a"
    },
    "Bnclient_MNE_74094e5d65d6": {
      "addresses": {
        "LoD/1.07": "0x6FF2AE30",
        "LoD/1.08": "0x6FF2AE50",
        "LoD/1.09": "0x6FF0BA50",
        "LoD/1.09b": "0x6FF0BA50",
        "LoD/1.09d": "0x6FF0BCA0"
      },
      "rvas": {
        "LoD/1.07": "0xAE30",
        "LoD/1.08": "0xAE50",
        "LoD/1.09": "0xBA50",
        "LoD/1.09b": "0xBA50",
        "LoD/1.09d": "0xBCA0"
      },
      "name": "ProcessSha1Block",
      "signature": "void ProcessSha1Block(Sha1Context * pContext)",
      "comment": "Process single 512-bit block through SHA-1 compression function\n\nAlgorithm:\n1. Copy 16 words (64 bytes) from input context to message schedule array\n2. Expand message schedule to 80 words using XOR feedback (W[i] = W[i-3] XOR W[i-8] XOR W[i-14] XOR W[i-16])\n3. Initialize working variables A,B,C,D,E from current hash state H0-H4\n4. Execute 80 rounds in 4 groups of 20:\n   - Rounds 0-19: F(B,C,D) = (B AND C) OR ((NOT B) AND D), K = 0x5A827999\n   - Rounds 20-39: F(B,C,D) = B XOR C XOR D, K = 0x6ED9EBA1\n   - Rounds 40-59: F(B,C,D) = (B AND C) OR (B AND D) OR (C AND D), K = 0x8F1BBCDC\n   - Rounds 60-79: F(B,C,D) = B XOR C XOR D, K = 0xCA62C1D6\n5. For each round: temp = ROTLEFT(A,5) + F(B,C,D) + E + K + W[i], then rotate registers\n6. Add working variables back to hash state: H0 += A, H1 += B, H2 += C, H3 += D, H4 += E\n\nParameters:\npSha1Context - Pointer to SHA-1 context structure containing:\n  - Hash state H0-H4 (5 uint values at offsets 0-16)\n  - Message block (16 uint values at offset 28, total 64 bytes)\n  IMPLICIT: Function accesses message block starting at offset +28 (pContext + 7)\n\nReturns:\nvoid - Updates hash state H0-H4 in-place within context structure\n\nSpecial Cases:\nMessage schedule expansion uses circular XOR of previous words per SHA-1 specification\nEach round group uses different Boolean function and round constant\nLeft rotation by 5 for A register, right rotation by 2 for working register shifts\n\nMagic Numbers Reference:\n0x5A827999 - SHA-1 round constant K1 for rounds 0-19\n0x6ED9EBA1 - SHA-1 round constant K2 for rounds 20-39  \n0x8F1BBCDC - SHA-1 round constant K3 for rounds 40-59 (0x8F1BBCDC = -0x70E44324)\n0xCA62C1D6 - SHA-1 round constant K4 for rounds 60-79 (0xCA62C1D6 = -0x359D3E2A)\n0x10 - Message block size in 32-bit words (16 words = 64 bytes)\n0x40 - Expansion rounds to generate W[16] through W[79] (64 additional words)\n0x14 - Rounds per group (20 rounds each in 4 groups = 80 total)\n\nStructure Layout:\nSha1Context (92 bytes total):\nOffset  Size  Field Name        Type    Description\n0x00    4     h0               uint    Hash state H0\n0x04    4     h1               uint    Hash state H1  \n0x08    4     h2               uint    Hash state H2\n0x0C    4     h3               uint    Hash state H3\n0x10    4     h4               uint    Hash state H4\n0x14    64    messageBlock     uint[16] Current 512-bit message block\n0x54    4     messageBlockIndex uint   Index into message block\n0x58    8     length           ulong   Total message length in bits",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:74094e5d65d69c526300770e62b7ffd8"
    },
    "Bnclient_MNE_750c71b47c1a": {
      "addresses": {
        "LoD/1.07": "0x6FF3104F",
        "LoD/1.08": "0x6FF3106F",
        "LoD/1.09": "0x6FF11C8F",
        "LoD/1.09b": "0x6FF11C8F",
        "LoD/1.09d": "0x6FF11F7F",
        "LoD/1.10": "0x6FF124CF",
        "LoD/1.11": "0x6FF37526",
        "LoD/1.11b": "0x6FF374F6",
        "LoD/1.12a": "0x6FF383A6",
        "LoD/1.13c": "0x6FF38386",
        "LoD/1.13d": "0x6FF382C6"
      },
      "rvas": {
        "LoD/1.07": "0x1104F",
        "LoD/1.08": "0x1106F",
        "LoD/1.09": "0x11C8F",
        "LoD/1.09b": "0x11C8F",
        "LoD/1.09d": "0x11F7F",
        "LoD/1.10": "0x124CF",
        "LoD/1.11": "0x17526",
        "LoD/1.11b": "0x174F6",
        "LoD/1.12a": "0x183A6",
        "LoD/1.13c": "0x18386",
        "LoD/1.13d": "0x182C6"
      },
      "name": "InitializeCharacterTypeTableOnce",
      "signature": "void InitializeCharacterTypeTableOnce(void)",
      "comment": "Initializes the character type table exactly once using singleton pattern.\n\nAlgorithm:\n1. Check global initialization flag (g_dwInitializationFlag) to determine if already initialized\n2. If flag is 0 (not initialized), call InitializeCharacterTypeTable with parameter 0xfffffffd (-3)\n3. Set global initialization flag to 1 to prevent re-initialization\n4. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Safe to call multiple times due to initialization flag guard\n- Uses magic number 0xfffffffd (-3) as parameter to InitializeCharacterTypeTable\n- Global flag ensures thread-safe single initialization\n\nMagic Numbers Reference:\n0xfffffffd (decimal -3) - Parameter passed to InitializeCharacterTypeTable initialization\n0x1 - Initialization complete flag value\n0x0 - Uninitialized state flag value",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:750c71b47c1aaa7e04385ca0c70f7831"
    },
    "Bnclient_MNE_772d22c2541e": {
      "addresses": {
        "LoD/1.11": "0x6FF366D7",
        "LoD/1.11b": "0x6FF366A8",
        "LoD/1.12a": "0x6FF37557",
        "LoD/1.13c": "0x6FF3753D",
        "LoD/1.13d": "0x6FF37476"
      },
      "rvas": {
        "LoD/1.11": "0x166D7",
        "LoD/1.11b": "0x166A8",
        "LoD/1.12a": "0x17557",
        "LoD/1.13c": "0x1753D",
        "LoD/1.13d": "0x17476"
      },
      "name": "FID_conflict:_CallMemberFunction1",
      "signature": "undefined FID_conflict:_CallMemberFunction1(undefined4 param_1, undefined * UNRECOVERED_JUMPTABLE)",
      "comment": "Library Function - Multiple Matches With Different Base Names\n void __stdcall _CallMemberFunction1(void *,void *,void *)\n void __stdcall _CallMemberFunction2(void *,void *,void *,int)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:772d22c2541e825eefebea33eefd1baf",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF022B0",
          "rva": "0x22B0",
          "confidence": 0.405,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF067D0",
          "rva": "0x67D0",
          "confidence": 0.215,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_777097edea10": {
      "addresses": {
        "LoD/1.07": "0x6FF2A9A0",
        "LoD/1.08": "0x6FF2A9C0",
        "LoD/1.09": "0x6FF0B5C0",
        "LoD/1.09b": "0x6FF0B5C0",
        "LoD/1.09d": "0x6FF0B810",
        "LoD/1.10": "0x6FF0BE90"
      },
      "rvas": {
        "LoD/1.07": "0xA9A0",
        "LoD/1.08": "0xA9C0",
        "LoD/1.09": "0xB5C0",
        "LoD/1.09b": "0xB5C0",
        "LoD/1.09d": "0xB810",
        "LoD/1.10": "0xBE90"
      },
      "name": "ScrambleCryptoState",
      "signature": "void ScrambleCryptoState(int nSlotIndex, int nDirectStore, CryptoState * pCryptoState)",
      "comment": "Perform cryptographic state scrambling using bit rotation and array manipulation.\n\nAlgorithm:\n\n1. Extract 4-element crypto state from input structure (state0, state1, state2, state3)\n2. Check bDirectStore flag to determine operation mode\n3. If direct store (bDirectStore != 0):\n   a. Calculate global buffer offset: nSlotIndex * 0x68 + 0x208\n   b. Copy 4 crypto state values to global buffer at calculated offset\n   c. Perform 44 iterations of bit rotation scramble on global buffer data\n   d. Each iteration: rotate bits using (next >> 7) | (current << 9) pattern\n   e. Advance buffer pointer by conditional offset (& 8) * 2 every 8th iteration\n4. If local processing (bDirectStore == 0):\n   a. Copy crypto state to local stack buffer starting with state0\n   b. Perform identical 44 iterations of bit rotation on local buffer\n   c. Call ProcessModularInverseArray with local buffer and global buffer as parameters\n5. Return without value\n\nParameters:\n\n- nSlotIndex (ECX): int - Slot index for calculating global buffer offset\n- bDirectStore (EDX): int - Flag determining operation mode (0=local processing, non-zero=direct store)  \n- pCryptoState (Stack+4): CryptoState * - Pointer to 4-element crypto state structure\n\nReturns:\n\n- void - No return value\n\nSpecial Cases:\n\n- Magic number 0x68 (104): Slot stride size in global buffer\n- Magic number 0x208 (520): Base offset in global buffer for crypto slots\n- Magic number 0x2c (44): Number of scrambling iterations\n- Magic number 0xe (14): Offset for result storage in rotation algorithm\n\nStructure Layout:\n\nCryptoState (16 bytes):\nOffset  Size  Field     Type  Description\n0x0     4     dwState0  uint  First crypto state value\n0x4     4     dwState1  uint  Second crypto state value  \n0x8     4     dwState2  uint  Third crypto state value\n0xc     4     dwState3  uint  Fourth crypto state value\n\nBit Rotation Algorithm:\n\nThe scrambling uses a 16-bit rotation pattern over 8-element windows:\n- Index masking: (index + 1) & 7, (index + 2) & 7 create 8-element circular buffer\n- Bit operations: source >> 7 extracts high 9 bits, target << 9 shifts low 7 bits\n- Result combination: (source >> 7) | (target << 9) creates rotated 16-bit value\n- Buffer advancement: pointer += ((index & 8) * 2) advances every 8 iterations",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:777097edea10233e57beefd29b0bf318",
      "candidates": {
        "LoD/1.12a": {
          "address": "0x6FF28650",
          "rva": "0x8650",
          "confidence": 0.279,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF28630",
          "rva": "0x8630",
          "confidence": 0.279,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_781017f4d855": {
      "addresses": {
        "LoD/1.07": "0x6FF32076",
        "LoD/1.08": "0x6FF32096",
        "LoD/1.09": "0x6FF12C8B",
        "LoD/1.09b": "0x6FF12C8B",
        "LoD/1.09d": "0x6FF12FA6",
        "LoD/1.10": "0x6FF1352A"
      },
      "rvas": {
        "LoD/1.07": "0x12076",
        "LoD/1.08": "0x12096",
        "LoD/1.09": "0x12C8B",
        "LoD/1.09b": "0x12C8B",
        "LoD/1.09d": "0x12FA6",
        "LoD/1.10": "0x1352A"
      },
      "name": "FindCharacterInMultiByteString",
      "signature": "byte * FindCharacterInMultiByteString(byte * pbString, uint dwCharacter)",
      "comment": "Searches for the first occurrence of a character in a string, supporting multibyte character encodings.\n\nAlgorithm:\n1. Check global flag g_fIsMultiByteCodePage to determine if multibyte encoding is active\n2. If single-byte mode (flag == 0), delegate to FindCharacterInString for optimized single-byte search\n3. If multibyte mode, acquire critical section lock (index 0x19) for thread-safe character table access\n4. Enter main scanning loop iterating through each character in the string\n5. Load current character byte and convert to unsigned integer for table lookup\n6. Check if character is null terminator (0) - if so, exit loop\n7. Test character type using g_abCharacterTypeTable[character + 1] & 0x4 to determine if multibyte lead byte\n8. For single-byte characters (type & 4 == 0), compare directly with target character\n9. For multibyte lead bytes (type & 4 != 0), read next byte to form complete character\n10. Validate multibyte sequence - return NULL if second byte is null (incomplete sequence)\n11. Combine bytes using CONCAT11 to form 16-bit character value for comparison\n12. If multibyte character matches target, release lock and return pointer to character start\n13. Advance pointer by appropriate increment (1 for single-byte, 2 for multibyte)\n14. Continue loop until null terminator or character found\n15. Release critical section lock before returning\n16. Return pointer to found character, or calculated result based on final comparison\n\nParameters:\nlpszString (byte *): Pointer to null-terminated string to search within\ndwCharacter (uint): Target character value to search for (single-byte or multibyte)\n\nReturns:\nbyte *: Pointer to first occurrence of character in string, or NULL if not found\n        For multibyte mode, uses bitwise calculation to return either found position or NULL\n\nSpecial Cases:\n- If g_fIsMultiByteCodePage is false, bypasses multibyte logic for performance\n- Incomplete multibyte sequences (lead byte followed by null) return NULL\n- Thread synchronization required in multibyte mode due to shared character table access\n- Character table lookup uses offset +1 from base address for type classification\n\nMagic Numbers Reference:\n0x19 (25): Critical section index for character table synchronization\n0x4: Bit mask for multibyte lead byte detection in character type table\n0x6ff3a2e1: Base address of g_abCharacterTypeTable for character classification\n\nError Handling:\n- Incomplete multibyte sequence detection returns NULL immediately\n- Thread synchronization prevents race conditions on character table access\n- Null terminator detection prevents buffer overrun during string scanning",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:781017f4d855409582a95afe4ce13001"
    },
    "Bnclient_MNE_782644546d78": {
      "addresses": {
        "LoD/1.11": "0x6FF30F40",
        "LoD/1.11b": "0x6FF315B0",
        "LoD/1.12a": "0x6FF30030",
        "LoD/1.13c": "0x6FF331F0",
        "LoD/1.13d": "0x6FF2F1B0"
      },
      "rvas": {
        "LoD/1.11": "0x10F40",
        "LoD/1.11b": "0x115B0",
        "LoD/1.12a": "0x10030",
        "LoD/1.13c": "0x131F0",
        "LoD/1.13d": "0xF1B0"
      },
      "method": "MNE",
      "index": "MNE:782644546d78608ea0d8825ece49d778"
    },
    "Bnclient_MNE_78a86de15981": {
      "addresses": {
        "LoD/1.11": "0x6FF2748E",
        "LoD/1.11b": "0x6FF27BED",
        "LoD/1.12a": "0x6FF2785D",
        "LoD/1.13c": "0x6FF27C5F",
        "LoD/1.13d": "0x6FF2790A"
      },
      "rvas": {
        "LoD/1.11": "0x748E",
        "LoD/1.11b": "0x7BED",
        "LoD/1.12a": "0x785D",
        "LoD/1.13c": "0x7C5F",
        "LoD/1.13d": "0x790A"
      },
      "name": "_atol",
      "signature": "long _atol(char * _Str)",
      "comment": "Library Function - Single Match\n _atol\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:78a86de15981e3f1c945cde9fbd4be9b"
    },
    "Bnclient_MNE_78c0be793b20": {
      "addresses": {
        "LoD/1.07": "0x6FF2DF05",
        "LoD/1.08": "0x6FF2DF25",
        "LoD/1.09": "0x6FF0EB50",
        "LoD/1.09b": "0x6FF0EB50",
        "LoD/1.09d": "0x6FF0EE35",
        "LoD/1.10": "0x6FF0F423"
      },
      "rvas": {
        "LoD/1.07": "0xDF05",
        "LoD/1.08": "0xDF25",
        "LoD/1.09": "0xEB50",
        "LoD/1.09b": "0xEB50",
        "LoD/1.09d": "0xEE35",
        "LoD/1.10": "0xF423"
      },
      "name": "InitializeCommandLineParser",
      "signature": "void InitializeCommandLineParser(void)",
      "comment": "Initializes command-line parser by allocating memory for argument storage and setting up global variables.\n\nAlgorithm:\n1. Check if global module is initialized, call initialization function if needed\n2. Get current module filename and store in global buffer DAT_6ff39f48 (size 0x104 = 260 bytes)\n3. Set _DAT_6ff39e74 to point to module filename buffer\n4. Use command line string if non-empty, otherwise use module filename as input\n5. First call to FUN_6ff2df9e to determine required buffer sizes (nArgCount and nBufferSize)\n6. Allocate memory: nBufferSize + nArgCount * 4 bytes for argument array and string storage\n7. Exit with code 8 if malloc fails (out of memory)\n8. Second call to FUN_6ff2df9e to parse arguments into allocated buffers\n9. Store argument array pointer in _DAT_6ff39e5c\n10. Store argument count minus 1 in _DAT_6ff39e58 (excludes program name)\n\nParameters:\nNone (void function)\n\nReturns:\nNone (void function)\n\nSpecial Cases:\n- If DAT_6ff3b560 is 0, calls FUN_6ff3104f for module initialization\n- Uses g_lpszCommandLine if non-empty, otherwise falls back to module filename\n- AmsgExit(8) terminates process if memory allocation fails\n- Argument count stored is decremented by 1 (excludes program name)\n\nMagic Numbers Reference:\n0x104 (260) - Maximum path length for GetModuleFileNameA buffer\n0x8 - Exit code for out of memory condition\n0x4 - Size of pointer/uint32 for argument array allocation\n\nError Handling:\n- Memory allocation failure: AmsgExit(8) terminates process\n- No graceful fallback for allocation failure\n- Module initialization handled by conditional call to FUN_6ff3104f\n\nGlobal Variables Modified:\n- DAT_6ff39f48: Module filename buffer (260 bytes)\n- _DAT_6ff39e74: Pointer to module filename string\n- _DAT_6ff39e5c: Pointer to parsed argument array\n- _DAT_6ff39e58: Argument count (excluding program name)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:78c0be793b204c577b78460711bf70fb"
    },
    "Bnclient_MNE_78e7a0d23c2f": {
      "addresses": {
        "LoD/1.11": "0x6FF32920",
        "LoD/1.11b": "0x6FF2F560",
        "LoD/1.12a": "0x6FF34F90",
        "LoD/1.13c": "0x6FF30AE0",
        "LoD/1.13d": "0x6FF2C430"
      },
      "rvas": {
        "LoD/1.11": "0x12920",
        "LoD/1.11b": "0xF560",
        "LoD/1.12a": "0x14F90",
        "LoD/1.13c": "0x10AE0",
        "LoD/1.13d": "0xC430"
      },
      "method": "MNE",
      "index": "MNE:78e7a0d23c2fd695b4588fa4a74be3ae"
    },
    "Bnclient_MNE_79c576ae79b5": {
      "addresses": {
        "LoD/1.11": "0x6FF23671",
        "LoD/1.11b": "0x6FF23DA1",
        "LoD/1.12a": "0x6FF23D30",
        "LoD/1.13c": "0x6FF23E37",
        "LoD/1.13d": "0x6FF23A5E"
      },
      "rvas": {
        "LoD/1.11": "0x3671",
        "LoD/1.11b": "0x3DA1",
        "LoD/1.12a": "0x3D30",
        "LoD/1.13c": "0x3E37",
        "LoD/1.13d": "0x3A5E"
      },
      "name": "__XcptFilter",
      "signature": "int __XcptFilter(ulong _ExceptionNum, _EXCEPTION_POINTERS * _ExceptionPtr)",
      "comment": "Library Function - Single Match\n __XcptFilter\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:79c576ae79b525f94550b7e17b8f3e0b"
    },
    "Bnclient_MNE_79ede85cba5d": {
      "addresses": {
        "LoD/1.11": "0x6FF21110",
        "LoD/1.11b": "0x6FF210C0",
        "LoD/1.12a": "0x6FF21170",
        "LoD/1.13c": "0x6FF21110",
        "LoD/1.13d": "0x6FF21110"
      },
      "rvas": {
        "LoD/1.11": "0x1110",
        "LoD/1.11b": "0x10C0",
        "LoD/1.12a": "0x1170",
        "LoD/1.13c": "0x1110",
        "LoD/1.13d": "0x1110"
      },
      "method": "MNE",
      "index": "MNE:79ede85cba5d7d7af965bdcccf3b3cab"
    },
    "Bnclient_MNE_7a09c5a73235": {
      "addresses": {
        "LoD/1.11": "0x6FF2199F",
        "LoD/1.11b": "0x6FF214AE",
        "LoD/1.12a": "0x6FF21454",
        "LoD/1.13c": "0x6FF2129A",
        "LoD/1.13d": "0x6FF2177E"
      },
      "rvas": {
        "LoD/1.11": "0x199F",
        "LoD/1.11b": "0x14AE",
        "LoD/1.12a": "0x1454",
        "LoD/1.13c": "0x129A",
        "LoD/1.13d": "0x177E"
      },
      "name": "__onexit_lk",
      "signature": "undefined __onexit_lk(void)",
      "comment": "Library Function - Single Match\n __onexit_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:7a09c5a73235698eb35bf1fa40abce3a"
    },
    "Bnclient_MNE_7a5e6ed384be": {
      "addresses": {
        "LoD/1.07": "0x6FF2B2BE",
        "LoD/1.08": "0x6FF2B203",
        "LoD/1.09": "0x6FF0BE03",
        "LoD/1.09b": "0x6FF0BE03",
        "LoD/1.09d": "0x6FF0C13E",
        "LoD/1.10": "0x6FF0C69E",
        "LoD/1.11": "0x6FF21D26",
        "LoD/1.11b": "0x6FF2149F",
        "LoD/1.12a": "0x6FF21445",
        "LoD/1.13c": "0x6FF2158B",
        "LoD/1.13d": "0x6FF21707"
      },
      "rvas": {
        "LoD/1.07": "0xB2BE",
        "LoD/1.08": "0xB203",
        "LoD/1.09": "0xBE03",
        "LoD/1.09b": "0xBE03",
        "LoD/1.09d": "0xC13E",
        "LoD/1.10": "0xC69E",
        "LoD/1.11": "0x1D26",
        "LoD/1.11b": "0x149F",
        "LoD/1.12a": "0x1445",
        "LoD/1.13c": "0x158B",
        "LoD/1.13d": "0x1707"
      },
      "name": "InitiateDllCleanup",
      "signature": "void InitiateDllCleanup(void)",
      "comment": "Initiate DLL cleanup process during DLL termination or unloading.\n\nAlgorithm:\n1. Call main cleanup routine with specific parameters for DLL termination\n2. Pass error code 0 (no error condition)\n3. Pass secondary parameter 0 (default mode) \n4. Pass termination flag 1 (indicates DLL unload/cleanup mode)\n5. Return control to caller after cleanup completion\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nvoid - function performs cleanup and returns without value\n\nSpecial Cases:\nCalled exclusively by DllMain during DLL_PROCESS_DETACH handling\nTermination flag (1) triggers specific cleanup sequence in called function\n\nMagic Numbers Reference:\n0x0 - Error code parameter (no error)\n0x0 - Secondary parameter (default mode)\n0x1 - Termination flag (DLL cleanup mode)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:7a5e6ed384be31095abb7960c9f1d6d0"
    },
    "Bnclient_MNE_7b30fadc3428": {
      "addresses": {
        "LoD/1.07": "0x6FF257B0",
        "LoD/1.08": "0x6FF257D0",
        "LoD/1.09": "0x6FF06130",
        "LoD/1.09b": "0x6FF06130",
        "LoD/1.09d": "0x6FF063A0",
        "LoD/1.10": "0x6FF06300"
      },
      "rvas": {
        "LoD/1.07": "0x57B0",
        "LoD/1.08": "0x57D0",
        "LoD/1.09": "0x6130",
        "LoD/1.09b": "0x6130",
        "LoD/1.09d": "0x63A0",
        "LoD/1.10": "0x6300"
      },
      "name": "DeleteCriticalSectionCleanup",
      "signature": "UINT DeleteCriticalSectionCleanup(void)",
      "comment": "Cleanup function to delete critical section used for global string buffer synchronization.\n\nAlgorithm:\n1. Locate critical section at offset 0x130 within global string buffer\n2. Call DeleteCriticalSection to cleanup critical section resources\n3. Return success status (1)\n\nParameters:\n   None\n\nReturns:\n   UINT - Always returns 1 (success)\n\nSpecial Cases:\n   - Function always succeeds as DeleteCriticalSection handles invalid sections gracefully\n   - Offset 0x130 (decimal 304) represents hardcoded location of critical section within global buffer\n\nMagic Numbers Reference:\n   0x130 (304) - Byte offset to CRITICAL_SECTION structure within g_abGlobalStringBuffer\n   0x1 - Success return code indicating cleanup completed",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:7b30fadc3428bef6c542f8dd637ca891"
    },
    "Bnclient_MNE_7b4de9f0cf35": {
      "addresses": {
        "LoD/1.07": "0x6FF2A150",
        "LoD/1.08": "0x6FF2A170",
        "LoD/1.09": "0x6FF0AD70",
        "LoD/1.09b": "0x6FF0AD70",
        "LoD/1.09d": "0x6FF0AFC0",
        "LoD/1.10": "0x6FF0B800",
        "LoD/1.11": "0x6FF343D0",
        "LoD/1.11b": "0x6FF31100",
        "LoD/1.12a": "0x6FF2F730",
        "LoD/1.13c": "0x6FF37390",
        "LoD/1.13d": "0x6FF34BF0"
      },
      "rvas": {
        "LoD/1.07": "0xA150",
        "LoD/1.08": "0xA170",
        "LoD/1.09": "0xAD70",
        "LoD/1.09b": "0xAD70",
        "LoD/1.09d": "0xAFC0",
        "LoD/1.10": "0xB800",
        "LoD/1.11": "0x143D0",
        "LoD/1.11b": "0x11100",
        "LoD/1.12a": "0xF730",
        "LoD/1.13c": "0x17390",
        "LoD/1.13d": "0x14BF0"
      },
      "name": "GetNetworkErrorState",
      "signature": "uint GetNetworkErrorState(void)",
      "comment": "Retrieves the current network error state for connection status checking.\n\nAlgorithm:\n1. Return the global network error state variable\n\nParameters:\n  (none)\n\nReturns:\n  uint: Current network error state code\n    - 0 indicates normal operation\n    - Non-zero values indicate specific network error conditions\n\nSpecial Cases:\n  This is a simple accessor function with no error conditions.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b"
    },
    "Bnclient_MNE_7b88759a3824": {
      "addresses": {
        "LoD/1.11": "0x6FF21070",
        "LoD/1.11b": "0x6FF21020",
        "LoD/1.12a": "0x6FF210D0",
        "LoD/1.13c": "0x6FF21070",
        "LoD/1.13d": "0x6FF21070"
      },
      "rvas": {
        "LoD/1.11": "0x1070",
        "LoD/1.11b": "0x1020",
        "LoD/1.12a": "0x10D0",
        "LoD/1.13c": "0x1070",
        "LoD/1.13d": "0x1070"
      },
      "method": "MNE",
      "index": "MNE:7b88759a38243c9e14c36d192e204e40"
    },
    "Bnclient_MNE_7d35ed9a7294": {
      "addresses": {
        "LoD/1.07": "0x6FF2BFE4",
        "LoD/1.08": "0x6FF2C004",
        "LoD/1.09": "0x6FF0CC04",
        "LoD/1.09b": "0x6FF0CC04",
        "LoD/1.09d": "0x6FF0CF14",
        "LoD/1.10": "0x6FF0D47A"
      },
      "rvas": {
        "LoD/1.07": "0xBFE4",
        "LoD/1.08": "0xC004",
        "LoD/1.09": "0xCC04",
        "LoD/1.09b": "0xCC04",
        "LoD/1.09d": "0xCF14",
        "LoD/1.10": "0xD47A"
      },
      "name": "SnprintfWithOverflowHandling",
      "signature": "int SnprintfWithOverflowHandling(byte * pbBuffer, int nBufferSize, byte * pFormat, byte * * ppArgs)",
      "comment": "Safe sprintf implementation with buffer overflow protection and cleanup.\n\nAlgorithm:\n\n1. Initialize local copies of buffer pointer and size for manipulation\n2. Set magic number 0x42 for format parser state initialization\n3. Call printf-style formatter (FUN_6ff2d14c) with buffer, format string, and args\n4. Decrement remaining buffer size by 1 to account for null terminator space\n5. Check for buffer overflow condition (remaining size negative)\n6. If overflow detected, call cleanup function (FUN_6ff2d034) with zero flag\n7. If no overflow, manually null-terminate the buffer at current position\n8. Return formatting result from step 3\n\nParameters:\n\npbBuffer - Destination buffer for formatted output string\nnBufferSize - Total size of destination buffer in bytes\npFormat - Printf-style format string specifying output format\nppArgs - Pointer to variadic argument list for format specifiers\n\nReturns:\n\nNumber of characters written on success\nNegative value on formatting error\nBuffer overflow is handled internally without error return\n\nSpecial Cases:\n\nIf buffer size is too small for formatted output, function prevents overflow\nCleanup function is called on overflow to maintain buffer integrity\nMagic number 0x42 initializes internal parser state machine\n\nMagic Numbers Reference:\n\n0x42 (66) - Format parser initialization magic number",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:7d35ed9a72948cae0b0cf3a10f47ee1e"
    },
    "Bnclient_MNE_7d91b67eb56d": {
      "addresses": {
        "LoD/1.07": "0x6FF268B0",
        "LoD/1.08": "0x6FF268D0",
        "LoD/1.09": "0x6FF06E40",
        "LoD/1.09b": "0x6FF06E40",
        "LoD/1.09d": "0x6FF070B0",
        "LoD/1.10": "0x6FF077A0"
      },
      "rvas": {
        "LoD/1.07": "0x68B0",
        "LoD/1.08": "0x68D0",
        "LoD/1.09": "0x6E40",
        "LoD/1.09b": "0x6E40",
        "LoD/1.09d": "0x70B0",
        "LoD/1.10": "0x77A0"
      },
      "name": "TestNetworkPacketValidation",
      "signature": "bool TestNetworkPacketValidation(void)",
      "comment": "Tests network packet validation with default test parameters.\n\nAlgorithm:\n1. Call SendNetworkPacketWithValidation() with test parameters (0, 0, 0x10)\n2. Convert the returned status code to boolean result\n3. Return true if validation succeeded, false otherwise\n\nParameters:\nNone - uses hardcoded test parameters internally\n\nReturns:\nbool - true if packet validation test succeeded, false if it failed\n\nMagic Numbers Reference:\n0x0 - First test parameter (likely packet type or flags)\n0x0 - Second test parameter (likely destination or mode) \n0x10 - Third test parameter (packet size or validation flags, decimal 16)\n\nIMPLICIT:\nParameters are passed via registers/stack in calling convention:\n- First parameter (0x0) pushed to stack\n- Second parameter (0x0) passed in EDX register  \n- Third parameter (0x10) passed in CL register",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:7d91b67eb56d4761fb600e8141663f70"
    },
    "Bnclient_MNE_7fa238a0d1fe": {
      "addresses": {
        "LoD/1.11": "0x6FF23C21",
        "LoD/1.11b": "0x6FF23426",
        "LoD/1.12a": "0x6FF2278B",
        "LoD/1.13c": "0x6FF22427",
        "LoD/1.13d": "0x6FF237D5"
      },
      "rvas": {
        "LoD/1.11": "0x3C21",
        "LoD/1.11b": "0x3426",
        "LoD/1.12a": "0x278B",
        "LoD/1.13c": "0x2427",
        "LoD/1.13d": "0x37D5"
      },
      "name": "__msize",
      "signature": "size_t __msize(void * _Memory)",
      "comment": "Library Function - Single Match\n __msize\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:7fa238a0d1fe5549fc522252a2120d78"
    },
    "Bnclient_MNE_809728fdc7be": {
      "addresses": {
        "LoD/1.09": "0x6FF01E50",
        "LoD/1.09b": "0x6FF01E50",
        "LoD/1.09d": "0x6FF01E20",
        "LoD/1.10": "0x6FF01DE0"
      },
      "rvas": {
        "LoD/1.09": "0x1E50",
        "LoD/1.09b": "0x1E50",
        "LoD/1.09d": "0x1E20",
        "LoD/1.10": "0x1DE0"
      },
      "method": "MNE",
      "index": "MNE:809728fdc7be693a48aa1d7ed372e3ab"
    },
    "Bnclient_MNE_80dd4b2cd741": {
      "addresses": {
        "LoD/1.07": "0x6FF2AA80",
        "LoD/1.08": "0x6FF2AAA0",
        "LoD/1.09": "0x6FF0B6A0",
        "LoD/1.09b": "0x6FF0B6A0",
        "LoD/1.09d": "0x6FF0B8F0"
      },
      "rvas": {
        "LoD/1.07": "0xAA80",
        "LoD/1.08": "0xAAA0",
        "LoD/1.09": "0xB6A0",
        "LoD/1.09b": "0xB6A0",
        "LoD/1.09d": "0xB8F0"
      },
      "name": "Sha1ProcessMessageBlock",
      "signature": "void Sha1ProcessMessageBlock(uint * pSha1Context)",
      "comment": "Process a single 512-bit message block through the SHA-1 compression function.\n\nAlgorithm:\n1. Copy 16 input words (64 bytes) from message block to expanded message buffer\n2. Expand message schedule by generating 64 additional words using XOR rotation pattern\n3. Initialize working variables A,B,C,D,E from input hash state (5 words)\n4. Execute 80 rounds of SHA-1 compression in 4 phases of 20 rounds each:\n   - Phase 0 (rounds 0-19): f(B,C,D) = (B AND C) OR ((NOT B) AND D), K=0x5A827999\n   - Phase 1 (rounds 20-39): f(B,C,D) = B XOR C XOR D, K=0x6ED9EBA1  \n   - Phase 2 (rounds 40-59): f(B,C,D) = (B AND C) OR (B AND D) OR (C AND D), K=0x8F1BBCDC\n   - Phase 3 (rounds 60-79): f(B,C,D) = B XOR C XOR D, K=0xCA62C1D6\n5. Each round: A = ROTL(A,5) + f(B,C,D) + E + W[i] + K; C = ROTL(B,30); rotate states\n6. Add final working variables back to original hash state\n\nParameters:\npSha1Context - Pointer to SHA-1 context buffer containing hash state and message block\n               [0-4]: Current hash state (H0,H1,H2,H3,H4)  \n               [5-20]: 512-bit message block (16 words)\n\nReturns:\nvoid - Hash state is updated in place in the context buffer\n\nMagic Numbers Reference:\n0x5A827999 - Phase 0 round constant (decimal: 1518500249)\n0x6ED9EBA1 - Phase 1 round constant (decimal: 1859775393)  \n0x8F1BBCDC - Phase 2 round constant (decimal: -1894007588)\n0xCA62C1D6 - Phase 3 round constant (decimal: -899497514)\n0x10 - Copy 16 words from input message block\n0x40 - Generate 64 additional words for message schedule expansion  \n0x14 - Process 20 rounds per phase (4 phases total = 80 rounds)\n0x1F - Mask for rotation shift amount (5-bit rotation)\n0x1B - Left shift by 27 (equivalent to right shift by 5 for 32-bit rotation)\n0x1E - Left shift by 30 for B register rotation\n\nError Handling:\nNo error checking - assumes valid input pointer and properly initialized context\n\nSpecial Cases:\nMessage schedule expansion uses circular XOR pattern: W[i] = ROTL(W[i-3] XOR W[i-8] XOR W[i-14] XOR W[i-16], 1)\nState rotation pattern ensures each register cycles through A->E->D->C->B->A positions\nFinal addition prevents loss of entropy by preserving original state contribution",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:80dd4b2cd741156b20ce832b3e4ac99b"
    },
    "Bnclient_MNE_810249366bd3": {
      "addresses": {
        "LoD/1.11": "0x6FF361B0",
        "LoD/1.11b": "0x6FF30470",
        "LoD/1.13d": "0x6FF30490"
      },
      "rvas": {
        "LoD/1.11": "0x161B0",
        "LoD/1.11b": "0x10470",
        "LoD/1.13d": "0x10490"
      },
      "method": "MNE",
      "index": "MNE:810249366bd3750715061490bf846f85"
    },
    "Bnclient_MNE_81bc6e282733": {
      "addresses": {
        "LoD/1.11": "0x6FF26F08",
        "LoD/1.11b": "0x6FF256D2",
        "LoD/1.12a": "0x6FF24B3A",
        "LoD/1.13c": "0x6FF2591E",
        "LoD/1.13d": "0x6FF261FB"
      },
      "rvas": {
        "LoD/1.11": "0x6F08",
        "LoD/1.11b": "0x56D2",
        "LoD/1.12a": "0x4B3A",
        "LoD/1.13c": "0x591E",
        "LoD/1.13d": "0x61FB"
      },
      "name": "__ValidateEH3RN",
      "signature": "undefined4 __ValidateEH3RN(void * param_1)",
      "comment": "Library Function - Single Match\n __ValidateEH3RN\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:81bc6e2827332721bcd73a06db9fcb5a"
    },
    "Bnclient_MNE_81e9594266df": {
      "addresses": {
        "LoD/1.07": "0x6FF25B20",
        "LoD/1.08": "0x6FF25B40",
        "LoD/1.09": "0x6FF064A0",
        "LoD/1.09b": "0x6FF064A0",
        "LoD/1.09d": "0x6FF06710"
      },
      "rvas": {
        "LoD/1.07": "0x5B20",
        "LoD/1.08": "0x5B40",
        "LoD/1.09": "0x64A0",
        "LoD/1.09b": "0x64A0",
        "LoD/1.09d": "0x6710"
      },
      "name": "GetConnectionParams",
      "signature": "int GetConnectionParams(ConnectionParams * pConnectionParams)",
      "comment": "Retrieves connection parameters from global configuration data.\n\nAlgorithm:\n1. Enter critical section to synchronize access to global data\n2. Copy first configuration value to output structure offset 0x0\n3. Copy second configuration value to output structure offset 0x4  \n4. Leave critical section to release synchronization lock\n5. Return success indicator\n\nParameters:\n- pConnectionParams: Pointer to ConnectionParams structure to receive configuration values\n\nReturns:\n- 1: Always returns success (function cannot fail)\n\nStructure Layout:\nOffset | Size | Field Name | Type | Description\n-------|------|------------|------|------------\n0x0    | 4    | dwField1   | uint | First configuration parameter\n0x4    | 4    | dwField2   | uint | Second configuration parameter\n\nMagic Numbers Reference:\n- 0x130: Offset to critical section in global string buffer\n- 0x1: Success return value (TRUE constant)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:81e9594266dfad198975d764af195e8d"
    },
    "Bnclient_MNE_81fc8ecddc12": {
      "addresses": {
        "LoD/1.11": "0x6FF22721",
        "LoD/1.11b": "0x6FF2377E",
        "LoD/1.12a": "0x6FF22E45",
        "LoD/1.13c": "0x6FF236D1",
        "LoD/1.13d": "0x6FF22D51"
      },
      "rvas": {
        "LoD/1.11": "0x2721",
        "LoD/1.11b": "0x377E",
        "LoD/1.12a": "0x2E45",
        "LoD/1.13c": "0x36D1",
        "LoD/1.13d": "0x2D51"
      },
      "name": "___updatetlocinfo_lk",
      "signature": "int ___updatetlocinfo_lk(void)",
      "comment": "Library Function - Single Match\n ___updatetlocinfo_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:81fc8ecddc12cc08d3d848c0224bdeb0"
    },
    "Bnclient_MNE_8215c33c2c8d": {
      "addresses": {
        "LoD/1.07": "0x6FF285B0",
        "LoD/1.08": "0x6FF285D0",
        "LoD/1.09": "0x6FF091E0",
        "LoD/1.09b": "0x6FF091E0",
        "LoD/1.09d": "0x6FF09440",
        "LoD/1.10": "0x6FF09D40"
      },
      "rvas": {
        "LoD/1.07": "0x85B0",
        "LoD/1.08": "0x85D0",
        "LoD/1.09": "0x91E0",
        "LoD/1.09b": "0x91E0",
        "LoD/1.09d": "0x9440",
        "LoD/1.10": "0x9D40"
      },
      "name": "ComputeStringHashWithContext",
      "signature": "dword ComputeStringHashWithContext(char * lpszInputString, int nContextIndex)",
      "comment": "Computes a context-aware hash value for a null-terminated string using case-insensitive processing.\n\nAlgorithm:\n1. Initialize hash result to 0x7fed7fed and accumulator to 0xeeeeeeee (-0x11111112)\n2. Return early with initial hash if input string pointer is null\n3. Loop through each character until null terminator:\n   a. Read current character from string\n   b. Return current hash if null terminator encountered\n   c. Increment string pointer to next character\n   d. Convert character to uppercase using ConvertCharacterToUpperCase\n   e. Calculate table index: (nContextIndex * 256) + uppercase_character_value\n   f. Lookup hash component from global lookup table at calculated index\n   g. XOR lookup value with (accumulator + current_hash)\n   h. Update hash result with XOR result\n   i. Update accumulator: uppercase_char + (accumulator * 33) + 3 + hash_result\n4. Continue loop if string pointer is non-null\n5. Return final hash result\n\nParameters:\nlpszInputString - Pointer to null-terminated string to hash (case-insensitive processing)\nnContextIndex - Context identifier used as table offset multiplier (0-based index)\n\nReturns:\ndword - 32-bit hash value, or 0x7fed7fed if input string is null\n\nSpecial Cases:\nEmpty string (immediate null terminator): Returns 0x7fed7fed\nContext index determines which 256-entry slice of lookup table is used\nHash algorithm combines lookup table values with accumulating character sum\n\nMagic Numbers Reference:\n0x7fed7fed (2146844653) - Initial hash seed value\n0xeeeeeeee (-286331154) - Initial accumulator seed (negative for hash mixing)\n0x100 (256) - Context multiplier for table indexing\n0x21 (33) - Accumulator multiplication factor for hash mixing\n0x3 (3) - Accumulator addition constant\n\nError Handling:\nNull input string: Returns initial seed value 0x7fed7fed\nInvalid characters: Processed through ConvertCharacterToUpperCase for normalization\n\nStructure Layout:\nGlobal lookup table at g_abGlobalStringBuffer._432_4_ (0x6ff39ba0):\nContext-based hash lookup table with 256 dword entries per context\nTable index calculation: (context_index * 256 + character_value) * 4",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:8215c33c2c8d299750f1a6f76bca5d80"
    },
    "Bnclient_MNE_82290fd4a986": {
      "addresses": {
        "LoD/1.11": "0x6FF27595",
        "LoD/1.11b": "0x6FF27515",
        "LoD/1.12a": "0x6FF27964",
        "LoD/1.13c": "0x6FF278CC",
        "LoD/1.13d": "0x6FF27577"
      },
      "rvas": {
        "LoD/1.11": "0x7595",
        "LoD/1.11b": "0x7515",
        "LoD/1.12a": "0x7964",
        "LoD/1.13c": "0x78CC",
        "LoD/1.13d": "0x7577"
      },
      "name": "__get_osfhandle",
      "signature": "intptr_t __get_osfhandle(int _FileHandle)",
      "comment": "Library Function - Single Match\n __get_osfhandle\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:82290fd4a986eda931e519e307e93b03"
    },
    "Bnclient_MNE_830812317bca": {
      "addresses": {
        "LoD/1.07": "0x6FF22990",
        "LoD/1.08": "0x6FF229B0",
        "LoD/1.09": "0x6FF03310",
        "LoD/1.09b": "0x6FF03310",
        "LoD/1.09d": "0x6FF03320",
        "LoD/1.10": "0x6FF03370",
        "LoD/1.11": "0x6FF2DB10",
        "LoD/1.11b": "0x6FF2BAB0",
        "LoD/1.12a": "0x6FF2DF30",
        "LoD/1.13c": "0x6FF2F050",
        "LoD/1.13d": "0x6FF2D390"
      },
      "rvas": {
        "LoD/1.07": "0x2990",
        "LoD/1.08": "0x29B0",
        "LoD/1.09": "0x3310",
        "LoD/1.09b": "0x3310",
        "LoD/1.09d": "0x3320",
        "LoD/1.10": "0x3370",
        "LoD/1.11": "0xDB10",
        "LoD/1.11b": "0xBAB0",
        "LoD/1.12a": "0xDF30",
        "LoD/1.13c": "0xF050",
        "LoD/1.13d": "0xD390"
      },
      "name": "PrepareAndSendNetworkPacket",
      "signature": "BOOL PrepareAndSendNetworkPacket(DWORD dwDataValue)",
      "comment": "Prepares a network packet using provided data and transmits it to the connected server.\n\nAlgorithm:\n1. Allocate 260-byte buffer on stack for packet construction\n2. Call Ordinal_501 to format/encode the input data into packet buffer\n3. Pass formatted buffer size (0x104 = 260 bytes) to packet formatting function\n4. Call SendNetworkPacketWithValidation to transmit the prepared packet\n5. Return success status (1) indicating packet was prepared and sent\n\nParameters:\n- dwDataValue: Input data value to be encoded into the network packet\n\nReturns:\n- Always returns 1 (TRUE) indicating successful packet preparation and transmission\n\nMagic Numbers:\n- 0x104 (260 decimal): Fixed packet buffer size for network transmission\n- 0x10c (268 decimal): Total stack allocation including alignment padding\n\nError Handling:\n- Function assumes all operations succeed and always returns 1\n- Error handling delegated to called functions (Ordinal_501, SendNetworkPacketWithValidation)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:830812317bca30dbd2eb7bc1d144b814"
    },
    "Bnclient_MNE_83295157daa3": {
      "addresses": {
        "LoD/1.07": "0x6FF2F93E",
        "LoD/1.08": "0x6FF2F95E",
        "LoD/1.09": "0x6FF10589",
        "LoD/1.09b": "0x6FF10589",
        "LoD/1.09d": "0x6FF1086E",
        "LoD/1.10": "0x6FF10E5C"
      },
      "rvas": {
        "LoD/1.07": "0xF93E",
        "LoD/1.08": "0xF95E",
        "LoD/1.09": "0x10589",
        "LoD/1.09b": "0x10589",
        "LoD/1.09d": "0x1086E",
        "LoD/1.10": "0x10E5C"
      },
      "name": "AdjustFileBufferBounds",
      "signature": "int AdjustFileBufferBounds(BufferManager * pBufferManager, FileBuffer * pFileBuffer, byte * pbData, uint dwNewSize)",
      "comment": "Adjusts file buffer boundaries and updates associated metadata structures.\n\nAlgorithm:\n1. Extract current buffer size from the first byte of buffer data\n2. Calculate metadata table entry pointer using buffer manager base address and file buffer position\n3. If new size is smaller than current size:\n   - Update buffer size byte to new smaller value\n   - Increase free space count in metadata entry by difference\n   - Set metadata entry type flag to 0xF1 (compressed/reduced)\n4. If new size equals current size, return success (0) immediately  \n5. If new size is larger than current size:\n   - Validate new end position doesn't exceed buffer manager bounds (0x3E offset limit)\n   - Scan expansion region from current end to new end, verifying all bytes are zero\n   - If any non-zero bytes found in expansion region, return error (0)\n   - Update buffer size byte to new larger value\n   - If buffer manager's current pointer falls within the expanded region:\n     - If new end is within bounds, advance pointer to new end and skip leading zeros\n     - If new end exceeds bounds, reset pointer to buffer start + 8 and clear offset\n   - Decrease free space count in metadata entry by expansion amount (current - new)\n6. Return success (1) for all successful operations\n\nParameters:\npBufferManager - BufferManager structure containing base addresses and metadata table\npFileBuffer - FileBuffer structure with current pointer and offset information  \npbData - Pointer to buffer data, first byte contains current size value\nnNewSize - Desired new buffer size (must be <= 255 due to byte storage)\n\nReturns:\n1 - Success, buffer bounds adjusted and metadata updated\n0 - Failure due to size match, bounds violation, or non-zero expansion data\n\nSpecial Cases:\n- Size reduction always succeeds and marks buffer as compressed (0xF1)\n- Size expansion requires zero-filled expansion region for safety\n- Buffer manager pointer is automatically adjusted when it falls in expanded region\n- Metadata entry tracks free space changes for memory management\n- Buffer bounds are limited by 0x3E byte boundary from buffer manager base\n\nMagic Numbers Reference:\n0x10 - Offset to buffer manager base address pointer\n0x18 - Offset to buffer manager metadata table array  \n0x3E - Maximum buffer boundary offset (62 bytes = 248 bits)\n0xC - Right shift amount for metadata table index calculation (4KB pages)\n0xF1 - Metadata type flag indicating compressed/reduced buffer\n0x8 - Size of metadata table entry structure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:83295157daa32d8a2ec17bdc4754c492"
    },
    "Bnclient_MNE_83435bef043f": {
      "addresses": {
        "LoD/1.07": "0x6FF29870",
        "LoD/1.08": "0x6FF29890",
        "LoD/1.09": "0x6FF0A4A0",
        "LoD/1.09b": "0x6FF0A4A0",
        "LoD/1.09d": "0x6FF0A6F0",
        "LoD/1.10": "0x6FF0AF50"
      },
      "rvas": {
        "LoD/1.07": "0x9870",
        "LoD/1.08": "0x9890",
        "LoD/1.09": "0xA4A0",
        "LoD/1.09b": "0xA4A0",
        "LoD/1.09d": "0xA6F0",
        "LoD/1.10": "0xAF50"
      },
      "name": "HashPasswordWithSalt",
      "signature": "void HashPasswordWithSalt(int nHashContext, char * lpszPassword)",
      "comment": "Generates salted password hash using random salt and multiple hash rounds.\n\nAlgorithm:\n1. Validate input password pointer is non-null, exit with error if null\n2. Initialize random number generator with seed value 0x4fa7 \n3. Generate 112 bytes of random salt data using Rand() function\n4. Update system time cache and re-seed generator with current time\n5. Copy up to 64 bytes of input password into local buffer, wrapping to start if string ends early\n6. Initialize hash context (round 0) and compute initial hash of password buffer\n7. XOR the 112-byte random salt with repeating 20-byte hash output pattern\n8. Process XORed salt data in three 16-byte blocks through hash context rounds 0, 1, 2\n9. Each block advances hash context state and processes next 16-byte chunk of salt\n\nParameters:\nnHashContext (ECX): Hash algorithm context identifier for cryptographic operations  \nlpszPassword (EDX): Pointer to null-terminated password string to hash\n\nReturns:\nvoid - Function performs in-place hash operations on global hash context\n\nSpecial Cases:\nIf lpszPassword is NULL: Calls error logging function and exits with code -1\nIf password shorter than 64 bytes: Wraps to beginning of string to fill buffer\nRandom salt generation uses system time as additional entropy source\n\nMagic Numbers:\n0x4fa7 (20391): Initial random seed value for salt generation\n0x70 (112): Size in bytes of random salt buffer  \n0x40 (64): Maximum password buffer size in bytes\n0x30 (48): Offset into salt buffer for block 1 processing  \n0x10 (16): Size of each hash processing block\n0x14 (20): Size in bytes of hash output (160-bit hash)\n3: Number of hash processing rounds (blocks 0, 1, 2)\n\nError Handling:\nValidates non-null password pointer before processing\nUses Ordinal_10023 for error logging with source file information\nFUN_6ff2b29c(-1) terminates process on null password error\n\nCryptographic Flow:\nSalt Generation -> Password Buffering -> Initial Hashing -> Salt XOR Mixing -> Multi-Round Block Processing\nThis implements a salted password hashing scheme with multiple cryptographic rounds for enhanced security.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:83435bef043fa11104f36696d4ba0388"
    },
    "Bnclient_MNE_83d07e3c014d": {
      "addresses": {
        "LoD/1.07": "0x6FF2C231",
        "LoD/1.08": "0x6FF2C35C",
        "LoD/1.09": "0x6FF0CF5C",
        "LoD/1.09b": "0x6FF0CF5C",
        "LoD/1.09d": "0x6FF0D161",
        "LoD/1.10": "0x6FF0D6C7",
        "LoD/1.11": "0x6FF25D42",
        "LoD/1.11b": "0x6FF25529",
        "LoD/1.12a": "0x6FF26BD7",
        "LoD/1.13c": "0x6FF267C7",
        "LoD/1.13d": "0x6FF26142"
      },
      "rvas": {
        "LoD/1.07": "0xC231",
        "LoD/1.08": "0xC35C",
        "LoD/1.09": "0xCF5C",
        "LoD/1.09b": "0xCF5C",
        "LoD/1.09d": "0xD161",
        "LoD/1.10": "0xD6C7",
        "LoD/1.11": "0x5D42",
        "LoD/1.11b": "0x5529",
        "LoD/1.12a": "0x6BD7",
        "LoD/1.13c": "0x67C7",
        "LoD/1.13d": "0x6142"
      },
      "name": "TlsCleanupSlot",
      "signature": "void TlsCleanupSlot(void)",
      "comment": "Cleans up TLS (Thread Local Storage) resources and calls additional cleanup\n\nAlgorithm:\n1. Call FUN_6ff2c392() for additional cleanup operations\n2. Load current TLS slot index from g_dwTlsSlotIndex global variable\n3. Compare slot index against invalid value 0xffffffff \n4. If slot is valid (not 0xffffffff), proceed with TLS cleanup\n5. Call TlsFree() with the valid slot index to release TLS slot\n6. Set g_dwTlsSlotIndex to 0xffffffff to mark as invalid\n7. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nIf g_dwTlsSlotIndex is already 0xffffffff (invalid), skip TLS cleanup\n\nMagic Numbers Reference:\n0xffffffff (4294967295) - Invalid TLS slot index constant used by Windows API\n\nError Handling:\nNo explicit error handling - relies on TlsFree() API behavior",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:83d07e3c014d31c19cf14861bc62b0a0"
    },
    "Bnclient_MNE_83f6daa31383": {
      "addresses": {
        "LoD/1.10": "0x6FF13680"
      },
      "rvas": {
        "LoD/1.10": "0x13680"
      },
      "method": "MNE",
      "index": "MNE:83f6daa31383d30d2e85d94d4d92a01c",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF2C340",
          "rva": "0xC340",
          "confidence": 0.397,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_8413e044a8bf": {
      "addresses": {
        "LoD/1.09": "0x6FF15100",
        "LoD/1.09b": "0x6FF15100",
        "LoD/1.09d": "0x6FF15420",
        "LoD/1.10": "0x6FF159B0"
      },
      "rvas": {
        "LoD/1.09": "0x15100",
        "LoD/1.09b": "0x15100",
        "LoD/1.09d": "0x15420",
        "LoD/1.10": "0x159B0"
      },
      "method": "MNE",
      "index": "MNE:8413e044a8bf531959b317bb672dfc95"
    },
    "Bnclient_MNE_8414efd6c6e4": {
      "addresses": {
        "LoD/1.07": "0x6FF2B39E",
        "LoD/1.08": "0x6FF2B3BF",
        "LoD/1.09": "0x6FF0BFBF",
        "LoD/1.09b": "0x6FF0BFBF",
        "LoD/1.09d": "0x6FF0C21E",
        "LoD/1.10": "0x6FF0C77E",
        "LoD/1.11": "0x6FF21D8B",
        "LoD/1.11b": "0x6FF2128E",
        "LoD/1.12a": "0x6FF21ABE",
        "LoD/1.13c": "0x6FF215F2",
        "LoD/1.13d": "0x6FF21716"
      },
      "rvas": {
        "LoD/1.07": "0xB39E",
        "LoD/1.08": "0xB3BF",
        "LoD/1.09": "0xBFBF",
        "LoD/1.09b": "0xBFBF",
        "LoD/1.09d": "0xC21E",
        "LoD/1.10": "0xC77E",
        "LoD/1.11": "0x1D8B",
        "LoD/1.11b": "0x128E",
        "LoD/1.12a": "0x1ABE",
        "LoD/1.13c": "0x15F2",
        "LoD/1.13d": "0x1716"
      },
      "name": "SetThreadContextValue",
      "signature": "void SetThreadContextValue(uint dwValue)",
      "comment": "Stores a value at index 5 (offset 0x14) of the current thread's context structure.\n\nAlgorithm:\n1. Retrieve or create thread context structure using GetOrCreateThreadContext\n2. Store the provided value at array index 5 (offset 0x14) of the context structure\n3. Return immediately (no validation or error checking)\n\nParameters:\ndwValue (uint) - The value to store in the thread context at index 5\n\nReturns:\nvoid - This function does not return a value\n\nSpecial Cases:\nThis function performs no validation on the input value or context structure.\nThe offset 0x14 corresponds to a 32-bit value at position 5 in a DWORD array.\n\nStructure Layout:\nThreadContext structure field at offset 0x14:\nOffset | Size | Field Name | Type | Description\n0x14   | 4    | field5     | uint | Storage location for authentication state\n\nMagic Numbers Reference:\n0x14 (20 decimal) - Offset in thread context structure for field 5\nIndex 5 - Array position in DWORD array (5 * sizeof(DWORD) = 0x14)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:8414efd6c6e404130e1c0a48010e9ecb"
    },
    "Bnclient_MNE_843e3db8ac56": {
      "addresses": {
        "LoD/1.11b": "0x6FF27D12",
        "LoD/1.13c": "0x6FF27D84",
        "LoD/1.13d": "0x6FF27D7A"
      },
      "rvas": {
        "LoD/1.11b": "0x7D12",
        "LoD/1.13c": "0x7D84",
        "LoD/1.13d": "0x7D7A"
      },
      "method": "MNE",
      "index": "MNE:843e3db8ac5607bba3d919f4ee9bcace"
    },
    "Bnclient_MNE_845fc5044ff1": {
      "addresses": {
        "LoD/1.07": "0x6FF2FF90",
        "LoD/1.08": "0x6FF2FFB0",
        "LoD/1.09": "0x6FF10BD0",
        "LoD/1.09b": "0x6FF10BD0",
        "LoD/1.09d": "0x6FF10EC0",
        "LoD/1.10": "0x6FF11410"
      },
      "rvas": {
        "LoD/1.07": "0xFF90",
        "LoD/1.08": "0xFFB0",
        "LoD/1.09": "0x10BD0",
        "LoD/1.09b": "0x10BD0",
        "LoD/1.09d": "0x10EC0",
        "LoD/1.10": "0x11410"
      },
      "name": "StringConcatenate",
      "signature": "byte * StringConcatenate(byte * pbDestination, byte * pbSource)",
      "comment": "Concatenates source string to destination string using optimized word-based copying.\n\nAlgorithm:\n1. Validate input pointers (lpszDestination and lpszSource)\n2. Find end of destination string using 4-byte alignment optimization\n3. Check alignment of destination pointer (test for 3-byte boundary)\n4. If misaligned, process bytes individually until aligned\n5. Use 4-byte word processing with null-detection magic value 0x7EFEFEFF\n6. Apply null-byte detection formula: (value ^ 0xFFFFFFFF ^ (value + 0x7EFEFEFF)) & 0x81010100\n7. When null detected in word, determine exact position by testing individual bytes\n8. Set destination end pointer to null terminator position\n9. Copy source string to destination end position\n10. Check alignment of source pointer for optimization\n11. If misaligned, copy bytes individually until aligned\n12. Use 4-byte word copying with same null-detection technique\n13. When null detected in source word, copy remaining bytes and null terminator\n14. Return original destination pointer\n\nParameters:\nlpszDestination - Pointer to destination string buffer (must be large enough)\nlpszSource - Pointer to source string to append (null-terminated)\n\nReturns:\nPointer to destination string (same as lpszDestination parameter)\n\nSpecial Cases:\nUses 4-byte alignment optimization for faster memory operations\nHandles misaligned pointers by processing individual bytes first\nMagic value 0x7EFEFEFF enables detection of null bytes within 32-bit words\n\nMagic Numbers Reference:\n0x7EFEFEFF - Null-byte detection magic constant for 32-bit words\n0x81010100 - Mask for isolating null-byte detection results\n0x3 - Alignment mask for 4-byte boundary detection",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:845fc5044ff181fe96e2ae868d3aa1f6"
    },
    "Bnclient_MNE_848023888ca1": {
      "addresses": {
        "LoD/1.11": "0x6FF2A5D0",
        "LoD/1.11b": "0x6FF2A5D0",
        "LoD/1.12a": "0x6FF2AC00",
        "LoD/1.13c": "0x6FF2ABE0",
        "LoD/1.13d": "0x6FF2ABF0"
      },
      "rvas": {
        "LoD/1.11": "0xA5D0",
        "LoD/1.11b": "0xA5D0",
        "LoD/1.12a": "0xAC00",
        "LoD/1.13c": "0xABE0",
        "LoD/1.13d": "0xABF0"
      },
      "method": "MNE",
      "index": "MNE:848023888ca1a9af9ceb1d7d12421217"
    },
    "Bnclient_MNE_84ae3f60ff7b": {
      "addresses": {
        "LoD/1.10": "0x6FF08310",
        "LoD/1.11": "0x6FF21F24",
        "LoD/1.11b": "0x6FF216C4",
        "LoD/1.12a": "0x6FF21F7D",
        "LoD/1.13c": "0x6FF21C14",
        "LoD/1.13d": "0x6FF219F4"
      },
      "rvas": {
        "LoD/1.10": "0x8310",
        "LoD/1.11": "0x1F24",
        "LoD/1.11b": "0x16C4",
        "LoD/1.12a": "0x1F7D",
        "LoD/1.13c": "0x1C14",
        "LoD/1.13d": "0x19F4"
      },
      "name": "~type_info",
      "signature": "void ~type_info(type_info * this)",
      "comment": "Library Function - Single Match\n public: virtual __thiscall type_info::~type_info(void)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:84ae3f60ff7b13dd862d9aa1a8b361cd"
    },
    "Bnclient_MNE_856ee0d81ef8": {
      "addresses": {
        "LoD/1.10": "0x6FF065E0"
      },
      "rvas": {
        "LoD/1.10": "0x65E0"
      },
      "method": "MNE",
      "index": "MNE:856ee0d81ef8d6ab83ba4fd382618f6a",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF32230",
          "rva": "0x12230",
          "confidence": 0.399,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.09d": {
          "address": "0x6FF06650",
          "rva": "0x6650",
          "confidence": 0.405,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_85de0cee1ebe": {
      "addresses": {
        "LoD/1.07": "0x6FF2B760"
      },
      "rvas": {
        "LoD/1.07": "0xB760"
      },
      "name": "FindCharacterInString",
      "signature": "char * FindCharacterInString(char * szString, int nSearchChar)",
      "comment": "Locate first occurrence of character in string using optimized DWORD scanning\n\nAlgorithm:\n1. Handle unaligned bytes one-by-one until pointer is DWORD-aligned\n2. Check each unaligned byte for target character or null terminator\n3. Build 32-bit search pattern by replicating target character 4 times\n4. Scan aligned memory in 4-byte chunks using bit manipulation tricks\n5. Use XOR and arithmetic to detect target character or null terminator\n6. When match detected, examine individual bytes to find exact position\n7. Return pointer to matching character or NULL if not found\n\nParameters:\nszString (char *): Input string to search, must be null-terminated\nnSearchChar (int): Character to find (only low byte used)\n\nReturns:\nchar *: Pointer to first occurrence of character in string\n        NULL if character not found or string is null\n\nSpecial Cases:\nSearch character 0x00 finds null terminator location\nOptimized for x86 architecture with DWORD-aligned memory access\nUses magic constant 0x7EFEFEFF for simultaneous null detection\n\nMagic Numbers Reference:\n0x7EFEFEFF: Magic constant for null byte detection in DWORD\n0x81010100: Bit mask to isolate null detection results\n0x1010100: Secondary mask for null detection edge cases\n0x80000000: Sign bit mask for overflow detection\n\nPerformance Notes:\nHandles 1-3 unaligned bytes individually for alignment\nProcesses 4 bytes per iteration in main loop\nReturns immediately upon finding target or null terminator",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:85de0cee1ebe7ed32270da528f819b99"
    },
    "Bnclient_MNE_85e183d11080": {
      "addresses": {
        "LoD/1.09": "0x6FF14E60",
        "LoD/1.09b": "0x6FF14E60",
        "LoD/1.09d": "0x6FF15180",
        "LoD/1.10": "0x6FF15720"
      },
      "rvas": {
        "LoD/1.09": "0x14E60",
        "LoD/1.09b": "0x14E60",
        "LoD/1.09d": "0x15180",
        "LoD/1.10": "0x15720"
      },
      "method": "MNE",
      "index": "MNE:85e183d110801f4f0aa8b54b7201c2da",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF34640",
          "rva": "0x14640",
          "confidence": 0.291,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.11b": {
          "address": "0x6FF2C6E0",
          "rva": "0xC6E0",
          "confidence": 0.291,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.12a": {
          "address": "0x6FF2BD40",
          "rva": "0xBD40",
          "confidence": 0.291,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF2CE60",
          "rva": "0xCE60",
          "confidence": 0.291,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13d": {
          "address": "0x6FF30B80",
          "rva": "0x10B80",
          "confidence": 0.172,
          "method": "minhash",
          "direction": "forward",
          "source": "LoD/1.13c"
        }
      }
    },
    "Bnclient_MNE_893c0b8891aa": {
      "addresses": {
        "LoD/1.09": "0x6FF15150",
        "LoD/1.09b": "0x6FF15150",
        "LoD/1.09d": "0x6FF15470",
        "LoD/1.10": "0x6FF15A00"
      },
      "rvas": {
        "LoD/1.09": "0x15150",
        "LoD/1.09b": "0x15150",
        "LoD/1.09d": "0x15470",
        "LoD/1.10": "0x15A00"
      },
      "method": "MNE",
      "index": "MNE:893c0b8891aaf5c774a4dd3d44b57e34"
    },
    "Bnclient_MNE_89c8ec97483b": {
      "addresses": {
        "LoD/1.07": "0x6FF31601",
        "LoD/1.08": "0x6FF31621",
        "LoD/1.09": "0x6FF12241",
        "LoD/1.09b": "0x6FF12241",
        "LoD/1.09d": "0x6FF12531",
        "LoD/1.10": "0x6FF12A81"
      },
      "rvas": {
        "LoD/1.07": "0x11601",
        "LoD/1.08": "0x11621",
        "LoD/1.09": "0x12241",
        "LoD/1.09b": "0x12241",
        "LoD/1.09d": "0x12531",
        "LoD/1.10": "0x12A81"
      },
      "name": "AcquireStreamCriticalSection",
      "signature": "void AcquireStreamCriticalSection(uint dwStreamId)",
      "comment": "Acquires exclusive access to a stream by entering its critical section.\n\nAlgorithm:\n1. Calculate bucket index by shifting stream ID right by 5 bits (divide by 32)\n2. Calculate slot index by masking stream ID with 0x1F (modulo 32)\n3. Retrieve stream descriptor pointer from global stream descriptor table\n4. Check if critical section is initialized (pCurrent != NULL)\n5. If not initialized, acquire global initialization lock (index 0x11)\n6. Double-check initialization state under lock\n7. If still uninitialized, initialize critical section and mark as initialized\n8. Release global initialization lock\n9. Enter the stream-specific critical section for exclusive access\n\nParameters:\ndwStreamId (uint) - Stream identifier used to locate the corresponding stream descriptor\n\nReturns:\nvoid - Function does not return a value\n\nSpecial Cases:\n- Double-checked locking pattern prevents race conditions during initialization\n- Global lock index 0x11 serializes critical section initialization across all threads\n- Stream descriptors organized in buckets of 32 streams each for efficient lookup\n\nMagic Numbers Reference:\n0x1F (31) - Bitmask for modulo 32 operation to get slot index within bucket\n0x11 (17) - Global critical section index for stream initialization synchronization\n5 - Right shift amount to divide stream ID by 32 for bucket calculation\n\nStructure Layout:\nStreamIO structure (36 bytes):\nOffset | Size | Field Name | Type | Description\n   +8  |  4   | pCurrent   | void*| Initialization marker (NULL=uninitialized)\n   +12 |  24  | dwFlags    | CRITICAL_SECTION | Windows critical section object\n\nAlgorithm Verification:\nStep 1: dwSlotIndex = dwStreamId & 0x1F (MOV EAX,param; AND EAX,0x1f)\nStep 2: bucket = dwStreamId >> 5 (MOV ECX,param; SAR ECX,0x5)  \nStep 3: pStreamDescriptor = g_apStreamDescriptors[bucket] (MOV ESI,[ECX*4+g_apStreamDescriptors])\nStep 4: Check pStreamDescriptor[dwSlotIndex].pCurrent == NULL (CMP [ESI+EDI+0x8],0x0)\nStep 5: AcquireCriticalSectionByIndex(0x11) if uninitialized\nStep 6: InitializeCriticalSection(&pStreamDescriptor[dwSlotIndex].dwFlags)\nStep 7: EnterCriticalSection(&pStreamDescriptor[dwSlotIndex].dwFlags)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:89c8ec97483b3d89b792dc7acc8a9af7"
    },
    "Bnclient_MNE_89d1b6190541": {
      "addresses": {
        "LoD/1.07": "0x6FF2D019",
        "LoD/1.08": "0x6FF2D039",
        "LoD/1.09": "0x6FF0DC39",
        "LoD/1.09b": "0x6FF0DC39",
        "LoD/1.09d": "0x6FF0DF49",
        "LoD/1.10": "0x6FF0E4B1",
        "LoD/1.11": "0x6FF2399E",
        "LoD/1.11b": "0x6FF2325E",
        "LoD/1.12a": "0x6FF225BE",
        "LoD/1.13c": "0x6FF22692",
        "LoD/1.13d": "0x6FF2359E"
      },
      "rvas": {
        "LoD/1.07": "0xD019",
        "LoD/1.08": "0xD039",
        "LoD/1.09": "0xDC39",
        "LoD/1.09b": "0xDC39",
        "LoD/1.09d": "0xDF49",
        "LoD/1.10": "0xE4B1",
        "LoD/1.11": "0x399E",
        "LoD/1.11b": "0x325E",
        "LoD/1.12a": "0x25BE",
        "LoD/1.13c": "0x2692",
        "LoD/1.13d": "0x359E"
      },
      "name": "__seh_longjmp_unwind@4",
      "signature": "undefined __seh_longjmp_unwind@4(int param_1)",
      "comment": "Library Function - Single Match\n __seh_longjmp_unwind@4\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release, Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:89d1b619054116ad559c7c543db397fd"
    },
    "Bnclient_MNE_89f4dd5ffbab": {
      "addresses": {
        "LoD/1.07": "0x6FF2B194",
        "LoD/1.08": "0x6FF2B2E3",
        "LoD/1.09": "0x6FF0BEE3",
        "LoD/1.09b": "0x6FF0BEE3",
        "LoD/1.09d": "0x6FF0C010",
        "LoD/1.10": "0x6FF0C576"
      },
      "rvas": {
        "LoD/1.07": "0xB194",
        "LoD/1.08": "0xB2E3",
        "LoD/1.09": "0xBEE3",
        "LoD/1.09b": "0xBEE3",
        "LoD/1.09d": "0xC010",
        "LoD/1.10": "0xC576"
      },
      "name": "TokenizeStringWithDelimiters",
      "signature": "byte * TokenizeStringWithDelimiters(byte * pbInput, byte * pbDelimiters)",
      "comment": "Tokenize string using delimiter set, with thread context persistence\n\nAlgorithm:\n1. Get thread context structure for state persistence\n2. Build 32-byte bit vector from delimiter characters in pbDelimiters\n3. Determine input string source (pbInput or thread context string)  \n4. Skip leading delimiters to find token start\n5. Process token by removing trailing delimiters\n6. Update thread context and return token pointer\n\nParameters:\npbInput - Input string to tokenize (NULL to use thread context string)\npbDelimiters - Null-terminated string of delimiter characters\n\nReturns:\nbyte * - Pointer to null-terminated token, or NULL if no more tokens",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:89f4dd5ffbabb9ad6d64be0e709db24d"
    },
    "Bnclient_MNE_8ac92c76a51a": {
      "addresses": {
        "LoD/1.11": "0x6FF36E2E",
        "LoD/1.11b": "0x6FF36DFE",
        "LoD/1.12a": "0x6FF37CAE",
        "LoD/1.13c": "0x6FF37C8E",
        "LoD/1.13d": "0x6FF37BCE"
      },
      "rvas": {
        "LoD/1.11": "0x16E2E",
        "LoD/1.11b": "0x16DFE",
        "LoD/1.12a": "0x17CAE",
        "LoD/1.13c": "0x17C8E",
        "LoD/1.13d": "0x17BCE"
      },
      "name": "__heap_alloc",
      "signature": "void * __heap_alloc(size_t _Size)",
      "comment": "Library Function - Single Match\n __heap_alloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:8ac92c76a51a8b065a1fac94d719ae1f"
    },
    "Bnclient_MNE_8b6d11914714": {
      "addresses": {
        "LoD/1.11": "0x6FF32BD0",
        "LoD/1.11b": "0x6FF2F320",
        "LoD/1.12a": "0x6FF35170",
        "LoD/1.13c": "0x6FF30CC0",
        "LoD/1.13d": "0x6FF2C120"
      },
      "rvas": {
        "LoD/1.11": "0x12BD0",
        "LoD/1.11b": "0xF320",
        "LoD/1.12a": "0x15170",
        "LoD/1.13c": "0x10CC0",
        "LoD/1.13d": "0xC120"
      },
      "method": "MNE",
      "index": "MNE:8b6d11914714a660b28813d76863598c",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF01000",
          "rva": "0x1000",
          "confidence": 0.436,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF01000",
          "rva": "0x1000",
          "confidence": 0.353,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.10"
        },
        "LoD/1.09b": {
          "address": "0x6FF032F0",
          "rva": "0x32F0",
          "confidence": 0.318,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09": {
          "address": "0x6FF032F0",
          "rva": "0x32F0",
          "confidence": 0.209,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_8b97ebec1e2b": {
      "addresses": {
        "LoD/1.11": "0x6FF26458",
        "LoD/1.11b": "0x6FF25989",
        "LoD/1.12a": "0x6FF24DF1",
        "LoD/1.13c": "0x6FF24A3C",
        "LoD/1.13d": "0x6FF264B2"
      },
      "rvas": {
        "LoD/1.11": "0x6458",
        "LoD/1.11b": "0x5989",
        "LoD/1.12a": "0x4DF1",
        "LoD/1.13c": "0x4A3C",
        "LoD/1.13d": "0x64B2"
      },
      "name": "___sbh_free_block",
      "signature": "undefined ___sbh_free_block(uint * param_1, int param_2)",
      "comment": "Library Function - Single Match\n ___sbh_free_block\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:8b97ebec1e2ba4f1376a18655897a974"
    },
    "Bnclient_MNE_8c1ef08c1332": {
      "addresses": {
        "LoD/1.07": "0x6FF2B5F0",
        "LoD/1.08": "0x6FF2B610",
        "LoD/1.09": "0x6FF0C210",
        "LoD/1.09b": "0x6FF0C210",
        "LoD/1.09d": "0x6FF0C470",
        "LoD/1.10": "0x6FF0C9D0"
      },
      "rvas": {
        "LoD/1.07": "0xB5F0",
        "LoD/1.08": "0xB610",
        "LoD/1.09": "0xC210",
        "LoD/1.09b": "0xC210",
        "LoD/1.09d": "0xC470",
        "LoD/1.10": "0xC9D0"
      },
      "name": "CompareStringsIgnoreCase",
      "signature": "uint CompareStringsIgnoreCase(void * this, byte * pbString1, byte * pbString2)",
      "comment": "Performs case-insensitive string comparison with optional locale support\n\nAlgorithm:\n1. Load saved critical section counter value for potential restoration\n2. Check if locale data is available (DAT_6ff39f20 == 0 for simple mode)\n3. Simple mode (no locale): Compare characters directly with ASCII case conversion\n   - Read characters from both strings until difference found or null terminator\n   - Convert to lowercase using ASCII transformation: char + 0xbf + conditional 0x20 + 0x41\n   - Return comparison result: -1 if string1 < string2, 0 if equal, 1 if string1 > string2\n4. Locale mode: Thread-safe comparison with locale-specific character conversion\n   - Increment critical section counter with atomic operation\n   - Check critical section depth limit (DAT_6ff3b544)\n   - If depth exceeded, restore counter and call error handler FUN_6ff2c3fe(0x13)\n   - Compare characters using locale conversion function FUN_6ff2bdda\n   - Decrement critical section counter or call cleanup FUN_6ff2c45f(0x13)\n5. Return normalized comparison result as unsigned integer\n\nParameters:\nthis (pLocaleContext): Locale context object for character conversion operations\nlpszString1: First null-terminated string to compare\nlpszString2: Second null-terminated string to compare\n\nReturns:\n0x00000000: Strings are equal (case-insensitive)\n0x00000001: First string is lexically greater than second string\n0xFFFFFFFF: First string is lexically less than second string\n\nSpecial Cases:\n- Empty strings (immediate null terminator) return 0x00000000\n- Null pointer parameters cause undefined behavior\n- Critical section overflow triggers error handler and may modify comparison behavior\n\nMagic Numbers:\n0xbf: ASCII case conversion offset (-65 decimal)\n0x1a: Check for alphabetic character range (26 decimal) \n0x20: Space character offset for lowercase conversion (32 decimal)\n0x41: ASCII 'A' character base (65 decimal)\n0x13: Error code passed to critical section handlers\n0xff: Initial comparison state marker (255 decimal)\n\nError Handling:\n- Critical section depth limit exceeded: Call FUN_6ff2c3fe(0x13) and restore counter\n- Normal exit from critical section: Call FUN_6ff2c45f(0x13) for cleanup\n- Locale conversion errors are handled by FUN_6ff2bdda callee\n\nGlobal Dependencies:\n_DAT_6ff3b548: Critical section entry counter (thread synchronization)\nDAT_6ff39f20: Locale availability flag (0 = simple mode, non-zero = locale mode)\nDAT_6ff3b544: Critical section depth limit threshold",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:8c1ef08c13327b78f680f81ff5d26364"
    },
    "Bnclient_MNE_8c4228500987": {
      "addresses": {
        "LoD/1.11": "0x6FF23A74",
        "LoD/1.11b": "0x6FF23279",
        "LoD/1.13d": "0x6FF23628"
      },
      "rvas": {
        "LoD/1.11": "0x3A74",
        "LoD/1.11b": "0x3279",
        "LoD/1.13d": "0x3628"
      },
      "name": "_realloc",
      "signature": "void * _realloc(void * _Memory, size_t _NewSize)",
      "comment": "Library Function - Single Match\n _realloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:8c4228500987c1daeeb1fa9fd68f17a9"
    },
    "Bnclient_MNE_8de8a991a945": {
      "addresses": {
        "LoD/1.11": "0x6FF2BD10",
        "LoD/1.11b": "0x6FF33FB0",
        "LoD/1.12a": "0x6FF33B20",
        "LoD/1.13c": "0x6FF2C340",
        "LoD/1.13d": "0x6FF32F90"
      },
      "rvas": {
        "LoD/1.11": "0xBD10",
        "LoD/1.11b": "0x13FB0",
        "LoD/1.12a": "0x13B20",
        "LoD/1.13c": "0xC340",
        "LoD/1.13d": "0x12F90"
      },
      "method": "MNE",
      "index": "MNE:8de8a991a94591c0d86b19a394c4f79d"
    },
    "Bnclient_MNE_8e0ca63e1078": {
      "addresses": {
        "LoD/1.07": "0x6FF2B040",
        "LoD/1.08": "0x6FF2B060",
        "LoD/1.09": "0x6FF0BC60",
        "LoD/1.09b": "0x6FF0BC60",
        "LoD/1.09d": "0x6FF0BEB0",
        "LoD/1.10": "0x6FF0C470"
      },
      "rvas": {
        "LoD/1.07": "0xB040",
        "LoD/1.08": "0xB060",
        "LoD/1.09": "0xBC60",
        "LoD/1.09b": "0xBC60",
        "LoD/1.09d": "0xBEB0",
        "LoD/1.10": "0xC470"
      },
      "name": "InitializeMD5Context",
      "signature": "void InitializeMD5Context(int nContextIndex)",
      "comment": "Initializes an MD5 context structure with standard MD5 initialization vectors in the global buffer array.\n\nAlgorithm:\n1. Calculate byte offset in global buffer: nContextIndex * 0x5c (92 bytes per context)\n2. Add base offset 0x340 to reach MD5 context array start\n3. Initialize MD5 hash state with standard RFC 1321 initialization vectors:\n   - h0 = 0x67452301 (little-endian representation of 0x01234567)\n   - h1 = 0xefcdab89 (little-endian representation of 0x89abcdef)\n   - h2 = 0x98badcfe (little-endian representation of 0xfedcba98)\n   - h3 = 0x10325476 (little-endian representation of 0x76543210)\n   - h4 = 0xc3d2e1f0 (little-endian representation of 0xf0e1d2c3)\n4. Zero-initialize message count fields (count_low and count_high)\n\nParameters:\nnContextIndex (int): Zero-based index selecting which MD5 context to initialize in global array\n\nReturns:\nvoid: Function performs initialization only, no return value\n\nSpecial Cases:\n- Index bounds not validated; caller must ensure valid range\n- Context stride of 0x5c (92 bytes) allows multiple simultaneous MD5 operations\n- Base offset 0x340 positions MD5 contexts after other data in global buffer\n\nMagic Numbers Reference:\n0x5c (92): MD5 context structure size in bytes\n0x340: Base offset of MD5 context array in global buffer\n0x67452301: MD5 h0 initialization vector (RFC 1321)\n0xefcdab89: MD5 h1 initialization vector (RFC 1321)\n0x98badcfe: MD5 h2 initialization vector (RFC 1321)\n0x10325476: MD5 h3 initialization vector (RFC 1321)\n0xc3d2e1f0: MD5 h4 initialization vector (RFC 1321)\n\nStructure Layout:\nOffset | Size | Field Name  | Type | Description\n-------|------|-------------|------|-------------\n0x00   | 4    | h0          | uint | MD5 hash state word 0\n0x04   | 4    | h1          | uint | MD5 hash state word 1  \n0x08   | 4    | h2          | uint | MD5 hash state word 2\n0x0c   | 4    | h3          | uint | MD5 hash state word 3\n0x10   | 4    | h4          | uint | MD5 hash state word 4\n0x14   | 4    | count_low   | uint | Message length low 32 bits\n0x18   | 4    | count_high  | uint | Message length high 32 bits",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:8e0ca63e10786dad37cf93955045f2b4"
    },
    "Bnclient_MNE_8e6938d27160": {
      "addresses": {
        "LoD/1.11": "0x6FF216F8",
        "LoD/1.11b": "0x6FF21C76",
        "LoD/1.12a": "0x6FF21C84",
        "LoD/1.13c": "0x6FF2165A",
        "LoD/1.13d": "0x6FF212F2"
      },
      "rvas": {
        "LoD/1.11": "0x16F8",
        "LoD/1.11b": "0x1C76",
        "LoD/1.12a": "0x1C84",
        "LoD/1.13c": "0x165A",
        "LoD/1.13d": "0x12F2"
      },
      "name": "__strnicmp",
      "signature": "int __strnicmp(char * _Str1, char * _Str2, size_t _MaxCount)",
      "comment": "Library Function - Single Match\n __strnicmp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:8e6938d27160c5389a23dd4589ddfd12"
    },
    "Bnclient_MNE_8f2a733057dd": {
      "addresses": {
        "LoD/1.07": "0x6FF30E24",
        "LoD/1.08": "0x6FF30E44",
        "LoD/1.09": "0x6FF11A64",
        "LoD/1.09b": "0x6FF11A64",
        "LoD/1.09d": "0x6FF11D54",
        "LoD/1.10": "0x6FF122A4"
      },
      "rvas": {
        "LoD/1.07": "0x10E24",
        "LoD/1.08": "0x10E44",
        "LoD/1.09": "0x11A64",
        "LoD/1.09b": "0x11A64",
        "LoD/1.09d": "0x11D54",
        "LoD/1.10": "0x122A4"
      },
      "name": "SelectCodePageForLocale",
      "signature": "int SelectCodePageForLocale(int nLocaleSpecifier)",
      "comment": "Selects appropriate Windows code page based on locale specifier value.\n\nAlgorithm:\n1. Clear code page initialization flag (g_fCodePageInitialized = 0)\n2. Check if nLocaleSpecifier equals -2 (CP_OEMCP constant)\n   - Set initialization flag to 1 \n   - Call GetOEMCP() via function pointer table to get OEM code page\n   - Return OEM code page identifier\n3. Check if nLocaleSpecifier equals -3 (CP_ACP constant)\n   - Set initialization flag to 1\n   - Call GetACP() via function pointer table to get ANSI code page  \n   - Return ANSI code page identifier\n4. Check if nLocaleSpecifier equals -4 (CP_MACCP or custom default)\n   - Load default code page from g_dwDefaultCodePage global\n   - Set initialization flag to 1\n   - Return default code page value\n5. For any other value, return parameter unchanged with flag cleared\n\nParameters:\nnLocaleSpecifier - Code page selection constant:\n  -2 (0xFFFFFFFE): Request OEM code page via GetOEMCP()\n  -3 (0xFFFFFFFD): Request ANSI code page via GetACP()  \n  -4 (0xFFFFFFFC): Request system default code page\n  Other values: Return as-is without modification\n\nReturns:\nCode page identifier (UINT):\n- OEM code page ID when nLocaleSpecifier = -2\n- ANSI code page ID when nLocaleSpecifier = -3\n- Default code page from g_dwDefaultCodePage when nLocaleSpecifier = -4\n- Original nLocaleSpecifier value for all other inputs\n\nSpecial Cases:\nFunction uses indirect jumps through function pointer tables at:\n- 0x6ff3315c: Pointer to GetOEMCP() Windows API\n- 0x6ff3312c: Pointer to GetACP() Windows API\nGlobal g_fCodePageInitialized tracks whether code page lookup was performed.\nUsed by character type initialization system for locale-aware text processing.\n\nMagic Numbers Reference:\n-2 (0xFFFFFFFE): CP_OEMCP - OEM code page constant\n-3 (0xFFFFFFFD): CP_ACP - ANSI code page constant  \n-4 (0xFFFFFFFC): CP_MACCP or system default indicator\n0x6ff39f30: Address of g_dwDefaultCodePage global storage\n0x6ff3a18c: Address of g_fCodePageInitialized flag",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:8f2a733057dd5a290f0e17d077c53986"
    },
    "Bnclient_MNE_8f7df14e6456": {
      "addresses": {
        "LoD/1.11": "0x6FF26770",
        "LoD/1.11b": "0x6FF25CA1",
        "LoD/1.12a": "0x6FF25109",
        "LoD/1.13c": "0x6FF24D54",
        "LoD/1.13d": "0x6FF267CA"
      },
      "rvas": {
        "LoD/1.11": "0x6770",
        "LoD/1.11b": "0x5CA1",
        "LoD/1.12a": "0x5109",
        "LoD/1.13c": "0x4D54",
        "LoD/1.13d": "0x67CA"
      },
      "name": "___sbh_alloc_new_region",
      "signature": "undefined4 * ___sbh_alloc_new_region(void)",
      "comment": "Library Function - Single Match\n ___sbh_alloc_new_region\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:8f7df14e6456cd93f8028b09582e6071"
    },
    "Bnclient_MNE_91411ab42478": {
      "addresses": {
        "LoD/1.11": "0x6FF239B9",
        "LoD/1.11b": "0x6FF23F20",
        "LoD/1.13d": "0x6FF23BDD"
      },
      "rvas": {
        "LoD/1.11": "0x39B9",
        "LoD/1.11b": "0x3F20",
        "LoD/1.13d": "0x3BDD"
      },
      "name": "_calloc",
      "signature": "void * _calloc(size_t _Count, size_t _Size)",
      "comment": "Library Function - Single Match\n _calloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:91411ab4247869eeb28238e92930a4a5"
    },
    "Bnclient_MNE_91b5192dddb8": {
      "addresses": {
        "LoD/1.07": "0x6FF2B26F",
        "LoD/1.08": "0x6FF2B1B4",
        "LoD/1.09": "0x6FF0BDB4",
        "LoD/1.09b": "0x6FF0BDB4",
        "LoD/1.09d": "0x6FF0C0EF",
        "LoD/1.10": "0x6FF0C64F"
      },
      "rvas": {
        "LoD/1.07": "0xB26F",
        "LoD/1.08": "0xB1B4",
        "LoD/1.09": "0xBDB4",
        "LoD/1.09b": "0xBDB4",
        "LoD/1.09d": "0xC0EF",
        "LoD/1.10": "0xC64F"
      },
      "name": "InitializeStaticConstructors",
      "signature": "void InitializeStaticConstructors(void)",
      "comment": "Initialize all static constructor and destructor functions during DLL load.\n\nAlgorithm:\n1. Check if global initialization function pointer is set (g_pfnGlobalInitializer)\n2. If set, call the global initialization function\n3. Call all static destructor functions in the range [g_apfnDestructorsBegin, g_apfnDestructorsEnd)\n4. Call all static constructor functions in the range [g_apfnConstructorsBegin, g_apfnConstructorsEnd)\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nvoid - no return value\n\nSpecial Cases:\n- Global initializer function may be NULL (0x0), in which case it is skipped\n- Constructor/destructor arrays may be empty if begin == end pointers\n- Function pointers in arrays are validated before calling (NULL pointers skipped)\n\nMagic Numbers Reference:\n- 0x6ff3b56c: g_pfnGlobalInitializer (optional global init function)\n- 0x6ff35000: g_apfnConstructorsBegin (start of constructor array)\n- 0x6ff35014: g_apfnConstructorsEnd (end of constructor array)\n- 0x6ff35018: g_apfnDestructorsBegin (start of destructor array)\n- 0x6ff35028: g_apfnDestructorsEnd (end of destructor array)\n\nError Handling:\n- No explicit error handling - relies on called functions to handle errors\n- NULL function pointers are safely skipped by conditional checks\n- Array bounds are compiler-generated and assumed valid\n\nState Machine:\nState 1: Check global initializer - if NULL, skip to State 2\nState 2: Call destructors array processing\nState 3: Call constructors array processing  \nState 4: Return to caller (DllMain)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:91b5192dddb89e963abc2be4471149da"
    },
    "Bnclient_MNE_9202742c31e7": {
      "addresses": {
        "LoD/1.12a": "0x6FF22928",
        "LoD/1.13c": "0x6FF2391E"
      },
      "rvas": {
        "LoD/1.12a": "0x2928",
        "LoD/1.13c": "0x391E"
      },
      "method": "MNE",
      "index": "MNE:9202742c31e7fad9c07478efa934202a"
    },
    "Bnclient_MNE_921d14ea2db8": {
      "addresses": {
        "LoD/1.11": "0x6FF23D8F",
        "LoD/1.11b": "0x6FF22F18",
        "LoD/1.12a": "0x6FF22277",
        "LoD/1.13c": "0x6FF23010",
        "LoD/1.13d": "0x6FF23258"
      },
      "rvas": {
        "LoD/1.11": "0x3D8F",
        "LoD/1.11b": "0x2F18",
        "LoD/1.12a": "0x2277",
        "LoD/1.13c": "0x3010",
        "LoD/1.13d": "0x3258"
      },
      "name": "__mtinitlocks",
      "signature": "int __mtinitlocks(void)",
      "comment": "Library Function - Single Match\n __mtinitlocks\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:921d14ea2db8ace7085d489017738fb1"
    },
    "Bnclient_MNE_925a8d581e90": {
      "addresses": {
        "LoD/1.07": "0x6FF315BF",
        "LoD/1.08": "0x6FF315DF",
        "LoD/1.09": "0x6FF121FF",
        "LoD/1.09b": "0x6FF121FF",
        "LoD/1.09d": "0x6FF124EF",
        "LoD/1.10": "0x6FF12A3F"
      },
      "rvas": {
        "LoD/1.07": "0x115BF",
        "LoD/1.08": "0x115DF",
        "LoD/1.09": "0x121FF",
        "LoD/1.09b": "0x121FF",
        "LoD/1.09d": "0x124EF",
        "LoD/1.10": "0x12A3F"
      },
      "name": "GetStreamBasePointer",
      "signature": "int GetStreamBasePointer(int nStreamIndex)",
      "comment": "Retrieves the base data pointer for a valid stream descriptor from the global stream table.\n\nAlgorithm:\n1. Validate stream index against global stream count (g_dwStreamCount)\n2. Calculate bucket index using right shift: nStreamIndex >> 5 (divide by 32)\n3. Calculate element index within bucket: nStreamIndex & 0x1f (modulo 32) \n4. Access stream descriptor using two-level indexing: g_apStreamDescriptors[bucket][element]\n5. Check stream validity flag in nPosition field (bit 0 must be set)\n6. Return pBase pointer if stream is valid and active\n7. Set thread context error code 9 (invalid stream) if validation fails\n8. Clear thread context error code to 0\n9. Return 0xffffffff (-1) to indicate error\n\nParameters:\nnStreamIndex (int): Zero-based index into global stream descriptor table\n\nReturns:\nvoid *: Base data pointer for valid stream, 0xffffffff (-1) on error\n\nSpecial Cases:\nIndex >= g_dwStreamCount: Invalid index, return error\nStream nPosition bit 0 clear: Stream not active/valid, return error\nValid stream: Return actual pBase pointer from StreamIO structure\n\nMagic Numbers Reference:\n0x1f (31): Bit mask for modulo 32 operation (element index within bucket)\n0x5 (5): Right shift count for divide by 32 operation (bucket calculation) \n0x9 (9): Thread context error code for invalid stream access\n0xffffffff (-1): Error return value indicating invalid stream\n\nStructure Layout:\nStreamIO (36 bytes total):\nOffset  Size  Field Name   Type      Description\n0x00    4     pBase        void*     Pointer to stream data buffer\n0x04    4     nPosition    uint      Stream position with validity flag in bit 0\n0x08    28    [other]      [varies]  Additional stream management fields\n\nIndexing Scheme:\nTwo-level bucket system for stream descriptor storage:\n- g_apStreamDescriptors[bucket_index][element_index]\n- bucket_index = nStreamIndex >> 5 (supports up to 32 * bucket_count streams)\n- element_index = nStreamIndex & 0x1f (0-31 within each bucket)\n- Each StreamIO structure is 36 bytes (9 DWORDs)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:925a8d581e90d1850e90a2aaf94686cb"
    },
    "Bnclient_MNE_93d0dc9fd831": {
      "addresses": {
        "LoD/1.11": "0x6FF225DA",
        "LoD/1.11b": "0x6FF23C36",
        "LoD/1.12a": "0x6FF22CFE",
        "LoD/1.13c": "0x6FF23852",
        "LoD/1.13d": "0x6FF231E1"
      },
      "rvas": {
        "LoD/1.11": "0x25DA",
        "LoD/1.11b": "0x3C36",
        "LoD/1.12a": "0x2CFE",
        "LoD/1.13c": "0x3852",
        "LoD/1.13d": "0x31E1"
      },
      "name": "___isctype_mt",
      "signature": "uint ___isctype_mt(void * this, int param_1, int param_2, uint param_3)",
      "comment": "Library Function - Single Match\n ___isctype_mt\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:93d0dc9fd8314e8d90414fa46b2e66d4"
    },
    "Bnclient_MNE_93e58c5dccca": {
      "addresses": {
        "LoD/1.07": "0x6FF29390",
        "LoD/1.08": "0x6FF293B0",
        "LoD/1.09": "0x6FF09FC0",
        "LoD/1.09b": "0x6FF09FC0",
        "LoD/1.09d": "0x6FF0A220",
        "LoD/1.10": "0x6FF0AA80"
      },
      "rvas": {
        "LoD/1.07": "0x9390",
        "LoD/1.08": "0x93B0",
        "LoD/1.09": "0x9FC0",
        "LoD/1.09b": "0x9FC0",
        "LoD/1.09d": "0xA220",
        "LoD/1.10": "0xAA80"
      },
      "name": "LookupStringHashTableEntry",
      "signature": "uint LookupStringHashTableEntry(char * lpszSearchString, uint dwTargetValue)",
      "comment": "Performs hash table lookup for string with target value using triple hash algorithm.\n\nAlgorithm:\n1. Validate input string pointer is not null\n2. Compute first hash value (dwHash1) by iterating through string characters:\n   - Convert each character to uppercase using ConvertCharacterToUpperCase\n   - XOR with lookup table at g_abGlobalStringBuffer._432_4_ + char*4\n   - Accumulate with multiplier 0x21 and offset 3\n3. Compute second hash value (dwHash2) using same string iteration:\n   - Use lookup table at g_abGlobalStringBuffer._432_4_ + 0x400 + char*4\n   - Apply same accumulation algorithm with different table offset\n4. Compute third hash value (dwHash3) using same string iteration:\n   - Use lookup table at g_abGlobalStringBuffer._432_4_ + 0x800 + char*4\n   - Apply same accumulation algorithm with different table offset\n5. Calculate hash table mask from global size at g_abGlobalStringBuffer._424_4_ + 0x18\n6. Apply mask to first hash for initial table index\n7. Perform linear probing search through hash table at g_abGlobalStringBuffer._436_4_:\n   - Check if entry state is 0xffffffff (empty) - return not found\n   - Compare dwHash1 and dwHash2 values with entry[0] and entry[1]\n   - If hashes match and entry state != 0xfffffffe (deleted):\n     - If entry value matches dwTargetValue exactly - return current index\n     - If entry value is 0 (empty slot) - save as potential return index\n   - Advance to next slot with wraparound\n   - Continue until original index reached or match found\n8. Return saved empty slot index or 0xffffffff if no match found\n\nParameters:\nlpszSearchString (char *): Input string to hash and search for (ECX register)\ndwTargetValue (uint): Target value to match in hash table entry (EDX register)\n\nReturns:\nuint: Hash table index of matching entry, empty slot index, or 0xffffffff if not found\n- Exact match: Returns index where both hashes and value match\n- Empty slot: Returns index of first empty slot encountered during search  \n- Not found: Returns 0xffffffff when table is full or no suitable slot found\n\nSpecial Cases:\n- Null input string: Skips hash computation, uses initial hash values 0x7fed7fed\n- Hash collision: Uses linear probing to find next available slot\n- Deleted entries: Entries with state 0xfffffffe are skipped during matching\n- Wraparound search: Search continues from index 0 after reaching table end\n\nMagic Numbers Reference:\n0x7fed7fed: Initial hash seed value\n0x11111112: Initial accumulator seed (negated as -0x11111112)  \n0x21: Hash multiplier constant (33 decimal)\n0x400: Second hash table offset (1024 bytes)\n0x800: Third hash table offset (2048 bytes)\n0x10: Hash table entry stride (16 bytes per HashTableEntry)\n0xffffffff: Empty entry marker\n0xfffffffe: Deleted entry marker\n\nStructure Layout:\nHashTableEntry (16 bytes):\nOffset | Size | Field Name   | Type | Description\n0x00   | 4    | dwHash1      | uint | First hash value for string\n0x04   | 4    | dwHash2      | uint | Second hash value for string  \n0x08   | 4    | dwValue      | uint | Associated value for lookup\n0x0C   | 4    | dwHashState  | uint | Entry state (empty/deleted/used)\n\nGlobal Data Dependencies:\ng_abGlobalStringBuffer._432_4_: Base address of hash lookup tables\ng_abGlobalStringBuffer._424_4_ + 0x18: Hash table size configuration\ng_abGlobalStringBuffer._436_4_: Base address of hash table entries",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:93e58c5dccca18776ed9428a245ffdcd"
    },
    "Bnclient_MNE_940b36171c84": {
      "addresses": {
        "LoD/1.11": "0x6FF367A1",
        "LoD/1.11b": "0x6FF36772",
        "LoD/1.12a": "0x6FF37621",
        "LoD/1.13c": "0x6FF37607",
        "LoD/1.13d": "0x6FF37540"
      },
      "rvas": {
        "LoD/1.11": "0x167A1",
        "LoD/1.11b": "0x16772",
        "LoD/1.12a": "0x17621",
        "LoD/1.13c": "0x17607",
        "LoD/1.13d": "0x17540"
      },
      "name": "_CallSETranslator",
      "signature": "int _CallSETranslator(EHExceptionRecord * param_1, EHRegistrationNode * param_2, void * param_3, void * param_4, _s_FuncInfo * param_5, int param_6, EHRegistrationNode * param_7)",
      "comment": "Library Function - Single Match\n int __cdecl _CallSETranslator(struct EHExceptionRecord *,struct EHRegistrationNode *,void *,void *,struct _s_FuncInfo const *,int,struct EHRegistrationNode *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:940b36171c849cbdb70fa26527e4a4dd"
    },
    "Bnclient_MNE_96131ed5f3d3": {
      "addresses": {
        "LoD/1.07": "0x6FF24D90",
        "LoD/1.08": "0x6FF24DB0",
        "LoD/1.09": "0x6FF05710",
        "LoD/1.09b": "0x6FF05710",
        "LoD/1.09d": "0x6FF05980",
        "LoD/1.10": "0x6FF058F0",
        "LoD/1.11": "0x6FF33900",
        "LoD/1.11b": "0x6FF2E7D0",
        "LoD/1.12a": "0x6FF2EC60",
        "LoD/1.13c": "0x6FF34C90",
        "LoD/1.13d": "0x6FF36400"
      },
      "rvas": {
        "LoD/1.07": "0x4D90",
        "LoD/1.08": "0x4DB0",
        "LoD/1.09": "0x5710",
        "LoD/1.09b": "0x5710",
        "LoD/1.09d": "0x5980",
        "LoD/1.10": "0x58F0",
        "LoD/1.11": "0x13900",
        "LoD/1.11b": "0xE7D0",
        "LoD/1.12a": "0xEC60",
        "LoD/1.13c": "0x14C90",
        "LoD/1.13d": "0x16400"
      },
      "name": "SetCurGateway",
      "signature": "void SetCurGateway(BNGatewayAccess * pThis)",
      "comment": "Sets the current active gateway index for the BNGatewayAccess object.\n\nAlgorithm:\n1. Validate gateway list exists (check non-null pointer at +0x10)\n2. Validate gateway index is positive (greater than 0)\n3. Validate gateway index is within bounds (less than or equal to max count at +0x8)\n4. Cap gateway index to maximum of 99 if exceeds limit\n5. Store validated gateway index in current gateway field (+0xc)\n6. Set gateway active status flag (+0x4) to 1\n\nParameters:\npThis (BNGatewayAccess *): Pointer to BNGatewayAccess object instance\nIMPLICIT in_stack_00000008 (int): Gateway index to set as current (1-based indexing)\n\nReturns:\nvoid: No return value, operates on object state\n\nSpecial Cases:\nMagic Numbers: 0x63 (99) - Maximum allowed gateway index limit\nInvalid cases cause early return without state changes:\n- Gateway list pointer is NULL\n- Gateway index is zero or negative\n- Gateway index exceeds object's gateway count\n\nStructure Layout:\nOffset | Size | Field Name        | Type | Description\n+0x4   | 4    | gatewayActive     | uint | Gateway selection active flag (0=inactive, 1=active)\n+0x8   | 4    | maxGatewayCount   | uint | Maximum number of gateways available\n+0xc   | 4    | currentGateway    | uint | Currently selected gateway index (1-based)\n+0x10  | 4    | pGatewayList      | ptr  | Pointer to gateway list data",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:96131ed5f3d37376d0de306cde37149c"
    },
    "Bnclient_MNE_961a148416f4": {
      "addresses": {
        "LoD/1.07": "0x6FF25780",
        "LoD/1.08": "0x6FF257A0",
        "LoD/1.09": "0x6FF06100",
        "LoD/1.09b": "0x6FF06100",
        "LoD/1.09d": "0x6FF06370",
        "LoD/1.10": "0x6FF062D0"
      },
      "rvas": {
        "LoD/1.07": "0x5780",
        "LoD/1.08": "0x57A0",
        "LoD/1.09": "0x6100",
        "LoD/1.09b": "0x6100",
        "LoD/1.09d": "0x6370",
        "LoD/1.10": "0x62D0"
      },
      "name": "InitializeGlobalCriticalSection",
      "signature": "uint InitializeGlobalCriticalSection(void)",
      "comment": "Initializes the global critical section embedded in g_abGlobalStringBuffer.\n\nAlgorithm:\n1. Zero out SpinCount and related fields at buffer offsets 0x14c-0x157 (12 bytes total)\n2. Initialize the CRITICAL_SECTION structure at buffer offset 0x130\n3. Return success status (1)\n\nParameters:\nNone\n\nReturns:\n1 (uint) - Always returns success\n\nSpecial Cases:\nThe function clears 12 bytes starting at offset 0x14c which corresponds to the\nSpinCount and DebugInfo fields of the CRITICAL_SECTION structure before\ninitializing it with InitializeCriticalSection.\n\nMagic Numbers Reference:\n0x130 - Offset within g_abGlobalStringBuffer where CRITICAL_SECTION begins\n0x14c - Start offset for SpinCount field clearing (0x130 + 0x1c)\n0x157 - End offset for field clearing (0x14c + 12 bytes)\n0x1 - Success return value",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:961a148416f414084be53ece44c5b604"
    },
    "Bnclient_MNE_966ae3d3931d": {
      "addresses": {
        "LoD/1.07": "0x6FF2C034",
        "LoD/1.08": "0x6FF2C054",
        "LoD/1.09": "0x6FF0CC54",
        "LoD/1.09b": "0x6FF0CC54",
        "LoD/1.09d": "0x6FF0CF64",
        "LoD/1.10": "0x6FF0D4CA"
      },
      "rvas": {
        "LoD/1.07": "0xC034",
        "LoD/1.08": "0xC054",
        "LoD/1.09": "0xCC54",
        "LoD/1.09b": "0xCC54",
        "LoD/1.09d": "0xCF64",
        "LoD/1.10": "0xD4CA"
      },
      "name": "DllMain",
      "signature": "bool DllMain(void * phinstDLL, uint dwReason)",
      "comment": "DLL entry point that handles process and thread attach/detach notifications.\n\nAlgorithm:\n1. Check dwReason parameter to determine DLL notification type\n2. DLL_PROCESS_ATTACH (1): Initialize DLL when process loads\n   a. Call GetVersion() to get Windows version and store in global\n   b. Extract version components: major (low byte), minor (second byte), build (high word)\n   c. Store version data in separate globals for compatibility checks\n   d. Call initialization routine to verify DLL can load\n   e. Get command line with GetCommandLineA() for argument parsing\n   f. Initialize core subsystems in sequence\n   g. Increment process reference counter\n3. DLL_PROCESS_DETACH (0): Cleanup when process unloads\n   a. Check if process reference counter is positive\n   b. Decrement process reference counter\n   c. Check cleanup flag and call cleanup routine if needed\n   d. Shutdown subsystems in reverse order\n4. DLL_THREAD_DETACH (3): Handle thread cleanup\n   a. Call thread-specific cleanup routine with NULL parameter\n5. Return appropriate status code\n\nParameters:\nphinstDLL (void *): HINSTANCE handle to DLL instance (Windows opaque handle type)\n  IMPLICIT: Parameter passed but not used in this implementation\ndwReason (uint): Reason for calling DLL entry point\n  - 1 (DLL_PROCESS_ATTACH): Process is loading DLL\n  - 0 (DLL_PROCESS_DETACH): Process is unloading DLL  \n  - 3 (DLL_THREAD_DETACH): Thread is exiting\n\nReturns:\nbool: Success status\n  - true (1): DLL initialization/cleanup succeeded\n  - false (0): DLL initialization failed, prevent DLL loading\n\nSpecial Cases:\n- DLL_PROCESS_ATTACH: Returns false if version check or initialization fails\n- DLL_PROCESS_DETACH: Only performs cleanup if reference counter > 0\n- DLL_THREAD_ATTACH (2): Not handled, falls through to return true\n- Invalid dwReason values: Fall through to return true\n\nMagic Numbers Reference:\n0x1 - DLL_PROCESS_ATTACH constant\n0x0 - DLL_PROCESS_DETACH constant  \n0x3 - DLL_THREAD_DETACH constant\n0xff - Byte mask for extracting version components\n0x8 - Bit shift for extracting minor version (second byte)\n0x10 - Bit shift for extracting build number (high word)\n0x100 - Multiplier for combining major and minor version\n\nError Handling:\n- Version API failure: Continues with uninitialized version globals\n- Initialization failure: Returns false to prevent DLL loading\n- Cleanup errors: No error propagation, always returns true for detach\n\nType Design Notes:\n- HINSTANCE parameter correctly typed as void* (Windows opaque handle convention)\n- SSA temporaries (fResult, nTempResult) used for intermediate calculations",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:966ae3d3931d4719f3b38eb61e43e94b"
    },
    "Bnclient_MNE_9696a1fa07b4": {
      "addresses": {
        "LoD/1.07": "0x6FF2D938",
        "LoD/1.08": "0x6FF2D958",
        "LoD/1.09": "0x6FF0E558",
        "LoD/1.09b": "0x6FF0E558",
        "LoD/1.09d": "0x6FF0E868",
        "LoD/1.10": "0x6FF0EDD0"
      },
      "rvas": {
        "LoD/1.07": "0xD938",
        "LoD/1.08": "0xD958",
        "LoD/1.09": "0xE558",
        "LoD/1.09b": "0xE558",
        "LoD/1.09d": "0xE868",
        "LoD/1.10": "0xEDD0"
      },
      "name": "ReadLongLongAndAdvancePointer",
      "signature": "longlong ReadLongLongAndAdvancePointer(uint * * ppnArgsPtr)",
      "comment": "ReadLongLongAndAdvancePointer - reads 8-byte value from variable arguments pointer and advances pointer\n\nAlgorithm:\n1. Dereference pointer to get current position in arguments array\n2. Advance the pointer by 8 bytes (2 * sizeof(uint)) to skip over the 8-byte value\n3. Read and return the 8-byte value from the original position before advancement\n\nParameters:\n  ppnArgsPtr (uint **) - pointer to variable arguments array pointer, modified in place\n\nReturns:\n  longlong - 8-byte signed integer value read from the arguments array\n\nSpecial Cases:\n  - Used specifically for I64 length modifier in printf format processing\n  - Advances pointer by exactly 8 bytes regardless of actual data alignment\n  - Reads value from position before advancement (offset -8 from new position)\n\nMagic Numbers Reference:\n  0x8 - size in bytes of 64-bit value (2 * sizeof(uint))\n  -0x8 - negative offset to read value from position before advancement",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:9696a1fa07b46e8a513683c75ff67fe3"
    },
    "Bnclient_MNE_96b57c2abe5d": {
      "addresses": {
        "LoD/1.11": "0x6FF27698",
        "LoD/1.11b": "0x6FF27618",
        "LoD/1.12a": "0x6FF27A67",
        "LoD/1.13c": "0x6FF279CF",
        "LoD/1.13d": "0x6FF2767A"
      },
      "rvas": {
        "LoD/1.11": "0x7698",
        "LoD/1.11b": "0x7618",
        "LoD/1.12a": "0x7A67",
        "LoD/1.13c": "0x79CF",
        "LoD/1.13d": "0x767A"
      },
      "name": "__lseeki64_lk",
      "signature": "undefined8 __lseeki64_lk(uint param_1, LONG param_2, LONG param_3, DWORD param_4)",
      "comment": "Library Function - Single Match\n __lseeki64_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:96b57c2abe5dc5792785a0347b715545"
    },
    "Bnclient_MNE_9765460a3049": {
      "addresses": {
        "LoD/1.07": "0x6FF2E4FE",
        "LoD/1.08": "0x6FF2E51E",
        "LoD/1.09": "0x6FF0F149",
        "LoD/1.09b": "0x6FF0F149",
        "LoD/1.09d": "0x6FF0F42E",
        "LoD/1.10": "0x6FF0FA1C",
        "LoD/1.11": "0x6FF24914",
        "LoD/1.11b": "0x6FF24904",
        "LoD/1.12a": "0x6FF24975",
        "LoD/1.13c": "0x6FF24975",
        "LoD/1.13d": "0x6FF24974"
      },
      "rvas": {
        "LoD/1.07": "0xE4FE",
        "LoD/1.08": "0xE51E",
        "LoD/1.09": "0xF149",
        "LoD/1.09b": "0xF149",
        "LoD/1.09d": "0xF42E",
        "LoD/1.10": "0xFA1C",
        "LoD/1.11": "0x4914",
        "LoD/1.11b": "0x4904",
        "LoD/1.12a": "0x4975",
        "LoD/1.13c": "0x4975",
        "LoD/1.13d": "0x4974"
      },
      "name": "ProcessExitCleanup",
      "signature": "void ProcessExitCleanup(void)",
      "comment": "Processes application exit cleanup when exit conditions are met.\n\nAlgorithm:\n1. Check primary exit flag (g_dwExitFlag1) for value 1\n2. If not set, check if primary flag is 0 AND secondary flag (g_dwExitFlag2) is 1\n3. If either condition true, execute cleanup sequence:\n   a. Call cleanup handler with shutdown code 0xFC\n   b. Execute optional exit callback if function pointer exists\n   c. Call cleanup handler with finalization code 0xFF\n4. Return after cleanup or if no exit conditions met\n\nParameters:\nNone (void function)\n\nReturns:\nNone (void function)\n\nSpecial Cases:\n- If g_dwExitFlag1 is neither 0 nor 1, no cleanup is performed\n- Exit callback at DAT_6ff3a050 is optional (null check performed)\n- Function is idempotent and safe to call multiple times\n\nMagic Numbers Reference:\n0xFC (252) - Shutdown preparation code for cleanup handler\n0xFF (255) - Final cleanup/termination code for cleanup handler",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:9765460a30498931557fab10cfc0be00"
    },
    "Bnclient_MNE_9782a399963b": {
      "addresses": {
        "LoD/1.11": "0x6FF2E6B0",
        "LoD/1.11b": "0x6FF309D0",
        "LoD/1.12a": "0x6FF36750",
        "LoD/1.13c": "0x6FF36810",
        "LoD/1.13d": "0x6FF2B5A0"
      },
      "rvas": {
        "LoD/1.11": "0xE6B0",
        "LoD/1.11b": "0x109D0",
        "LoD/1.12a": "0x16750",
        "LoD/1.13c": "0x16810",
        "LoD/1.13d": "0xB5A0"
      },
      "method": "MNE",
      "index": "MNE:9782a399963b8fbb6acccf4f575c9f56"
    },
    "Bnclient_MNE_97c22a850703": {
      "addresses": {
        "LoD/1.11": "0x6FF22D87",
        "LoD/1.11b": "0x6FF22318",
        "LoD/1.12a": "0x6FF233EE",
        "LoD/1.13c": "0x6FF227C6",
        "LoD/1.13d": "0x6FF2238D"
      },
      "rvas": {
        "LoD/1.11": "0x2D87",
        "LoD/1.11b": "0x2318",
        "LoD/1.12a": "0x33EE",
        "LoD/1.13c": "0x27C6",
        "LoD/1.13d": "0x238D"
      },
      "name": "write_char",
      "signature": "undefined write_char(void)",
      "comment": "Library Function - Single Match\n _write_char\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:97c22a85070344f102bcf14ee4f0ea92"
    },
    "Bnclient_MNE_97e3a914c5f8": {
      "addresses": {
        "LoD/1.12a": "0x6FF21020",
        "LoD/1.13c": "0x6FF21240",
        "LoD/1.13d": "0x6FF21240"
      },
      "rvas": {
        "LoD/1.12a": "0x1020",
        "LoD/1.13c": "0x1240",
        "LoD/1.13d": "0x1240"
      },
      "method": "MNE",
      "index": "MNE:97e3a914c5f88486e2298321854664e5"
    },
    "Bnclient_MNE_9882f49b4616": {
      "addresses": {
        "LoD/1.11": "0x6FF23F13",
        "LoD/1.11b": "0x6FF2309C",
        "LoD/1.12a": "0x6FF223FB",
        "LoD/1.13c": "0x6FF23194",
        "LoD/1.13d": "0x6FF233DC"
      },
      "rvas": {
        "LoD/1.11": "0x3F13",
        "LoD/1.11b": "0x309C",
        "LoD/1.12a": "0x23FB",
        "LoD/1.13c": "0x3194",
        "LoD/1.13d": "0x33DC"
      },
      "name": "__RTC_Initialize",
      "signature": "undefined __RTC_Initialize(void)",
      "comment": "Library Function - Single Match\n __RTC_Initialize\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:9882f49b46164551a852d0e5558c3763"
    },
    "Bnclient_MNE_98eebec3741b": {
      "addresses": {
        "LoD/1.07": "0x6FF2B3AB",
        "LoD/1.08": "0x6FF2B3CC",
        "LoD/1.09": "0x6FF0BFCC",
        "LoD/1.09b": "0x6FF0BFCC",
        "LoD/1.09d": "0x6FF0C22B",
        "LoD/1.10": "0x6FF0C78B",
        "LoD/1.11": "0x6FF21D98",
        "LoD/1.11b": "0x6FF2129B",
        "LoD/1.12a": "0x6FF21ACB",
        "LoD/1.13c": "0x6FF215FF",
        "LoD/1.13d": "0x6FF21723"
      },
      "rvas": {
        "LoD/1.07": "0xB3AB",
        "LoD/1.08": "0xB3CC",
        "LoD/1.09": "0xBFCC",
        "LoD/1.09b": "0xBFCC",
        "LoD/1.09d": "0xC22B",
        "LoD/1.10": "0xC78B",
        "LoD/1.11": "0x1D98",
        "LoD/1.11b": "0x129B",
        "LoD/1.12a": "0x1ACB",
        "LoD/1.13c": "0x15FF",
        "LoD/1.13d": "0x1723"
      },
      "name": "Rand",
      "signature": "int Rand(void)",
      "comment": "Generates a pseudo-random number using linear congruential generator algorithm.\n\nAlgorithm:\n1. Get thread-local storage data structure containing random number generator state\n2. Load current seed value from TLS offset 0x14 (field [5])\n3. Apply linear congruential formula: new_seed = (old_seed * 0x343fd) + 0x269ec3\n4. Store updated seed back to TLS structure for next call\n5. Return upper 15 bits of seed (shifted right 16, masked with 0x7fff)\n\nParameters:\nNone\n\nReturns:\nint: Pseudo-random number in range 0 to 32767 (0x7fff)\n     Upper 15 bits of internal 32-bit seed value\n\nMagic Numbers Reference:\n0x343fd (214013): LCG multiplier constant\n0x269ec3 (2531011): LCG addend constant  \n0x14 (20): TLS structure offset to random seed storage\n0x10 (16): Right shift count to extract upper bits\n0x7fff (32767): Bitmask to limit range to 15 bits (max positive signed 16-bit)\n\nError Handling:\nDelegates to FUN_6ff2c262 for TLS allocation and error handling\nNo local error checking - assumes valid TLS data structure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:98eebec3741bc1addf7fafbeff16d621"
    },
    "Bnclient_MNE_9915db1b6011": {
      "addresses": {
        "LoD/1.07": "0x6FF26B10",
        "LoD/1.08": "0x6FF26B30",
        "LoD/1.09": "0x6FF070A0",
        "LoD/1.09b": "0x6FF070A0",
        "LoD/1.09d": "0x6FF07310",
        "LoD/1.10": "0x6FF07A80"
      },
      "rvas": {
        "LoD/1.07": "0x6B10",
        "LoD/1.08": "0x6B30",
        "LoD/1.09": "0x70A0",
        "LoD/1.09b": "0x70A0",
        "LoD/1.09d": "0x7310",
        "LoD/1.10": "0x7A80"
      },
      "name": "ReleaseGlobalBuffer",
      "signature": "void ReleaseGlobalBuffer(void)",
      "comment": "Releases allocated memory buffer and resets global buffer allocation state.\n\nAlgorithm:\n1. Check if global buffer has active allocation pointer at offset 0x356\n2. If allocated, call Ordinal_10043 to free the memory with parameters (0x1d4, 0)\n3. Clear 4-byte allocation pointer at g_abGlobalStringBuffer offset 0x356\n4. Reset buffer header state by zeroing 4 consecutive bytes at offsets 0x164-0x167\n\nParameters:\nvoid: No parameters required\n\nReturns:\nvoid: No return value, success indicated by cleared global buffer state\n\nSpecial Cases:\n- No allocation present: Function completes safely without error\n- Double-free protection: Allocation pointer checked before freeing\n\nMagic Numbers Reference:\n0x1d4 (468): Ordinal parameter for memory deallocation function\n0x356 (854): Offset to allocation pointer in global string buffer  \n0x164 (356): Start offset of 4-byte buffer header state field\n\nStructure Layout:\nGlobal Buffer (g_abGlobalStringBuffer):\nOffset | Size | Field Name    | Type  | Description\n0x164  | 4    | headerState   | uint  | Buffer header/state flags\n0x356  | 4    | pAllocation   | void* | Pointer to allocated memory block",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:9915db1b6011f72a4ebe0dc45a742999"
    },
    "Bnclient_MNE_99486f21581c": {
      "addresses": {
        "LoD/1.11": "0x6FF21DBA",
        "LoD/1.11b": "0x6FF21F2D",
        "LoD/1.12a": "0x6FF21DC2",
        "LoD/1.13c": "0x6FF21E1F",
        "LoD/1.13d": "0x6FF21FA2"
      },
      "rvas": {
        "LoD/1.11": "0x1DBA",
        "LoD/1.11b": "0x1F2D",
        "LoD/1.12a": "0x1DC2",
        "LoD/1.13c": "0x1E1F",
        "LoD/1.13d": "0x1FA2"
      },
      "name": "_isdigit",
      "signature": "int _isdigit(int _C)",
      "comment": "Library Function - Single Match\n _isdigit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:99486f21581ce5ab9e85ee964f03efa4"
    },
    "Bnclient_MNE_996569cbec98": {
      "addresses": {
        "LoD/1.11": "0x6FF296F0",
        "LoD/1.11b": "0x6FF296F0",
        "LoD/1.12a": "0x6FF29D20",
        "LoD/1.13c": "0x6FF29D00",
        "LoD/1.13d": "0x6FF29D10"
      },
      "rvas": {
        "LoD/1.11": "0x96F0",
        "LoD/1.11b": "0x96F0",
        "LoD/1.12a": "0x9D20",
        "LoD/1.13c": "0x9D00",
        "LoD/1.13d": "0x9D10"
      },
      "method": "MNE",
      "index": "MNE:996569cbec98d4b86028ce8125738a27"
    },
    "Bnclient_MNE_996e3f0c6129": {
      "addresses": {
        "LoD/1.11": "0x6FF21BBF",
        "LoD/1.11b": "0x6FF21338",
        "LoD/1.12a": "0x6FF212DE",
        "LoD/1.13c": "0x6FF21424",
        "LoD/1.13d": "0x6FF215A0"
      },
      "rvas": {
        "LoD/1.11": "0x1BBF",
        "LoD/1.11b": "0x1338",
        "LoD/1.12a": "0x12DE",
        "LoD/1.13c": "0x1424",
        "LoD/1.13d": "0x15A0"
      },
      "name": "__initterm",
      "signature": "undefined __initterm(undefined4 * param_1)",
      "comment": "Library Function - Single Match\n __initterm\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:996e3f0c6129985d37a2b36d657b6892"
    },
    "Bnclient_MNE_99acdabe6d3a": {
      "addresses": {
        "LoD/1.07": "0x6FF2B720",
        "LoD/1.08": "0x6FF2B740",
        "LoD/1.09": "0x6FF0C340",
        "LoD/1.09b": "0x6FF0C340",
        "LoD/1.09d": "0x6FF0C670",
        "LoD/1.10": "0x6FF0CBD0"
      },
      "rvas": {
        "LoD/1.07": "0xB720",
        "LoD/1.08": "0xB740",
        "LoD/1.09": "0xC340",
        "LoD/1.09b": "0xC340",
        "LoD/1.09d": "0xC670",
        "LoD/1.10": "0xCBD0"
      },
      "name": "FindLastCharacterOccurrence",
      "signature": "char * FindLastCharacterOccurrence(char * lpszString, int nCharacter)",
      "comment": "Finds the last occurrence of a character in a string using backward search optimization.\n\nAlgorithm:\n1. Find the end of the string by scanning forward for null terminator using REPNE SCASB\n2. Calculate string length by negating and adjusting the counter from step 1\n3. Set direction flag (STD) for backward scanning from end of string\n4. Search backward for target character using REPNE SCASB with decremented counter\n5. Check if character at current position matches target character\n6. Return pointer to character if found, otherwise return NULL\n\nParameters:\nlpszString (char *): Null-terminated string to search in\nnCharacter (int): Character to find (passed as int but used as char)\n\nReturns:\nchar *: Pointer to last occurrence of character in string\nNULL (0x0): Character not found in string\n\nSpecial Cases:\nSearch character 0x00 (null terminator): Returns pointer to string terminator\nEmpty string input: Returns NULL immediately\nCharacter not present: Returns NULL after full backward scan\n\nMagic Numbers Reference:\n0xffffffff: Initial counter value for REPNE SCASB (scan unlimited)\n0x0: NULL return value when character not found",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:99acdabe6d3af6d62646118ba964cdfb"
    },
    "Bnclient_MNE_9afcf8355cba": {
      "addresses": {
        "LoD/1.10": "0x6FF02010",
        "LoD/1.11": "0x6FF237F0",
        "LoD/1.11b": "0x6FF23555",
        "LoD/1.12a": "0x6FF23EAF",
        "LoD/1.13c": "0x6FF23CF4",
        "LoD/1.13d": "0x6FF23904"
      },
      "rvas": {
        "LoD/1.10": "0x2010",
        "LoD/1.11": "0x37F0",
        "LoD/1.11b": "0x3555",
        "LoD/1.12a": "0x3EAF",
        "LoD/1.13c": "0x3CF4",
        "LoD/1.13d": "0x3904"
      },
      "name": "_free",
      "signature": "void _free(void * _Memory)",
      "comment": "Library Function - Single Match\n _free\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:9afcf8355cbadc30be8a17f37332337f"
    },
    "Bnclient_MNE_9b01511769ac": {
      "addresses": {
        "LoD/1.09d": "0x6FF0CE30",
        "LoD/1.10": "0x6FF0D3D0",
        "LoD/1.11": "0x6FF36A90",
        "LoD/1.11b": "0x6FF36A60",
        "LoD/1.12a": "0x6FF37910",
        "LoD/1.13c": "0x6FF378F0",
        "LoD/1.13d": "0x6FF37830"
      },
      "rvas": {
        "LoD/1.09d": "0xCE30",
        "LoD/1.10": "0xD3D0",
        "LoD/1.11": "0x16A90",
        "LoD/1.11b": "0x16A60",
        "LoD/1.12a": "0x17910",
        "LoD/1.13c": "0x178F0",
        "LoD/1.13d": "0x17830"
      },
      "name": "__alldiv",
      "signature": "undefined8 __alldiv(uint param_1, uint param_2, uint param_3, uint param_4)",
      "comment": "Library Function - Single Match\n __alldiv\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.09d",
      "method": "MNE",
      "index": "MNE:9b01511769ac441c2a2af1e484a6e426"
    },
    "Bnclient_MNE_9c858eb5fe1e": {
      "addresses": {
        "LoD/1.07": "0x6FF2D956",
        "LoD/1.08": "0x6FF2D976",
        "LoD/1.09": "0x6FF0E576",
        "LoD/1.09b": "0x6FF0E576",
        "LoD/1.09d": "0x6FF0E886",
        "LoD/1.10": "0x6FF0EE74"
      },
      "rvas": {
        "LoD/1.07": "0xD956",
        "LoD/1.08": "0xD976",
        "LoD/1.09": "0xE576",
        "LoD/1.09b": "0xE576",
        "LoD/1.09d": "0xE886",
        "LoD/1.10": "0xEE74"
      },
      "name": "ConvertDateTimeToTimestamp",
      "signature": "int ConvertDateTimeToTimestamp(int nYear, int nMonth, int nDay, int nHour, int nMinute, int nSecond, int nDaylightSavingFlag)",
      "comment": "Converts date and time components to a Unix-style timestamp value.\n\nAlgorithm:\n1. Validate year is in supported range (1900-1994, offset from 0x76c base)\n2. Return -1 if year is outside valid range [0x46, 0x8a] from base\n3. Calculate cumulative days from month table at g_adDaysInMonths[nMonth]\n4. Add specified day to cumulative month days\n5. Apply leap year adjustment: if year divisible by 4 and month > 2, add 1 day\n6. Call FUN_6ff306b5() to update internal state\n7. Calculate total timestamp: ((nHour + (yearOffset * 365 + daysFromMonth + (year-1)/4) * 24) * 60 + nMinute) * 60 + baseOffset + second\n8. Apply timezone adjustment if nDaylightSavingFlag == 1 or timezone check passes\n9. Return final timestamp value\n\nParameters:\nnYear - Year value (1900-1994 supported range)\nnMonth - Month index (0-11, used to index days table)\nnDay - Day of month (1-31)\nnHour - Hour component (0-23)\nnMinute - Minute component (0-59) \nnSecond - Second component (0-59)\nnDaylightSavingFlag - DST flag: 1=apply DST, -1=check timezone, 0=standard time\n\nReturns:\nCalculated timestamp as signed integer\n-1 if year is outside supported range\n\nSpecial Cases:\nLeap year handling: Years divisible by 4 get +1 day if month > February\nTimezone adjustment: Applied based on g_dwTimezoneFlag and DST settings\nBase offset: 0x7c558180 provides epoch adjustment\n\nMagic Numbers Reference:\n0x76c (1900) - Base year offset for calculations\n0x46 (70) - Minimum year offset (1970)\n0x8a (138) - Maximum year offset (2038)\n0x16d (365) - Days per year for calculation\n0x18 (24) - Hours per day\n0x3c (60) - Minutes per hour, seconds per minute\n0x7c558180 - Unix epoch base offset\n\nGlobal Data Access:\ng_adDaysInMonths[0x6ff38f24] - Table of cumulative days per month\ng_dwTimezoneOffset[0x6ff38e40] - Timezone offset value\ng_dwTimezoneFlag[0x6ff38e44] - Timezone enabled flag\ng_dwDaylightAdjust[0x6ff38e48] - Daylight savings time adjustment",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:9c858eb5fe1ec691a02f47fae502b1b8"
    },
    "Bnclient_MNE_9ca8b994d17a": {
      "addresses": {
        "LoD/1.11": "0x6FF375A0",
        "LoD/1.11b": "0x6FF37570",
        "LoD/1.12a": "0x6FF38420",
        "LoD/1.13c": "0x6FF38400",
        "LoD/1.13d": "0x6FF38340"
      },
      "rvas": {
        "LoD/1.11": "0x175A0",
        "LoD/1.11b": "0x17570",
        "LoD/1.12a": "0x18420",
        "LoD/1.13c": "0x18400",
        "LoD/1.13d": "0x18340"
      },
      "name": "_raise",
      "signature": "int _raise(int _SigNum)",
      "comment": "Library Function - Single Match\n _raise\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:9ca8b994d17aa0674346136517490025"
    },
    "Bnclient_MNE_9d9b1aee8517": {
      "addresses": {
        "LoD/1.07": "0x6FF22940",
        "LoD/1.08": "0x6FF22960",
        "LoD/1.09": "0x6FF032B0",
        "LoD/1.09b": "0x6FF032B0",
        "LoD/1.09d": "0x6FF032C0",
        "LoD/1.10": "0x6FF03310"
      },
      "rvas": {
        "LoD/1.07": "0x2940",
        "LoD/1.08": "0x2960",
        "LoD/1.09": "0x32B0",
        "LoD/1.09b": "0x32B0",
        "LoD/1.09d": "0x32C0",
        "LoD/1.10": "0x3310"
      },
      "name": "ProcessPacketSynchronized",
      "signature": "bool ProcessPacketSynchronized(int nPacketType, int nPacketData)",
      "comment": "Thread-safe wrapper for packet processing ordinal function\n\nAlgorithm:\n1. Enter critical section using packet handler critical section (offset 0xad)\n2. Call ordinal function Ordinal_491 with packet type and data parameters\n3. Leave critical section to release synchronization lock\n4. Return success status (always returns true)\n\nParameters:\n- dwPacketType (int): Packet type identifier passed to ordinal handler\n- dwPacketData (int): Packet data content passed to ordinal handler\n\nReturns:\n- bool: Always returns true indicating successful processing\n\nSpecial Cases:\n- Critical section at g_apfnPacketHandlers + 0xad provides thread synchronization\n- Ordinal_491 is the actual packet processing function at 0x6ff398f0\n- Function acts as synchronized wrapper ensuring atomic packet processing\n\nError Handling:\n- No explicit error handling - relies on critical section and ordinal function\n- Always returns true regardless of ordinal function behavior",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:9d9b1aee8517e59520d7a0058383a02e"
    },
    "Bnclient_MNE_9dba01f3a3f5": {
      "addresses": {
        "LoD/1.12a": "0x6FF26758",
        "LoD/1.13c": "0x6FF26348"
      },
      "rvas": {
        "LoD/1.12a": "0x6758",
        "LoD/1.13c": "0x6348"
      },
      "method": "MNE",
      "index": "MNE:9dba01f3a3f519a348d690b818dfa854"
    },
    "Bnclient_MNE_9dfbd1c154e2": {
      "addresses": {
        "LoD/1.11": "0x6FF2F6B0",
        "LoD/1.11b": "0x6FF35F40",
        "LoD/1.12a": "0x6FF31F90",
        "LoD/1.13c": "0x6FF36070",
        "LoD/1.13d": "0x6FF35AD0"
      },
      "rvas": {
        "LoD/1.11": "0xF6B0",
        "LoD/1.11b": "0x15F40",
        "LoD/1.12a": "0x11F90",
        "LoD/1.13c": "0x16070",
        "LoD/1.13d": "0x15AD0"
      },
      "method": "MNE",
      "index": "MNE:9dfbd1c154e276215f386aab8b7799fc",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF0D15A",
          "rva": "0xD15A",
          "confidence": 0.398,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF0CAB0",
          "rva": "0xCAB0",
          "confidence": 0.323,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF0C850",
          "rva": "0xC850",
          "confidence": 0.212,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_9e01ab6a0c2f": {
      "addresses": {
        "LoD/1.07": "0x6FF305D0",
        "LoD/1.08": "0x6FF305F0",
        "LoD/1.09": "0x6FF11210",
        "LoD/1.09b": "0x6FF11210",
        "LoD/1.09d": "0x6FF11500",
        "LoD/1.10": "0x6FF11A50",
        "LoD/1.11": "0x6FF22B30",
        "LoD/1.11b": "0x6FF22EB0",
        "LoD/1.12a": "0x6FF228C0",
        "LoD/1.13c": "0x6FF23530",
        "LoD/1.13d": "0x6FF235C0"
      },
      "rvas": {
        "LoD/1.07": "0x105D0",
        "LoD/1.08": "0x105F0",
        "LoD/1.09": "0x11210",
        "LoD/1.09b": "0x11210",
        "LoD/1.09d": "0x11500",
        "LoD/1.10": "0x11A50",
        "LoD/1.11": "0x2B30",
        "LoD/1.11b": "0x2EB0",
        "LoD/1.12a": "0x28C0",
        "LoD/1.13c": "0x3530",
        "LoD/1.13d": "0x35C0"
      },
      "name": "AullDiv",
      "signature": "ulonglong AullDiv(uint dwDividendLow, uint dwDividendHigh, uint dwDivisorLow, uint dwDivisorHigh)",
      "comment": "Performs 64-bit unsigned integer division (__aulldiv runtime library function).\n\nAlgorithm:\n1. Combine 32-bit parameter pairs into 64-bit dividend and divisor values\n2. Check if divisor high word is zero (simple 64/32 division case)\n3. Simple case: Use 32-bit division operations to compute quotient directly\n4. Complex case: Normalize both operands by shifting right until divisor fits in 32 bits\n5. Perform approximate division using normalized 32-bit values\n6. Multiply trial quotient by original divisor to get product\n7. Compare product with original dividend to verify quotient accuracy\n8. Decrement quotient if product exceeds dividend (correction step)\n9. Return 64-bit quotient as combined high/low 32-bit words\n\nParameters:\n  dwDividendLow   - Low 32 bits of 64-bit dividend\n  dwDividendHigh  - High 32 bits of 64-bit dividend  \n  dwDivisorLow    - Low 32 bits of 64-bit divisor\n  dwDivisorHigh   - High 32 bits of 64-bit divisor\n\nReturns:\n  Success: 64-bit quotient (dividend / divisor)\n  \nSpecial Cases:\n  Division by zero: Undefined behavior (not validated)\n  Overflow: Cannot occur with unsigned division\n  \nAlgorithm Details:\n  - Uses binary long division when divisor > 32 bits\n  - Normalizes operands to avoid overflow during intermediate calculations\n  - Trial-and-error approach with correction ensures accuracy\n  - Optimized for common case where divisor fits in 32 bits",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:9e01ab6a0c2f67c73794c17804322b4d"
    },
    "Bnclient_MNE_9e5265f16e6b": {
      "addresses": {
        "LoD/1.10": "0x6FF0C2B0"
      },
      "rvas": {
        "LoD/1.10": "0xC2B0"
      },
      "method": "MNE",
      "index": "MNE:9e5265f16e6ba9b8f3cd18687396a69d"
    },
    "Bnclient_MNE_9ed74c09db5e": {
      "addresses": {
        "LoD/1.11": "0x6FF36868",
        "LoD/1.11b": "0x6FF36839",
        "LoD/1.12a": "0x6FF376E8",
        "LoD/1.13c": "0x6FF376CE",
        "LoD/1.13d": "0x6FF37607"
      },
      "rvas": {
        "LoD/1.11": "0x16868",
        "LoD/1.11b": "0x16839",
        "LoD/1.12a": "0x176E8",
        "LoD/1.13c": "0x176CE",
        "LoD/1.13d": "0x17607"
      },
      "name": "TranslatorGuardHandler",
      "signature": "_EXCEPTION_DISPOSITION TranslatorGuardHandler(EHExceptionRecord * param_1, TranslatorGuardRN * param_2, void * param_3, void * param_4)",
      "comment": "Library Function - Single Match\n enum _EXCEPTION_DISPOSITION __cdecl TranslatorGuardHandler(struct EHExceptionRecord *,struct TranslatorGuardRN *,void *,void *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:9ed74c09db5ea664214a06af5e9eacff"
    },
    "Bnclient_MNE_9fd359b66679": {
      "addresses": {
        "LoD/1.11": "0x6FF23D50",
        "LoD/1.11b": "0x6FF23FDB",
        "LoD/1.12a": "0x6FF23CF1",
        "LoD/1.13c": "0x6FF23DF8",
        "LoD/1.13d": "0x6FF23C98"
      },
      "rvas": {
        "LoD/1.11": "0x3D50",
        "LoD/1.11b": "0x3FDB",
        "LoD/1.12a": "0x3CF1",
        "LoD/1.13c": "0x3DF8",
        "LoD/1.13d": "0x3C98"
      },
      "name": "report_failure",
      "signature": "undefined report_failure(void)",
      "comment": "Library Function - Single Match\n _report_failure\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:9fd359b66679d8b6a2f1c57a264fe596"
    },
    "Bnclient_MNE_a0707ad44a57": {
      "addresses": {
        "LoD/1.07": "0x6FF2C392",
        "LoD/1.08": "0x6FF2C226",
        "LoD/1.09": "0x6FF0CE26",
        "LoD/1.09b": "0x6FF0CE26",
        "LoD/1.09d": "0x6FF0D2C2",
        "LoD/1.10": "0x6FF0D828"
      },
      "rvas": {
        "LoD/1.07": "0xC392",
        "LoD/1.08": "0xC226",
        "LoD/1.09": "0xCE26",
        "LoD/1.09b": "0xCE26",
        "LoD/1.09d": "0xD2C2",
        "LoD/1.10": "0xD828"
      },
      "name": "CleanupCriticalSections",
      "signature": "void CleanupCriticalSections(void)",
      "comment": "Cleanup and destroy all thread synchronization critical sections.\n\nAlgorithm:\n1. Initialize pointer to start of critical section array (0x6ff364c8)\n2. Loop through array of critical section pointers until end (0x6ff36588)\n3. For each entry, check if pointer is non-null\n4. Skip predefined special critical sections (PTR_DAT_6ff3650c, PTR_DAT_6ff364fc, PTR_DAT_6ff364ec, PTR_DAT_6ff364cc)\n5. If not special section, delete critical section and call cleanup function FUN_6ff2cac5\n6. Advance to next array entry (increment by 4 bytes)\n7. After main loop, explicitly cleanup the four special critical sections\n8. Return to caller\n\nParameters:\nNone - function operates on global critical section array\n\nReturns:\nvoid - no return value, cleanup function\n\nSpecial Cases:\n- Four special critical sections skipped in main loop but cleaned up explicitly at end\n- Array spans 0x320 bytes (200 pointer entries) from 0x6ff364c8 to 0x6ff36588\n- DeleteCriticalSection function pointer loaded from [0x6ff330d8]\n\nMagic Numbers Reference:\n0x6ff364c8 - Start address of critical section pointer array\n0x6ff36588 - End address of critical section pointer array  \n0x6ff3650c - Special critical section 1 (PTR_DAT_6ff3650c)\n0x6ff364fc - Special critical section 2 (PTR_DAT_6ff364fc)\n0x6ff364ec - Special critical section 3 (PTR_DAT_6ff364ec)\n0x6ff364cc - Special critical section 4 (PTR_DAT_6ff364cc)\n0x6ff330d8 - Function pointer to DeleteCriticalSection\n0x4 - Pointer size increment for array iteration\n\nError Handling:\nNone - assumes all pointers valid, DeleteCriticalSection handles invalid input",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a0707ad44a579985e4c3b985375d38cb"
    },
    "Bnclient_MNE_a1900c49d3b8": {
      "addresses": {
        "LoD/1.07": "0x6FF2C24F",
        "LoD/1.08": "0x6FF2C37A",
        "LoD/1.09": "0x6FF0CF7A",
        "LoD/1.09b": "0x6FF0CF7A",
        "LoD/1.09d": "0x6FF0D17F",
        "LoD/1.10": "0x6FF0D6E5",
        "LoD/1.11": "0x6FF22843",
        "LoD/1.11b": "0x6FF22BC6",
        "LoD/1.12a": "0x6FF22F67",
        "LoD/1.13c": "0x6FF23242",
        "LoD/1.13d": "0x6FF22E73"
      },
      "rvas": {
        "LoD/1.07": "0xC24F",
        "LoD/1.08": "0xC37A",
        "LoD/1.09": "0xCF7A",
        "LoD/1.09b": "0xCF7A",
        "LoD/1.09d": "0xD17F",
        "LoD/1.10": "0xD6E5",
        "LoD/1.11": "0x2843",
        "LoD/1.11b": "0x2BC6",
        "LoD/1.12a": "0x2F67",
        "LoD/1.13c": "0x3242",
        "LoD/1.13d": "0x2E73"
      },
      "name": "InitializeThreadContext",
      "signature": "void InitializeThreadContext(ThreadContext * pThreadContext)",
      "comment": "Initialize thread-specific context structure with SEH error handler table.\n\nAlgorithm:\n1. Store pointer to global SEH error code table in reserved2 field (offset 0x50)\n2. Set reserved1[0xc] field (offset 0x14) to 1 to mark context as initialized\n3. Set reserved1[0xd] through reserved1[0xf] fields to 0 for cleanup\n4. Return to caller with context structure initialized\n\nParameters:\npThreadContext - Pointer to ThreadContext structure to initialize\n\nReturns:\nvoid - No return value, initializes context structure in-place\n\nSpecial Cases:\nMagic number 0x1 at offset 0x14 indicates successful initialization state\n\nStructure Layout:\nOffset | Size | Field Name    | Type     | Description\n-------|------|---------------|----------|----------------------------------\n0x14   | 4    | reserved1[12] | byte     | Initialization flag (1=initialized)\n0x15   | 1    | reserved1[13] | byte     | Clear to 0 during initialization\n0x16   | 1    | reserved1[14] | byte     | Clear to 0 during initialization  \n0x17   | 1    | reserved1[15] | byte     | Clear to 0 during initialization\n0x50   | 4    | reserved2[0]  | uint *   | Pointer to SEH error code table",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a1900c49d3b847e69ff3bf21a94518de"
    },
    "Bnclient_MNE_a2ba163d384d": {
      "addresses": {
        "LoD/1.11": "0x6FF307C0",
        "LoD/1.11b": "0x6FF2E190",
        "LoD/1.12a": "0x6FF2F8B0",
        "LoD/1.13c": "0x6FF36F40",
        "LoD/1.13d": "0x6FF2EA30"
      },
      "rvas": {
        "LoD/1.11": "0x107C0",
        "LoD/1.11b": "0xE190",
        "LoD/1.12a": "0xF8B0",
        "LoD/1.13c": "0x16F40",
        "LoD/1.13d": "0xEA30"
      },
      "method": "MNE",
      "index": "MNE:a2ba163d384d8483adf01c6960c44188"
    },
    "Bnclient_MNE_a2d392fa0db0": {
      "addresses": {
        "LoD/1.11": "0x6FF37019",
        "LoD/1.11b": "0x6FF36FE9",
        "LoD/1.12a": "0x6FF37E99",
        "LoD/1.13c": "0x6FF37E79",
        "LoD/1.13d": "0x6FF37DB9"
      },
      "rvas": {
        "LoD/1.11": "0x17019",
        "LoD/1.11b": "0x16FE9",
        "LoD/1.12a": "0x17E99",
        "LoD/1.13c": "0x17E79",
        "LoD/1.13d": "0x17DB9"
      },
      "name": "CatchIt",
      "signature": "void CatchIt(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4, _s_FuncInfo * param_5, _s_HandlerType * param_6, _s_CatchableType * param_7, _s_TryBlockMapEntry * param_8, int param_9, EHRegistrationNode * param_10, uchar param_11)",
      "comment": "Library Function - Single Match\n void __cdecl CatchIt(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,struct _s_HandlerType const *,struct _s_CatchableType const *,struct _s_TryBlockMapEntry const *,int,struct EHRegistrationNode *,unsigned char)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:a2d392fa0db0696e3e245bca3260930f"
    },
    "Bnclient_MNE_a334ab0a6f80": {
      "addresses": {
        "LoD/1.11": "0x6FF31120",
        "LoD/1.11b": "0x6FF31790",
        "LoD/1.12a": "0x6FF30210",
        "LoD/1.13c": "0x6FF333D0",
        "LoD/1.13d": "0x6FF2F390"
      },
      "rvas": {
        "LoD/1.11": "0x11120",
        "LoD/1.11b": "0x11790",
        "LoD/1.12a": "0x10210",
        "LoD/1.13c": "0x133D0",
        "LoD/1.13d": "0xF390"
      },
      "method": "MNE",
      "index": "MNE:a334ab0a6f80e3a2ac593507a7671fab"
    },
    "Bnclient_MNE_a51a9a5e7ceb": {
      "addresses": {
        "LoD/1.11": "0x6FF23E42",
        "LoD/1.11b": "0x6FF22FCB",
        "LoD/1.12a": "0x6FF2232A",
        "LoD/1.13c": "0x6FF230C3",
        "LoD/1.13d": "0x6FF2330B"
      },
      "rvas": {
        "LoD/1.11": "0x3E42",
        "LoD/1.11b": "0x2FCB",
        "LoD/1.12a": "0x232A",
        "LoD/1.13c": "0x30C3",
        "LoD/1.13d": "0x330B"
      },
      "name": "__mtinitlocknum",
      "signature": "int __mtinitlocknum(int _LockNum)",
      "comment": "Library Function - Single Match\n __mtinitlocknum\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:a51a9a5e7ceb2fab96b937dc9f784c13"
    },
    "Bnclient_MNE_a52ebb438c8f": {
      "addresses": {
        "LoD/1.09": "0x6FF07F60",
        "LoD/1.09b": "0x6FF07F60",
        "LoD/1.09d": "0x6FF081C0",
        "LoD/1.10": "0x6FF08BA0",
        "LoD/1.11": "0x6FF2FDF0",
        "LoD/1.11b": "0x6FF327F0",
        "LoD/1.12a": "0x6FF35D20",
        "LoD/1.13c": "0x6FF31870",
        "LoD/1.13d": "0x6FF2E060"
      },
      "rvas": {
        "LoD/1.09": "0x7F60",
        "LoD/1.09b": "0x7F60",
        "LoD/1.09d": "0x81C0",
        "LoD/1.10": "0x8BA0",
        "LoD/1.11": "0xFDF0",
        "LoD/1.11b": "0x127F0",
        "LoD/1.12a": "0x15D20",
        "LoD/1.13c": "0x11870",
        "LoD/1.13d": "0xE060"
      },
      "method": "MNE",
      "index": "MNE:a52ebb438c8fd87a1e94d7a9425117ad"
    },
    "Bnclient_MNE_a57b3ae583e4": {
      "addresses": {
        "LoD/1.07": "0x6FF2E7D3",
        "LoD/1.08": "0x6FF2E7F3",
        "LoD/1.09": "0x6FF0F41E",
        "LoD/1.09b": "0x6FF0F41E",
        "LoD/1.09d": "0x6FF0F703",
        "LoD/1.10": "0x6FF0FCF1",
        "LoD/1.11": "0x6FF263E5",
        "LoD/1.11b": "0x6FF25916",
        "LoD/1.12a": "0x6FF24D7E",
        "LoD/1.13c": "0x6FF249C9",
        "LoD/1.13d": "0x6FF2643F"
      },
      "rvas": {
        "LoD/1.07": "0xE7D3",
        "LoD/1.08": "0xE7F3",
        "LoD/1.09": "0xF41E",
        "LoD/1.09b": "0xF41E",
        "LoD/1.09d": "0xF703",
        "LoD/1.10": "0xFCF1",
        "LoD/1.11": "0x63E5",
        "LoD/1.11b": "0x5916",
        "LoD/1.12a": "0x4D7E",
        "LoD/1.13c": "0x49C9",
        "LoD/1.13d": "0x643F"
      },
      "name": "InitializeMemoryPool",
      "signature": "int InitializeMemoryPool(uint dwPoolSizeLimit)",
      "comment": "Initialize memory pool allocation system with specified size limit.\n\nAlgorithm:\n1. Allocate heap memory for MemoryAllocation table (320 bytes)\n2. Verify allocation succeeded, return failure if NULL\n3. Initialize allocation tracking globals to zero state\n4. Set allocation table base pointer in global variables\n5. Store pool size limit parameter in global state\n6. Set default allocation granularity to 16 bytes\n\nParameters:\ndwPoolSizeLimit (uint) - Maximum size in bytes for the memory pool\n\nReturns:\n1 - Memory pool successfully initialized\n0 - Allocation failed, pool not initialized\n\nMagic Numbers Reference:\n0x140 (320 bytes) - Size of MemoryAllocation table for tracking allocations\n0x10 (16 bytes) - Default allocation granularity/alignment value\n\nError Handling:\nAllocation failure: Returns 0 immediately if HeapAlloc fails\nNo exception handling: Function assumes valid heap handle exists\n\nStructure Layout:\nMemoryAllocation table - 20-byte structure for tracking individual allocations\nTable accommodates 16 allocation entries (320/20 = 16)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a57b3ae583e4f6f104245d4da8d3b9fe"
    },
    "Bnclient_MNE_a5a676ae341f": {
      "addresses": {
        "LoD/1.07": "0x6FF2A210",
        "LoD/1.08": "0x6FF2A230",
        "LoD/1.09": "0x6FF0AE30",
        "LoD/1.09b": "0x6FF0AE30",
        "LoD/1.09d": "0x6FF0B080"
      },
      "rvas": {
        "LoD/1.07": "0xA210",
        "LoD/1.08": "0xA230",
        "LoD/1.09": "0xAE30",
        "LoD/1.09b": "0xAE30",
        "LoD/1.09d": "0xB080"
      },
      "name": "ProcessModularInverseArray",
      "signature": "void ProcessModularInverseArray(ushort * pInputArray, ushort * pOutputArray)",
      "comment": "Processes array of cryptographic coefficients using modular multiplicative inverse calculations\n\nAlgorithm:\n1. Calculate modular inverse of first input coefficient using extended Euclidean algorithm (mod 0x10001)\n2. Compute negative values of input coefficients at positions 1 and 2\n3. Calculate modular inverse of coefficient at position 3 using extended Euclidean algorithm\n4. Process 7 coefficient groups in main loop, each group contains 6 values:\n   - Calculate modular inverse of coefficient at offset +2 within each group\n   - Store processed values in temporary local buffer advancing backwards\n   - Negate coefficients at specific positions within each group\n5. Process final coefficient group after main loop (positions 6-11)\n6. Call ComputeModularInverse for coefficient at position 11\n7. Copy all processed coefficients from local buffer to output array (52 values total)\n8. Clear local buffer during copy operation\n\nParameters:\n- pInputArray: Pointer to array of 16-bit input cryptographic coefficients\n- pOutputArray: Pointer to output array receiving processed 16-bit coefficients (52 elements)\n\nReturns:\n- void (results stored in output array)\n\nSpecial Cases:\n- Input coefficients <= 1 bypass modular inverse calculation\n- Extended Euclidean algorithm handles edge case when remainder equals 1\n- Buffer processing uses backwards pointer arithmetic for coefficient ordering\n\nMagic Numbers Reference:\n- 0x10001 (65537): Modulus for multiplicative inverse calculations (common in RSA cryptography)\n- 7: Number of coefficient groups to process in main loop\n- 6: Number of coefficients per group in main loop\n- 0x34 (52): Total number of coefficients to copy to output\n- 0xb (11): Final coefficient position for modular inverse calculation\n\nError Handling:\n- No explicit error checking - assumes valid input coefficient arrays\n- Division by zero prevented by coefficient > 1 checks before modular inverse\n- Buffer overflow prevented by fixed loop counters and array sizes\n\nStructure Layout:\nInput Array Layout (minimum 48 elements):\nOffset  Size  Field Name           Type    Description\n0       2     BaseCoeff           ushort  Primary coefficient for modular inverse\n1       2     NegCoeff1           ushort  Coefficient to be negated\n2       2     NegCoeff2           ushort  Coefficient to be negated  \n3       2     SecondaryCoeff      ushort  Secondary coefficient for modular inverse\n4-45    84    GroupCoeffs         ushort  42 coefficients in 7 groups of 6\n46-47   4     FinalCoeffs         ushort  Final 2 coefficients for processing",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a5a676ae341f007be14fe6db53cf78c9"
    },
    "Bnclient_MNE_a5b5a435a005": {
      "addresses": {
        "LoD/1.11": "0x6FF27676",
        "LoD/1.11b": "0x6FF275F6",
        "LoD/1.12a": "0x6FF27A45",
        "LoD/1.13c": "0x6FF279AD",
        "LoD/1.13d": "0x6FF27658"
      },
      "rvas": {
        "LoD/1.11": "0x7676",
        "LoD/1.11b": "0x75F6",
        "LoD/1.12a": "0x7A45",
        "LoD/1.13c": "0x79AD",
        "LoD/1.13d": "0x7658"
      },
      "name": "__unlock_fhandle",
      "signature": "void __unlock_fhandle(int _Filehandle)",
      "comment": "Library Function - Single Match\n __unlock_fhandle\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:a5b5a435a00574933ae7bc271f1b0178"
    },
    "Bnclient_MNE_a611f894b97d": {
      "addresses": {
        "LoD/1.07": "0x6FF22F00",
        "LoD/1.08": "0x6FF22F20",
        "LoD/1.09": "0x6FF03890",
        "LoD/1.09b": "0x6FF03890",
        "LoD/1.09d": "0x6FF03C40",
        "LoD/1.10": "0x6FF03C20"
      },
      "rvas": {
        "LoD/1.07": "0x2F00",
        "LoD/1.08": "0x2F20",
        "LoD/1.09": "0x3890",
        "LoD/1.09b": "0x3890",
        "LoD/1.09d": "0x3C40",
        "LoD/1.10": "0x3C20"
      },
      "name": "IsPacketHandlerSet",
      "signature": "bool IsPacketHandlerSet(void)",
      "comment": "Check if packet handler at index 0xf4 is registered and active.\n\nAlgorithm:\n1. Load packet handler function pointer from global array at index 0xf4 (244 decimal)\n2. Test if pointer value is greater than 0 (non-NULL and valid)\n3. Return boolean result indicating handler availability\n\nParameters:\nNone\n\nReturns:\ntrue - Packet handler at index 0xf4 is registered and active\nfalse - Packet handler is NULL or invalid (0)\n\nMagic Numbers Reference:\n0xf4 (244 decimal) - Packet handler index for specific packet type\n0x6ff398ec - Address of g_apfnPacketHandlers global array base",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a611f894b97d44af00a32affba7ed0ad"
    },
    "Bnclient_MNE_a6419fbc680a": {
      "addresses": {
        "LoD/1.07": "0x6FF2BB54",
        "LoD/1.08": "0x6FF2BB74",
        "LoD/1.09": "0x6FF0C774",
        "LoD/1.09b": "0x6FF0C774",
        "LoD/1.09d": "0x6FF0C9D4",
        "LoD/1.10": "0x6FF0D07E"
      },
      "rvas": {
        "LoD/1.07": "0xBB54",
        "LoD/1.08": "0xBB74",
        "LoD/1.09": "0xC774",
        "LoD/1.09b": "0xC774",
        "LoD/1.09d": "0xC9D4",
        "LoD/1.10": "0xD07E"
      },
      "name": "UpdateSystemTimeCache",
      "signature": "void UpdateSystemTimeCache(int * pTimestampOut)",
      "comment": "Updates cached system time values and returns timestamp with timezone adjustment\n\nAlgorithm:\n1. Get current local time using GetLocalTime into localTime structure\n2. Get current system time using GetSystemTime into systemTime structure  \n3. Check if current system time matches previously cached values (minute, hour, day, month, year)\n4. If time matches cache, skip timezone update and jump to timestamp calculation\n5. Call GetTimeZoneInformation to determine current timezone status\n6. Set timezone bias based on result: -1 for error, 1 for daylight time, 0 for standard time\n7. Update all cached time values with current system time components\n8. Call FUN_6ff2d956 with local time components and timezone bias to compute timestamp\n9. Store computed timestamp in output parameter if provided\n\nParameters:\npTimestampOut: Output parameter to receive computed timestamp value, may be NULL\n\nReturns:\nvoid (result returned through output parameter)\n\nSpecial Cases:\n- If GetTimeZoneInformation fails (returns 0xffffffff), timezone bias set to -1\n- If timezone is daylight time with valid date and bias, timezone bias set to 1\n- If output parameter is NULL, timestamp is computed but not stored\n- Time cache comparison optimizes timezone processing when time unchanged\n\nMagic Numbers:\n0xffffffff - TIME_ZONE_ID_INVALID from GetTimeZoneInformation\n0x2 - TIME_ZONE_ID_DAYLIGHT indicating daylight saving time\n1 - Daylight time bias flag\n0 - Standard time bias flag\n-1 - Timezone error flag\n\nStructure Layout:\n_SYSTEMTIME (16 bytes):\nOffset | Size | Field        | Type   | Description\n0x00   | 2    | wYear        | ushort | Year (1601-30827)\n0x02   | 2    | wMonth       | ushort | Month (1-12)\n0x04   | 2    | wDayOfWeek   | ushort | Day of week (0-6)\n0x06   | 2    | wDay         | ushort | Day of month (1-31)\n0x08   | 2    | wHour        | ushort | Hour (0-23)\n0x0A   | 2    | wMinute      | ushort | Minute (0-59)\n0x0C   | 2    | wSecond      | ushort | Second (0-59)\n0x0E   | 2    | wMilliseconds| ushort | Milliseconds (0-999)\n\nGlobal Cache Layout:\ng_nTimezoneBias: Current timezone bias status (-1=error, 0=standard, 1=daylight)\ng_dwCachedYearMonth: Cached year (low word) and month (high word)\ng_dwCachedDayOfWeekDay: Cached day of week (low word) and day (high word)  \ng_dwCachedHourMinute: Cached hour (low word) and minute (high word)\ng_dwCachedSecondMillisecond: Cached second (low word) and millisecond (high word)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a6419fbc680afe2a2527cf739cc17f89"
    },
    "Bnclient_MNE_a7046d73bbd2": {
      "addresses": {
        "LoD/1.07": "0x6FF2E68A",
        "LoD/1.08": "0x6FF2E6AA",
        "LoD/1.09": "0x6FF0F2D5",
        "LoD/1.09b": "0x6FF0F2D5",
        "LoD/1.09d": "0x6FF0F5BA",
        "LoD/1.10": "0x6FF0FBA8"
      },
      "rvas": {
        "LoD/1.07": "0xE68A",
        "LoD/1.08": "0xE6AA",
        "LoD/1.09": "0xF2D5",
        "LoD/1.09b": "0xF2D5",
        "LoD/1.09d": "0xF5BA",
        "LoD/1.10": "0xFBA8"
      },
      "name": "GetStringCharacterTypesCompat",
      "signature": "BOOL GetStringCharacterTypesCompat(DWORD dwCharTypeFlags, LPCSTR lpszSourceString, int nStringLength, LPWORD pwCharTypes, UINT nCodePage, LCID lcidLocale, int nConversionFlags)",
      "comment": "Compatibility wrapper for character type classification APIs that automatically routes between ANSI and Unicode implementations.\n\nAlgorithm:\n1. Initialize SEH (Structured Exception Handling) frame for error protection\n2. Check global API mode flag (DAT_6ff3a054) to determine system capability\n3. If API mode uninitialized (0), perform system capability detection:\n   - Test GetStringTypeW with empty Unicode string to check Unicode support\n   - If Unicode fails, test GetStringTypeA with ANSI string from global buffer\n   - Set API mode: 1=Unicode available, 2=ANSI only\n   - Cache detected mode in global variable for future calls\n4. Route to appropriate implementation based on cached API mode:\n   - Mode 1 (Unicode): Convert ANSI input to Unicode then call GetStringTypeW\n   - Mode 2 (ANSI): Call GetStringTypeA directly with locale parameter\n5. For Unicode path (Mode 1):\n   - Use default code page if nCodePage is 0 (g_dwDefaultCodePage)\n   - Calculate required buffer size with MultiByteToWideChar\n   - Allocate stack buffer and clear with _memset\n   - Convert ANSI string to Unicode in stack buffer\n   - Call GetStringTypeW with converted Unicode string\n6. For ANSI path (Mode 2):\n   - Use default locale if lcidLocale is 0 (g_dwLocaleAvailableFlag)\n   - Call GetStringTypeA directly with input parameters\n7. Clean up SEH frame and return result\n\nParameters:\ndwCharTypeFlags - Character type flags (CT_CTYPE1, CT_CTYPE2, CT_CTYPE3)\nlpszSourceString - Pointer to ANSI string to analyze\nnStringLength - Length of string in characters (-1 for null-terminated)\npwCharTypes - Output buffer to receive character type information\nnCodePage - Code page for ANSI to Unicode conversion (0=use default)\nlcidLocale - Locale identifier for ANSI API (0=use default)\nnConversionFlags - Flags affecting conversion behavior (enables MB_PRECOMPOSED if non-zero)\n\nReturns:\nTRUE - Character types successfully retrieved and stored in pwCharTypes\nFALSE - Operation failed (invalid parameters, conversion error, API failure)\n\nSpecial Cases:\n- First call performs expensive system capability detection and caches result\n- Unicode path requires stack allocation proportional to string length\n- Conversion flags affect MultiByteToWideChar behavior (bit 3 = MB_PRECOMPOSED)\n- Global variables cache default code page and locale for performance\n\nMagic Numbers Reference:\n0xffffffff - SEH exception filter initialization value\n0x180 - Offset into global string buffer for ANSI test string\n1 - CT_CTYPE1 flag for character type classification\n2 - Size multiplier for Unicode character buffer (2 bytes per character)\n8 - MB_PRECOMPOSED flag mask for conversion flags\n0x38 - Stack allocation safety check threshold\n\nError Handling:\n- SEH frame protects against access violations during stack operations\n- GetStringTypeW/GetStringTypeA failures return FALSE\n- MultiByteToWideChar failures abort Unicode conversion path\n- Stack allocation failures detected via safety threshold check\n- All error paths restore original SEH exception list\n\nState Machine:\nState 0: Uninitialized - Perform capability detection\nState 1: Unicode Mode - Route through Unicode conversion path  \nState 2: ANSI Mode - Route directly to ANSI API",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a7046d73bbd286a50d5e7204509858d2"
    },
    "Bnclient_MNE_a721de135fd1": {
      "addresses": {
        "LoD/1.12a": "0x6FF32770",
        "LoD/1.13c": "0x6FF30080"
      },
      "rvas": {
        "LoD/1.12a": "0x12770",
        "LoD/1.13c": "0x10080"
      },
      "method": "MNE",
      "index": "MNE:a721de135fd183811dd83638d9e60c8f"
    },
    "Bnclient_MNE_a82412e86c7e": {
      "addresses": {
        "LoD/1.12a": "0x6FF25C97",
        "LoD/1.13c": "0x6FF26FA7"
      },
      "rvas": {
        "LoD/1.12a": "0x5C97",
        "LoD/1.13c": "0x6FA7"
      },
      "method": "MNE",
      "index": "MNE:a82412e86c7e059d3af6ea9d376e2875"
    },
    "Bnclient_MNE_a97e6f018794": {
      "addresses": {
        "LoD/1.11": "0x6FF316F0",
        "LoD/1.11b": "0x6FF31D60",
        "LoD/1.12a": "0x6FF307E0",
        "LoD/1.13c": "0x6FF339A0",
        "LoD/1.13d": "0x6FF2F960"
      },
      "rvas": {
        "LoD/1.11": "0x116F0",
        "LoD/1.11b": "0x11D60",
        "LoD/1.12a": "0x107E0",
        "LoD/1.13c": "0x139A0",
        "LoD/1.13d": "0xF960"
      },
      "method": "MNE",
      "index": "MNE:a97e6f018794df3560893bf0948fdb2e"
    },
    "Bnclient_MNE_a99e2d6eee28": {
      "addresses": {
        "LoD/1.11": "0x6FF2D520",
        "LoD/1.11b": "0x6FF2B4D0",
        "LoD/1.12a": "0x6FF2D940",
        "LoD/1.13c": "0x6FF2EA60",
        "LoD/1.13d": "0x6FF2CE60"
      },
      "rvas": {
        "LoD/1.11": "0xD520",
        "LoD/1.11b": "0xB4D0",
        "LoD/1.12a": "0xD940",
        "LoD/1.13c": "0xEA60",
        "LoD/1.13d": "0xCE60"
      },
      "method": "MNE",
      "index": "MNE:a99e2d6eee2857b72fb45bd928e7ab0d",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF057C0",
          "rva": "0x57C0",
          "confidence": 0.401,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_ab1eb8b21e2b": {
      "addresses": {
        "LoD/1.07": "0x6FF2F5CD",
        "LoD/1.08": "0x6FF2F5ED",
        "LoD/1.09": "0x6FF10218",
        "LoD/1.09b": "0x6FF10218",
        "LoD/1.09d": "0x6FF104FD",
        "LoD/1.10": "0x6FF10AEB"
      },
      "rvas": {
        "LoD/1.07": "0xF5CD",
        "LoD/1.08": "0xF5ED",
        "LoD/1.09": "0x10218",
        "LoD/1.09b": "0x10218",
        "LoD/1.09d": "0x104FD",
        "LoD/1.10": "0x10AEB"
      },
      "name": "UpdateMemoryPoolTracking",
      "signature": "void UpdateMemoryPoolTracking(MemoryPool * pMemoryPool, uint dwAddress, byte * pbFlag)",
      "comment": "Updates memory pool tracking information and triggers cleanup when threshold reached.\n\nAlgorithm:\n1. Calculate pointer to tracking entry in memory pool descriptor array\n2. Add flag byte value to tracking entry allocation count  \n3. Clear the input flag byte to zero\n4. Set tracking entry status field to 0xf1 (active tracking)\n5. Check if allocation count reached threshold (0xf0 = 240 allocations)\n6. If threshold reached, increment global allocated pages counter\n7. If global counter reaches 0x20 (32 pages), trigger memory cleanup\n\nParameters:\npMemoryPool - Pointer to MemoryPool structure containing tracking arrays\ndwAddress - Virtual address used to calculate tracking entry index\npbFlag - Pointer to byte flag containing allocation count to add\n\nReturns:\nNone (void function)\n\nSpecial Cases:\nThreshold of 0xf0 (240) allocations triggers page counting mechanism\nGlobal threshold of 0x20 (32) pages triggers FreeMemoryPoolPages cleanup\nStatus value 0xf1 indicates active tracking state\n\nMagic Numbers Reference:\n0x10 - Base offset in memory pool structure for address calculations\n0x18 - Array offset in memory pool structure for tracking entries  \n0xc - Right shift count for address-to-index conversion (4096-byte pages)\n0x8 - Size of each tracking entry (8 bytes: count + status)\n0xf0 - Allocation count threshold (240 decimal)\n0xf1 - Active tracking status marker\n0x20 - Global page limit (32 decimal) before cleanup\n0x10 - Parameter passed to FreeMemoryPoolPages for cleanup\n\nStructure Layout:\nMemoryPool tracking entry (8 bytes):\nOffset | Size | Field Name | Type | Description\n+0x0   | 4    | nCount     | uint | Allocation count for this pool segment\n+0x4   | 4    | dwStatus   | uint | Status flags (0xf1 = active tracking)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ab1eb8b21e2bded2678160ac668c3175"
    },
    "Bnclient_MNE_ac2bbc91aa48": {
      "addresses": {
        "LoD/1.12a": "0x6FF37470",
        "LoD/1.13c": "0x6FF349E0",
        "LoD/1.13d": "0x6FF34430"
      },
      "rvas": {
        "LoD/1.12a": "0x17470",
        "LoD/1.13c": "0x149E0",
        "LoD/1.13d": "0x14430"
      },
      "method": "MNE",
      "index": "MNE:ac2bbc91aa481abd970b608fd1289d3b"
    },
    "Bnclient_MNE_aca83c0b308e": {
      "addresses": {
        "LoD/1.11": "0x6FF25A62",
        "LoD/1.11b": "0x6FF25249",
        "LoD/1.13d": "0x6FF25E62"
      },
      "rvas": {
        "LoD/1.11": "0x5A62",
        "LoD/1.11b": "0x5249",
        "LoD/1.13d": "0x5E62"
      },
      "name": "__setmbcp_lk",
      "signature": "undefined __setmbcp_lk(UINT param_1)",
      "comment": "Library Function - Single Match\n __setmbcp_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:aca83c0b308ebe5f47dff9cf83f354c7"
    },
    "Bnclient_MNE_acd2f1b89e1f": {
      "addresses": {
        "LoD/1.09": "0x6FF150A0",
        "LoD/1.09b": "0x6FF150A0",
        "LoD/1.09d": "0x6FF153C0",
        "LoD/1.10": "0x6FF15950"
      },
      "rvas": {
        "LoD/1.09": "0x150A0",
        "LoD/1.09b": "0x150A0",
        "LoD/1.09d": "0x153C0",
        "LoD/1.10": "0x15950"
      },
      "method": "MNE",
      "index": "MNE:acd2f1b89e1fada3d5641fb7495ec8ba",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF25E5B",
          "rva": "0x5E5B",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.08": {
          "address": "0x6FF2B2B7",
          "rva": "0xB2B7",
          "confidence": 0.378,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.09"
        },
        "LoD/1.11b": {
          "address": "0x6FF24A38",
          "rva": "0x4A38",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.12a": {
          "address": "0x6FF26CF0",
          "rva": "0x6CF0",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF25C42",
          "rva": "0x5C42",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_adafedc33ce1": {
      "addresses": {
        "LoD/1.11": "0x6FF228C7",
        "LoD/1.11b": "0x6FF22C4A",
        "LoD/1.12a": "0x6FF22FEB",
        "LoD/1.13c": "0x6FF232C6",
        "LoD/1.13d": "0x6FF22EF7"
      },
      "rvas": {
        "LoD/1.11": "0x28C7",
        "LoD/1.11b": "0x2C4A",
        "LoD/1.12a": "0x2FEB",
        "LoD/1.13c": "0x32C6",
        "LoD/1.13d": "0x2EF7"
      },
      "name": "__freefls@4",
      "signature": "undefined __freefls@4(void * param_1)",
      "comment": "Library Function - Single Match\n __freefls@4\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:adafedc33ce199c85ef6d812cf9b5974"
    },
    "Bnclient_MNE_ae8798e965e2": {
      "addresses": {
        "LoD/1.07": "0x6FF3096A",
        "LoD/1.08": "0x6FF3098A",
        "LoD/1.09": "0x6FF115AA",
        "LoD/1.09b": "0x6FF115AA",
        "LoD/1.09d": "0x6FF1189A",
        "LoD/1.10": "0x6FF11DEA"
      },
      "rvas": {
        "LoD/1.07": "0x1096A",
        "LoD/1.08": "0x1098A",
        "LoD/1.09": "0x115AA",
        "LoD/1.09b": "0x115AA",
        "LoD/1.09d": "0x1189A",
        "LoD/1.10": "0x11DEA"
      },
      "name": "CheckDaylightSavingTime",
      "signature": "bool CheckDaylightSavingTime(int * pTimeComponents)",
      "comment": "Thread-safe wrapper to check if a given time falls within daylight saving time period.\n\nAlgorithm:\n1. Acquire critical section lock (index 0xb) to ensure thread safety during timezone checks\n2. Call FUN_6ff3098b() with time component array to perform actual DST calculation\n3. Store boolean result indicating whether time falls within DST period\n4. Release critical section lock to allow other threads access\n5. Return DST status result to caller\n\nParameters:\npTimeComponents - Pointer to array containing time components in specific format\n  [0] = seconds (0-59)\n  [1] = minutes (0-59) \n  [2] = hours (0-23)\n  [5] = timezone-related value used for DST boundary checks\n  [7] = year value used for DST period determination\n\nReturns:\ntrue - Time falls within active daylight saving time period\nfalse - Time falls within standard time period or timezone processing disabled\n\nSpecial Cases:\nCritical section index 0xb provides exclusive access to timezone calculation globals\nFunction is wrapper around FUN_6ff3098b which contains actual DST boundary logic\nUsed by ConvertDateTimeToTimestamp when nDaylightSavingFlag == -1 (auto-detect mode)\n\nMagic Numbers Reference:\n0xb (11) - Critical section index for timezone/DST operations",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ae8798e965e2d466141dd479c4c8f8f5"
    },
    "Bnclient_MNE_aef9935d5818": {
      "addresses": {
        "LoD/1.11": "0x6FF23864",
        "LoD/1.11b": "0x6FF23124",
        "LoD/1.12a": "0x6FF22484",
        "LoD/1.13c": "0x6FF22558",
        "LoD/1.13d": "0x6FF23464"
      },
      "rvas": {
        "LoD/1.11": "0x3864",
        "LoD/1.11b": "0x3124",
        "LoD/1.12a": "0x2484",
        "LoD/1.13c": "0x2558",
        "LoD/1.13d": "0x3464"
      },
      "name": "__SEH_prolog",
      "signature": "undefined __SEH_prolog(undefined4 param_1, int param_2)",
      "comment": "Library Function - Single Match\n __SEH_prolog\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:aef9935d5818b16bbad0952f5da65380"
    },
    "Bnclient_MNE_afc6bf96e31e": {
      "addresses": {
        "LoD/1.07": "0x6FF2D8F3",
        "LoD/1.08": "0x6FF2D913",
        "LoD/1.09": "0x6FF0E513",
        "LoD/1.09b": "0x6FF0E513",
        "LoD/1.09d": "0x6FF0E823",
        "LoD/1.10": "0x6FF0ED8B"
      },
      "rvas": {
        "LoD/1.07": "0xD8F3",
        "LoD/1.08": "0xD913",
        "LoD/1.09": "0xE513",
        "LoD/1.09b": "0xE513",
        "LoD/1.09d": "0xE823",
        "LoD/1.10": "0xED8B"
      },
      "name": "WriteStringToBuffer",
      "signature": "void WriteStringToBuffer(char * lpszString, int nLength, FileBuffer * pBuffer, int * pnCharsWritten)",
      "comment": "Writes a string to a buffered output stream character by character with error checking.\n\nAlgorithm:\n1. Validate that string length is greater than zero\n2. Initialize loop variables and counters  \n3. For each character in the string:\n   a. Decrement remaining character count\n   b. Load current character from string pointer\n   c. Advance string pointer to next character\n   d. Call BufferedPutChar to write character to buffer\n   e. Check if write operation failed (error code -1)\n   f. If error occurred, exit immediately\n   g. If characters remain, continue to next character\n4. Return when all characters processed or error encountered\n\nParameters:\nlpszString (char *): Pointer to null-terminated or fixed-length string to write\nnLength (int): Number of characters to write from string\npBuffer (FileBuffer *): Pointer to buffered output stream structure\npnCharsWritten (int *): Pointer to counter tracking total characters written\n\nReturns:\nvoid - No return value; error status communicated through pnCharsWritten pointer\n\nSpecial Cases:\nIf nLength <= 0, function returns immediately without processing\nIf BufferedPutChar fails (sets *pnCharsWritten to -1), loop exits early\nString pointer is advanced byte-by-byte regardless of character encoding\n\nMagic Numbers Reference:\n0x1: Byte increment for string pointer advancement (0x6ff2d90d: INC ESI)\n-1 (0xFFFFFFFF): Error status code indicating write failure (0x6ff2d91b: CMP dword ptr [EDI],-0x1)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:afc6bf96e31e41127728e4d6585e174f"
    },
    "Bnclient_MNE_aff5ecc93302": {
      "addresses": {
        "LoD/1.11": "0x6FF22826",
        "LoD/1.11b": "0x6FF22BA9",
        "LoD/1.12a": "0x6FF22F4A",
        "LoD/1.13c": "0x6FF23225",
        "LoD/1.13d": "0x6FF22E56"
      },
      "rvas": {
        "LoD/1.11": "0x2826",
        "LoD/1.11b": "0x2BA9",
        "LoD/1.12a": "0x2F4A",
        "LoD/1.13c": "0x3225",
        "LoD/1.13d": "0x2E56"
      },
      "name": "__mtterm",
      "signature": "void __mtterm(void)",
      "comment": "Library Function - Single Match\n __mtterm\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:aff5ecc933020ea9f6660ca70cb9d16a"
    },
    "Bnclient_MNE_b02d085de523": {
      "addresses": {
        "LoD/1.07": "0x6FF2B51F",
        "LoD/1.08": "0x6FF2B540",
        "LoD/1.09": "0x6FF0C140",
        "LoD/1.09b": "0x6FF0C140",
        "LoD/1.09d": "0x6FF0C39F",
        "LoD/1.10": "0x6FF13C40"
      },
      "rvas": {
        "LoD/1.07": "0xB51F",
        "LoD/1.08": "0xB540",
        "LoD/1.09": "0xC140",
        "LoD/1.09b": "0xC140",
        "LoD/1.09d": "0xC39F",
        "LoD/1.10": "0x13C40"
      },
      "name": "InitializeThreadContext",
      "signature": "int InitializeThreadContext(ThreadInitContext * pContext)",
      "comment": "Initialize thread context with TLS storage and execute thread procedure.\n\nAlgorithm:\n1. Set up Structured Exception Handling (SEH) frame with handler at SehHandlerFunction\n2. Associate thread context with TLS slot using g_dwTlsSlotIndex\n3. Exit with fatal error (0x10) if TLS association fails\n4. Store current thread ID in first field of context structure\n5. Call optional thread initialization callback if g_pfnThreadInitCallback is set\n6. Execute the thread procedure function pointer from context (offset 0x48) with parameter (offset 0x4c)\n7. Call cleanup function FUN_6ff2b5bb with thread procedure return value\n8. Restore exception handling chain and return success\n\nParameters:\n- pContext: ThreadInitContext* - Thread context structure containing thread ID storage and function pointers\n\nReturns:\n- 0: Success - thread initialized and procedure executed successfully\n- Does not return if TLS association fails (calls __amsg_exit with code 0x10)\n\nSpecial Cases:\n- If g_pfnThreadInitCallback is NULL, skips callback execution\n- SEH frame protects against exceptions during thread procedure execution\n- Function exits process if TLS slot is invalid or full\n\nMagic Numbers Reference:\n- 0x10 (decimal 16): Fatal error code for TLS failure in __amsg_exit\n- 0xffffffff: Initial SEH state indicating exception handling active\n- 0x48: Offset to thread procedure function pointer in ThreadInitContext\n- 0x4c: Offset to thread procedure parameter in ThreadInitContext\n\nStructure Layout:\nOffset | Size | Field Name      | Type    | Description\n0x00   | 4    | dwThreadId     | uint    | Current thread identifier\n0x04   | 68   | reserved1      | byte[]  | Reserved/padding space\n0x48   | 4    | pfnThreadProc  | void*   | Thread procedure function pointer\n0x4c   | 4    | pThreadParam   | void*   | Parameter passed to thread procedure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b02d085de523a603715f9d6839e0feb7"
    },
    "Bnclient_MNE_b0752bee787a": {
      "addresses": {
        "LoD/1.09": "0x6FF13650",
        "LoD/1.09b": "0x6FF13650",
        "LoD/1.09d": "0x6FF13970",
        "LoD/1.10": "0x6FF13F70"
      },
      "rvas": {
        "LoD/1.09": "0x13650",
        "LoD/1.09b": "0x13650",
        "LoD/1.09d": "0x13970",
        "LoD/1.10": "0x13F70"
      },
      "method": "MNE",
      "index": "MNE:b0752bee787a760f28734023698299a6"
    },
    "Bnclient_MNE_b10e654b1e08": {
      "addresses": {
        "LoD/1.07": "0x6FF2F31A",
        "LoD/1.08": "0x6FF2F33A",
        "LoD/1.09": "0x6FF0FF65",
        "LoD/1.09b": "0x6FF0FF65",
        "LoD/1.09d": "0x6FF1024A",
        "LoD/1.10": "0x6FF10838"
      },
      "rvas": {
        "LoD/1.07": "0xF31A",
        "LoD/1.08": "0xF33A",
        "LoD/1.09": "0xFF65",
        "LoD/1.09b": "0xFF65",
        "LoD/1.09d": "0x1024A",
        "LoD/1.10": "0x10838"
      },
      "name": "InitializeMemoryAllocator",
      "signature": "ErrorTableEntry * InitializeMemoryAllocator(void)",
      "comment": "Initializes a memory allocator with virtual memory management and free list structures.\n\nAlgorithm:\n1. Check global allocator mode (g_nAllocatorMode) to determine allocation strategy\n2. If mode is -1, use static global error table offset (g_aErrorTable + 0x12)\n3. Otherwise, allocate 0x2020 bytes from heap for descriptor structure\n4. Reserve 4MB (0x400000) of virtual address space with MEM_RESERVE flag\n5. Commit first 64KB (0x10000) with PAGE_READWRITE protection\n6. Initialize allocator descriptor linking to global error table chain\n7. Setup memory structure pointers: base, end, free list start\n8. Initialize 1024 (0x400) free list entries with size masks and patterns\n9. Clear committed memory region to zero\n10. Setup memory blocks with headers and free list linkage\n11. Return pointer to allocator descriptor on success, NULL on failure\n\nParameters:\nNone\n\nReturns:\nErrorTableEntry * - Pointer to allocator descriptor on success, NULL on failure\n  - Success: Valid pointer to initialized memory allocator structure\n  - Error: NULL if heap allocation fails or virtual memory allocation fails\n\nSpecial Cases:\n- Static mode (g_nAllocatorMode == -1): Uses pre-allocated global structure\n- Dynamic mode (g_nAllocatorMode != -1): Allocates new descriptor from heap\n- Memory allocation failures trigger cleanup of partial allocations\n- Error table is repurposed as allocator descriptor structure\n\nMagic Numbers Reference:\n0x2020 (8224 decimal) - Heap allocation size for allocator descriptor\n0x400000 (4194304 decimal) - Virtual memory reservation size (4MB)\n0x10000 (65536 decimal) - Initial committed memory size (64KB)  \n0x2000 (8192 decimal) - MEM_RESERVE flag for VirtualAlloc\n0x1000 (4096 decimal) - MEM_COMMIT flag for VirtualAlloc\n0x8000 (32768 decimal) - MEM_RELEASE flag for VirtualFree\n0x400 (1024 decimal) - Number of free list entries to initialize\n0xf1 (241 decimal) - Free block size pattern mask\n0xff (255 decimal) - Block header marker byte\n0xf0 (240 decimal) - Block size field value\n0x1000 (4096 decimal) - Block stride size\n\nError Handling:\n- HeapAlloc failure: Returns NULL immediately\n- VirtualAlloc reserve failure: Cleans up heap allocation if dynamic mode\n- VirtualAlloc commit failure: Releases reserved memory and cleans up heap\n- All cleanup paths properly restore system state before returning NULL\n\nStructure Layout:\nErrorTableEntry repurposed as AllocatorDescriptor:\nOffset  Size  Field Name          Type              Description\n0x00    4     dwErrorCode         uint              Base pointer or link field  \n0x04    4     lpszMessage         char *            Next pointer or link field\n0x08    4     [field2].dwCode     uint              Free list start pointer\n0x0C    4     [field2].lpMsg      char *            Memory descriptor pointer  \n0x10    4     [field3].dwCode     uint              Virtual memory base\n0x14    4     [field3].lpMsg      char *            Virtual memory end\n0x18    ...   Free List Entries   ErrorTableEntry[] Array of 1024 free block entries",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b10e654b1e0872dc227e39198444a376"
    },
    "Bnclient_MNE_b14dfb771e9c": {
      "addresses": {
        "LoD/1.07": "0x6FF3193D",
        "LoD/1.08": "0x6FF3195D",
        "LoD/1.09": "0x6FF1257D",
        "LoD/1.09b": "0x6FF1257D",
        "LoD/1.09d": "0x6FF1286D",
        "LoD/1.10": "0x6FF12DF1"
      },
      "rvas": {
        "LoD/1.07": "0x1193D",
        "LoD/1.08": "0x1195D",
        "LoD/1.09": "0x1257D",
        "LoD/1.09b": "0x1257D",
        "LoD/1.09d": "0x1286D",
        "LoD/1.10": "0x12DF1"
      },
      "name": "FlushStreamBuffer",
      "signature": "uint FlushStreamBuffer(uint dwStreamIndex)",
      "comment": "Flush the file buffer for a specified stream to ensure all pending write operations are committed to disk.\n\nAlgorithm:\n1. Validate stream index against global stream count (g_dwStreamCount)\n2. Check if stream is active by testing bit 0x1 in StreamIO.nPosition field\n3. Acquire critical section lock for thread-safe access to stream descriptor\n4. Re-validate stream active state (double-check pattern)\n5. Get file handle from stream using GetStreamBasePointer()\n6. Call Windows FlushFileBuffers() API to commit pending writes\n7. Handle flush result - capture error code if flush failed\n8. Set thread context error fields based on operation result\n9. Release critical section lock regardless of success/failure\n10. Return success (0) or failure (0xFFFFFFFF)\n\nParameters:\ndwStreamIndex (uint): Zero-based index into g_apStreamDescriptors 2D array\n                     Uses bucket indexing: bucket = index >> 5, slot = index & 0x1F\n                     Must be less than g_dwStreamCount\n\nReturns:\n0x00000000 (0): Success - stream buffer flushed successfully\n0xFFFFFFFF (-1): Failure - invalid stream index, inactive stream, or flush error\n\nSpecial Cases:\n- Invalid stream index (>= g_dwStreamCount): Sets thread error field to 9, returns 0xFFFFFFFF\n- Inactive stream (nPosition bit 0x1 clear): Sets thread error field to 9, returns 0xFFFFFFFF  \n- FlushFileBuffers() failure: Sets thread error field to GetLastError() code, returns 0xFFFFFFFF\n- Double-check pattern ensures stream remains active between initial check and critical section\n\nMagic Numbers Reference:\n0x1 (1): Active stream flag bit mask in StreamIO.nPosition field\n0x5 (5): Right shift count for bucket calculation (divide by 32)\n0x1F (31): Bit mask for slot calculation (modulo 32) \n0x9 (9): Thread error code for invalid/inactive stream operations\n0xFFFFFFFF: Standard failure return value (-1)\n\nError Handling:\n- Thread context error codes set via GetThreadContextErrorCodePtr() and GetThreadContextFieldAt8()\n- Error code 9: Invalid stream index or inactive stream\n- Error codes from GetLastError(): File system or handle errors from FlushFileBuffers()\n- Critical section always released to prevent deadlocks\n\nStructure Layout:\nStreamIO (36 bytes) - accessed at g_apStreamDescriptors[bucket][slot]:\nOffset  Size  Field Name   Type    Description\n+0x00   4     ???          uint    Unknown field\n+0x04   4     nPosition    uint    Stream position with active flag in bit 0x1\n+0x08   28    ???          ???     Remaining fields (28 bytes)\n\nNote: Function uses DVar1 and pDVar2 SSA temporaries that are not renameable in decompiled view.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b14dfb771e9c85951130aa7c0ee6e7bc"
    },
    "Bnclient_MNE_b1691d6b7b8b": {
      "addresses": {
        "LoD/1.07": "0x6FF2CABC",
        "LoD/1.08": "0x6FF2CADC",
        "LoD/1.09": "0x6FF0D6DC",
        "LoD/1.09b": "0x6FF0D6DC",
        "LoD/1.09d": "0x6FF0D9EC",
        "LoD/1.10": "0x6FF0DF52",
        "LoD/1.11": "0x6FF22BA1",
        "LoD/1.11b": "0x6FF23CB6",
        "LoD/1.12a": "0x6FF23259",
        "LoD/1.13c": "0x6FF237D6",
        "LoD/1.13d": "0x6FF23165"
      },
      "rvas": {
        "LoD/1.07": "0xCABC",
        "LoD/1.08": "0xCADC",
        "LoD/1.09": "0xD6DC",
        "LoD/1.09b": "0xD6DC",
        "LoD/1.09d": "0xD9EC",
        "LoD/1.10": "0xDF52",
        "LoD/1.11": "0x2BA1",
        "LoD/1.11b": "0x3CB6",
        "LoD/1.12a": "0x3259",
        "LoD/1.13c": "0x37D6",
        "LoD/1.13d": "0x3165"
      },
      "name": "GetThreadContextFieldAt8",
      "signature": "DWORD * GetThreadContextFieldAt8(void)",
      "comment": "Get pointer to DWORD field at offset +8 bytes within thread context data.\n\nAlgorithm:\n1. Retrieve thread context pointer via GetOrCreateThreadContext()\n2. Calculate offset +8 bytes (2 DWORDs) from context base\n3. Return pointer to field at calculated offset\n\nParameters:\nNone\n\nReturns:\nuint * - Pointer to DWORD field at offset +8 within ThreadContext structure\n         Returns valid pointer if thread context exists\n         May return invalid pointer if context allocation failed\n\nSpecial Cases:\n- Relies on GetOrCreateThreadContext() for context availability\n- Offset +8 assumes fixed ThreadContext structure layout\n- Caller must validate returned pointer before dereferencing\n\nMagic Numbers Reference:\n0x8 (8 decimal) - Byte offset to target field within ThreadContext structure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b1691d6b7b8ba065c3fc1a089e8db64e"
    },
    "Bnclient_MNE_b292ada82c00": {
      "addresses": {
        "LoD/1.07": "0x6FF2A170",
        "LoD/1.08": "0x6FF2A190",
        "LoD/1.09": "0x6FF0AD90",
        "LoD/1.09b": "0x6FF0AD90",
        "LoD/1.09d": "0x6FF0AFE0"
      },
      "rvas": {
        "LoD/1.07": "0xA170",
        "LoD/1.08": "0xA190",
        "LoD/1.09": "0xAD90",
        "LoD/1.09b": "0xAD90",
        "LoD/1.09d": "0xAFE0"
      },
      "name": "ComputeModularInverse",
      "signature": "dword ComputeModularInverse(dword nModulus)",
      "comment": "Computes the modular multiplicative inverse using Extended Euclidean Algorithm.\n\nAlgorithm:\n1. Input validation: Return nModulus if nModulus < 2 (trivial cases 0, 1)\n2. Initialize Extended Euclidean Algorithm with modulus 0x10001 (65537)\n   - Compute initial quotient: nCoeffS = 0x10001 / nModulus  \n   - Compute initial remainder: qwRemainder = 0x10001 % nModulus\n3. Early termination: If qwRemainder == 1, return final result (1 - nCoeffS) & 0xffff\n4. Extended Euclidean iteration setup:\n   - dwPrevRemainder = nModulus % qwRemainder\n   - dwCoeffT = (nModulus / qwRemainder) * nCoeffS + 1\n5. Main Extended Euclidean loop:\n   - While dwPrevRemainder != 1:\n     a. Compute quotient: dwQuotient = dwCurrentRemainder / dwPrevRemainder\n     b. Compute new remainder: qwRemainder = dwCurrentRemainder % dwPrevRemainder\n     c. Update coefficient: nCoeffS = nCoeffS + dwQuotient * dwCoeffT\n     d. Check termination: If new remainder == 1, return dwCoeffT\n     e. Prepare next iteration: Update remainders and coefficients\n6. Return final modular inverse: (1 - nCoeffS) & 0xffff\n\nParameters:\nnModulus - Input modulus value for inverse computation (must be > 1, coprime to 65537)\n\nReturns:\nModular multiplicative inverse of nModulus modulo 65537 (0x10001)\nReturns original value for trivial cases (nModulus < 2)\nResult masked to 16-bit range (0x0000-0xFFFF)\n\nSpecial Cases:\nInput 0: Returns 0 (undefined mathematical case but handled gracefully)\nInput 1: Returns 1 (1^-1 \u2261 1 mod 65537)\nNon-coprime inputs: Algorithm may not terminate or return invalid results\n\nMagic Numbers Reference:\n0x10001 (65537) - RSA public exponent and modulus for inverse computation\n0xffff (65535) - 16-bit mask for final result truncation\n2 - Minimum input threshold for algorithm execution\n\nError Handling:\nNo explicit error handling for non-coprime inputs\nCaller responsible for ensuring gcd(nModulus, 65537) = 1\nMathematical overflow protected by 64-bit intermediate calculations",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b292ada82c00457390c37cbeec158f6e"
    },
    "Bnclient_MNE_b2a8f1a86586": {
      "addresses": {
        "LoD/1.11": "0x6FF272FA",
        "LoD/1.11b": "0x6FF25547",
        "LoD/1.12a": "0x6FF249AE",
        "LoD/1.13c": "0x6FF26255",
        "LoD/1.13d": "0x6FF26160"
      },
      "rvas": {
        "LoD/1.11": "0x72FA",
        "LoD/1.11b": "0x5547",
        "LoD/1.12a": "0x49AE",
        "LoD/1.13c": "0x6255",
        "LoD/1.13d": "0x6160"
      },
      "name": "___crtInitCritSecNoSpinCount@8",
      "signature": "undefined4 ___crtInitCritSecNoSpinCount@8(LPCRITICAL_SECTION param_1)",
      "comment": "Library Function - Single Match\n ___crtInitCritSecNoSpinCount@8\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:b2a8f1a86586c795d4e7ef4b4053c58e"
    },
    "Bnclient_MNE_b3d0a45c15a9": {
      "addresses": {
        "LoD/1.07": "0x6FF24490",
        "LoD/1.08": "0x6FF244B0",
        "LoD/1.09": "0x6FF04E10",
        "LoD/1.09b": "0x6FF04E10",
        "LoD/1.09d": "0x6FF05090",
        "LoD/1.10": "0x6FF05020"
      },
      "rvas": {
        "LoD/1.07": "0x4490",
        "LoD/1.08": "0x44B0",
        "LoD/1.09": "0x4E10",
        "LoD/1.09b": "0x4E10",
        "LoD/1.09d": "0x5090",
        "LoD/1.10": "0x5020"
      },
      "name": "CopyToGlobalBuffer",
      "signature": "uint CopyToGlobalBuffer(uint dwDataLength)",
      "comment": "Copies data to global buffer using STORM.DLL memory copy function. This wrapper\nprovides a standardized interface for copying data to a global 128-byte buffer\nused throughout the application for temporary data storage operations.\n\nAlgorithm:\n1. Validate inputs and prepare parameters for STORM.DLL call\n2. Call STORM.DLL Ordinal_501 (SMemCpy variant) with global buffer address\n3. Pass data length parameter and fixed size limit of 0x80 bytes  \n4. Return success status indicating operation completed\n\nParameters:\n- dwDataLength: uint - Length of data to copy to global buffer\n\nReturns:\n- uint: Always returns 1 indicating successful completion of copy operation\n\nSpecial Cases:\n- Fixed copy size of 0x80 (128 bytes) regardless of dwDataLength parameter\n- Global buffer g_abGlobalBuffer is pre-zeroed 128-byte array\n- No bounds checking performed on input data length\n\nMagic Numbers Reference:\n- 0x80 (128): Fixed buffer copy size for global buffer operations\n- 0x1: Success return code indicating completion\n\nError Handling:\n- No error validation performed on input parameters\n- Relies on STORM.DLL Ordinal_501 for memory copy safety and bounds checking",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b3d0a45c15a95c38e4feee8f297ac666"
    },
    "Bnclient_MNE_b4560a79897b": {
      "addresses": {
        "LoD/1.09": "0x6FF04BC0",
        "LoD/1.09b": "0x6FF04BC0",
        "LoD/1.09d": "0x6FF04E40"
      },
      "rvas": {
        "LoD/1.09": "0x4BC0",
        "LoD/1.09b": "0x4BC0",
        "LoD/1.09d": "0x4E40"
      },
      "method": "MNE",
      "index": "MNE:b4560a79897b3746ca825e25ebb3decd"
    },
    "Bnclient_MNE_b532f32a77f2": {
      "addresses": {
        "LoD/1.07": "0x6FF21F90",
        "LoD/1.08": "0x6FF21FB0",
        "LoD/1.09": "0x6FF02070",
        "LoD/1.09b": "0x6FF02070",
        "LoD/1.09d": "0x6FF02040"
      },
      "rvas": {
        "LoD/1.07": "0x1F90",
        "LoD/1.08": "0x1FB0",
        "LoD/1.09": "0x2070",
        "LoD/1.09b": "0x2070",
        "LoD/1.09d": "0x2040"
      },
      "name": "CompactDataStream",
      "signature": "void CompactDataStream(char * szBuffer, int nBufferSize)",
      "comment": "Processes and compacts a binary data stream containing variable-length entries.\n\nAlgorithm:\n1. Scan buffer sequentially searching for entries with marker byte 0xFF\n2. For each entry found, validate buffer boundaries against entry length field\n3. Extract entry type from offset +1 and length from offset +2 (ushort)\n4. Call processing function with entry type if boundaries are valid\n5. Advance current position by entry length to next entry\n6. Continue until insufficient buffer space for minimum entry (4 bytes)\n7. Compact remaining unprocessed data by copying to buffer start\n8. Perform 32-bit aligned copy for efficiency, then byte copy for remainder\n\nParameters:\nszBuffer - Pointer to binary data buffer containing variable-length entries\nnBufferSize - Total size of buffer in bytes\n\nReturns:\nvoid - Function modifies buffer in-place by compacting unprocessed data\n\nStructure Layout:\nDataEntry structure (4 bytes total):\nOffset | Size | Field Name | Type   | Description\n0      | 1    | bMarker    | byte   | Entry marker (0xFF indicates entry start)\n1      | 1    | bType      | byte   | Entry type identifier for processing\n2      | 2    | wLength    | ushort | Total entry length including header\n\nMagic Numbers:\n0xFF - Entry marker byte indicating start of valid data entry\n0x4  - Minimum entry size (4 bytes for DataEntry header)\n\nSpecial Cases:\n- Function terminates when remaining buffer space < 4 bytes (minimum entry size)\n- Buffer boundaries are validated before accessing entry length field\n- Memory copy operations use optimized 32-bit transfers followed by byte transfers\n- Function handles partial entries at buffer end by leaving them unprocessed",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b532f32a77f2f6563dd6ff3001c93e18"
    },
    "Bnclient_MNE_b5756233a5a7": {
      "addresses": {
        "LoD/1.07": "0x6FF2B3F5",
        "LoD/1.08": "0x6FF2B416",
        "LoD/1.09": "0x6FF0C016",
        "LoD/1.09b": "0x6FF0C016",
        "LoD/1.09d": "0x6FF0C275",
        "LoD/1.10": "0x6FF0C7D5"
      },
      "rvas": {
        "LoD/1.07": "0xB3F5",
        "LoD/1.08": "0xB416",
        "LoD/1.09": "0xC016",
        "LoD/1.09b": "0xC016",
        "LoD/1.09d": "0xC275",
        "LoD/1.10": "0xC7D5"
      },
      "name": "AddToDynamicBuffer",
      "signature": "uint AddToDynamicBuffer(uint dwValue)",
      "comment": "Adds a 32-bit value to the global dynamic buffer, expanding the buffer if necessary.\n\nAlgorithm:\n1. Acquire buffer lock via FUN_6ff2b372()\n2. Calculate current buffer size using FUN_6ff2c818(g_pbDynamicBufferStart)\n3. Check if sufficient space exists (at least 4 bytes free)\n4. If buffer too small:\n   a. Get current buffer size\n   b. Expand buffer by 16 additional bytes via FUN_6ff2c4e9(buffer, size+16)\n   c. If expansion fails, return 0 for failure\n   d. Update g_pbDynamicBufferStart and g_pbDynamicBufferEnd pointers\n5. Store the 32-bit value at g_pbDynamicBufferEnd\n6. Advance g_pbDynamicBufferEnd by 4 bytes\n7. Release buffer lock via FUN_6ff2b37b()\n8. Return the original value that was stored\n\nParameters:\ndwValue (uint) - The 32-bit value to append to the buffer\n\nReturns:\nuint - The same value that was added on success, or 0 on allocation failure\n\nSpecial Cases:\n- Returns 0 if buffer expansion fails (allocation error)\n- Buffer is expanded in 16-byte increments (0x10)\n- Global buffer pointers are updated atomically during expansion\n\nMagic Numbers Reference:\n0x10 (16) - Buffer expansion increment in bytes\n0x4 (4) - Size of each buffer element (32-bit values)\n\nError Handling:\n- Memory allocation failure returns 0\n- Buffer state remains consistent on allocation failure\n- Function is thread-safe via lock/unlock calls",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b5756233a5a7628ebca8fed8bafffdce"
    },
    "Bnclient_MNE_b59a8a7d2c8f": {
      "addresses": {
        "LoD/1.07": "0x6FF2EE78",
        "LoD/1.08": "0x6FF2EE98",
        "LoD/1.09": "0x6FF0FAC3",
        "LoD/1.09b": "0x6FF0FAC3",
        "LoD/1.09d": "0x6FF0FDA8",
        "LoD/1.10": "0x6FF10396"
      },
      "rvas": {
        "LoD/1.07": "0xEE78",
        "LoD/1.08": "0xEE98",
        "LoD/1.09": "0xFAC3",
        "LoD/1.09b": "0xFAC3",
        "LoD/1.09d": "0xFDA8",
        "LoD/1.10": "0x10396"
      },
      "name": "AllocateMemoryDescriptor",
      "signature": "uint * AllocateMemoryDescriptor(void)",
      "comment": "Allocates and initializes a new memory descriptor for dual heap/virtual memory management.\n\nAlgorithm:\n1. Check if allocation table is full (count == granularity)\n2. If full, reallocate table with increased capacity (+16 entries)\n3. Calculate next available descriptor slot in table\n4. Allocate 0x41c4 bytes of heap memory with HEAP_ZERO_MEMORY flag\n5. If heap allocation succeeds, allocate 0x100000 bytes virtual memory (MEM_RESERVE)\n6. If virtual allocation succeeds, initialize descriptor fields and increment count\n7. Set first DWORD of heap memory to 0xffffffff as allocation marker\n8. Return pointer to dwReserved1 field for client tracking\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nuint * - Pointer to dwReserved1 field in MemoryAllocation descriptor for client use\nNULL - Allocation failure (heap or virtual memory allocation failed)\n\nSpecial Cases:\nTable reallocation failure returns NULL immediately\nHeap allocation failure returns NULL\nVirtual allocation failure frees heap memory and returns NULL\nAllocation marker 0xffffffff written to start of heap block\n\nMagic Numbers Reference:\n0x41c4 (16836) - Fixed heap allocation size for client use\n0x100000 (1048576) - Virtual memory reservation size (1MB)\n0x2000 (MEM_RESERVE) - Virtual memory allocation type\n0x4 (PAGE_READWRITE) - Virtual memory protection\n0x8 (HEAP_ZERO_MEMORY) - Heap allocation flag\n0xffffffff - Allocation marker and field initializer\n0x50 (80) - Base allocation granularity offset\n0x10 (16) - Granularity increment size\n\nStructure Layout:\nOffset | Size | Field Name      | Type     | Description\n-------|------|-----------------|----------|----------------------------------\n0x00   | 4    | dwReserved1     | uint     | Client tracking field (returned)\n0x04   | 4    | dwReserved2     | uint     | Client reserved field\n0x08   | 4    | dwReserved3     | uint     | Descriptor flags (set to 0xffffffff)\n0x0C   | 4    | pVirtualMemory  | void *   | Virtual allocation base address\n0x10   | 4    | pHeapMemory     | void *   | Heap allocation base address\n\nError Handling:\nHeapReAlloc failure - Returns NULL without modifying global state\nHeapAlloc failure - Returns NULL, no cleanup required\nVirtualAlloc failure - Frees heap memory using HeapFree, returns NULL",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b59a8a7d2c8fdcc2aac183f01f99a847"
    },
    "Bnclient_MNE_b5dbf3686e3d": {
      "addresses": {
        "LoD/1.11": "0x6FF30CC0",
        "LoD/1.11b": "0x6FF31330",
        "LoD/1.12a": "0x6FF2FDB0",
        "LoD/1.13c": "0x6FF32F70",
        "LoD/1.13d": "0x6FF2EF30"
      },
      "rvas": {
        "LoD/1.11": "0x10CC0",
        "LoD/1.11b": "0x11330",
        "LoD/1.12a": "0xFDB0",
        "LoD/1.13c": "0x12F70",
        "LoD/1.13d": "0xEF30"
      },
      "method": "MNE",
      "index": "MNE:b5dbf3686e3d83b2a01fe833686995f4"
    },
    "Bnclient_MNE_b5e8d68191f2": {
      "addresses": {
        "LoD/1.11b": "0x6FF27E87",
        "LoD/1.13c": "0x6FF27EF7",
        "LoD/1.13d": "0x6FF27EF7"
      },
      "rvas": {
        "LoD/1.11b": "0x7E87",
        "LoD/1.13c": "0x7EF7",
        "LoD/1.13d": "0x7EF7"
      },
      "name": "__close",
      "signature": "int __close(int _FileHandle)",
      "comment": "Library Function - Single Match\n __close\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11b",
      "method": "MNE",
      "index": "MNE:b5e8d68191f204e2d43adbcf540da123"
    },
    "Bnclient_MNE_b6c4981ac166": {
      "addresses": {
        "LoD/1.11": "0x6FF2CFA0",
        "LoD/1.11b": "0x6FF34B40",
        "LoD/1.12a": "0x6FF34810",
        "LoD/1.13c": "0x6FF32390",
        "LoD/1.13d": "0x6FF37020"
      },
      "rvas": {
        "LoD/1.11": "0xCFA0",
        "LoD/1.11b": "0x14B40",
        "LoD/1.12a": "0x14810",
        "LoD/1.13c": "0x12390",
        "LoD/1.13d": "0x17020"
      },
      "method": "MNE",
      "index": "MNE:b6c4981ac1663d2a4307a741d9729a88"
    },
    "Bnclient_MNE_b7003782678f": {
      "addresses": {
        "LoD/1.07": "0x6FF30C77",
        "LoD/1.08": "0x6FF30C97",
        "LoD/1.09": "0x6FF118B7",
        "LoD/1.09b": "0x6FF118B7",
        "LoD/1.09d": "0x6FF11BA7",
        "LoD/1.10": "0x6FF120F7"
      },
      "rvas": {
        "LoD/1.07": "0x10C77",
        "LoD/1.08": "0x10C97",
        "LoD/1.09": "0x118B7",
        "LoD/1.09b": "0x118B7",
        "LoD/1.09d": "0x11BA7",
        "LoD/1.10": "0x120F7"
      },
      "name": "InitializeCharacterTypeTable",
      "signature": "uint InitializeCharacterTypeTable(uint dwCodePage)",
      "comment": "Initialize character type classification table for the specified code page.\n\nAlgorithm:\n1. Acquire critical section lock (index 0x19) for thread-safe table updates\n2. Retrieve normalized code page from parameter using FUN_6ff30e24()  \n3. Check if requested code page already matches current global code page (g_dwCurrentCodePage)\n4. If code page is zero, call cleanup function and return 0\n5. Search predefined code page table (g_adwCodePageTable) for matching entry\n6. If found in predefined table:\n   a. Clear global character type table (g_abCharacterTypeTable) to zero\n   b. Load character type ranges from predefined table entry\n   c. For each of 4 type categories, process character ranges\n   d. Set character type bits by ORing predefined values with table entries\n   e. Update global code page state and configuration values\n7. If not in predefined table:\n   a. Call GetCPInfo() to retrieve Windows code page information\n   b. Clear character type table and reset DBCS configuration\n   c. If single-byte code page (MaxCharSize < 2), set single-byte flag\n   d. If multi-byte code page, process lead byte ranges from CPINFO\n   e. Set lead byte bit (0x04) for all characters in lead byte ranges\n   f. Set trail byte bit (0x08) for all characters 1-254\n8. Call finalization functions FUN_6ff30eca() and optionally FUN_6ff30ea1()\n9. Release critical section lock and return success\n\nParameters:\ndwCodePage (uint): Windows code page identifier (e.g., 1252 for Latin-1, 932 for Shift-JIS)\n\nReturns:\nuint: 0 on successful initialization, 0xFFFFFFFF on failure\n\nSpecial Cases:\nIf code page is already current, return 0 immediately without reprocessing\nIf GetCPInfo fails and global flag g_fCodePageInitialized is clear, return 0xFFFFFFFF\nZero code page triggers cleanup sequence via FUN_6ff30ea1()\n\nMagic Numbers Reference:\n0x19 - Critical section index for character type table protection\n0x04 - Lead byte character type bit flag  \n0x08 - Trail byte character type bit flag\n0x30 - Size of each predefined code page table entry\n0x40 - Loop count for clearing 256-byte character table (64 * 4 bytes)\n0xFF - Maximum character value for trail byte processing",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b7003782678f33a2ea4e8b0cc2bae15e"
    },
    "Bnclient_MNE_b7026c232ba5": {
      "addresses": {
        "LoD/1.07": "0x6FF2DDF8",
        "LoD/1.08": "0x6FF2DE18",
        "LoD/1.09": "0x6FF0EA43",
        "LoD/1.09b": "0x6FF0EA43",
        "LoD/1.09d": "0x6FF0ED28",
        "LoD/1.10": "0x6FF0F316"
      },
      "rvas": {
        "LoD/1.07": "0xDDF8",
        "LoD/1.08": "0xDE18",
        "LoD/1.09": "0xEA43",
        "LoD/1.09b": "0xEA43",
        "LoD/1.09d": "0xED28",
        "LoD/1.10": "0xF316"
      },
      "name": "CleanupStreamDescriptors",
      "signature": "void CleanupStreamDescriptors(void)",
      "comment": "Cleanup and deallocate all StreamIO descriptor arrays during DLL shutdown.\n\nAlgorithm:\n1. Initialize pointer to global stream descriptor array at 0x6ff3b440\n2. For each descriptor pointer in the array (up to 0x6ff3b540):\n   a. Check if descriptor pointer is non-null\n   b. If valid, iterate through 32 StreamIO structures (0x20 entries)\n   c. For each StreamIO structure, check critical section at offset -4 from dwFlags\n   d. If critical section exists, call DeleteCriticalSection to cleanup\n   e. Advance to next StreamIO structure (0x24 byte stride)\n3. After processing all structures in descriptor, deallocate entire descriptor memory\n4. Set descriptor pointer to null to prevent double-free\n5. Move to next descriptor pointer and repeat\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Handles null descriptor pointers safely by skipping\n- Uses boundary checking (pStreamEnd < pStreamEnd + 0x20) for validation\n- Critical section cleanup only performed if critical section field is non-null\n- Memory deallocation performed after all critical sections cleaned up\n\nMagic Numbers Reference:\n- 0x20 (32): Number of StreamIO structures per descriptor array\n- 0x24 (36): Size of each StreamIO structure in bytes\n- 0x6ff3b440: Base address of global stream descriptor array\n- 0x6ff3b540: End address of global stream descriptor array\n- -0x4: Offset from dwFlags field to critical section field in StreamIO structure\n\nStructure Layout:\nStreamIO (36 bytes):\nOffset | Size | Field Name        | Type                    | Description\n+0x00  | 4    | pCriticalSection  | _RTL_CRITICAL_SECTION*  | Synchronization object\n+0x04  | 4    | dwFlags          | uint                    | Stream status flags\n+0x08  | 28   | (remaining)      | byte[28]               | Additional stream data",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b7026c232ba5b32b3521a3c7482af720"
    },
    "Bnclient_MNE_b8869635da2e": {
      "addresses": {
        "LoD/1.07": "0x6FF24FD0",
        "LoD/1.08": "0x6FF24FF0",
        "LoD/1.09": "0x6FF05950",
        "LoD/1.09b": "0x6FF05950",
        "LoD/1.09d": "0x6FF05BC0",
        "LoD/1.10": "0x6FF05B30"
      },
      "rvas": {
        "LoD/1.07": "0x4FD0",
        "LoD/1.08": "0x4FF0",
        "LoD/1.09": "0x5950",
        "LoD/1.09b": "0x5950",
        "LoD/1.09d": "0x5BC0",
        "LoD/1.10": "0x5B30"
      },
      "name": "SkipToEOL",
      "signature": "char * SkipToEOL(BNGatewayAccess * this, char * lpszStart, char * lpszEnd)",
      "comment": "Scan buffer for end-of-line characters, stopping at CR, LF, or null terminator.\n\nAlgorithm:\n1. Validate buffer boundaries (start < end)\n2. Enter scanning loop at current position\n3. Load character from current buffer position\n4. Check for null terminator (0x00) - if found, return current position\n5. Check for carriage return (0x0D) - if found, return current position  \n6. Check for line feed (0x0A) - if found, return current position\n7. Advance buffer pointer by one character\n8. Continue loop while position < end boundary\n9. Return final position when boundary reached\n\nParameters:\n- this: BNGatewayAccess * - Gateway object instance (implicit in ECX register)\n- lpszStart: char * - Starting position in buffer to scan\n- lpszEnd: char * - End boundary of buffer (exclusive limit)\n\nReturns:\n- Success: Pointer to first EOL character found (CR, LF, or null)\n- Boundary: Pointer to end position when no EOL found within range\n- Invalid: Returns lpszStart if start >= end (boundary validation)\n\nSpecial Cases:\n- Empty buffer: Returns lpszStart immediately\n- Single character: Checks character and returns position\n- No EOL found: Returns lpszEnd when scan reaches boundary\n- Null in middle: Treats null as EOL and returns that position\n\nMagic Numbers Reference:\n- 0x0D (13): Carriage return character '\\r' \n- 0x0A (10): Line feed character '\n'\n- 0x00 (0): Null terminator character '\\0'",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b8869635da2e7f436b1eef0547d896fe"
    },
    "Bnclient_MNE_b98b5dfcbc6f": {
      "addresses": {
        "LoD/1.10": "0x6FF0BF70"
      },
      "rvas": {
        "LoD/1.10": "0xBF70"
      },
      "method": "MNE",
      "index": "MNE:b98b5dfcbc6f29407bb4d94bab0456bc"
    },
    "Bnclient_MNE_b99d3962c0b2": {
      "addresses": {
        "LoD/1.07": "0x6FF2FD50",
        "LoD/1.08": "0x6FF2FD70",
        "LoD/1.09": "0x6FF10990",
        "LoD/1.09b": "0x6FF10990",
        "LoD/1.09d": "0x6FF10C80",
        "LoD/1.10": "0x6FF11260"
      },
      "rvas": {
        "LoD/1.07": "0xFD50",
        "LoD/1.08": "0xFD70",
        "LoD/1.09": "0x10990",
        "LoD/1.09b": "0x10990",
        "LoD/1.09d": "0x10C80",
        "LoD/1.10": "0x11260"
      },
      "name": "_memset",
      "signature": "void * _memset(void * pDst, int nVal, size_t stSize)",
      "comment": "Fills a memory block with a specified byte value using optimized DWORD operations\n\nAlgorithm:\n1. Check if size is zero and return original pointer immediately if so\n2. Extract low byte from fill value into dwBytePattern \n3. Check if size is less than 4 bytes, skip optimization if so\n4. Calculate alignment offset needed to align destination to 4-byte boundary\n5. Fill unaligned bytes individually to reach 4-byte alignment if needed\n6. Create 32-bit fill pattern by replicating byte value (0x0A becomes 0x0A0A0A0A)\n7. Calculate number of 4-byte chunks and remainder bytes from remaining size\n8. Use REP STOSD instruction to fill 4-byte chunks efficiently in bulk\n9. Fill any remaining 1-3 bytes individually at end of buffer\n10. Return original destination pointer as per standard memset contract\n\nParameters:\npDst: void* - Destination buffer to fill with specified byte value\nnVal: int - Fill value (only low byte used, high bytes ignored) \nstSize: size_t - Number of bytes to fill in destination buffer\n\nReturns:\nvoid* - Original destination pointer (pDst parameter value)\nAlways returns input pDst pointer regardless of size or alignment\n\nSpecial Cases:\nZero size: Returns immediately without memory access for stSize == 0\nSmall buffers: Uses byte-by-byte fill for sizes less than 4 bytes\nUnaligned buffers: Pre-aligns to 4-byte boundary before bulk operations\nPattern generation: Converts single byte to 32-bit pattern via shift-add operations\n\nMagic Numbers Reference:\n0x4 (4): Minimum size threshold for DWORD optimization and alignment boundary\n0x3 (3): Bit mask for extracting alignment offset and remainder calculation\n0x8 (8): Bit shift amount for building 32-bit pattern from byte value\n0x10 (16): Second shift amount for completing 32-bit pattern construction\n0x2 (2): Right shift amount for converting byte count to DWORD count\n0x1010101: Mathematical constant - byte replication pattern for 32-bit value\n\nError Handling:\nNo explicit error checking performed - assumes valid pointers and size\nHandles zero size gracefully by immediate return without memory access\nAlignment calculations use bit operations to avoid division overhead",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b99d3962c0b26901db87269607fbf85a"
    },
    "Bnclient_MNE_ba06e6249289": {
      "addresses": {
        "LoD/1.11": "0x6FF3755A",
        "LoD/1.11b": "0x6FF3752A",
        "LoD/1.12a": "0x6FF383DA",
        "LoD/1.13c": "0x6FF383BA",
        "LoD/1.13d": "0x6FF382FA"
      },
      "rvas": {
        "LoD/1.11": "0x1755A",
        "LoD/1.11b": "0x1752A",
        "LoD/1.12a": "0x183DA",
        "LoD/1.13c": "0x183BA",
        "LoD/1.13d": "0x182FA"
      },
      "name": "_abort",
      "signature": "void _abort(void)",
      "comment": "Library Function - Single Match\n _abort\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:ba06e624928980d9b2c569e5db716aab"
    },
    "Bnclient_MNE_ba896e89d5b4": {
      "addresses": {
        "LoD/1.11": "0x6FF24547",
        "LoD/1.11b": "0x6FF24539",
        "LoD/1.12a": "0x6FF245A7",
        "LoD/1.13c": "0x6FF245AC",
        "LoD/1.13d": "0x6FF245B2"
      },
      "rvas": {
        "LoD/1.11": "0x4547",
        "LoD/1.11b": "0x4539",
        "LoD/1.12a": "0x45A7",
        "LoD/1.13c": "0x45AC",
        "LoD/1.13d": "0x45B2"
      },
      "name": "___crtGetEnvironmentStringsA",
      "signature": "LPVOID ___crtGetEnvironmentStringsA(void)",
      "comment": "Library Function - Single Match\n ___crtGetEnvironmentStringsA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:ba896e89d5b4e319d02dcd31648ce3d9"
    },
    "Bnclient_MNE_ba94d8bc873f": {
      "addresses": {
        "LoD/1.07": "0x6FF250D0",
        "LoD/1.08": "0x6FF250F0",
        "LoD/1.09": "0x6FF05A50",
        "LoD/1.09b": "0x6FF05A50",
        "LoD/1.09d": "0x6FF05CC0",
        "LoD/1.10": "0x6FF05C30"
      },
      "rvas": {
        "LoD/1.07": "0x50D0",
        "LoD/1.08": "0x50F0",
        "LoD/1.09": "0x5A50",
        "LoD/1.09b": "0x5A50",
        "LoD/1.09d": "0x5CC0",
        "LoD/1.10": "0x5C30"
      },
      "name": "FindKey",
      "signature": "char * FindKey(BNGatewayAccess * this, char * lpszSearchBuffer, char * lpszKeyPattern)",
      "comment": "Searches for a key pattern within a buffer and returns pointer to data following the key.\n\nAlgorithm:\n1. Calculate length of search buffer using strlen-like operation (SCASB.REPNE)\n2. Calculate length of key pattern using strlen-like operation (SCASB.REPNE)\n3. Validate search buffer is not empty and doesn't start with ']' (0x5d)\n4. Search for key pattern in buffer using FUN_6ff2b820 (string comparison function)\n5. If match found, calculate position after key pattern and return pointer\n6. If no match found, advance to end of current line (skip until CR/LF)\n7. Skip whitespace and newline characters (CR=0x0d, LF=0x0a) \n8. Continue search from next line until buffer exhausted or ']' character found\n9. Return NULL if key pattern not found in buffer\n\nParameters:\n- this: BNGatewayAccess object instance (implicit ECX register)\n- lpszSearchBuffer: Buffer to search within for key pattern\n- lpszKeyPattern: Key pattern string to locate in search buffer\n\nReturns:\n- Pointer to data immediately following the found key pattern\n- NULL (0x0) if key pattern not found or buffer empty/invalid\n\nSpecial Cases:\n- Returns NULL immediately if search buffer starts with ']' (0x5d) terminator\n- Skips lines that don't contain the key pattern\n- Handles both CR (0x0d) and LF (0x0a) line terminators\n- Search terminates at buffer end or ']' character\n\nMagic Numbers Reference:\n- 0x5d (93): ']' character - section terminator in configuration format\n- 0x0d (13): Carriage return (CR) character  \n- 0x0a (10): Line feed (LF) character\n- 0xffffffff: Initial value for strlen calculation using SCASB.REPNE",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ba94d8bc873ff9f95b5a48419bb1afea"
    },
    "Bnclient_MNE_bac569fc88fb": {
      "addresses": {
        "LoD/1.07": "0x6FF30148",
        "LoD/1.08": "0x6FF30168",
        "LoD/1.09": "0x6FF10D88",
        "LoD/1.09b": "0x6FF10D88",
        "LoD/1.09d": "0x6FF11078",
        "LoD/1.10": "0x6FF115C8"
      },
      "rvas": {
        "LoD/1.07": "0x10148",
        "LoD/1.08": "0x10168",
        "LoD/1.09": "0x10D88",
        "LoD/1.09b": "0x10D88",
        "LoD/1.09d": "0x11078",
        "LoD/1.10": "0x115C8"
      },
      "name": "StreamOperationWrapper",
      "signature": "uint StreamOperationWrapper(uint dwStreamIndex, int nParam2, uint dwParam3)",
      "comment": "Thread-safe wrapper for stream operations that validates stream index and provides exclusive access.\n\nAlgorithm:\n1. Validate stream index is within bounds (< g_dwStreamCount)\n2. Calculate bucket index (dwStreamIndex >> 5) and within-bucket index (dwStreamIndex & 0x1f)  \n3. Access stream descriptor array g_apStreamDescriptors[bucket][index]\n4. Check if stream is active by testing position flag (bit 0 of nPosition field)\n5. If stream invalid or inactive, jump to error_invalid_stream (0x6ff300bd)\n6. If stream valid and active, proceed to process_valid_stream (0x6ff30098):\n   - Lock stream access via FUN_6ff31601(dwStreamIndex)\n   - Call actual operation FUN_6ff300d5(dwStreamIndex, nParam2, dwParam3)\n   - Store result in dwResult\n   - Unlock stream access via FUN_6ff31660(dwStreamIndex)  \n   - Return dwResult\n7. Error path sets thread context error code to 9, clears extended error, returns -1\n\nParameters:\ndwStreamIndex (uint): Zero-based stream index to operate on, must be < g_dwStreamCount\nnParam2 (int): Second parameter passed to underlying operation (purpose varies by operation)\ndwParam3 (uint): Third parameter passed to underlying operation (purpose varies by operation)\n\nReturns:\nSuccess: Result value from underlying stream operation (varies by operation type)\nFailure: 0xFFFFFFFF (-1) when stream index invalid or stream inactive\n\nSpecial Cases:\nBucket-based indexing supports up to 32 streams per bucket in g_apStreamDescriptors array\nStream active flag is bit 0 of nPosition field in StreamIO structure (offset +4)\nThread context error code 9 indicates invalid stream access attempt\n\nMagic Numbers Reference:\n0x05 (5): Bit shift count for bucket calculation (divide by 32)\n0x1f (31): Mask for within-bucket index (modulo 32) \n0x01 (1): Stream active flag mask for nPosition field\n0x09 (9): Thread context error code for invalid stream access\n0xffffffff (-1): Error return value for invalid/inactive streams\n\nStructure Layout:\nStreamIO structure (36 bytes):\nOffset  Size  Field      Type    Description\n+0x00   4     unknown    uint    Purpose unknown\n+0x04   4     nPosition  uint    Stream position with active flag in bit 0\n+0x08   28    unknown    varies  Additional fields (purpose unknown)\n\nFlag Bits:\nnPosition field bit layout:\nBit 0 (0x01): Stream active flag (1=active, 0=inactive)\nBits 1-31: Actual position value (right shift by 1 to get position)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:bac569fc88fbfeebd4a5205bbcce1faf",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF2BB80",
          "rva": "0xBB80",
          "confidence": 0.285,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF2C1B0",
          "rva": "0xC1B0",
          "confidence": 0.285,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13d": {
          "address": "0x6FF32E70",
          "rva": "0x12E70",
          "confidence": 0.136,
          "method": "minhash",
          "direction": "forward",
          "source": "LoD/1.11b"
        }
      }
    },
    "Bnclient_MNE_bafce56213ce": {
      "addresses": {
        "LoD/1.07": "0x6FF2C10D",
        "LoD/1.08": "0x6FF2C12D",
        "LoD/1.09": "0x6FF0CD2D",
        "LoD/1.09b": "0x6FF0CD2D",
        "LoD/1.09d": "0x6FF0D03D",
        "LoD/1.10": "0x6FF0D5A3"
      },
      "rvas": {
        "LoD/1.07": "0xC10D",
        "LoD/1.08": "0xC12D",
        "LoD/1.09": "0xCD2D",
        "LoD/1.09b": "0xCD2D",
        "LoD/1.09d": "0xD03D",
        "LoD/1.10": "0xD5A3"
      },
      "name": "DllEntryPoint",
      "signature": "int DllEntryPoint(void * phinstDLL, int nReason, void * pReserved)",
      "comment": "DLL entry point that orchestrates DLL attach/detach operations and manages initialization state.\n\nAlgorithm:\n1. Store original reason code for potential restoration during cleanup\n2. Check if nReason is 0 (DLL_PROCESS_DETACH or DLL_THREAD_DETACH) - if so, skip to main handler\n3. For attach operations (DLL_PROCESS_ATTACH=1 or DLL_THREAD_ATTACH=2):\n   a. If optional entry handler exists (g_pfnOptionalEntryHandler != NULL), call it first\n   b. If optional handler returns 0 (failure), abort with return 0\n   c. Call DllMain with current parameters for primary initialization\n   d. Store DllMain result in nResult\n4. If any initialization step failed (nResult == 0), return 0 immediately\n5. Call main handler function (FUN_6ff29650) with all parameters\n6. For DLL_PROCESS_ATTACH (nReason == 1):\n   a. If main handler failed (returned 0), call DllMain(phinstDLL, 0) for cleanup\n   b. Return main handler result if non-zero\n7. For detach operations (nReason == 0 or nReason == 3):\n   a. Call DllMain with current parameters for cleanup\n   b. If DllMain fails, clear nResult to 0\n8. If nResult is non-zero and optional handler exists, call optional handler with original reason\n9. Return final result (nResult or 0 on any failure)\n\nParameters:\nphinstDLL - Module handle for this DLL instance (HINSTANCE from Windows API)\nnReason - DLL attachment reason: 1=DLL_PROCESS_ATTACH, 0=DLL_PROCESS_DETACH, 2=DLL_THREAD_ATTACH, 3=DLL_THREAD_DETACH\npReserved - Reserved parameter for LoadLibrary/FreeLibrary operations (LPVOID from Windows API)\n\nReturns:\nNon-zero (TRUE) - DLL initialization/cleanup succeeded\n0 (FALSE) - DLL operation failed, DLL should be unloaded\n\nSpecial Cases:\n- nReason == 0: Skips optional handler pre-check, goes directly to main handler\n- Optional handler (g_pfnOptionalEntryHandler): Called before and after DLL operations if present\n- DLL_PROCESS_ATTACH failure triggers immediate DllMain(phinstDLL, 0) cleanup call\n- All handler failures result in return 0 to prevent DLL from remaining loaded\n\nMagic Numbers Reference:\n0x0 - DLL_PROCESS_DETACH or null pointer check\n0x1 - DLL_PROCESS_ATTACH (process initialization)\n0x2 - DLL_THREAD_ATTACH (thread initialization)\n0x3 - DLL_THREAD_DETACH (thread cleanup)\n\nNote: Function uses 2 assembly-only temporary variables (extraout_var, extraout_var_00) optimized away by decompiler for CONCAT31 operations converting boolean DllMain results to integers.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:bafce56213ce6cb4a7088c594df572ea"
    },
    "Bnclient_MNE_bb6caf8fa91f": {
      "addresses": {
        "LoD/1.11": "0x6FF2389F",
        "LoD/1.11b": "0x6FF2315F",
        "LoD/1.12a": "0x6FF224BF",
        "LoD/1.13c": "0x6FF22593",
        "LoD/1.13d": "0x6FF2349F"
      },
      "rvas": {
        "LoD/1.11": "0x389F",
        "LoD/1.11b": "0x315F",
        "LoD/1.12a": "0x24BF",
        "LoD/1.13c": "0x2593",
        "LoD/1.13d": "0x349F"
      },
      "name": "__SEH_epilog",
      "signature": "undefined __SEH_epilog(void)",
      "comment": "Library Function - Single Match\n __SEH_epilog\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:bb6caf8fa91f28d8c9b4f7822655fe6b"
    },
    "Bnclient_MNE_bceec9bac51b": {
      "addresses": {
        "LoD/1.09": "0x6FF134E0",
        "LoD/1.09b": "0x6FF134E0",
        "LoD/1.09d": "0x6FF13800"
      },
      "rvas": {
        "LoD/1.09": "0x134E0",
        "LoD/1.09b": "0x134E0",
        "LoD/1.09d": "0x13800"
      },
      "method": "MNE",
      "index": "MNE:bceec9bac51b7c2bfc77b81e0e5b879d"
    },
    "Bnclient_MNE_bd2e318ad253": {
      "addresses": {
        "LoD/1.11": "0x6FF36994",
        "LoD/1.11b": "0x6FF36965",
        "LoD/1.12a": "0x6FF37814",
        "LoD/1.13c": "0x6FF377FA",
        "LoD/1.13d": "0x6FF37733"
      },
      "rvas": {
        "LoD/1.11": "0x16994",
        "LoD/1.11b": "0x16965",
        "LoD/1.12a": "0x17814",
        "LoD/1.13c": "0x177FA",
        "LoD/1.13d": "0x17733"
      },
      "name": "_CreateFrameInfo",
      "signature": "FrameInfo * _CreateFrameInfo(FrameInfo * param_1, void * param_2)",
      "comment": "Library Function - Single Match\n struct FrameInfo * __cdecl _CreateFrameInfo(struct FrameInfo *,void *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:bd2e318ad25348813665cf4effb251a4"
    },
    "Bnclient_MNE_bd5a39beceb8": {
      "addresses": {
        "LoD/1.07": "0x6FF244D0",
        "LoD/1.08": "0x6FF244F0",
        "LoD/1.09": "0x6FF04E50",
        "LoD/1.09b": "0x6FF04E50",
        "LoD/1.09d": "0x6FF050D0",
        "LoD/1.10": "0x6FF05060",
        "LoD/1.11": "0x6FF21040",
        "LoD/1.11b": "0x6FF21210",
        "LoD/1.12a": "0x6FF210A0",
        "LoD/1.13c": "0x6FF21040",
        "LoD/1.13d": "0x6FF21030"
      },
      "rvas": {
        "LoD/1.07": "0x44D0",
        "LoD/1.08": "0x44F0",
        "LoD/1.09": "0x4E50",
        "LoD/1.09b": "0x4E50",
        "LoD/1.09d": "0x50D0",
        "LoD/1.10": "0x5060",
        "LoD/1.11": "0x1040",
        "LoD/1.11b": "0x1210",
        "LoD/1.12a": "0x10A0",
        "LoD/1.13c": "0x1040",
        "LoD/1.13d": "0x1030"
      },
      "name": "NumGateways",
      "signature": "int NumGateways(void)",
      "comment": "Get the number of available gateways from the BNGatewayAccess instance.\n\nAlgorithm:\n1. Retrieve the this pointer from the stack parameter\n2. Access the gateway count field at offset +8 within the class instance \n3. Return the gateway count as an integer value\n\nParameters:\nIMPLICIT this pointer (BNGatewayAccess *): Passed on stack at ESP+4, pointer to the gateway access object\n\nReturns:\nint: Number of available gateways (0 or positive integer)\n     Returns the value stored at this+8 offset in the class structure\n\nSpecial Cases:\nNone - Direct field access with no validation or error handling\n\nStructure Layout:\nBNGatewayAccess class layout (partial):\nOffset  Size  Field Name       Type  Description\n+0x0    ?     Unknown fields   ?     Class data before gateway count  \n+0x8    4     gatewayCount     int   Number of available gateways",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:bd5a39beceb8cd57f5ee31b3d8a56984"
    },
    "Bnclient_MNE_bd8c947bed50": {
      "addresses": {
        "LoD/1.09": "0x6FF13740",
        "LoD/1.09b": "0x6FF13740",
        "LoD/1.09d": "0x6FF13A60"
      },
      "rvas": {
        "LoD/1.09": "0x13740",
        "LoD/1.09b": "0x13740",
        "LoD/1.09d": "0x13A60"
      },
      "method": "MNE",
      "index": "MNE:bd8c947bed50af8a0206a8e72bf14d60"
    },
    "Bnclient_MNE_bdb6fd2e7f75": {
      "addresses": {
        "LoD/1.09": "0x6FF12D50",
        "LoD/1.09b": "0x6FF12D50",
        "LoD/1.09d": "0x6FF13070",
        "LoD/1.10": "0x6FF13670"
      },
      "rvas": {
        "LoD/1.09": "0x12D50",
        "LoD/1.09b": "0x12D50",
        "LoD/1.09d": "0x13070",
        "LoD/1.10": "0x13670"
      },
      "method": "MNE",
      "index": "MNE:bdb6fd2e7f75198785ff135dea92f318"
    },
    "Bnclient_MNE_be05c38d951a": {
      "addresses": {
        "LoD/1.07": "0x6FF2C918",
        "LoD/1.08": "0x6FF2C938",
        "LoD/1.09": "0x6FF0D538",
        "LoD/1.09b": "0x6FF0D538",
        "LoD/1.09d": "0x6FF0D848",
        "LoD/1.10": "0x6FF0DDAE",
        "LoD/1.11": "0x6FF23D12",
        "LoD/1.11b": "0x6FF23517",
        "LoD/1.12a": "0x6FF2287C",
        "LoD/1.13c": "0x6FF22518",
        "LoD/1.13d": "0x6FF238C6"
      },
      "rvas": {
        "LoD/1.07": "0xC918",
        "LoD/1.08": "0xC938",
        "LoD/1.09": "0xD538",
        "LoD/1.09b": "0xD538",
        "LoD/1.09d": "0xD848",
        "LoD/1.10": "0xDDAE",
        "LoD/1.11": "0x3D12",
        "LoD/1.11b": "0x3517",
        "LoD/1.12a": "0x287C",
        "LoD/1.13c": "0x2518",
        "LoD/1.13d": "0x38C6"
      },
      "name": "NhMalloc",
      "signature": "void * NhMalloc(size_t nSize, int nNhFlag)",
      "comment": "New Heap Memory Allocator - No-throw heap allocation with custom new handler support\n\nAlgorithm:\n1. Validate requested size is within allocation limits (< 0xFFFFFFE1 bytes)\n2. If size too large, return NULL immediately without allocation attempt\n3. Enter allocation retry loop at loop_retry_allocation\n4. Attempt memory allocation via internal heap allocator (FUN_6ff2c944)\n5. If allocation succeeds, return allocated memory pointer\n6. If allocation fails and nNhFlag is 0 (no handler), return NULL\n7. If allocation fails and nNhFlag is non-zero, call new handler (FUN_6ff2f9e7)\n8. If new handler returns non-zero (retry requested), loop back to step 4\n9. If new handler returns zero (abort requested), exit loop and return NULL\n\nParameters:\nnSize (size_t): Number of bytes to allocate from heap\nnNhFlag (int): New handler behavior flag (0 = no handler, non-zero = call handler on failure)\n\nReturns:\nNon-NULL void*: Pointer to allocated memory block of requested size\nNULL: Allocation failed and either no handler specified or handler requested abort\n\nSpecial Cases:\nAllocation requests >= 0xFFFFFFE1 bytes are rejected to prevent integer overflow\nHandler may be called multiple times until it returns 0 or allocation succeeds\nFunction follows no-throw semantics - never raises exceptions on allocation failure\n\nMagic Numbers Reference:\n0xFFFFFFE1: Maximum safe allocation size (4294967265 bytes) to prevent overflow\n0x0: NULL pointer constant and handler abort signal",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:be05c38d951a724b98e30bc46956a8c1"
    },
    "Bnclient_MNE_bf29a1022731": {
      "addresses": {
        "LoD/1.11": "0x6FF2A000",
        "LoD/1.11b": "0x6FF2A000",
        "LoD/1.12a": "0x6FF2A630",
        "LoD/1.13c": "0x6FF2A610",
        "LoD/1.13d": "0x6FF2A620"
      },
      "rvas": {
        "LoD/1.11": "0xA000",
        "LoD/1.11b": "0xA000",
        "LoD/1.12a": "0xA630",
        "LoD/1.13c": "0xA610",
        "LoD/1.13d": "0xA620"
      },
      "method": "MNE",
      "index": "MNE:bf29a102273107a56f778cfe084ac362"
    },
    "Bnclient_MNE_bff09423b51f": {
      "addresses": {
        "LoD/1.07": "0x6FF31180",
        "LoD/1.08": "0x6FF311A0",
        "LoD/1.09": "0x6FF11DC0",
        "LoD/1.09b": "0x6FF11DC0",
        "LoD/1.09d": "0x6FF120B0",
        "LoD/1.10": "0x6FF12600"
      },
      "rvas": {
        "LoD/1.07": "0x11180",
        "LoD/1.08": "0x111A0",
        "LoD/1.09": "0x11DC0",
        "LoD/1.09b": "0x11DC0",
        "LoD/1.09d": "0x120B0",
        "LoD/1.10": "0x12600"
      },
      "name": "OptimizedMemoryMove",
      "signature": "void * OptimizedMemoryMove(void * pDestination, void * pSource, uint dwSizeBytes)",
      "comment": "Copies memory from source to destination buffer with overlap detection and DWORD-optimized transfer.\n\nAlgorithm:\n1. Check for overlapping memory regions (source < dest < source+size)\n2. If overlapping, copy backwards from end to avoid corruption\n3. Check destination alignment for DWORD optimization\n4. If aligned, divide transfer into DWORD chunks and remainder bytes\n5. Use optimized REP MOVSD for bulk 4-byte transfers (7+ DWORDs)\n6. Handle unaligned bytes with individual byte copies\n7. Switch statement handles remainder bytes (0-3) after DWORD transfers\n\nParameters:\n  pDestination - Destination memory buffer pointer (void *)\n  pSource - Source memory buffer pointer (void *)\n  dwSizeBytes - Number of bytes to copy (uint)\n\nReturns:\n  void * - Original destination pointer (pDestination)\n\nSpecial Cases:\n  - Zero byte copy returns immediately\n  - Overlapping regions trigger backward copy mode\n  - Unaligned destination uses byte-wise copy with alignment fixup\n  - Small copies (< 32 bytes) use unrolled switch statements\n\nMagic Numbers Reference:\n  0x03 (3) - Alignment mask for 4-byte boundary check\n  0x04 (4) - DWORD size for pointer arithmetic  \n  0x07 (7) - Minimum DWORD count threshold for REP optimization\n\nError Handling:\n  - No explicit validation (low-level utility function)\n  - Assumes valid non-null pointers and size parameters\n  - Caller responsible for buffer boundary checks",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:bff09423b51fd121ea30afec957819f4",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF25280",
          "rva": "0x5280",
          "confidence": 0.293,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.11b": {
          "address": "0x6FF26440",
          "rva": "0x6440",
          "confidence": 0.293,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.12a": {
          "address": "0x6FF258B0",
          "rva": "0x58B0",
          "confidence": 0.293,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF254F0",
          "rva": "0x54F0",
          "confidence": 0.293,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_c0a536e0e6da": {
      "addresses": {
        "LoD/1.11": "0x6FF22A0E",
        "LoD/1.11b": "0x6FF22D91",
        "LoD/1.12a": "0x6FF23132",
        "LoD/1.13c": "0x6FF2340D",
        "LoD/1.13d": "0x6FF2303E"
      },
      "rvas": {
        "LoD/1.11": "0x2A0E",
        "LoD/1.11b": "0x2D91",
        "LoD/1.12a": "0x3132",
        "LoD/1.13c": "0x340D",
        "LoD/1.13d": "0x303E"
      },
      "name": "__freeptd",
      "signature": "void __freeptd(_ptiddata _Ptd)",
      "comment": "Library Function - Single Match\n __freeptd\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:c0a536e0e6dadcb5b945a8303814ecb3",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF0C99B",
          "rva": "0xC99B",
          "confidence": 0.4,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF0C43B",
          "rva": "0xC43B",
          "confidence": 0.324,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF0C1DC",
          "rva": "0xC1DC",
          "confidence": 0.213,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_c1d05e132bc8": {
      "addresses": {
        "LoD/1.07": "0x6FF2DA18",
        "LoD/1.08": "0x6FF2DA38",
        "LoD/1.09": "0x6FF0E638",
        "LoD/1.09b": "0x6FF0E638",
        "LoD/1.09d": "0x6FF0E948",
        "LoD/1.10": "0x6FF0EF36"
      },
      "rvas": {
        "LoD/1.07": "0xDA18",
        "LoD/1.08": "0xDA38",
        "LoD/1.09": "0xE638",
        "LoD/1.09b": "0xE638",
        "LoD/1.09d": "0xE948",
        "LoD/1.10": "0xEF36"
      },
      "name": "LocaleMapStringWithFallback",
      "signature": "int LocaleMapStringWithFallback(LCID lcid, uint dwMapFlags, char * lpszSrcStr, int nSrcLength, wchar_t * wszDestStr, int nDestLength, uint dwCodePage, int nFlags)",
      "comment": "Performs locale-aware string mapping with automatic Unicode/ANSI fallback detection.\n\nAlgorithm:\n1. Initialize SEH exception handling frame for safe string operations\n2. Test locale capability on first call by probing LCMapStringW and LCMapStringA\n   - If LCMapStringW succeeds: set g_dwLocaleCapability = 1 (Unicode support)\n   - If LCMapStringA succeeds: set g_dwLocaleCapability = 2 (ANSI fallback)\n   - If both fail: return 0 (no locale support available)\n3. Validate input string length using FUN_6ff31e05() if cchSrc > 0\n4. Route to appropriate mapping function based on detected capability:\n   - Capability 2 (ANSI): Direct call to LCMapStringA with input parameters\n   - Capability 1 (Unicode): Multi-stage Unicode conversion process\n5. For Unicode path (capability 1):\n   a. Use default code page g_dwDefaultCodePage if uCodePage = 0\n   b. Convert ANSI source to Unicode using MultiByteToWideChar\n   c. Allocate stack buffer for Unicode temporary storage\n   d. Perform locale mapping on Unicode string using LCMapStringW\n   e. Handle two output modes based on LCMAP_BYTEREV flag (0x400):\n      - Without LCMAP_BYTEREV: Convert back to ANSI using WideCharToMultiByte\n      - With LCMAP_BYTEREV: Copy Unicode result directly to output buffer\n6. Validate buffer sizes and handle overflow conditions\n7. Clean up SEH frame and return mapped string length\n\nParameters:\nlcid - Locale identifier for string mapping operation\ndwMapFlags - String mapping flags (LCMAP_UPPERCASE, LCMAP_LOWERCASE, etc.)\nlpSrcStr - Source string to be mapped (ANSI format)\ncchSrc - Length of source string in characters (-1 for null-terminated)\nlpDestStr - Destination buffer for mapped string (Unicode or ANSI based on flags)\ncchDest - Size of destination buffer in characters (0 to query required size)\nuCodePage - Code page for ANSI/Unicode conversion (0 uses default from g_dwDefaultCodePage)\ndwFlags - Additional conversion flags for MultiByteToWideChar (affects MB_PRECOMPOSED vs MB_COMPOSITE)\nIMPLICIT dwExceptionState - SEH exception handling state tracking\nIMPLICIT pPrevExceptionRecord - Previous exception handler in SEH chain\n\nReturns:\nSuccess: Length of mapped string in characters (not including null terminator)\nFailure: 0 on error conditions (invalid locale, buffer overflow, conversion failure)\nQuery mode: Required buffer size when cchDest = 0\n\nSpecial Cases:\n- First call detection: Probes both Unicode and ANSI capabilities to set g_dwLocaleCapability\n- Buffer overflow: Returns 0 if output buffer too small for mapped result\n- Stack allocation failure: Returns 0 if StackProbe() detects insufficient stack space\n- Exception handling: Uses SEH to protect against access violations during string operations\n\nMagic Numbers Reference:\n0x100 - LCMAP_LOWERCASE flag for capability testing\n0x180 - Offset into g_abGlobalStringBuffer for ANSI test string  \n0x400 - LCMAP_BYTEREV flag indicating Unicode output mode\n0x220 - WC_NO_BEST_FIT_CHARS flag for WideCharToMultiByte conversion\n0x3c - Stack safety threshold for StackProbe() allocation checks\n1 - Unicode capability indicator in g_dwLocaleCapability\n2 - ANSI capability indicator in g_dwLocaleCapability  \n8 - MB_PRECOMPOSED flag derived from dwFlags parameter\n\nError Handling:\n- Invalid locale: Returns 0 if system doesn't support specified LCID\n- Conversion failures: Returns 0 if MultiByteToWideChar or WideCharToMultiByte fail\n- Buffer validation: Returns 0 if destination buffer insufficient for result\n- Stack overflow: Returns 0 if stack allocation exceeds safety limits\n- Exception propagation: SEH frame protects caller from access violations\n\nNote: Function uses 6 phantom stack variables (local_1c through local_3c) optimized away by decompiler but visible in assembly for temporary calculations and register spills.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c1d05e132bc8c3bc87e7a971916e9b9b",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF2F4B0",
          "rva": "0xF4B0",
          "confidence": 0.28,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_c276c411b75c": {
      "addresses": {
        "LoD/1.11": "0x6FF2D340",
        "LoD/1.11b": "0x6FF34EE0",
        "LoD/1.12a": "0x6FF34BB0",
        "LoD/1.13c": "0x6FF32730",
        "LoD/1.13d": "0x6FF373C0"
      },
      "rvas": {
        "LoD/1.11": "0xD340",
        "LoD/1.11b": "0x14EE0",
        "LoD/1.12a": "0x14BB0",
        "LoD/1.13c": "0x12730",
        "LoD/1.13d": "0x173C0"
      },
      "method": "MNE",
      "index": "MNE:c276c411b75cfa4743b0e1006e51a95c"
    },
    "Bnclient_MNE_c2bda2cc0331": {
      "addresses": {
        "LoD/1.07": "0x6FF31540",
        "LoD/1.08": "0x6FF31560",
        "LoD/1.09": "0x6FF12180",
        "LoD/1.09b": "0x6FF12180",
        "LoD/1.09d": "0x6FF12470",
        "LoD/1.10": "0x6FF129C0",
        "LoD/1.11b": "0x6FF27496",
        "LoD/1.13c": "0x6FF2784D",
        "LoD/1.13d": "0x6FF274F8"
      },
      "rvas": {
        "LoD/1.07": "0x11540",
        "LoD/1.08": "0x11560",
        "LoD/1.09": "0x12180",
        "LoD/1.09b": "0x12180",
        "LoD/1.09d": "0x12470",
        "LoD/1.10": "0x129C0",
        "LoD/1.11b": "0x7496",
        "LoD/1.13c": "0x784D",
        "LoD/1.13d": "0x74F8"
      },
      "name": "CloseStreamByIndex",
      "signature": "int CloseStreamByIndex(uint dwStreamIndex)",
      "comment": "Closes and invalidates a stream descriptor by index, clearing its file handle.\n\nAlgorithm:\n1. Validate stream index against global stream count boundary\n2. Calculate stream descriptor using bucket indexing: bucket = index >> 5, offset = index & 0x1F\n3. Check if stream is active (nPosition & 1) and not already invalidated (pBase != 0xFFFFFFFF)\n4. If global exit flag is set, clear standard handles for stdin(0)/stdout(1)/stderr(2)\n5. Mark stream descriptor as invalidated by setting pBase = 0xFFFFFFFF\n6. Return success (0) if stream was valid and closed\n7. Set thread error context (errno=9, GetLastError=0) and return failure (-1) for invalid streams\n\nParameters:\nnStreamIndex (uint): Zero-based index into global stream descriptor array\n\nReturns:\nint: 0 on successful stream closure, -1 if stream index invalid or already closed\n\nSpecial Cases:\nStream indices 0, 1, 2 correspond to stdin, stdout, stderr standard handles\nGlobal exit flag (g_dwExitFlag2) triggers standard handle cleanup via SetStdHandle\n\nMagic Numbers Reference:\n0x1F (31): Mask for within-bucket offset (32 descriptors per bucket)\n0x5: Right shift for bucket calculation (divide by 32)\n0xFFFFFFFF: Sentinel value indicating invalidated stream descriptor\n0xFFFFFFF6 (-10): STD_INPUT_HANDLE constant\n0xFFFFFFF5 (-11): STD_OUTPUT_HANDLE constant  \n0xFFFFFFF4 (-12): STD_ERROR_HANDLE constant\n0x9: EBADF errno code (Bad file descriptor)\n\nStructure Layout:\nStreamIO (36 bytes total)\nOffset | Size | Field Name | Type    | Description\n0x00   | 4    | pBase      | void *  | File handle or buffer base pointer\n0x04   | 4    | nPosition  | uint    | Current position/flags (bit 0 = active)\n0x08   | 28   | [fields]   | varies  | Additional stream metadata\n\nArray Indexing:\ng_apStreamDescriptors uses bucket-based indexing for memory efficiency:\n- bucket = nStreamIndex >> 5 (divide by 32)\n- offset = nStreamIndex & 0x1F (modulo 32) \n- Each bucket contains 32 StreamIO descriptors (32 * 36 = 1152 bytes)\n- Total address = g_apStreamDescriptors[bucket] + (offset * 36)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c2bda2cc0331ae5bf6246d61a0224d72"
    },
    "Bnclient_MNE_c2ccec134924": {
      "addresses": {
        "LoD/1.07": "0x6FF2E456",
        "LoD/1.08": "0x6FF2E476",
        "LoD/1.09": "0x6FF0F0A1",
        "LoD/1.09b": "0x6FF0F0A1",
        "LoD/1.09d": "0x6FF0F386",
        "LoD/1.10": "0x6FF0F974"
      },
      "rvas": {
        "LoD/1.07": "0xE456",
        "LoD/1.08": "0xE476",
        "LoD/1.09": "0xF0A1",
        "LoD/1.09b": "0xF0A1",
        "LoD/1.09d": "0xF386",
        "LoD/1.10": "0xF974"
      },
      "name": "CleanupMemoryAllocations",
      "signature": "void CleanupMemoryAllocations(void)",
      "comment": "Releases all allocated memory and destroys heap handles during application shutdown.\n\nAlgorithm:\n\n1. Check global allocation strategy (g_dwAllocationStrategy)\n2. If strategy == 3 (array-based allocation):\n   a. Loop through all allocation entries (g_dwAllocationCount)\n   b. For each entry at g_pAllocationTable + (index * 20) + 0xc:\n      - Call VirtualFree twice with MEM_DECOMMIT (0x4000) and MEM_RELEASE (0x8000)\n      - Call HeapFree on associated heap memory block\n   c. Free the entire allocation table with HeapFree\n3. If strategy == 2 (linked list allocation):\n   a. Traverse circular linked list starting at PTR_LOOP_6ff36b70\n   b. For each node with valid memory pointer at offset 0x10:\n      - Call VirtualFree with MEM_RELEASE (0x8000) \n   c. Continue until returning to head node\n4. Destroy the main heap handle with HeapDestroy\n\nParameters:\n\nNone\n\nReturns:\n\nNone (void function)\n\nMagic Numbers Reference:\n\n0x3 - Array-based allocation strategy constant\n0x2 - Linked list allocation strategy constant  \n0xc - Offset to memory pointers within allocation entry structure\n0x14 (20) - Size of each MemoryAllocation structure entry\n0x100000 (1MB) - Virtual memory size to decommit\n0x4000 - MEM_DECOMMIT flag for VirtualFree\n0x8000 - MEM_RELEASE flag for VirtualFree\n0x10 (16) - Offset to memory pointer in linked list node\n\nStructure Layout:\n\nMemoryAllocation (20 bytes):\nOffset | Size | Field Name        | Type   | Description\n-------|------|-------------------|--------|---------------------------\n0x00   | 4    | dwReserved1       | uint   | Reserved field\n0x04   | 4    | dwReserved2       | uint   | Reserved field  \n0x08   | 4    | dwReserved3       | uint   | Reserved field\n0x0c   | 4    | pVirtualMemory    | void*  | Virtual memory base address\n0x10   | 4    | pHeapMemory       | void*  | Heap allocation pointer\n\nGlobal Variables:\n\ng_dwAllocationStrategy - Current memory allocation strategy (2 or 3)\ng_dwAllocationCount - Number of entries in allocation table\ng_pAllocationTable - Pointer to MemoryAllocation array\ng_hHeapHandle - Handle to main application heap\nPTR_LOOP_6ff36b70 - Head node of circular linked list for strategy 2",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c2ccec13492440089beaf10a53536424"
    },
    "Bnclient_MNE_c3e67f0f66e9": {
      "addresses": {
        "LoD/1.11": "0x6FF36730",
        "LoD/1.11b": "0x6FF36701",
        "LoD/1.12a": "0x6FF375B0",
        "LoD/1.13c": "0x6FF37596",
        "LoD/1.13d": "0x6FF374CF"
      },
      "rvas": {
        "LoD/1.11": "0x16730",
        "LoD/1.11b": "0x16701",
        "LoD/1.12a": "0x175B0",
        "LoD/1.13c": "0x17596",
        "LoD/1.13d": "0x174CF"
      },
      "name": "___CxxFrameHandler",
      "signature": "undefined4 ___CxxFrameHandler(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4)",
      "comment": "Library Function - Single Match\n ___CxxFrameHandler\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:c3e67f0f66e9fe1748a93603f0dc99e6"
    },
    "Bnclient_MNE_c3ffc1f8ee55": {
      "addresses": {
        "LoD/1.10": "0x6FF14060"
      },
      "rvas": {
        "LoD/1.10": "0x14060"
      },
      "method": "MNE",
      "index": "MNE:c3ffc1f8ee551988dd0cb685ae994830"
    },
    "Bnclient_MNE_c412a852faa3": {
      "addresses": {
        "LoD/1.09": "0x6FF133B0",
        "LoD/1.09b": "0x6FF133B0",
        "LoD/1.09d": "0x6FF136D0",
        "LoD/1.10": "0x6FF13CD0",
        "LoD/1.11": "0x6FF322E0",
        "LoD/1.11b": "0x6FF2B080",
        "LoD/1.12a": "0x6FF313D0",
        "LoD/1.13c": "0x6FF2FCF0",
        "LoD/1.13d": "0x6FF34ED0"
      },
      "rvas": {
        "LoD/1.09": "0x133B0",
        "LoD/1.09b": "0x133B0",
        "LoD/1.09d": "0x136D0",
        "LoD/1.10": "0x13CD0",
        "LoD/1.11": "0x122E0",
        "LoD/1.11b": "0xB080",
        "LoD/1.12a": "0x113D0",
        "LoD/1.13c": "0xFCF0",
        "LoD/1.13d": "0x14ED0"
      },
      "method": "MNE",
      "index": "MNE:c412a852faa374becf00273377c892e9",
      "candidates": {
        "LoD/1.08": {
          "address": "0x6FF25A50",
          "rva": "0x5A50",
          "confidence": 0.4,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.09"
        },
        "LoD/1.07": {
          "address": "0x6FF25A30",
          "rva": "0x5A30",
          "confidence": 0.324,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.09"
        }
      }
    },
    "Bnclient_MNE_c41f2d1f421c": {
      "addresses": {
        "LoD/1.11": "0x6FF26827",
        "LoD/1.11b": "0x6FF25D58",
        "LoD/1.12a": "0x6FF251C0",
        "LoD/1.13c": "0x6FF24E0B",
        "LoD/1.13d": "0x6FF26881"
      },
      "rvas": {
        "LoD/1.11": "0x6827",
        "LoD/1.11b": "0x5D58",
        "LoD/1.12a": "0x51C0",
        "LoD/1.13c": "0x4E0B",
        "LoD/1.13d": "0x6881"
      },
      "name": "___sbh_alloc_new_group",
      "signature": "int ___sbh_alloc_new_group(int param_1)",
      "comment": "Library Function - Single Match\n ___sbh_alloc_new_group\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:c41f2d1f421c471451958bea4a10fa66"
    },
    "Bnclient_MNE_c43b47bac3ec": {
      "addresses": {
        "LoD/1.11": "0x6FF2585D",
        "LoD/1.11b": "0x6FF256B1",
        "LoD/1.12a": "0x6FF24B19",
        "LoD/1.13c": "0x6FF258FD",
        "LoD/1.13d": "0x6FF25C5D"
      },
      "rvas": {
        "LoD/1.11": "0x585D",
        "LoD/1.11b": "0x56B1",
        "LoD/1.12a": "0x4B19",
        "LoD/1.13c": "0x58FD",
        "LoD/1.13d": "0x5C5D"
      },
      "name": "__NLG_Notify1",
      "signature": "undefined __NLG_Notify1(undefined4 param_1)",
      "comment": "Library Function - Single Match\n __NLG_Notify1\n\nLibraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual Studio 2019 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:c43b47bac3ec2db7a3f12c66010e2c00"
    },
    "Bnclient_MNE_c4685906a5c4": {
      "addresses": {
        "LoD/1.11": "0x6FF22C6E",
        "LoD/1.11b": "0x6FF221FF",
        "LoD/1.12a": "0x6FF232D5",
        "LoD/1.13c": "0x6FF226AD",
        "LoD/1.13d": "0x6FF22274"
      },
      "rvas": {
        "LoD/1.11": "0x2C6E",
        "LoD/1.11b": "0x21FF",
        "LoD/1.12a": "0x32D5",
        "LoD/1.13c": "0x26AD",
        "LoD/1.13d": "0x2274"
      },
      "name": "__flsbuf",
      "signature": "int __flsbuf(int _Ch, FILE * _File)",
      "comment": "Library Function - Single Match\n __flsbuf\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:c4685906a5c4fe97104af70b25069ec2"
    },
    "Bnclient_MNE_c500a55e2567": {
      "addresses": {
        "LoD/1.09": "0x6FF13120",
        "LoD/1.09b": "0x6FF13120",
        "LoD/1.09d": "0x6FF13440",
        "LoD/1.10": "0x6FF13A40"
      },
      "rvas": {
        "LoD/1.09": "0x13120",
        "LoD/1.09b": "0x13120",
        "LoD/1.09d": "0x13440",
        "LoD/1.10": "0x13A40"
      },
      "method": "MNE",
      "index": "MNE:c500a55e256796bc9b75fa13bcf639c5"
    },
    "Bnclient_MNE_c5ea4b7d18ee": {
      "addresses": {
        "LoD/1.07": "0x6FF22180",
        "LoD/1.08": "0x6FF221A0",
        "LoD/1.09": "0x6FF02260",
        "LoD/1.09b": "0x6FF02260",
        "LoD/1.09d": "0x6FF02230",
        "LoD/1.10": "0x6FF02220",
        "LoD/1.11": "0x6FF37542",
        "LoD/1.11b": "0x6FF37512",
        "LoD/1.12a": "0x6FF383C2",
        "LoD/1.13c": "0x6FF383A2",
        "LoD/1.13d": "0x6FF382E2"
      },
      "rvas": {
        "LoD/1.07": "0x2180",
        "LoD/1.08": "0x21A0",
        "LoD/1.09": "0x2260",
        "LoD/1.09b": "0x2260",
        "LoD/1.09d": "0x2230",
        "LoD/1.10": "0x2220",
        "LoD/1.11": "0x17542",
        "LoD/1.11b": "0x17512",
        "LoD/1.12a": "0x183C2",
        "LoD/1.13c": "0x183A2",
        "LoD/1.13d": "0x182E2"
      },
      "name": "CheckServerConnectionAndCall",
      "signature": "uint CheckServerConnectionAndCall(uint dwReserved, uint dwData)",
      "comment": "Conditionally calls ordinal function based on active server connection status\n\nAlgorithm:\n1. Check if global server connection pointer is non-null\n2. If connection exists, call Ordinal_10012 with data parameter\n3. Return result from ordinal function call\n4. If no connection exists, return zero (failure/not available)\n\nParameters:\ndwReserved - Reserved parameter (currently unused)\ndwData - Data parameter passed to ordinal function when connection active\n\nReturns:\nSuccess: Result value from Ordinal_10012 call\nFailure: 0 when no active server connection exists\n\nSpecial Cases:\n- Function serves as connection guard for ordinal function access\n- dwReserved parameter indicates potential future expansion\n- Zero return indicates both connection unavailable and potential ordinal function failure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c5ea4b7d18ee114fccc74de0e6ed9db7"
    },
    "Bnclient_MNE_c68fdb439d7b": {
      "addresses": {
        "LoD/1.07": "0x6FF227E0",
        "LoD/1.08": "0x6FF22800",
        "LoD/1.09": "0x6FF028C0",
        "LoD/1.09b": "0x6FF028C0",
        "LoD/1.09d": "0x6FF02870",
        "LoD/1.10": "0x6FF028A0"
      },
      "rvas": {
        "LoD/1.07": "0x27E0",
        "LoD/1.08": "0x2800",
        "LoD/1.09": "0x28C0",
        "LoD/1.09b": "0x28C0",
        "LoD/1.09d": "0x2870",
        "LoD/1.10": "0x28A0"
      },
      "name": "ProcessAndCopyToGlobalBuffer",
      "signature": "int ProcessAndCopyToGlobalBuffer(int nDataValue)",
      "comment": "Processes data value through sequential pipeline and copies to global buffer.\n\nAlgorithm:\n\n1. Register data value with type identifier 0x02 via FUN_6ff258a0\n2. Copy processed data value to global buffer via CopyToGlobalBuffer\n3. Return success status (1) to indicate completion\n\nParameters:\n\nnDataValue (int) - Data value to process and copy to global buffer\n\nReturns:\n\n1 - Operation completed successfully\n\nSpecial Cases:\n\nThe hardcoded type identifier 0x02 suggests this function handles a specific\ndata type or category within a larger processing system.\n\nMagic Numbers Reference:\n\n0x02 (2) - Data type identifier passed to registration function",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c68fdb439d7b0ed5e1e8c72c7caa3a9b"
    },
    "Bnclient_MNE_c6a9215b06a8": {
      "addresses": {
        "LoD/1.10": "0x6FF04DD0"
      },
      "rvas": {
        "LoD/1.10": "0x4DD0"
      },
      "method": "MNE",
      "index": "MNE:c6a9215b06a8919611fd3ff0e92d7dd4"
    },
    "Bnclient_MNE_c774f4d30918": {
      "addresses": {
        "LoD/1.07": "0x6FF29650",
        "LoD/1.08": "0x6FF29670",
        "LoD/1.09": "0x6FF0A280",
        "LoD/1.09b": "0x6FF0A280",
        "LoD/1.09d": "0x6FF0A4D0",
        "LoD/1.10": "0x6FF0AD30"
      },
      "rvas": {
        "LoD/1.07": "0x9650",
        "LoD/1.08": "0x9670",
        "LoD/1.09": "0xA280",
        "LoD/1.09b": "0xA280",
        "LoD/1.09d": "0xA4D0",
        "LoD/1.10": "0xAD30"
      },
      "name": "DllProcessAttachDetach",
      "signature": "BOOL DllProcessAttachDetach(HINSTANCE hInstance, DWORD dwReason)",
      "comment": "Handles DLL process attach and detach events for critical section management.\n\nAlgorithm:\n1. Compare dwReason against DLL_PROCESS_DETACH (0)\n2. If detach: Call DeleteCriticalSectionCleanup() to cleanup critical sections\n3. If not detach: Compare dwReason against DLL_PROCESS_ATTACH (1)\n4. If attach: Call InitializeGlobalCriticalSection() to setup critical sections\n5. Store hInstance in global storage at g_abGlobalStringBuffer._488_4_\n6. Return TRUE (1) to indicate successful initialization\n\nParameters:\n- hInstance (HINSTANCE): Handle to DLL instance being attached/detached\n- dwReason (DWORD): Reason for DLL entry - 0=DLL_PROCESS_DETACH, 1=DLL_PROCESS_ATTACH\n\nReturns:\n- TRUE (1): Always returns success after handling attach/detach logic\n\nSpecial Cases:\n- Unknown dwReason values (not 0 or 1): Still stores hInstance and returns success\n- Function is __stdcall with 0xC bytes stack cleanup (2 parameters \u00d7 4 bytes + return address)\n\nMagic Numbers Reference:\n- 0x0: DLL_PROCESS_DETACH - Process is detaching from DLL\n- 0x1: DLL_PROCESS_ATTACH - Process is attaching to DLL\n- 0x1: TRUE return value indicating successful DLL initialization",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c774f4d30918c39af6098008399f2de1",
      "candidates": {
        "LoD/1.11b": {
          "address": "0x6FF27C75",
          "rva": "0x7C75",
          "confidence": 0.273,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF27CE7",
          "rva": "0x7CE7",
          "confidence": 0.273,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_c85f8270e3f1": {
      "addresses": {
        "LoD/1.07": "0x6FF30505",
        "LoD/1.08": "0x6FF30525",
        "LoD/1.09": "0x6FF11145",
        "LoD/1.09b": "0x6FF11145",
        "LoD/1.09d": "0x6FF11435",
        "LoD/1.10": "0x6FF11985"
      },
      "rvas": {
        "LoD/1.07": "0x10505",
        "LoD/1.08": "0x10525",
        "LoD/1.09": "0x11145",
        "LoD/1.09b": "0x11145",
        "LoD/1.09d": "0x11435",
        "LoD/1.10": "0x11985"
      },
      "name": "ThreadSafeStringProcessor",
      "signature": "char * ThreadSafeStringProcessor(char * lpszInputString, wchar_t wDelimiterChar)",
      "comment": "Thread-safe wrapper for string processing operations with conditional critical section management.\n\nAlgorithm:\n1. Increment global critical section counter atomically using InterlockedIncrement\n2. Check if critical section limit is enabled (g_dwCriticalSectionLimit != 0)\n3. If limit enabled:\n   - Decrement counter atomically to balance initial increment\n   - Acquire critical section index 0x13 using AcquireCriticalSectionByIndex\n   - Set lock acquired flag to true\n4. Call core string processing function FUN_6ff3055e with input parameters\n5. Store function result for return value\n6. If lock was acquired:\n   - Release critical section index 0x13 using ReleaseCriticalSectionByIndex\n   - Otherwise: decrement global counter atomically to clean up\n7. Return result from core processing function\n\nParameters:\n- lpszInputString: char * - Input string to process\n- wDelimiterChar: wchar_t - Wide character used as delimiter in processing\n\nReturns:\n- char * - Processed string result from core function, may be NULL on failure\n\nSpecial Cases:\n- When g_dwCriticalSectionLimit is 0, bypasses critical section entirely for performance\n- Critical section index 0x13 (decimal 19) suggests specialized synchronization context\n- Atomic operations ensure thread-safe counter management even without critical sections\n\nMagic Numbers Reference:\n- 0x13 (19): Critical section index for string processing synchronization context",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c85f8270e3f1487f07a5ecca3d9faf90"
    },
    "Bnclient_MNE_c8b59bb5b7ec": {
      "addresses": {
        "LoD/1.07": "0x6FF301AD",
        "LoD/1.08": "0x6FF301CD",
        "LoD/1.09": "0x6FF10DED",
        "LoD/1.09b": "0x6FF10DED",
        "LoD/1.09d": "0x6FF110DD",
        "LoD/1.10": "0x6FF1162D"
      },
      "rvas": {
        "LoD/1.07": "0x101AD",
        "LoD/1.08": "0x101CD",
        "LoD/1.09": "0x10DED",
        "LoD/1.09b": "0x10DED",
        "LoD/1.09d": "0x110DD",
        "LoD/1.10": "0x1162D"
      },
      "name": "WriteStreamWithTextConversion",
      "signature": "int WriteStreamWithTextConversion(DWORD nStreamHandle, char * lpszData, DWORD dwDataSize)",
      "comment": "Writes data to a stream with automatic text mode line ending conversion (LF to CRLF).\n\nAlgorithm:\n1. Validate input parameters - return 0 if dwDataSize is zero\n2. Calculate stream descriptor array index (nStreamHandle >> 5) and slot (nStreamHandle & 0x1F)  \n3. Check append mode flag (0x20) - seek to end if set\n4. Branch based on text/binary mode flag (0x80):\n   a. Binary mode: Write data directly using WriteFile API\n   b. Text mode: Process character-by-character with LF to CRLF conversion\n5. Text mode processing loop:\n   a. Copy characters to 1K buffer, inserting CR before each LF\n   b. Track newlines added for accurate byte count calculation\n   c. Write buffer when full (1024 bytes) or all input processed\n   d. Continue until all input data processed\n6. Handle WriteFile errors by calling GetLastError and TranslateErrorCode\n7. Check EOF marker detection flag (0x40) - return 0 if first byte is 0x1A\n8. Set thread context error codes for specific error conditions\n9. Return total bytes written minus newlines added, or -1 on error\n\nParameters:\nnStreamHandle - Stream handle containing descriptor index in upper 27 bits and slot in lower 5 bits  \nlpszData - Pointer to data buffer to write\ndwDataSize - Number of bytes to write from data buffer\n\nReturns:\nSuccess: Number of bytes from original buffer written (excluding added CR characters)\nError: -1 indicating write failure or stream error\nZero: If dwDataSize is 0 or EOF marker (0x1A) detected in text mode\n\nSpecial Cases:\nEOF marker (0x1A) detection causes immediate return of 0 in text mode\nError code 5 (access denied) triggers special thread context field handling\nBuffer size limited to 1024 bytes for text conversion requiring chunked writes\n\nMagic Numbers Reference:\n0x20 (32) - Append mode flag in stream position field\n0x40 (64) - EOF detection flag in stream position field  \n0x80 (128) - Text mode flag in stream position field\n0x1A (26) - EOF marker character (Ctrl+Z)\n0x400 (1024) - Text conversion buffer size\n0x1F (31) - Bit mask for slot index extraction\n0x5 (5) - Access denied error code\n0x9 (9) - Thread context error field value for access denied\n0x1C (28) - Thread context error field value for EOF marker\n\nError Handling:\nWriteFile failure triggers GetLastError and TranslateErrorCode calls\nAccess denied (error 5) sets thread context fields to specific values\nAll other errors call TranslateErrorCode for error mapping\nEOF marker detection in text mode with flag 0x40 returns success\n\nStructure Layout:\nStreamIO structure (36 bytes):\nOffset | Size | Field Name | Type    | Description\n0x00   | 4    | pBase      | HANDLE  | File handle for WriteFile calls  \n0x04   | 4    | nPosition  | uint    | Position flags (0x20=append, 0x40=EOF detect, 0x80=text mode)\n[Additional fields at higher offsets not accessed by this function]",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c8b59bb5b7eca5aa50d6fe27320b53cd"
    },
    "Bnclient_MNE_c9529d246abf": {
      "addresses": {
        "LoD/1.11": "0x6FF3691A",
        "LoD/1.11b": "0x6FF368EB",
        "LoD/1.12a": "0x6FF3779A",
        "LoD/1.13c": "0x6FF37780",
        "LoD/1.13d": "0x6FF376B9"
      },
      "rvas": {
        "LoD/1.11": "0x1691A",
        "LoD/1.11b": "0x168EB",
        "LoD/1.12a": "0x1779A",
        "LoD/1.13c": "0x17780",
        "LoD/1.13d": "0x176B9"
      },
      "name": "_GetRangeOfTrysToCheck",
      "signature": "_s_TryBlockMapEntry * _GetRangeOfTrysToCheck(_s_FuncInfo * param_1, int param_2, int param_3, uint * param_4, uint * param_5)",
      "comment": "Library Function - Single Match\n struct _s_TryBlockMapEntry const * __cdecl _GetRangeOfTrysToCheck(struct _s_FuncInfo const *,int,int,unsigned int *,unsigned int *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:c9529d246abf4faab672947c5021a4d5"
    },
    "Bnclient_MNE_ca7f27832b0d": {
      "addresses": {
        "LoD/1.11": "0x6FF23D81",
        "LoD/1.11b": "0x6FF2400C",
        "LoD/1.12a": "0x6FF23D22",
        "LoD/1.13c": "0x6FF23E29",
        "LoD/1.13d": "0x6FF23CC9"
      },
      "rvas": {
        "LoD/1.11": "0x3D81",
        "LoD/1.11b": "0x400C",
        "LoD/1.12a": "0x3D22",
        "LoD/1.13c": "0x3E29",
        "LoD/1.13d": "0x3CC9"
      },
      "method": "MNE",
      "index": "MNE:ca7f27832b0deaebe496b377f1c5001a"
    },
    "Bnclient_MNE_cb1779c70c34": {
      "addresses": {
        "LoD/1.11": "0x6FF37419",
        "LoD/1.11b": "0x6FF373E9",
        "LoD/1.12a": "0x6FF38299",
        "LoD/1.13c": "0x6FF38279",
        "LoD/1.13d": "0x6FF381B9"
      },
      "rvas": {
        "LoD/1.11": "0x17419",
        "LoD/1.11b": "0x173E9",
        "LoD/1.12a": "0x18299",
        "LoD/1.13c": "0x18279",
        "LoD/1.13d": "0x181B9"
      },
      "name": "_inconsistency",
      "signature": "void _inconsistency(void)",
      "comment": "Library Function - Single Match\n void __cdecl _inconsistency(void)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:cb1779c70c348b8b7c641ac7b46a80dd"
    },
    "Bnclient_MNE_cb39780517b1": {
      "addresses": {
        "LoD/1.11": "0x6FF24950",
        "LoD/1.11b": "0x6FF26BA0",
        "LoD/1.12a": "0x6FF25BF0",
        "LoD/1.13c": "0x6FF26C00",
        "LoD/1.13d": "0x6FF254F0"
      },
      "rvas": {
        "LoD/1.11": "0x4950",
        "LoD/1.11b": "0x6BA0",
        "LoD/1.12a": "0x5BF0",
        "LoD/1.13c": "0x6C00",
        "LoD/1.13d": "0x54F0"
      },
      "name": "_memset",
      "signature": "void * _memset(void * _Dst, int _Val, size_t _Size)",
      "comment": "Library Function - Single Match\n _memset\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release, Visual Studio 2019 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:cb39780517b1dd8e5312f6fce0a00812"
    },
    "Bnclient_MNE_cb7271f23b18": {
      "addresses": {
        "LoD/1.11": "0x6FF22C20",
        "LoD/1.11b": "0x6FF23660",
        "LoD/1.12a": "0x6FF23C40",
        "LoD/1.13c": "0x6FF238D0",
        "LoD/1.13d": "0x6FF23A10"
      },
      "rvas": {
        "LoD/1.11": "0x2C20",
        "LoD/1.11b": "0x3660",
        "LoD/1.12a": "0x3C40",
        "LoD/1.13c": "0x38D0",
        "LoD/1.13d": "0x3A10"
      },
      "name": "___ascii_stricmp",
      "signature": "int ___ascii_stricmp(char * _Str1, char * _Str2)",
      "comment": "Library Function - Single Match\n ___ascii_stricmp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:cb7271f23b18085c633325272e533a6a"
    },
    "Bnclient_MNE_cbc66d2ca782": {
      "addresses": {
        "LoD/1.09": "0x6FF132C0",
        "LoD/1.09b": "0x6FF132C0",
        "LoD/1.09d": "0x6FF135E0",
        "LoD/1.10": "0x6FF13BE0"
      },
      "rvas": {
        "LoD/1.09": "0x132C0",
        "LoD/1.09b": "0x132C0",
        "LoD/1.09d": "0x135E0",
        "LoD/1.10": "0x13BE0"
      },
      "method": "MNE",
      "index": "MNE:cbc66d2ca7824952670b754bf9753331"
    },
    "Bnclient_MNE_cbf32bf6cf4a": {
      "addresses": {
        "LoD/1.07": "0x6FF2ADA0",
        "LoD/1.08": "0x6FF2ADC0",
        "LoD/1.09": "0x6FF0B9C0",
        "LoD/1.09b": "0x6FF0B9C0",
        "LoD/1.09d": "0x6FF0BC10",
        "LoD/1.10": "0x6FF0C220"
      },
      "rvas": {
        "LoD/1.07": "0xADA0",
        "LoD/1.08": "0xADC0",
        "LoD/1.09": "0xB9C0",
        "LoD/1.09b": "0xB9C0",
        "LoD/1.09d": "0xBC10",
        "LoD/1.10": "0xC220"
      },
      "name": "ExtractDecryptionKeys",
      "signature": "void ExtractDecryptionKeys(int nKeyIndex, uint * pdwDestBuffer)",
      "comment": "Extracts decryption keys from global buffer for use in cryptographic operations.\n\nAlgorithm:\n1. Validate destination buffer pointer is not NULL\n2. Calculate source offset: g_abGlobalStringBuffer + (nKeyIndex \u00d7 0x5c) + 0x340\n3. Initialize copy counter to 5 DWORDs (20 bytes total)\n4. Copy each DWORD from source to destination buffer sequentially\n5. Increment both source and destination pointers by 4 bytes each iteration\n6. Decrement counter and repeat until all 5 DWORDs are copied\n7. Return void (no error checking beyond NULL pointer validation)\n\nParameters:\n- nKeyIndex (int): Index into key table (multiplied by 92-byte stride)\n- pdwDestBuffer (uint *): Destination buffer to receive 5 DWORDs of key data\n\nReturns:\n- void: No return value, silent failure if destination buffer is NULL\n\nSpecial Cases:\n- NULL destination buffer: Function returns early without copying any data\n- No bounds checking: Caller responsible for valid nKeyIndex and sufficient buffer space\n\nMagic Numbers Reference:\n- 0x5c (92 decimal): Size of each key structure in global buffer\n- 0x340 (832 decimal): Offset to key data within global buffer structure\n- 5: Number of DWORDs copied (20 bytes total key size)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cbf32bf6cf4accfd4115c3e00373cf7c"
    },
    "Bnclient_MNE_cc0e19248bdb": {
      "addresses": {
        "LoD/1.07": "0x6FF2BDDA",
        "LoD/1.08": "0x6FF2BDFA",
        "LoD/1.09": "0x6FF0C9FA",
        "LoD/1.09b": "0x6FF0C9FA",
        "LoD/1.09d": "0x6FF0CC5A",
        "LoD/1.10": "0x6FF0D304",
        "LoD/1.12a": "0x6FF23F20",
        "LoD/1.13c": "0x6FF23FB6"
      },
      "rvas": {
        "LoD/1.07": "0xBDDA",
        "LoD/1.08": "0xBDFA",
        "LoD/1.09": "0xC9FA",
        "LoD/1.09b": "0xC9FA",
        "LoD/1.09d": "0xCC5A",
        "LoD/1.10": "0xD304",
        "LoD/1.12a": "0x3F20",
        "LoD/1.13c": "0x3FB6"
      },
      "name": "ConvertCharacterToLowerCase",
      "signature": "uint ConvertCharacterToLowerCase(void * this, void * pLocaleContext, uint dwCharacterValue)",
      "comment": "Converts a character value to its lowercase equivalent using locale-aware processing.\n\nAlgorithm:\n1. Check if locale processing is enabled via g_dwLocaleAvailableFlag\n2. If locale disabled, perform simple ASCII conversion (A-Z \u2192 a-z by adding 0x20)\n3. If locale enabled and character < 0x100, determine character attributes\n4. Use direct table lookup if g_dwCharacterProcessingMode < 2, else call complex function\n5. If character has no uppercase attribute, return original value\n6. For multibyte characters, check high byte for 0x80 attribute flag\n7. Prepare character encoding (single byte or double byte) for conversion\n8. Call locale conversion function FUN_6ff2da18 with proper parameters\n9. Extract result based on conversion byte count (1 or 2 bytes)\n10. Return converted lowercase character or original if conversion fails\n\nParameters:\npLocaleContext - Locale context object pointer (this parameter in ECX register)\ndwCharacterValue - 32-bit character value to convert (supports Unicode codepoints)\n\nReturns:\nLowercase character value as 32-bit unsigned integer\nOriginal value if no conversion needed or conversion failed\n\nSpecial Cases:\nSimple ASCII: Characters 0x41-0x5A (A-Z) converted to 0x61-0x7A (a-z)\nUnicode fallback: Non-ASCII characters processed via locale conversion API\nMultibyte handling: Double-byte characters encoded properly for conversion\n\nMagic Numbers Reference:\n0x20 - ASCII lowercase offset (difference between 'A' and 'a')\n0x40 - Upper bound check for ASCII range (64, just below 'A')\n0x41 - ASCII 'A' character code (65)\n0x5A - ASCII 'Z' character code (90)\n0x5B - Just above 'Z' for range check (91)\n0x80 - High byte multibyte flag in character attribute table\n0x100 - Unicode BMP boundary (256, single-byte character limit)\n\nError Handling:\nReturns original character value if locale conversion fails\nFalls back to original value for characters without uppercase attributes\nNo explicit error codes - uses return value semantics",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cc0e19248bdb90cb6bf790db102f9ddf"
    },
    "Bnclient_MNE_cc80bc73a373": {
      "addresses": {
        "LoD/1.10": "0x6FF066F0"
      },
      "rvas": {
        "LoD/1.10": "0x66F0"
      },
      "method": "MNE",
      "index": "MNE:cc80bc73a373b0bee91742ce5c266d40"
    },
    "Bnclient_MNE_cd0285e9441f": {
      "addresses": {
        "LoD/1.11": "0x6FF21050",
        "LoD/1.11b": "0x6FF21220",
        "LoD/1.12a": "0x6FF210B0",
        "LoD/1.13c": "0x6FF21050",
        "LoD/1.13d": "0x6FF21040"
      },
      "rvas": {
        "LoD/1.11": "0x1050",
        "LoD/1.11b": "0x1220",
        "LoD/1.12a": "0x10B0",
        "LoD/1.13c": "0x1050",
        "LoD/1.13d": "0x1040"
      },
      "name": "operator=",
      "signature": "BNGatewayAccess * operator=(BNGatewayAccess * this, BNGatewayAccess * param_1)",
      "comment": "public: class BNGatewayAccess & __thiscall BNGatewayAccess::operator=(class BNGatewayAccess const &)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:cd0285e9441f5e782995c62b7f40a547",
      "candidates": {
        "LoD/1.09b": {
          "address": "0x6FF01000",
          "rva": "0x1000",
          "confidence": 0.295,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09": {
          "address": "0x6FF01000",
          "rva": "0x1000",
          "confidence": 0.194,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_cd4ab8e23ed6": {
      "addresses": {
        "LoD/1.07": "0x6FF2CEA6",
        "LoD/1.08": "0x6FF2CEC6",
        "LoD/1.09": "0x6FF0DAC6",
        "LoD/1.09b": "0x6FF0DAC6",
        "LoD/1.09d": "0x6FF0DDD6",
        "LoD/1.10": "0x6FF0E33E",
        "LoD/1.11": "0x6FF257D2",
        "LoD/1.11b": "0x6FF25626",
        "LoD/1.12a": "0x6FF24A8E",
        "LoD/1.13c": "0x6FF25872",
        "LoD/1.13d": "0x6FF25BD2"
      },
      "rvas": {
        "LoD/1.07": "0xCEA6",
        "LoD/1.08": "0xCEC6",
        "LoD/1.09": "0xDAC6",
        "LoD/1.09b": "0xDAC6",
        "LoD/1.09d": "0xDDD6",
        "LoD/1.10": "0xE33E",
        "LoD/1.11": "0x57D2",
        "LoD/1.11b": "0x5626",
        "LoD/1.12a": "0x4A8E",
        "LoD/1.13c": "0x5872",
        "LoD/1.13d": "0x5BD2"
      },
      "name": "LocalUnwind",
      "signature": "void LocalUnwind(SehRegistrationFrame * pRegistrationFrame, int nTargetLevel)",
      "comment": "Unwinds local exception handlers during structured exception handling cleanup.\n\nAlgorithm:\n1. Validate registration frame pointer (pRegistrationFrame != NULL)\n2. Set up exception frame with custom handler (0x6ff2ce84)\n3. Install temporary exception frame to protect unwinding process\n4. Extract scope table pointer and current level from registration frame\n5. Loop while current level != -1 and current level != target level:\n   a. Read next level value from scope table[current_level].dwNextLevel\n   b. Update registration frame current level to next level\n   c. Check if scope table[current_level].dwFilterType == 0 (cleanup handler)\n   d. If cleanup handler: call FUN_6ff2cf3a() then execute handler function\n   e. Continue to next scope level\n6. Restore previous exception list pointer\n7. Return to caller\n\nParameters:\npRegistrationFrame - Pointer to SEH registration frame containing scope table and current level\nnTargetLevel - Target scope level to unwind to (-1 = unwind all, other = stop at level)\n\nReturns:\nvoid - No return value, performs unwinding side effects\n\nSpecial Cases:\n- If current level equals target level, stops unwinding immediately\n- If current level equals -1, stops unwinding (end of chain reached)\n- Filter type 0 indicates cleanup handler, non-zero skips handler execution\n- Custom exception handler at 0x6ff2ce84 protects unwinding process\n\nStructure Layout:\nSehRegistrationFrame (16 bytes):\nOffset | Size | Field Name      | Type                 | Description\n+0x00  | 4    | pNext          | void*                | Next frame in chain\n+0x04  | 4    | pfnHandler     | void*                | Exception handler function\n+0x08  | 4    | pScopeTable    | SehHandlerDescriptor*| Scope table array\n+0x0C  | 4    | dwCurrentLevel | uint                 | Current scope level\n\nSehHandlerDescriptor (12 bytes):\nOffset | Size | Field Name     | Type  | Description\n+0x00  | 4    | dwNextLevel    | uint  | Next enclosing scope level\n+0x04  | 4    | dwFilterType   | uint  | 0=cleanup, non-zero=filter\n+0x08  | 4    | pfnHandler     | void* | Cleanup/filter function\n\nError Handling:\n- Custom exception handler 0x6ff2ce84 catches exceptions during unwinding\n- Temporary exception frame prevents infinite recursion during cleanup\n- Invalid scope table accesses protected by exception frame\n\nMagic Numbers Reference:\n0x6ff2ce84 - Custom exception handler for protecting unwind process\n0xc (12) - Size of SehHandlerDescriptor structure in scope table\n-1 (0xFFFFFFFF) - Sentinel value indicating end of scope chain",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cd4ab8e23ed6997cd2e2434b8d375458"
    },
    "Bnclient_MNE_cd85d17a6b19": {
      "addresses": {
        "LoD/1.07": "0x6FF2B2AD",
        "LoD/1.08": "0x6FF2B1F2",
        "LoD/1.09": "0x6FF0BDF2",
        "LoD/1.09b": "0x6FF0BDF2",
        "LoD/1.09d": "0x6FF0C12D",
        "LoD/1.10": "0x6FF0C68D",
        "LoD/1.11": "0x6FF21D15",
        "LoD/1.11b": "0x6FF2148E",
        "LoD/1.12a": "0x6FF21434",
        "LoD/1.13c": "0x6FF2157A",
        "LoD/1.13d": "0x6FF216F6"
      },
      "rvas": {
        "LoD/1.07": "0xB2AD",
        "LoD/1.08": "0xB1F2",
        "LoD/1.09": "0xBDF2",
        "LoD/1.09b": "0xBDF2",
        "LoD/1.09d": "0xC12D",
        "LoD/1.10": "0xC68D",
        "LoD/1.11": "0x1D15",
        "LoD/1.11b": "0x148E",
        "LoD/1.12a": "0x1434",
        "LoD/1.13c": "0x157A",
        "LoD/1.13d": "0x16F6"
      },
      "name": "ReportError",
      "signature": "void ReportError(uint dwErrorCode)",
      "comment": "Simple error reporting wrapper that forwards error codes with default parameters.\n\nAlgorithm:\n1. Accept the error code parameter from the caller\n2. Forward the error code to FUN_6ff2b2cd along with two zero parameters\n3. Return immediately after the function call\n\nParameters:\ndwErrorCode (uint) - Error code to be reported or logged\n\nReturns:\nvoid - No return value (noreturn function based on callers)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cd85d17a6b193c95680d3fdca645abba"
    },
    "Bnclient_MNE_ced68f090488": {
      "addresses": {
        "LoD/1.11": "0x6FF376DB",
        "LoD/1.11b": "0x6FF376AB",
        "LoD/1.12a": "0x6FF3855B",
        "LoD/1.13c": "0x6FF3853B",
        "LoD/1.13d": "0x6FF3847B"
      },
      "rvas": {
        "LoD/1.11": "0x176DB",
        "LoD/1.11b": "0x176AB",
        "LoD/1.12a": "0x1855B",
        "LoD/1.13c": "0x1853B",
        "LoD/1.13d": "0x1847B"
      },
      "method": "MNE",
      "index": "MNE:ced68f09048890319abe4e844972fc66"
    },
    "Bnclient_MNE_cf4bba8373cc": {
      "addresses": {
        "LoD/1.07": "0x6FF2B938",
        "LoD/1.08": "0x6FF2B958",
        "LoD/1.09": "0x6FF0C558",
        "LoD/1.09b": "0x6FF0C558",
        "LoD/1.09d": "0x6FF0C7B8",
        "LoD/1.10": "0x6FF0CD18"
      },
      "rvas": {
        "LoD/1.07": "0xB938",
        "LoD/1.08": "0xB958",
        "LoD/1.09": "0xC558",
        "LoD/1.09b": "0xC558",
        "LoD/1.09d": "0xC7B8",
        "LoD/1.10": "0xCD18"
      },
      "name": "StringToUnsignedLongWithBase",
      "signature": "void * StringToUnsignedLongWithBase(void * this, void * pContext, byte * pbString, byte * * ppbEndPtr, int nBase, uint dwFlags)",
      "comment": "Convert string to unsigned long integer with specified base.\n\nAlgorithm:\n1. Skip leading whitespace characters using character attribute table\n2. Process optional sign character (+ or -)\n3. Validate base parameter (must be 0-36, excluding 1)\n4. Auto-detect base if base parameter is 0:\n   - If string starts with '0x' or '0X': hexadecimal (base 16)\n   - If string starts with '0': octal (base 8) \n   - Otherwise: decimal (base 10)\n5. Skip '0x' or '0X' prefix for hexadecimal numbers\n6. Calculate maximum value threshold for overflow detection\n7. Process each character in conversion loop:\n   - Check if character is valid digit for specified base\n   - For digits 0-9: convert using character code - 0x30\n   - For letters A-F/a-f: use FUN_6ff2bc30 and subtract 0x37\n   - Validate digit value is less than base\n   - Check for overflow before multiplication\n   - Accumulate result: result = result * base + digit\n8. Handle overflow conditions and set errno to ERANGE (0x22)\n9. Apply negative sign if flag bit 2 is set\n10. Update end pointer to point to first non-converted character\n\nParameters:\npContext (void*): Context data pointer for character processing mode\npbString (byte*): Input string to convert\nppbEndPtr (byte**): Output pointer to first unconverted character (may be NULL)\nnBase (int): Numeric base for conversion (0 for auto-detect, 2-36)\ndwFlags (uint): Control flags for conversion behavior\n\nReturns:\nvoid*: Converted unsigned long value, or 0 on invalid input\n- Returns 0x00000000 for invalid base or no valid digits\n- Returns 0xFFFFFFFF for unsigned overflow with UINT_MAX flag\n- Returns 0x7FFFFFFF for signed positive overflow\n- Returns 0x80000000 for signed negative overflow\n\nSpecial Cases:\nInvalid base values (base < 0, base == 1, base > 36) return 0\nEmpty strings or strings with no valid digits return 0\nOverflow conditions set errno via FUN_6ff2cab3() to ERANGE (0x22)\n\nFlag Bits:\n0x01: UINT_MAX flag - return 0xFFFFFFFF on overflow\n0x02: Negative sign detected\n0x04: Overflow detected during conversion\n0x08: At least one digit successfully processed\n\nMagic Numbers Reference:\n0x2D: ASCII '-' (minus sign)\n0x2B: ASCII '+' (plus sign)\n0x30: ASCII '0' (digit zero)\n0x78: ASCII 'x' (lowercase hex prefix)\n0x58: ASCII 'X' (uppercase hex prefix)\n0x37: Offset for converting A-F to 10-15\n0x08: Character attribute bit for whitespace\n0x04: Character attribute bit for digit\n0x103: Character attribute bits for hex digit\n0x22: ERANGE errno value\n0x7FFFFFFF: Maximum positive signed 32-bit value\n0x80000000: Maximum negative signed 32-bit value\n0xFFFFFFFF: Maximum unsigned 32-bit value\n\nError Handling:\nBase validation failure: Returns 0, sets endptr to original string\nOverflow detection: Sets errno to ERANGE, returns appropriate limit value\nInvalid characters: Stops conversion, sets endptr to invalid character",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cf4bba8373cc6f7fefec3dac17cb97f9"
    },
    "Bnclient_MNE_cf6e169535cd": {
      "addresses": {
        "LoD/1.11": "0x6FF23FA0",
        "LoD/1.11b": "0x6FF235D0",
        "LoD/1.12a": "0x6FF24000",
        "LoD/1.13c": "0x6FF23D70",
        "LoD/1.13d": "0x6FF23980"
      },
      "rvas": {
        "LoD/1.11": "0x3FA0",
        "LoD/1.11b": "0x35D0",
        "LoD/1.12a": "0x4000",
        "LoD/1.13c": "0x3D70",
        "LoD/1.13d": "0x3980"
      },
      "name": "_strcmp",
      "signature": "int _strcmp(char * _Str1, char * _Str2)",
      "comment": "Library Function - Single Match\n _strcmp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:cf6e169535cd0b739256cb2ecfc119ba"
    },
    "Bnclient_MNE_cf8a4cc2c524": {
      "addresses": {
        "LoD/1.07": "0x6FF295E0",
        "LoD/1.08": "0x6FF29600",
        "LoD/1.09": "0x6FF0A210",
        "LoD/1.09b": "0x6FF0A210",
        "LoD/1.09d": "0x6FF0A470",
        "LoD/1.10": "0x6FF0ACD0",
        "LoD/1.11": "0x6FF34460",
        "LoD/1.11b": "0x6FF31190",
        "LoD/1.12a": "0x6FF2F7C0",
        "LoD/1.13c": "0x6FF37420",
        "LoD/1.13d": "0x6FF34C80"
      },
      "rvas": {
        "LoD/1.07": "0x95E0",
        "LoD/1.08": "0x9600",
        "LoD/1.09": "0xA210",
        "LoD/1.09b": "0xA210",
        "LoD/1.09d": "0xA470",
        "LoD/1.10": "0xACD0",
        "LoD/1.11": "0x14460",
        "LoD/1.11b": "0x11190",
        "LoD/1.12a": "0xF7C0",
        "LoD/1.13c": "0x17420",
        "LoD/1.13d": "0x14C80"
      },
      "name": "LogFormattedMessageThreadSafe",
      "signature": "void LogFormattedMessageThreadSafe(byte * pbFormatString, ...)",
      "comment": "Thread-safe logging function that formats and logs messages to global string buffer.\n\nAlgorithm:\n1. Enter critical section for thread-safe access to global string buffer\n2. Format input string with variable arguments using SnprintfWithOverflowHandling\n3. Set null terminator at end of formatted buffer to ensure proper string termination\n4. Call Ordinal_548 to write formatted message to global string buffer target location\n5. Exit critical section to allow other threads access\n\nParameters:\npbFormatString (byte *): Format string with printf-style format specifiers\n... (variadic): Variable arguments matching format specifiers in pbFormatString\n\nReturns:\nvoid: Function does not return a value\n\nSpecial Cases:\nBuffer size limited to 0x200 (512) bytes for formatted output\nThread synchronization handled via critical section at g_abGlobalStringBuffer+0x1c8\nOrdinal_548 handles actual logging output to global buffer at offset 0x480\n\nMagic Numbers Reference:\n0x200 (512): Maximum buffer size for formatted string output\n0x1c8 (456): Offset to critical section structure in global string buffer\n0x480 (1152): Offset to target location in global string buffer for log output",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cf8a4cc2c52417ab360d8bb963189e36"
    },
    "Bnclient_MNE_d016b68ecb5d": {
      "addresses": {
        "LoD/1.11": "0x6FF2604D",
        "LoD/1.11b": "0x6FF24C2A",
        "LoD/1.12a": "0x6FF26ED0",
        "LoD/1.13c": "0x6FF25E22",
        "LoD/1.13d": "0x6FF24C9A"
      },
      "rvas": {
        "LoD/1.11": "0x604D",
        "LoD/1.11b": "0x4C2A",
        "LoD/1.12a": "0x6ED0",
        "LoD/1.13c": "0x5E22",
        "LoD/1.13d": "0x4C9A"
      },
      "name": "__lseek",
      "signature": "long __lseek(int _FileHandle, long _Offset, int _Origin)",
      "comment": "Library Function - Single Match\n __lseek\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:d016b68ecb5da6df87847adf03c73f3a"
    },
    "Bnclient_MNE_d020e6e6f383": {
      "addresses": {
        "LoD/1.07": "0x6FF3037C",
        "LoD/1.08": "0x6FF3039C",
        "LoD/1.09": "0x6FF10FBC",
        "LoD/1.09b": "0x6FF10FBC",
        "LoD/1.09d": "0x6FF112AC",
        "LoD/1.10": "0x6FF117FC"
      },
      "rvas": {
        "LoD/1.07": "0x1037C",
        "LoD/1.08": "0x1039C",
        "LoD/1.09": "0x10FBC",
        "LoD/1.09b": "0x10FBC",
        "LoD/1.09d": "0x112AC",
        "LoD/1.10": "0x117FC"
      },
      "name": "IsStreamBinaryMode",
      "signature": "byte IsStreamBinaryMode(uint dwStreamIndex)",
      "comment": "Checks if a stream is operating in binary mode (non-text mode).\n\nAlgorithm:\n1. Validate stream index against total stream count\n2. Return 0 (false) if stream index is out of bounds  \n3. Calculate bucket index using stream index divided by 32 (right shift 5)\n4. Calculate offset within bucket using stream index modulo 32 (AND 0x1f)\n5. Access StreamIO descriptor at calculated position in 2D array\n6. Extract nPosition field from the descriptor structure (offset 0x4)\n7. Test binary mode flag bit (0x40) in the position field\n8. Return non-zero if binary mode flag is set, 0 otherwise\n\nParameters:\ndwStreamIndex (uint) - Zero-based index of the stream to check\n\nReturns:\nNon-zero (byte) - Stream is in binary mode (flag 0x40 set)\n0 (byte) - Stream is in text mode or invalid index\n\nSpecial Cases:\nStream index validation prevents buffer overrun on invalid stream numbers\n\nMagic Numbers Reference:\n0x1f (31) - Mask for modulo 32 operation (5 low bits)\n0x5 (5) - Right shift count for division by 32 \n0x40 (64) - Binary mode flag bit in nPosition field\n0x4 - Offset to nPosition field in StreamIO structure\n\nStructure Layout:\nStreamIO structure accessed via g_apStreamDescriptors[bucket][index]:\nOffset | Size | Field Name | Type | Description\n0x0    | 4    | Unknown    | uint | (Not accessed in this function)\n0x4    | 4    | nPosition  | uint | Position/flags field containing binary mode bit\n...additional fields not accessed...",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d020e6e6f383c625d5fd112b88b641eb"
    },
    "Bnclient_MNE_d09ab6579f07": {
      "addresses": {
        "LoD/1.07": "0x6FF2CCEB",
        "LoD/1.08": "0x6FF2CD0B",
        "LoD/1.09": "0x6FF0D90B",
        "LoD/1.09b": "0x6FF0D90B",
        "LoD/1.09d": "0x6FF0DC1B",
        "LoD/1.10": "0x6FF0E181"
      },
      "rvas": {
        "LoD/1.07": "0xCCEB",
        "LoD/1.08": "0xCD0B",
        "LoD/1.09": "0xD90B",
        "LoD/1.09b": "0xD90B",
        "LoD/1.09d": "0xDC1B",
        "LoD/1.10": "0xE181"
      },
      "name": "CustomExceptionFilter",
      "signature": "long CustomExceptionFilter(int nExceptionCode, _EXCEPTION_POINTERS * pExceptionInfo)",
      "comment": "Custom exception filter that routes exceptions to registered handlers and maps exception codes\n\nAlgorithm:\n1. Get thread context structure via GetOrCreateThreadContext()\n2. Lookup exception handler record using FUN_6ff2ce29(nExceptionCode, context[0x14])  \n3. If no handler found or handler function pointer is NULL, call UnhandledExceptionFilter()\n4. If handler type is 5 (EXCEPTION_CONTINUE_SEARCH), clear handler and return 1\n5. If handler type is 1 (EXCEPTION_CONTINUE_EXECUTION), return -1 to continue execution\n6. Save current exception pointer to context[0x15] and process handler\n7. If handler expects type 8 (structured exception), clear exception array and map exception codes:\n   - Loop from g_nExceptionArrayStart to g_nExceptionArrayStart + g_nExceptionArraySize\n   - Clear each 12-byte exception array entry at offset +8\n   - Map NT exception codes to handler-specific codes:\n     * 0xC000008E (FLOAT_DIVIDE_BY_ZERO) \u2192 0x83\n     * 0xC0000090 (FLOAT_INVALID_OPERATION) \u2192 0x81  \n     * 0xC0000091 (FLOAT_OVERFLOW) \u2192 0x84\n     * 0xC0000093 (FLOAT_UNDERFLOW) \u2192 0x85\n     * 0xC000008D (FLOAT_DENORMAL_OPERAND) \u2192 0x82\n     * 0xC000008F (FLOAT_INEXACT_RESULT) \u2192 0x86\n     * 0xC0000092 (FLOAT_STACK_CHECK) \u2192 0x8A\n   - Call handler function with (8, mapped_code)\n8. For non-type-8 handlers, clear handler type and call with original handler type\n9. Restore saved exception pointer and return -1\n\nParameters:\nnExceptionCode - Exception code from the system\npExceptionInfo - Pointer to EXCEPTION_POINTERS structure containing exception and context records\n\nReturns:\n1 - EXCEPTION_EXECUTE_HANDLER (terminate and handle)  \n-1 - EXCEPTION_CONTINUE_EXECUTION (resume at exception point)\nUnhandledExceptionFilter result - If no custom handler found\n\nSpecial Cases:\nHandler type 5 forces exception search continuation\nHandler type 1 forces execution continuation  \nType 8 handlers receive mapped floating-point exception codes\nException array clearing uses 12-byte stride (0xC) suggesting structured exception records\n\nMagic Numbers Reference:\n0x5 - EXCEPTION_CONTINUE_SEARCH handler type\n0x1 - EXCEPTION_CONTINUE_EXECUTION handler type  \n0x8 - Structured exception handler type expecting mapped codes\n0xC - Exception array entry stride (12 bytes)\n0x14 - ThreadContext offset to exception array base (offset 20)\n0x15 - ThreadContext offset to saved exception pointer (offset 21)\n0x16 - ThreadContext offset to exception code storage (offset 22)\n0xC000008E - NT_STATUS FLOAT_DIVIDE_BY_ZERO \u2192 maps to 0x83\n0xC0000090 - NT_STATUS FLOAT_INVALID_OPERATION \u2192 maps to 0x81\n0xC0000091 - NT_STATUS FLOAT_OVERFLOW \u2192 maps to 0x84\n0xC0000093 - NT_STATUS FLOAT_UNDERFLOW \u2192 maps to 0x85  \n0xC000008D - NT_STATUS FLOAT_DENORMAL_OPERAND \u2192 maps to 0x82\n0xC000008F - NT_STATUS FLOAT_INEXACT_RESULT \u2192 maps to 0x86\n0xC0000092 - NT_STATUS FLOAT_STACK_CHECK \u2192 maps to 0x8A\n\nError Handling:\nReturns UnhandledExceptionFilter() result if no custom handler registered\nHandler lookup failure falls back to system default exception handling\nInvalid handler types default to execution continuation (-1)\n\nGlobal Variables:\ng_nExceptionArrayStart - Starting index for exception array clearing loop\ng_nExceptionArraySize - Number of exception array entries to clear",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d09ab6579f07f3f7e60cd130b4db709e"
    },
    "Bnclient_MNE_d1375bb0092b": {
      "addresses": {
        "LoD/1.11": "0x6FF22DDE",
        "LoD/1.11b": "0x6FF2236F",
        "LoD/1.12a": "0x6FF23445",
        "LoD/1.13c": "0x6FF2281D",
        "LoD/1.13d": "0x6FF223E4"
      },
      "rvas": {
        "LoD/1.11": "0x2DDE",
        "LoD/1.11b": "0x236F",
        "LoD/1.12a": "0x3445",
        "LoD/1.13c": "0x281D",
        "LoD/1.13d": "0x23E4"
      },
      "name": "write_string",
      "signature": "undefined write_string(int param_1)",
      "comment": "Library Function - Single Match\n _write_string\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:d1375bb0092b441c0ed3bd5dfaaa61cb"
    },
    "Bnclient_MNE_d286a589c482": {
      "addresses": {
        "LoD/1.11": "0x6FF24272",
        "LoD/1.11b": "0x6FF24264",
        "LoD/1.12a": "0x6FF242D2",
        "LoD/1.13c": "0x6FF242D7",
        "LoD/1.13d": "0x6FF242DD"
      },
      "rvas": {
        "LoD/1.11": "0x4272",
        "LoD/1.11b": "0x4264",
        "LoD/1.12a": "0x42D2",
        "LoD/1.13c": "0x42D7",
        "LoD/1.13d": "0x42DD"
      },
      "name": "__setenvp",
      "signature": "int __setenvp(void)",
      "comment": "Library Function - Single Match\n __setenvp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:d286a589c48283a2eda13c52495cb951"
    },
    "Bnclient_MNE_d2ef459ed5b9": {
      "addresses": {
        "LoD/1.07": "0x6FF2B4B4",
        "LoD/1.08": "0x6FF2B4D5",
        "LoD/1.09": "0x6FF0C0D5",
        "LoD/1.09b": "0x6FF0C0D5",
        "LoD/1.09d": "0x6FF0C334",
        "LoD/1.10": "0x6FF0C894"
      },
      "rvas": {
        "LoD/1.07": "0xB4B4",
        "LoD/1.08": "0xB4D5",
        "LoD/1.09": "0xC0D5",
        "LoD/1.09b": "0xC0D5",
        "LoD/1.09d": "0xC334",
        "LoD/1.10": "0xC894"
      },
      "name": "CreateCustomThread",
      "signature": "HANDLE CreateCustomThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, int nParam1, int nParam2, DWORD dwCreationFlags, LPDWORD lpThreadId)",
      "comment": "Creates a custom worker thread with initialized thread context structure.\n\nAlgorithm:\n1. Initialize error tracking variable (dwLastError = 0)\n2. Allocate thread context structure (ThreadContext, 0x74 bytes)\n3. Validate allocation succeeded, jump to cleanup if failed\n4. Initialize context structure using FUN_6ff2c24f\n5. Set context flags field to -1 (0xFFFFFFFF) at offset 0x4\n6. Store user parameter 1 (nParam1) at context offset 0x48 \n7. Store user parameter 2 (nParam2) at context offset 0x4c\n8. Create thread using Win32 CreateThread API with custom thread procedure FUN_6ff2b51f\n9. Check thread creation success, return thread handle if successful\n10. On thread creation failure, capture last error code using GetLastError\n11. Always cleanup allocated context structure using FUN_6ff2cac5\n12. Set error state if failure occurred using FUN_6ff2ca40\n13. Return NULL handle (0x0) on any failure\n\nParameters:\nlpThreadAttributes - Security attributes for thread or NULL for default\ndwStackSize - Initial stack size in bytes or 0 for default\nnParam1 - User-defined parameter 1 stored in thread context\nnParam2 - User-defined parameter 2 stored in thread context  \ndwCreationFlags - Thread creation flags (CREATE_SUSPENDED, etc.)\nlpThreadId - Receives thread identifier or NULL if not needed\n\nReturns:\nThread handle on success, NULL (0x0) on failure\nError state set via FUN_6ff2ca40 on allocation or thread creation failure\n\nSpecial Cases:\nContext allocation failure: Skip thread creation, proceed to cleanup\nThread creation failure: Capture Win32 error code before cleanup\n\nMagic Numbers Reference:\n0x74 (116 decimal) - ThreadContext structure size in bytes\n0x4 - Offset to dwFlags field in ThreadContext structure  \n0x48 (72 decimal) - Offset to nParam1 field in ThreadContext structure\n0x4c (76 decimal) - Offset to nParam2 field in ThreadContext structure\n0xFFFFFFFF - Initial flags value (all flags set)\n\nStructure Layout:\nThreadContext (116 bytes total):\nOffset | Size | Field Name | Type | Description\n0x00   | 4    | reserved0  | byte[4] | Reserved padding\n0x04   | 4    | dwFlags    | uint    | Thread context flags (initialized to -1)\n0x08   | 64   | reserved1  | byte[64] | Reserved middle section  \n0x48   | 4    | nParam1    | int     | User parameter 1\n0x4c   | 4    | nParam2    | int     | User parameter 2\n0x50   | 40   | reserved2  | byte[40] | Reserved trailing section\n\nError Handling:\nContext allocation failure: Returns NULL, no error state set\nThread creation failure: Returns NULL, sets error state via FUN_6ff2ca40\nAlways performs context cleanup regardless of success/failure path",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d2ef459ed5b972389dc537b2b4518459"
    },
    "Bnclient_MNE_d3a4e36f3c07": {
      "addresses": {
        "LoD/1.12a": "0x6FF36F00",
        "LoD/1.13c": "0x6FF34470",
        "LoD/1.13d": "0x6FF33EC0"
      },
      "rvas": {
        "LoD/1.12a": "0x16F00",
        "LoD/1.13c": "0x14470",
        "LoD/1.13d": "0x13EC0"
      },
      "method": "MNE",
      "index": "MNE:d3a4e36f3c07ad9c22b479e880928893"
    },
    "Bnclient_MNE_d3fefb7c954c": {
      "addresses": {
        "LoD/1.11": "0x6FF3749C",
        "LoD/1.11b": "0x6FF3746C",
        "LoD/1.12a": "0x6FF3831C",
        "LoD/1.13c": "0x6FF382FC",
        "LoD/1.13d": "0x6FF3823C"
      },
      "rvas": {
        "LoD/1.11": "0x1749C",
        "LoD/1.11b": "0x1746C",
        "LoD/1.12a": "0x1831C",
        "LoD/1.13c": "0x182FC",
        "LoD/1.13d": "0x1823C"
      },
      "method": "MNE",
      "index": "MNE:d3fefb7c954cbb3bdf620b064e1026c9"
    },
    "Bnclient_MNE_d43d8fc047d2": {
      "addresses": {
        "LoD/1.07": "0x6FF3200F",
        "LoD/1.08": "0x6FF3202F",
        "LoD/1.09": "0x6FF12C24",
        "LoD/1.09b": "0x6FF12C24",
        "LoD/1.09d": "0x6FF12F3F",
        "LoD/1.10": "0x6FF134C3"
      },
      "rvas": {
        "LoD/1.07": "0x1200F",
        "LoD/1.08": "0x1202F",
        "LoD/1.09": "0x12C24",
        "LoD/1.09b": "0x12C24",
        "LoD/1.09d": "0x12F3F",
        "LoD/1.10": "0x134C3"
      },
      "name": "DuplicateStringArray",
      "signature": "char * * DuplicateStringArray(char * * lpszSourceArray)",
      "comment": "Creates a deep copy of a null-terminated array of string pointers with individually allocated strings.\n\nAlgorithm:\n1. Validate input array pointer (return NULL if null)\n2. Count non-null elements in source array by traversing until null terminator\n3. Allocate memory for destination array (count * 4 + 4 bytes for null terminator)\n4. Call AmsgExit(9) if allocation fails\n5. Iterate through source array, duplicating each string with FUN_6ff3210d\n6. Store each duplicated string pointer in destination array\n7. Append null terminator to destination array\n8. Return pointer to newly allocated array\n\nParameters:\nlpszSourceArray (char **): Null-terminated array of string pointers to duplicate\n                          Must not be null for successful execution\n\nReturns:\nchar **: Pointer to newly allocated array of duplicated strings\n         Returns NULL if source array is null\n         Each string in returned array is individually allocated\n\nSpecial Cases:\nEmpty source array (first element null): Allocates 4-byte array with single null pointer\nMemory allocation failure: Calls AmsgExit(9) to terminate program\n\nError Handling:\nNull source array: Returns NULL immediately\nMalloc failure: Calls AmsgExit(9) for fatal error termination\nIndividual string duplication handled by FUN_6ff3210d\n\nMagic Numbers Reference:\n0x4 (4): Size of pointer in 32-bit architecture\n0x9 (9): Fatal memory error code for AmsgExit",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d43d8fc047d25feaf61353d7aa1dcba8"
    },
    "Bnclient_MNE_d4c2d26a88b1": {
      "addresses": {
        "LoD/1.11": "0x6FF260D4",
        "LoD/1.11b": "0x6FF27EFE",
        "LoD/1.12a": "0x6FF26F57",
        "LoD/1.13c": "0x6FF27F6E",
        "LoD/1.13d": "0x6FF27F6E"
      },
      "rvas": {
        "LoD/1.11": "0x60D4",
        "LoD/1.11b": "0x7EFE",
        "LoD/1.12a": "0x6F57",
        "LoD/1.13c": "0x7F6E",
        "LoD/1.13d": "0x7F6E"
      },
      "method": "MNE",
      "index": "MNE:d4c2d26a88b113bd75739659d4ef7dd5"
    },
    "Bnclient_MNE_d53aa8167129": {
      "addresses": {
        "LoD/1.07": "0x6FF24750",
        "LoD/1.08": "0x6FF24770",
        "LoD/1.09": "0x6FF050D0",
        "LoD/1.09b": "0x6FF050D0",
        "LoD/1.09d": "0x6FF05350",
        "LoD/1.10": "0x6FF052D0",
        "LoD/1.11": "0x6FF32310",
        "LoD/1.11b": "0x6FF2B0B0",
        "LoD/1.12a": "0x6FF31400",
        "LoD/1.13c": "0x6FF2FD20",
        "LoD/1.13d": "0x6FF34F00"
      },
      "rvas": {
        "LoD/1.07": "0x4750",
        "LoD/1.08": "0x4770",
        "LoD/1.09": "0x50D0",
        "LoD/1.09b": "0x50D0",
        "LoD/1.09d": "0x5350",
        "LoD/1.10": "0x52D0",
        "LoD/1.11": "0x12310",
        "LoD/1.11b": "0xB0B0",
        "LoD/1.12a": "0x11400",
        "LoD/1.13c": "0xFD20",
        "LoD/1.13d": "0x14F00"
      },
      "name": "GetSystemTimeZone",
      "signature": "int GetSystemTimeZone(BNGatewayAccess * this)",
      "comment": "private: int __thiscall BNGatewayAccess::GetSystemTimeZone(void)",
      "name_source": "LoD/1.10",
      "method": "MNE",
      "index": "MNE:d53aa81671297fc28bd5c40ecedc4235"
    },
    "Bnclient_MNE_d54b31472f74": {
      "addresses": {
        "LoD/1.07": "0x6FF2BFB0",
        "LoD/1.08": "0x6FF2BFD0",
        "LoD/1.09": "0x6FF0CBD0",
        "LoD/1.09b": "0x6FF0CBD0",
        "LoD/1.09d": "0x6FF0CEE0",
        "LoD/1.11": "0x6FF33BD0",
        "LoD/1.11b": "0x6FF30970",
        "LoD/1.12a": "0x6FF366F0",
        "LoD/1.13c": "0x6FF367B0",
        "LoD/1.13d": "0x6FF36740"
      },
      "rvas": {
        "LoD/1.07": "0xBFB0",
        "LoD/1.08": "0xBFD0",
        "LoD/1.09": "0xCBD0",
        "LoD/1.09b": "0xCBD0",
        "LoD/1.09d": "0xCEE0",
        "LoD/1.11": "0x13BD0",
        "LoD/1.11b": "0x10970",
        "LoD/1.12a": "0x166F0",
        "LoD/1.13c": "0x167B0",
        "LoD/1.13d": "0x16740"
      },
      "name": "__allmul",
      "signature": "longlong __allmul(uint dwLowA, int nHighA, uint dwLowB, int nHighB)",
      "comment": "Performs 64-bit multiplication of two longlong values using 32-bit operations.\n\nAlgorithm:\n\n1. Check if both high parts are zero (simple case optimization)\n2. If both high parts zero: perform direct 32x32 multiplication returning 64-bit result\n3. Complex case: calculate cross-products for full 64x64 multiplication\n4. Multiply dwLowA * dwLowB for base 64-bit result\n5. Add cross-products (nHighA * dwLowB) and (dwLowA * nHighB) to high part\n6. Return combined 64-bit result in EDX:EAX\n\nParameters:\n\ndwLowA (uint): Low 32 bits of first 64-bit multiplicand\nnHighA (int): High 32 bits of first 64-bit multiplicand  \ndwLowB (uint): Low 32 bits of second 64-bit multiplicand\nnHighB (int): High 32 bits of second 64-bit multiplicand\n\nReturns:\n\nlonglong: 64-bit product of the two input values\nSuccess: Valid 64-bit multiplication result\nOverflow: Result may overflow but follows standard x86 multiplication behavior\n\nSpecial Cases:\n\nFast path: When both nHighA and nHighB are zero, uses optimized 32x32 MUL instruction\nFull calculation: Uses cross-multiplication when either high part is non-zero\nStandard calling convention: __stdcall with 16-byte stack cleanup (4 parameters x 4 bytes)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d54b31472f74b078be31f20f65c7b2d3"
    },
    "Bnclient_MNE_d606ab4b80a8": {
      "addresses": {
        "LoD/1.09": "0x6FF13680",
        "LoD/1.09b": "0x6FF13680",
        "LoD/1.09d": "0x6FF139A0",
        "LoD/1.10": "0x6FF13FA0"
      },
      "rvas": {
        "LoD/1.09": "0x13680",
        "LoD/1.09b": "0x13680",
        "LoD/1.09d": "0x139A0",
        "LoD/1.10": "0x13FA0"
      },
      "method": "MNE",
      "index": "MNE:d606ab4b80a800732667cc53cf2fef45"
    },
    "Bnclient_MNE_d858691b25ff": {
      "addresses": {
        "LoD/1.07": "0x6FF2C474",
        "LoD/1.08": "0x6FF2C494",
        "LoD/1.09": "0x6FF0D094",
        "LoD/1.09b": "0x6FF0D094",
        "LoD/1.09d": "0x6FF0D3A4",
        "LoD/1.10": "0x6FF0D90A"
      },
      "rvas": {
        "LoD/1.07": "0xC474",
        "LoD/1.08": "0xC494",
        "LoD/1.09": "0xD094",
        "LoD/1.09b": "0xD094",
        "LoD/1.09d": "0xD3A4",
        "LoD/1.10": "0xD90A"
      },
      "name": "CheckCharacterAttributes",
      "signature": "uint CheckCharacterAttributes(void * this, LocaleContext * pLocaleContext, int nCharacter, uint dwAttributeMask)",
      "comment": "Check character attributes against specified mask for locale-aware processing.\n\nAlgorithm:\n1. Check if character value is in direct table range (< 256)\n2. If in range: Load attribute flags directly from g_pCharacterAttributeTable\n3. If out of range: Handle multi-byte character conversion\n   - Extract high byte and check multi-byte flag (0x80) in attribute table\n   - If single-byte mode: Pack character into local buffer with 1-byte count\n   - If multi-byte mode: Pack character bytes in little-endian order with 2-byte count\n4. Call character conversion function FUN_6ff2e68a with packed buffer\n5. If conversion fails: Return 0 (no attributes match)\n6. Apply attribute mask to converted character result\n7. Return masked attribute flags\n\nParameters:\npLocaleContext (LocaleContext*): IMPLICIT ECX - Locale processing context for character conversion\nnCharacter (int): Character code to check attributes for (supports Unicode)\ndwAttributeMask (unsigned int): Attribute flags to test against character\n\nReturns:\nunsigned int: Masked attribute flags from character table, or 0 if conversion failed\n- Non-zero: Character has attributes matching the specified mask\n- 0x00000000: Character conversion failed or no attributes match\n\nSpecial Cases:\nCharacters < 256 bypass conversion and use direct table lookup\nMulti-byte characters require conversion through FUN_6ff2e68a before attribute checking\nConversion failure (function returns FALSE) results in 0 return value\n\nMagic Numbers Reference:\n0x100: Direct table lookup threshold (256 characters)\n0x80: Multi-byte character flag in attribute table\n0x01: Conversion mode for FUN_6ff2e68a (single conversion)\n0xFF: Byte mask for extracting character components\n0xFFU: High byte extraction mask for multi-byte detection\n\nError Handling:\nCharacter conversion failure: Returns 0 immediately without attribute checking\nInvalid character codes: Handled by conversion function, may return 0",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d858691b25ff9d68f1965dc04bb2a9aa"
    },
    "Bnclient_MNE_d8be7433da89": {
      "addresses": {
        "LoD/1.07": "0x6FF2E284",
        "LoD/1.08": "0x6FF2E2A4",
        "LoD/1.09": "0x6FF0EECF",
        "LoD/1.09b": "0x6FF0EECF",
        "LoD/1.09d": "0x6FF0F1B4",
        "LoD/1.10": "0x6FF0F7A2",
        "LoD/1.11": "0x6FF21B50",
        "LoD/1.11b": "0x6FF21F00",
        "LoD/1.12a": "0x6FF21F50",
        "LoD/1.13c": "0x6FF21FB0",
        "LoD/1.13d": "0x6FF21DA0"
      },
      "rvas": {
        "LoD/1.07": "0xE284",
        "LoD/1.08": "0xE2A4",
        "LoD/1.09": "0xEECF",
        "LoD/1.09b": "0xEECF",
        "LoD/1.09d": "0xF1B4",
        "LoD/1.10": "0xF7A2",
        "LoD/1.11": "0x1B50",
        "LoD/1.11b": "0x1F00",
        "LoD/1.12a": "0x1F50",
        "LoD/1.13c": "0x1FB0",
        "LoD/1.13d": "0x1DA0"
      },
      "name": "GetPEMachineType",
      "signature": "void GetPEMachineType(BYTE * pbMachineType)",
      "comment": "Extracts the processor architecture machine type from the current module's PE header.\n\nAlgorithm:\n1. Zero the output buffer to ensure clean state\n2. Get handle to current module using GetModuleHandleA(NULL)\n3. Validate PE signature by checking for MZ header (0x5A4D)\n4. Read PE header offset from DOS header at offset 0x3C\n5. Validate PE header offset is non-zero\n6. Calculate COFF header address: module base + PE offset + COFF header\n7. Extract 2-byte machine type from COFF header at offset +0x18\n8. Store machine type bytes in little-endian format in output buffer\n\nParameters:\npbMachineType: BYTE * - Pointer to 2-byte buffer to receive machine type value\n               Buffer receives little-endian machine type (IMAGE_FILE_MACHINE_* constants)\n\nReturns:\nvoid - No return value, machine type written to output buffer\n       If PE validation fails, buffer remains zeroed\n\nMagic Numbers Reference:\n0x5A4D - PE MZ signature (\"MZ\" in ASCII, marks valid DOS/PE executable)\n0x3C   - Offset in DOS header containing PE header file offset\n0x18   - Offset in PE COFF header containing machine type field\n\nError Handling:\n- Invalid module handle: Function exits, buffer remains zeroed\n- Invalid MZ signature: Function exits, buffer remains zeroed  \n- Zero PE header offset: Function exits, buffer remains zeroed\n- All error conditions leave output buffer in clean zeroed state\n\nPE Structure Layout:\nOffset | Size | Field Name    | Type   | Description\n-------|------|---------------|--------|----------------------------------\n0x00   | 2    | e_magic       | WORD   | MZ signature (0x5A4D)\n0x3C   | 4    | e_lfanew      | LONG   | Offset to PE header\n...    | ...  | ...           | ...    | DOS header continues\nPE+0x00| 4    | Signature     | DWORD  | PE signature (PE\\0\\0)\nPE+0x04| 2    | Machine       | WORD   | Target machine type\nPE+0x06| 2    | Sections      | WORD   | Number of sections\n\nMachine Type Constants:\n0x014C - IMAGE_FILE_MACHINE_I386 (Intel 386 or later, x86)\n0x8664 - IMAGE_FILE_MACHINE_AMD64 (AMD x64 architecture)\n0x01C4 - IMAGE_FILE_MACHINE_ARMNT (ARM little-endian)\n0xAA64 - IMAGE_FILE_MACHINE_ARM64 (ARM64 little-endian)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d8be7433da8984a6d08ceacc3367b90b"
    },
    "Bnclient_MNE_d903856acfed": {
      "addresses": {
        "LoD/1.10": "0x6FF06670"
      },
      "rvas": {
        "LoD/1.10": "0x6670"
      },
      "method": "MNE",
      "index": "MNE:d903856acfed73be6028d01853e2bedf"
    },
    "Bnclient_MNE_d9739637e22d": {
      "addresses": {
        "LoD/1.07": "0x6FF2F576",
        "LoD/1.08": "0x6FF2F596",
        "LoD/1.09": "0x6FF101C1",
        "LoD/1.09b": "0x6FF101C1",
        "LoD/1.09d": "0x6FF104A6",
        "LoD/1.10": "0x6FF10A94",
        "LoD/1.11": "0x6FF2C7A0",
        "LoD/1.11b": "0x6FF34FC0",
        "LoD/1.12a": "0x6FF2B5A0",
        "LoD/1.13c": "0x6FF32810",
        "LoD/1.13d": "0x6FF34540"
      },
      "rvas": {
        "LoD/1.07": "0xF576",
        "LoD/1.08": "0xF596",
        "LoD/1.09": "0x101C1",
        "LoD/1.09b": "0x101C1",
        "LoD/1.09d": "0x104A6",
        "LoD/1.10": "0x10A94",
        "LoD/1.11": "0xC7A0",
        "LoD/1.11b": "0x14FC0",
        "LoD/1.12a": "0xB5A0",
        "LoD/1.13c": "0x12810",
        "LoD/1.13d": "0x14540"
      },
      "name": "ValidateAllocationBlockAddress",
      "signature": "int ValidateAllocationBlockAddress(byte * pAddress, ErrorTableEntry * * ppTableEntry, uint * puBaseAddress)",
      "comment": "Validate memory address within allocation block and calculate adjusted address\n\nAlgorithm:\n1. Initialize table pointer to g_aErrorTable[18] (offset 0x12 * 8 bytes)\n2. Loop through linked error table entries checking address bounds\n3. Compare address against entry's lower bound (offset 0x10) and upper bound (offset 0x14)\n4. If address outside bounds, follow next pointer (offset 0x0) to continue search\n5. Exit loop if reach sentinel value 0x6ff36b70 indicating end of table\n6. Validate 16-byte alignment by checking (address & 0xf) == 0\n7. Validate minimum offset by checking (address & 0xfff) >= 0x100\n8. Store found table entry pointer in output parameter\n9. Calculate 4KB-aligned base address using (address & 0xfffff000)\n10. Store base address in output parameter  \n11. Calculate final address: ((address - base - 0x100) >> 4) + 8 + base\n\nParameters:\npAddress (void*): Memory address to validate and process\nppTableEntry (ErrorTableEntry**): Output pointer for found error table entry\npuBaseAddress (uint*): Output pointer for calculated 4KB base address\n\nReturns:\n0: Validation failed - address not found in table, misaligned, or offset too small\nNon-zero: Calculated adjusted address based on base address and offset\n\nSpecial Cases:\n- Returns 0 if address not found in any table entry bounds\n- Returns 0 if address not 16-byte aligned (address & 0xf != 0)  \n- Returns 0 if offset within 4KB page less than 0x100 bytes\n- Handles linked list traversal with sentinel check at 0x6ff36b70\n\nMagic Numbers Reference:\n0x12 (18): Starting offset in error table array\n0xf (15): Alignment mask for 16-byte boundary check\n0xfff (4095): Page offset mask for 4KB boundary\n0x100 (256): Minimum required offset within page\n0xfffff000: 4KB page base address mask\n0x4 (4): Right shift amount for 16-byte block calculation\n0x8 (8): Base offset added to final calculation\n0x6ff36b70: Sentinel value marking end of error table list\n\nStructure Layout:\nErrorTableEntry (8 bytes):\nOffset | Size | Field Name    | Type                  | Description\n0x00   | 4    | dwErrorCode   | ErrorTableEntry*      | Next entry pointer or error code\n0x04   | 4    | lpszMessage   | char*                 | Error message string pointer\n\nAddress Bounds Check:\nOffset 0x10: Lower bound address for allocation block\nOffset 0x14: Upper bound address for allocation block",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d9739637e22d71ed7283b5bc68a6c4ac"
    },
    "Bnclient_MNE_d98637d661e3": {
      "addresses": {
        "LoD/1.07": "0x6FF22EF0",
        "LoD/1.08": "0x6FF22F10",
        "LoD/1.09": "0x6FF03880",
        "LoD/1.09b": "0x6FF03880",
        "LoD/1.09d": "0x6FF03C30",
        "LoD/1.10": "0x6FF03C10"
      },
      "rvas": {
        "LoD/1.07": "0x2EF0",
        "LoD/1.08": "0x2F10",
        "LoD/1.09": "0x3880",
        "LoD/1.09b": "0x3880",
        "LoD/1.09d": "0x3C30",
        "LoD/1.10": "0x3C10"
      },
      "name": "EnablePacketHandler171",
      "signature": "void EnablePacketHandler171(void)",
      "comment": "Enable packet handler for packet type 171 (0xAB).\n\nAlgorithm:\n1. Set packet handler array entry 171 to enabled state (value 1)\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nMagic Numbers Reference:\n- 0xAB (171): Packet type identifier for specific packet handler\n- 0x1: Enabled state value for packet handler",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d98637d661e34ac4188330085482b5ab"
    },
    "Bnclient_MNE_d9a12ae164ce": {
      "addresses": {
        "LoD/1.11": "0x6FF366DE",
        "LoD/1.11b": "0x6FF366AF",
        "LoD/1.12a": "0x6FF3755E",
        "LoD/1.13c": "0x6FF37544",
        "LoD/1.13d": "0x6FF3747D"
      },
      "rvas": {
        "LoD/1.11": "0x166DE",
        "LoD/1.11b": "0x166AF",
        "LoD/1.12a": "0x1755E",
        "LoD/1.13c": "0x17544",
        "LoD/1.13d": "0x1747D"
      },
      "name": "_UnwindNestedFrames",
      "signature": "void _UnwindNestedFrames(EHRegistrationNode * param_1, EHExceptionRecord * param_2)",
      "comment": "Library Function - Single Match\n void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *,struct EHExceptionRecord *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:d9a12ae164ceeb71b3ef1de062e62e18"
    },
    "Bnclient_MNE_da9fe63256c7": {
      "addresses": {
        "LoD/1.07": "0x6FF2C4E9",
        "LoD/1.08": "0x6FF2C509",
        "LoD/1.09": "0x6FF0D109",
        "LoD/1.09b": "0x6FF0D109",
        "LoD/1.09d": "0x6FF0D419",
        "LoD/1.10": "0x6FF0D97F"
      },
      "rvas": {
        "LoD/1.07": "0xC4E9",
        "LoD/1.08": "0xC509",
        "LoD/1.09": "0xD109",
        "LoD/1.09b": "0xD109",
        "LoD/1.09d": "0xD419",
        "LoD/1.10": "0xD97F"
      },
      "name": "ReallocateMemoryWithStrategy",
      "signature": "void * ReallocateMemoryWithStrategy(void * pMemory, uint dwNewSize)",
      "comment": "Strategy-based memory reallocator with multiple allocation pathways and automatic retry logic.\n\nAlgorithm:\n1. Handle null pointer allocation: If pMemory is null, allocate nNewSize bytes using malloc()\n2. Handle deallocation: If nNewSize is null, deallocate pMemory using DeallocateMemory()\n3. Set up structured exception handling (SEH) frame for error recovery\n4. Check allocation strategy from global configuration (DAT_6ff3b424)\n5. Strategy 3 (Advanced Pool): Use critical section locking, attempt pool reallocation, fallback to heap\n   - Acquire critical section index 9 for thread safety\n   - Query allocator info for existing memory block\n   - If block size within limits (DAT_6ff3b41c), attempt in-place resize\n   - If in-place fails, allocate new block and copy data\n   - Release old block and update allocator tracking\n6. Strategy 2 (Block Manager): Use block-based allocation with size classes\n   - Round up size to 16-byte alignment for efficiency\n   - Query block header information for size class\n   - Attempt resize within same size class using block manager\n   - If resize fails, allocate new block and copy data\n7. Default Strategy: Use direct heap reallocation (HeapReAlloc)\n   - Round up size to 16-byte alignment\n   - Attempt direct heap reallocation\n8. Retry logic: If allocation fails and retry handler exists (DAT_6ff3a060), invoke retry handler\n9. Restore exception handling and return result pointer\n\nParameters:\npMemory - Pointer to existing memory block to reallocate (null for allocation)\nnNewSize - New size in bytes for memory block (0 for deallocation)\n\nReturns:\nPointer to reallocated memory block on success\nNULL on allocation failure or after deallocation\nOriginal pointer may be invalid after successful reallocation\n\nSpecial Cases:\nIf nNewSize is 0, function deallocates memory and returns NULL\nIf pMemory is null, function allocates new memory of nNewSize\nMinimum allocation size is 1 byte (0 size converted to 1)\nAll allocations rounded up to 16-byte alignment (size + 15) & 0xFFFFFFF0\n\nMagic Numbers Reference:\n0x0F (15) - Alignment mask for 16-byte boundaries\n0xFFFFFFF0 - Inverse mask for 16-byte alignment\n0xFFFFFFE1 (-31) - Maximum allocation size check threshold\n0x3 - Advanced pool allocation strategy identifier\n0x2 - Block manager allocation strategy identifier\n0x9 - Critical section index for allocation synchronization\n0x10 (16) - Default minimum allocation size for strategy 2\n0x4 - Size multiplier for block size calculations (shift left by 4 = multiply by 16)\n\nError Handling:\nStrategy 3: Acquires critical section, handles pool allocation failures, releases locks\nStrategy 2: Handles block manager failures, falls back to heap allocation\nAll strategies: Invoke retry handler (FUN_6ff2f9e7) if DAT_6ff3a060 is set\nSEH frame protects against access violations during allocation operations\nCritical sections released via finally blocks (FUN_6ff2c674, FUN_6ff2c7c2)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:da9fe63256c776da60d8a55e82f34c74"
    },
    "Bnclient_MNE_dca7de17bf02": {
      "addresses": {
        "LoD/1.11": "0x6FF34AD0",
        "LoD/1.11b": "0x6FF2CB70",
        "LoD/1.12a": "0x6FF2C1D0",
        "LoD/1.13c": "0x6FF2D2F0",
        "LoD/1.13d": "0x6FF31060"
      },
      "rvas": {
        "LoD/1.11": "0x14AD0",
        "LoD/1.11b": "0xCB70",
        "LoD/1.12a": "0xC1D0",
        "LoD/1.13c": "0xD2F0",
        "LoD/1.13d": "0x11060"
      },
      "method": "MNE",
      "index": "MNE:dca7de17bf02a89d8ff5661c0e91bf8a"
    },
    "Bnclient_MNE_dda7ad2210cc": {
      "addresses": {
        "LoD/1.07": "0x6FF26740",
        "LoD/1.08": "0x6FF26760",
        "LoD/1.09": "0x6FF06CD0",
        "LoD/1.09b": "0x6FF06CD0",
        "LoD/1.09d": "0x6FF06F40",
        "LoD/1.10": "0x6FF07630"
      },
      "rvas": {
        "LoD/1.07": "0x6740",
        "LoD/1.08": "0x6760",
        "LoD/1.09": "0x6CD0",
        "LoD/1.09b": "0x6CD0",
        "LoD/1.09d": "0x6F40",
        "LoD/1.10": "0x7630"
      },
      "name": "PrepareAndSendNetworkMessage",
      "signature": "int PrepareAndSendNetworkMessage(char * lpszMessage, int nConnectionFlag, int nModeFlag)",
      "comment": "Prepares and formats network message data, then sends via packet transmission\n\nAlgorithm:\n1. Initialize flags buffer (dwFlags) and message buffer (szBuffer) to zero\n2. Validate input message: check for null pointer or empty string\n3. If message invalid: set base flag (0x01), get global state, set mode flag (0x04) if needed\n4. If message invalid: use default \"Diablo II\" message from global string\n5. If message valid: set connection flag (0x02) based on nConnectionFlag parameter\n6. Copy message to local buffer using Ordinal_501 with 0x80 byte limit\n7. Calculate actual string length using manual null-terminator search\n8. Send formatted packet via SendNetworkPacketWithValidation\n9. Return success status (1)\n\nParameters:\nlpszMessage - Pointer to message string to send (can be null for default message)\nnConnectionFlag - Connection state flag (non-zero sets bit 1 in flags)  \nnModeFlag - Mode flag (0 enables global state check for bit 2)\n\nReturns:\n1 - Success (packet prepared and sent)\n\nSpecial Cases:\nDefault message fallback when lpszMessage is null or empty string\nGlobal state check only performed when nModeFlag is 0\nConnection flag (0x02) set only when nConnectionFlag is non-zero\n\nMagic Numbers Reference:\n0x01 - Base flag (always set for default message)\n0x02 - Connection flag (set when nConnectionFlag non-zero) \n0x04 - Mode flag (set when global state active and nModeFlag is 0)\n0x21 - Loop counter for zeroing 33 DWORDs (132 bytes total)\n0x80 - Buffer size limit for message copy (128 bytes)\n\nError Handling:\nInput validation with null/empty string detection\nAutomatic fallback to default \"Diablo II\" message\nBuffer overflow protection via 0x80 byte copy limit",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:dda7ad2210cc9a7186949f23e7879260"
    },
    "Bnclient_MNE_de76025ed283": {
      "addresses": {
        "LoD/1.07": "0x6FF2F612",
        "LoD/1.08": "0x6FF2F632",
        "LoD/1.09": "0x6FF1025D",
        "LoD/1.09b": "0x6FF1025D",
        "LoD/1.09d": "0x6FF10542",
        "LoD/1.10": "0x6FF10B30"
      },
      "rvas": {
        "LoD/1.07": "0xF612",
        "LoD/1.08": "0xF632",
        "LoD/1.09": "0x1025D",
        "LoD/1.09b": "0x1025D",
        "LoD/1.09d": "0x10542",
        "LoD/1.10": "0x10B30"
      },
      "name": "AllocateMemoryFromPool",
      "signature": "int * AllocateMemoryFromPool(uint dwBytesToAllocate)",
      "comment": "Allocates memory from a managed pool using a linked list of memory allocators with fallback to VirtualAlloc.\n\nAlgorithm:\n\n1. Traverse linked list of memory allocators starting from g_pErrorTableHead\n2. For each active allocator (piVar8[4] != -1):\n   - Search active memory blocks (offset 0x8 to 0x2018) for suitable free space\n   - Check if requested size fits within block's available range  \n   - Call FUN_6ff2f81a to attempt allocation from block\n   - If successful, update block metadata and return pointer\n   - If failed, update block end marker and continue search\n3. Search lower priority blocks (offset 0x18 to end) using same allocation logic\n4. If no space found in current allocator, advance to next allocator in list\n5. If all existing allocators exhausted, find empty allocator slot in g_aErrorTable\n6. For empty allocator: count consecutive free pages (up to 0x10 maximum)\n7. Call VirtualAlloc to allocate physical memory for counted pages (page_count << 0xc bytes)\n8. Call _memset to zero-initialize allocated memory \n9. Initialize each page with 0xF0 byte free space and link metadata\n10. Set up allocator tracking structures and update global head pointer\n11. Extract requested allocation from first initialized page\n12. Return pointer to allocated memory + 0x100 offset, or NULL on failure\n\nParameters:\n\ndwBytesToAllocate (uint) - Number of bytes to allocate from memory pool\n\nReturns:\n\nSUCCESS: Pointer to allocated memory block (base + 0x100 offset)\nFAILURE: NULL (0x0) if allocation fails or VirtualAlloc fails\n\nSpecial Cases:\n\n- If allocator reaches end of list (circular check), searches for empty slots\n- VirtualAlloc failure returns NULL immediately  \n- Memory is zero-initialized after VirtualAlloc\n- Each page provides 0xF0 (240) bytes of usable space\n- Allocator metadata uses 0x10 bytes overhead per page\n- Maximum consecutive pages per allocation: 0x10 (16 pages = 64KB)\n\nMagic Numbers Reference:\n\n0x100 (256) - Return pointer offset from memory block base\n0xF0 (240) - Usable bytes per memory page after metadata overhead  \n0xF1 (241) - Initial end marker for free space tracking\n0x1000 (4096) - Virtual memory page size for VirtualAlloc\n0x400 (1024) - Memory block stride in int* units (0x400 * 4 = 4096 bytes)\n0x806 (2054) - End boundary for active block search range  \n0x403 (1027) - Maximum entries in error table array\n0x18 (24) - Allocator metadata overhead size\n0x2018 (8216) - Upper boundary offset for active block range\n0x10 (16) - Maximum consecutive pages for single allocation\n0x3d (61) - Byte offset marker for page initialization flag (0xff)\n\nError Handling:\n\n- VirtualAlloc failure: Returns NULL without cleanup\n- FUN_6ff2f81a allocation failure: Updates block metadata and continues search  \n- Empty allocator list: Calls InitializeMemoryAllocator() for bootstrap\n- Invalid allocator state: Skips to next allocator in linked list\n- Circular list detection: Breaks loop and searches for empty slots\n\nStructure Layout:\n\nErrorTableEntry (8 bytes per entry):\nOffset | Size | Field Name  | Type   | Description\n-------|------|-------------|--------|------------------------------------------\n0x00   | 4    | dwErrorCode | uint   | Error code or next pointer for linking\n0x04   | 4    | lpszMessage | char * | Message pointer or memory tracking data\n\nMemory Allocator Node Layout (accessed as int* array):\nOffset | Size | Field Name    | Type  | Description  \n-------|------|---------------|-------|------------------------------------------\n0x00   | 4    | pNext         | int * | Next allocator in linked list\n0x04   | 4    | pReserved     | int * | Reserved/unused field\n0x08   | 4    | pMemoryStart  | int * | Pointer to first memory block entry\n0x0C   | 4    | pMemoryEnd    | int * | Pointer to end of memory block array  \n0x10   | 4    | pVirtualBase  | int * | Base address from VirtualAlloc\n0x14   | 4    | dwReserved    | int   | Reserved/unused field",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:de76025ed2839a23b964285c7e0d5701"
    },
    "Bnclient_MNE_decef60e401f": {
      "addresses": {
        "LoD/1.11": "0x6FF369DD",
        "LoD/1.11b": "0x6FF369AE",
        "LoD/1.12a": "0x6FF3785D",
        "LoD/1.13c": "0x6FF37843",
        "LoD/1.13d": "0x6FF3777C"
      },
      "rvas": {
        "LoD/1.11": "0x169DD",
        "LoD/1.11b": "0x169AE",
        "LoD/1.12a": "0x1785D",
        "LoD/1.13c": "0x17843",
        "LoD/1.13d": "0x1777C"
      },
      "name": "_FindAndUnlinkFrame",
      "signature": "void _FindAndUnlinkFrame(FrameInfo * param_1)",
      "comment": "Library Function - Single Match\n void __cdecl _FindAndUnlinkFrame(struct FrameInfo *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:decef60e401f8e90b7116a8a0959e784"
    },
    "Bnclient_MNE_dfcbf2c4340c": {
      "addresses": {
        "LoD/1.12a": "0x6FF28180",
        "LoD/1.13c": "0x6FF28160",
        "LoD/1.13d": "0x6FF28160"
      },
      "rvas": {
        "LoD/1.12a": "0x8180",
        "LoD/1.13c": "0x8160",
        "LoD/1.13d": "0x8160"
      },
      "method": "MNE",
      "index": "MNE:dfcbf2c4340c9d481934a7449bd7b6a0"
    },
    "Bnclient_MNE_e038b71e9908": {
      "addresses": {
        "LoD/1.07": "0x6FF2BD6B",
        "LoD/1.08": "0x6FF2BD8B",
        "LoD/1.09": "0x6FF0C98B",
        "LoD/1.09b": "0x6FF0C98B",
        "LoD/1.09d": "0x6FF0CBEB",
        "LoD/1.10": "0x6FF0D295"
      },
      "rvas": {
        "LoD/1.07": "0xBD6B",
        "LoD/1.08": "0xBD8B",
        "LoD/1.09": "0xC98B",
        "LoD/1.09b": "0xC98B",
        "LoD/1.09d": "0xCBEB",
        "LoD/1.10": "0xD295"
      },
      "name": "ConvertCharacterToUpperCase",
      "signature": "uint ConvertCharacterToUpperCase(uint dwCharacterCode)",
      "comment": "Converts lowercase ASCII character to uppercase with locale-aware support.\n\nAlgorithm:\n1. Check global locale availability flag (g_dwLocaleAvailableFlag)\n2. If locale disabled, perform simple ASCII range check and conversion:\n   - Validate character is in range 'a' (0x61) to 'z' (0x7A)\n   - Convert by subtracting 0x20 to get uppercase equivalent\n3. If locale enabled, use thread-safe locale conversion:\n   - Increment critical section counter using InterlockedIncrement\n   - Check if critical section limit exceeded (g_dwCriticalSectionLimit != 0)\n   - If limit exceeded, decrement counter and enter critical section\n   - Call FUN_6ff2bc9f for locale-aware character conversion\n   - Release critical section or decrement counter based on limit state\n4. Return converted character code\n\nParameters:\ndwCharacterCode (uint): Character code to convert to uppercase\n\nReturns:\nuint: Uppercase character code if conversion successful, original code otherwise\n\nSpecial Cases:\n- Non-alphabetic characters: Returned unchanged\n- Out of ASCII range 'a'-'z': Returned unchanged when locale disabled\n- Critical section limit exceeded: Uses synchronization primitives\n\nMagic Numbers Reference:\n0x61 (97): ASCII 'a' - lowercase range start\n0x7A (122): ASCII 'z' - lowercase range end  \n0x20 (32): ASCII case difference (uppercase = lowercase - 0x20)\n0x13 (19): Critical section resource identifier\n\nError Handling:\n- Invalid character codes: Returned unchanged\n- Critical section contention: Handled via InterlockedIncrement/Decrement\n- Locale conversion failure: Falls back to original character code",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e038b71e990839fd36df244ad8c1a314"
    },
    "Bnclient_MNE_e10b5e01aa72": {
      "addresses": {
        "LoD/1.07": "0x6FF319D0",
        "LoD/1.08": "0x6FF319F0",
        "LoD/1.09": "0x6FF12610",
        "LoD/1.09b": "0x6FF12610",
        "LoD/1.09d": "0x6FF12900",
        "LoD/1.10": "0x6FF12E84"
      },
      "rvas": {
        "LoD/1.07": "0x119D0",
        "LoD/1.08": "0x119F0",
        "LoD/1.09": "0x12610",
        "LoD/1.09b": "0x12610",
        "LoD/1.09d": "0x12900",
        "LoD/1.10": "0x12E84"
      },
      "name": "__mbsnbicoll",
      "signature": "int __mbsnbicoll(uchar * pbStr1, uchar * pbStr2, size_t cbMaxCount)",
      "comment": "Performs case-insensitive comparison of multibyte character strings with maximum character count.\n\nAlgorithm:\n1. Check if maximum count parameter is zero and return 0 for empty comparison\n2. Call Windows API CompareString function with case-insensitive comparison flags\n3. Pass both strings with same byte count limit and current code page settings\n4. Process API return value: 0 indicates error condition, return maximum positive value\n5. For successful comparison, adjust result by subtracting 2 to match C library semantics\n\nParameters:\npbStr1 (uchar *): Pointer to first multibyte string for comparison\npbStr2 (uchar *): Pointer to second multibyte string for comparison  \ncbMaxCount (size_t): Maximum number of bytes to compare from each string\n\nReturns:\nint: Comparison result following C library semantics\n     0 if strings are equal within specified byte count\n     <0 if pbStr1 is lexicographically less than pbStr2\n     >0 if pbStr1 is lexicographically greater than pbStr2\n     0x7FFFFFFF (2147483647) if Windows API comparison fails\n\nSpecial Cases:\ncbMaxCount = 0: Returns 0 immediately without performing comparison\nAPI failure: Returns maximum positive integer to indicate error condition\n\nMagic Numbers Reference:\n0x7FFFFFFF (2147483647): Maximum positive 32-bit signed integer, error indicator\n-2: Adjustment value to convert Windows API result (1,2,3) to C semantics (-1,0,1)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e10b5e01aa7213213653c89eecf239b0"
    },
    "Bnclient_MNE_e12afdedf65b": {
      "addresses": {
        "LoD/1.11": "0x6FF22107",
        "LoD/1.11b": "0x6FF220E8",
        "LoD/1.12a": "0x6FF22160",
        "LoD/1.13c": "0x6FF2215E",
        "LoD/1.13d": "0x6FF2215D"
      },
      "rvas": {
        "LoD/1.11": "0x2107",
        "LoD/1.11b": "0x20E8",
        "LoD/1.12a": "0x2160",
        "LoD/1.13c": "0x215E",
        "LoD/1.13d": "0x215D"
      },
      "method": "MNE",
      "index": "MNE:e12afdedf65b4f2d4ddeab4188a67460"
    },
    "Bnclient_MNE_e1a55473b8c8": {
      "addresses": {
        "LoD/1.11": "0x6FF2123C",
        "LoD/1.11b": "0x6FF2199F",
        "LoD/1.12a": "0x6FF216A4",
        "LoD/1.13c": "0x6FF21C76",
        "LoD/1.13d": "0x6FF21DCD"
      },
      "rvas": {
        "LoD/1.11": "0x123C",
        "LoD/1.11b": "0x199F",
        "LoD/1.12a": "0x16A4",
        "LoD/1.13c": "0x1C76",
        "LoD/1.13d": "0x1DCD"
      },
      "name": "___tolower_mt",
      "signature": "uint ___tolower_mt(void * this, int param_1, uint param_2)",
      "comment": "Library Function - Single Match\n ___tolower_mt\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e1a55473b8c876366de891db323c13fa"
    },
    "Bnclient_MNE_e1bb2af96e76": {
      "addresses": {
        "LoD/1.07": "0x6FF2C369",
        "LoD/1.08": "0x6FF2C1FD",
        "LoD/1.09": "0x6FF0CDFD",
        "LoD/1.09b": "0x6FF0CDFD",
        "LoD/1.09d": "0x6FF0D299",
        "LoD/1.10": "0x6FF0D7FF"
      },
      "rvas": {
        "LoD/1.07": "0xC369",
        "LoD/1.08": "0xC1FD",
        "LoD/1.09": "0xCDFD",
        "LoD/1.09b": "0xCDFD",
        "LoD/1.09d": "0xD299",
        "LoD/1.10": "0xD7FF"
      },
      "name": "InitializeCriticalSections",
      "signature": "void InitializeCriticalSections(void)",
      "comment": "Initialize four critical sections for thread synchronization.\n\nAlgorithm:\n1. Load InitializeCriticalSection function pointer into ESI register for optimization\n2. Initialize first critical section (g_pCriticalSection1) by calling InitializeCriticalSection\n3. Initialize second critical section (g_pCriticalSection2) by calling InitializeCriticalSection  \n4. Initialize third critical section (g_pCriticalSection3) by calling InitializeCriticalSection\n5. Initialize fourth critical section (g_pCriticalSection4) by calling InitializeCriticalSection\n6. Restore ESI register and return\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nFunction uses register optimization by loading InitializeCriticalSection function pointer \nonce into ESI and calling through the register four times instead of direct calls.\n\nGlobal Variables Referenced:\ng_pCriticalSection1 (0x6ff3650c) - Points to first critical section structure\ng_pCriticalSection2 (0x6ff364fc) - Points to second critical section structure  \ng_pCriticalSection3 (0x6ff364ec) - Points to third critical section structure\ng_pCriticalSection4 (0x6ff364cc) - Points to fourth critical section structure\n\nCalling Context:\nCalled during thread local storage initialization as part of multithreading setup.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e1bb2af96e763a0793e4aabbeb4bef2b"
    },
    "Bnclient_MNE_e21ee18d2e64": {
      "addresses": {
        "LoD/1.07": "0x6FF22330",
        "LoD/1.08": "0x6FF22350",
        "LoD/1.09": "0x6FF02410",
        "LoD/1.09b": "0x6FF02410",
        "LoD/1.09d": "0x6FF023E0",
        "LoD/1.10": "0x6FF02400"
      },
      "rvas": {
        "LoD/1.07": "0x2330",
        "LoD/1.08": "0x2350",
        "LoD/1.09": "0x2410",
        "LoD/1.09b": "0x2410",
        "LoD/1.09d": "0x23E0",
        "LoD/1.10": "0x2400"
      },
      "name": "LookupNotificationValue",
      "signature": "uint LookupNotificationValue(uint dwNotificationIndex)",
      "comment": "Retrieves a notification value from the global lookup table with bounds checking.\n\nAlgorithm:\n1. Apply index mask (input & 0xFF) to ensure bounds within 256-entry table\n2. Calculate array offset: base address + (masked_index * 4 bytes)  \n3. Load and return 32-bit value from calculated address\n4. Return notification value to caller\n\nParameters:\ndwNotificationIndex (uint) - Index into notification lookup table (masked to 0-255 range)\n\nReturns:\nuint - 32-bit notification value from lookup table at specified index\n       Returns zero if table entry is uninitialized\n\nSpecial Cases:\nIndex bounds protection via bitwise AND mask prevents buffer overflow\nNo explicit error return - invalid indices wrapped to valid range\n\nMagic Numbers Reference:\n0xFF (255 decimal) - Index mask to ensure table bounds (256 entries max)\n0x4 - DWORD size multiplier for array indexing (32-bit values)\n0x6ff39630 - Base address of g_adwNotificationLookupTable global array\n\nError Handling:\nIndex bounds protection via bitwise AND mask prevents buffer overflow\nNo error conditions - all inputs produce valid table lookups",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e21ee18d2e640e0be26569c20c9d2607"
    },
    "Bnclient_MNE_e23b1e49f051": {
      "addresses": {
        "LoD/1.07": "0x6FF21890",
        "LoD/1.08": "0x6FF218B0",
        "LoD/1.09": "0x6FF01890",
        "LoD/1.09b": "0x6FF01890",
        "LoD/1.09d": "0x6FF01860",
        "LoD/1.10": "0x6FF01830"
      },
      "rvas": {
        "LoD/1.07": "0x1890",
        "LoD/1.08": "0x18B0",
        "LoD/1.09": "0x1890",
        "LoD/1.09b": "0x1890",
        "LoD/1.09d": "0x1860",
        "LoD/1.10": "0x1830"
      },
      "name": "CreateAndMonitorWorkerThread",
      "signature": "void CreateAndMonitorWorkerThread(byte * pbCompletionFlag, uint dwThreadParameter)",
      "comment": "Creates a worker thread with specified buffer and flags, then waits for completion.\n\nAlgorithm:\n1. Set global thread active flag to indicate thread operation in progress\n2. Initialize buffer pointer to zero byte and store thread parameters in globals\n3. Sleep briefly (10ms) to allow system stabilization\n4. Create new worker thread pointing to WorkerThreadEntry with buffer parameters\n5. Enter polling loop checking termination flag and thread status\n6. Sleep 10ms between polls until thread completes or termination requested\n7. Return after thread completion or termination signal\n\nParameters:\npbBuffer - Pointer to byte buffer for thread operations\ndwBufferFlags - Flags controlling buffer processing behavior\n\nReturns:\nvoid - Function always returns after thread completion\n\nSpecial Cases:\n- If CreateThread fails, function still enters polling loop with null handle\n- Function exits immediately if g_dwThreadTerminate is set before thread creation\n- Sleep(10) provides 10ms delay for both initialization and polling intervals\n\nGlobal State:\ng_dwThreadActive (0x6ff392dc) - Set to 1 when thread operation starts\ng_pbThreadBuffer (0x6ff392f8) - Stores buffer pointer for worker thread access  \ng_dwThreadBufferFlags (0x6ff392fc) - Stores flags for worker thread access\ng_dwThreadTerminate (0x6ff3950c) - When non-zero, signals thread to terminate",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e23b1e49f0515c8ad28a61000e66c0fb"
    },
    "Bnclient_MNE_e318b2efa2b7": {
      "addresses": {
        "LoD/1.07": "0x6FF30640",
        "LoD/1.08": "0x6FF30660",
        "LoD/1.09": "0x6FF11280",
        "LoD/1.09b": "0x6FF11280",
        "LoD/1.09d": "0x6FF11570",
        "LoD/1.10": "0x6FF11AC0"
      },
      "rvas": {
        "LoD/1.07": "0x10640",
        "LoD/1.08": "0x10660",
        "LoD/1.09": "0x11280",
        "LoD/1.09b": "0x11280",
        "LoD/1.09d": "0x11570",
        "LoD/1.10": "0x11AC0"
      },
      "name": "UnsignedLongLongRemainder",
      "signature": "ulonglong UnsignedLongLongRemainder(uint dwDividendLow, uint dwDividendHigh, uint dwDivisorLow, uint dwDivisorHigh)",
      "comment": "Calculates 64-bit unsigned remainder (dividend % divisor) using optimized division algorithm.\n\nAlgorithm:\n1. Check if high 32 bits of divisor are zero for fast path optimization\n2. If divisor fits in 32 bits, perform standard division on combined 64-bit dividend\n3. Otherwise, normalize operands by right-shifting until divisor fits in 32 bits\n4. Perform division on normalized values to get approximate quotient\n5. Calculate full product of quotient and original divisor\n6. Compare product with original dividend and adjust quotient if needed\n7. Subtract final quotient\u00d7divisor from dividend to get remainder\n8. Return 64-bit remainder as combined high/low 32-bit values\n\nParameters:\ndwDividendLow (uint): Low 32 bits of 64-bit unsigned dividend\ndwDividendHigh (uint): High 32 bits of 64-bit unsigned dividend  \ndwDivisorLow (uint): Low 32 bits of 64-bit unsigned divisor\ndwDivisorHigh (uint): High 32 bits of 64-bit unsigned divisor\n\nReturns:\n64-bit unsigned remainder as ulonglong (high 32 bits in EDX, low 32 bits in EAX)\nReturns 0 for division by zero (undefined behavior)\n\nSpecial Cases:\nFast path when dwDivisorHigh == 0: Uses hardware DIV instruction directly\nNormalization loop when divisor > 32 bits: Shifts both operands right until divisor fits in 32 bits\nQuotient adjustment: If initial quotient estimate is too large, decrements and recalculates\n\nMagic Numbers Reference:\n0x20 (32 decimal): Left shift amount for combining high/low 32-bit parts into 64-bit value\n0x1f (31 decimal): Right shift amount for propagating carry bit during normalization\n0xffffffff: Mask to extract low 32 bits from 64-bit intermediate results",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e318b2efa2b7ed9dcb619fe5ba3fc2d5"
    },
    "Bnclient_MNE_e3474a85bce8": {
      "addresses": {
        "LoD/1.11": "0x6FF2ED60",
        "LoD/1.11b": "0x6FF31080",
        "LoD/1.12a": "0x6FF36E00",
        "LoD/1.13c": "0x6FF36EC0",
        "LoD/1.13d": "0x6FF2BC50"
      },
      "rvas": {
        "LoD/1.11": "0xED60",
        "LoD/1.11b": "0x11080",
        "LoD/1.12a": "0x16E00",
        "LoD/1.13c": "0x16EC0",
        "LoD/1.13d": "0xBC50"
      },
      "method": "MNE",
      "index": "MNE:e3474a85bce830e3b769ded0e4e90c71"
    },
    "Bnclient_MNE_e36ce61366f9": {
      "addresses": {
        "LoD/1.07": "0x6FF21050"
      },
      "rvas": {
        "LoD/1.07": "0x1050"
      },
      "name": "GetGlobalStateValue",
      "signature": "uint GetGlobalStateValue(void)",
      "comment": "Retrieve global state value by dereferencing state pointer.\n\nAlgorithm:\n1. Load pointer from global state variable (g_pdwGlobalState)\n2. Dereference pointer to get actual state value\n3. Return state value in EAX register\n\nParameters:\nNone\n\nReturns:\nuint - Current global state value\n       Returns 0 if global state pointer is NULL\n\nSpecial Cases:\nIf g_pdwGlobalState is NULL, attempting to dereference will cause access violation\n\nMagic Numbers Reference:\n0x6ff39bd4 - Address of global state pointer variable",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e36ce61366f9c3928ce2ccb97d91f009",
      "candidates": {
        "LoD/1.09": {
          "address": "0x6FF0BEB7",
          "rva": "0xBEB7",
          "confidence": 0.138,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.08"
        }
      }
    },
    "Bnclient_MNE_e3e7225badfc": {
      "addresses": {
        "LoD/1.07": "0x6FF32138",
        "LoD/1.08": "0x6FF32158",
        "LoD/1.09": "0x6FF151BC",
        "LoD/1.09b": "0x6FF151BC",
        "LoD/1.09d": "0x6FF154DC",
        "LoD/1.10": "0x6FF15A66",
        "LoD/1.11": "0x6FF2812C",
        "LoD/1.11b": "0x6FF28134",
        "LoD/1.12a": "0x6FF28760",
        "LoD/1.13c": "0x6FF28740",
        "LoD/1.13d": "0x6FF28746"
      },
      "rvas": {
        "LoD/1.07": "0x12138",
        "LoD/1.08": "0x12158",
        "LoD/1.09": "0x151BC",
        "LoD/1.09b": "0x151BC",
        "LoD/1.09d": "0x154DC",
        "LoD/1.10": "0x15A66",
        "LoD/1.11": "0x812C",
        "LoD/1.11b": "0x8134",
        "LoD/1.12a": "0x8760",
        "LoD/1.13c": "0x8740",
        "LoD/1.13d": "0x8746"
      },
      "name": "FogNetworkReceive",
      "signature": "int FogNetworkReceive(SOCKET * pConnection, byte * pbBuffer)",
      "comment": "Fog network library receive/read function import thunk.\n\nAlgorithm:\n1. Jump through import table pointer at 0x6ff33024\n2. Execute Ordinal_10007 from FOG.DLL\n3. Receive network data from established connection\n4. Return number of bytes received or error code\n5. Caller tests return value for success/failure\n\nParameters:\npConnection (ECX): Pointer to SOCKET connection handle/context\npbBuffer (EDX): Pointer to byte buffer for received data\nIMPLICIT: Buffer size may be passed in additional registers or on stack\n\nReturns:\nPositive integer: Number of bytes received successfully\nZero: No data available or connection closed gracefully\nNegative: Error code indicating receive failure or network error\n\nSpecial Cases:\nImport thunk pattern: JMP dword ptr [0x6ff33024]\nFOG.DLL Ordinal 10007: Battle.net networking library function\nUsed in packet validation and game server connection contexts\nReturn value tested with TEST EAX,EAX for error checking\n\nError Handling:\nCallers check for positive return values with JG instructions\nZero/negative returns trigger error handling routines at call sites\nConnection failures propagated through return codes to upper layers",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a"
    },
    "Bnclient_MNE_e3f73bfbf828": {
      "addresses": {
        "LoD/1.12a": "0x6FF28220",
        "LoD/1.13c": "0x6FF28200",
        "LoD/1.13d": "0x6FF28200"
      },
      "rvas": {
        "LoD/1.12a": "0x8220",
        "LoD/1.13c": "0x8200",
        "LoD/1.13d": "0x8200"
      },
      "method": "MNE",
      "index": "MNE:e3f73bfbf8288f9afa4340d874a9265e",
      "candidates": {
        "LoD/1.11b": {
          "address": "0x6FF35830",
          "rva": "0x15830",
          "confidence": 0.371,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.12a"
        },
        "LoD/1.11": {
          "address": "0x6FF2EFA0",
          "rva": "0xEFA0",
          "confidence": 0.301,
          "method": "minhash",
          "direction": "reverse",
          "source": "LoD/1.11b"
        }
      }
    },
    "Bnclient_MNE_e495bfe56b02": {
      "addresses": {
        "LoD/1.07": "0x6FF22200",
        "LoD/1.08": "0x6FF22220",
        "LoD/1.09": "0x6FF022E0",
        "LoD/1.09b": "0x6FF022E0",
        "LoD/1.09d": "0x6FF022B0",
        "LoD/1.10": "0x6FF022D0"
      },
      "rvas": {
        "LoD/1.07": "0x2200",
        "LoD/1.08": "0x2220",
        "LoD/1.09": "0x22E0",
        "LoD/1.09b": "0x22E0",
        "LoD/1.09d": "0x22B0",
        "LoD/1.10": "0x22D0"
      },
      "name": "SetNetworkErrorState",
      "signature": "void SetNetworkErrorState(void)",
      "comment": "Sets the global network error state flag to indicate connection failure.\n\nAlgorithm:\n1. Load constant value 1 into EAX register\n2. Store the value 1 into global network error state variable\n3. Return to caller\n\nParameters:\nNone (void function)\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Called when network connection validation fails\n- Sets g_dwNetworkErrorState to 1 to indicate error/disconnected state\n- Companion function to network state management system\n\nMagic Numbers Reference:\n0x1 - Error state value indicating network disconnection/failure\n0x6ff397bc - Address of g_dwNetworkErrorState global variable",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e495bfe56b02a553c57be8750ac6f809"
    },
    "Bnclient_MNE_e4c337356f23": {
      "addresses": {
        "LoD/1.07": "0x6FF2BB3D",
        "LoD/1.08": "0x6FF2BB5D",
        "LoD/1.09": "0x6FF0C75D",
        "LoD/1.09b": "0x6FF0C75D",
        "LoD/1.09d": "0x6FF0C9BD",
        "LoD/1.10": "0x6FF0CF1D",
        "LoD/1.11": "0x6FF21620",
        "LoD/1.11b": "0x6FF21C5F",
        "LoD/1.12a": "0x6FF21A4F",
        "LoD/1.13c": "0x6FF218AF",
        "LoD/1.13d": "0x6FF21547"
      },
      "rvas": {
        "LoD/1.07": "0xBB3D",
        "LoD/1.08": "0xBB5D",
        "LoD/1.09": "0xC75D",
        "LoD/1.09b": "0xC75D",
        "LoD/1.09d": "0xC9BD",
        "LoD/1.10": "0xCF1D",
        "LoD/1.11": "0x1620",
        "LoD/1.11b": "0x1C5F",
        "LoD/1.12a": "0x1A4F",
        "LoD/1.13c": "0x18AF",
        "LoD/1.13d": "0x1547"
      },
      "name": "InvokeNetworkHandler",
      "signature": "void InvokeNetworkHandler(void * this, byte * pbBuffer, int * pnLength, void * pContext)",
      "comment": "Wrapper function to invoke network handler with default parameter.\n\nAlgorithm:\n1. Pass all received parameters to FUN_6ff2b938\n2. Add a fifth parameter with value 0 (default/null value) \n3. Return immediately after function call\n4. Clean up stack parameters before returning\n\nParameters:\npbBuffer - Pointer to byte buffer containing network data\npnLength - Pointer to integer containing buffer length  \npContext - Context object pointer for operation state\nIMPLICIT: ECX register contains 'this' pointer for __thiscall convention\n\nReturns:\nvoid - No return value (wrapper function)\n\nSpecial Cases:\n- All parameters are passed through without validation\n- Fifth parameter is hardcoded to 0 (likely default operation mode)\n- Function acts as convenience wrapper for common case",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e4c337356f231e5baad169a03bc50c48"
    },
    "Bnclient_MNE_e4f799c77aca": {
      "addresses": {
        "LoD/1.07": "0x6FF2F024",
        "LoD/1.08": "0x6FF2F044",
        "LoD/1.09": "0x6FF0FC6F",
        "LoD/1.09b": "0x6FF0FC6F",
        "LoD/1.09d": "0x6FF0FF54",
        "LoD/1.10": "0x6FF10542"
      },
      "rvas": {
        "LoD/1.07": "0xF024",
        "LoD/1.08": "0xF044",
        "LoD/1.09": "0xFC6F",
        "LoD/1.09b": "0xFC6F",
        "LoD/1.09d": "0xFF54",
        "LoD/1.10": "0x10542"
      },
      "name": "ProcessHeapFreeBlock",
      "signature": "bool ProcessHeapFreeBlock(MemoryAllocation * pAllocator, uint dwBlockPtr, uint dwRequestedSize)",
      "comment": "Processes a heap memory block for allocation by splitting oversized blocks and updating free list structures.\n\nAlgorithm:\n1. Align requested size to 16-byte boundaries with header overhead (size + 0x17) & 0xfffffff0\n2. Calculate chunk index by shifting block address difference by 15 bits for 32KB regions\n3. Compute free list base address using chunk index * 0x204 + 0x144 + allocator state\n4. Read current block size from header at [block - 4] and block metadata from [block - 5]\n5. Validate block is not in use (bit 0 clear) and has sufficient size for request\n6. If current block size < aligned request: return false (insufficient space)\n7. If exact size match: mark block allocated and return true\n8. If oversized block: split into allocated portion and remainder\n9. Calculate size class index from block size (size >> 4) - 1, capped at 63 (0x3f)\n10. For blocks being removed from free list: update size class reference counters\n11. Clear size class bitmap bits when reference counter reaches zero\n12. For new remainder blocks: link into appropriate size class free list\n13. Set size class bitmap bits when first block added to empty list\n14. Update block headers with new sizes and allocation status flags\n\nParameters:\npAllocator - Pointer to MemoryAllocation structure containing allocator state and bitmaps\nnBlockPtr - Memory address of block to process for allocation\nnRequestedSize - Size in bytes requested by caller (will be aligned internally)\n\nReturns:\ntrue (1) - Block successfully processed and allocated\nfalse (0) - Block cannot satisfy request (insufficient size or validation failed)\n\nSpecial Cases:\nSize class bitmap management uses dual bitmap arrays for 64 size classes:\n- Classes 0-31: Primary bitmap at pAllocator[0], counters at [state + 4], chunk bitmaps at [state + 0x44]\n- Classes 32-63: Secondary bitmap at pAllocator[1], counters at [state + 4], chunk bitmaps at [state + 0xc4]\n\nMagic Numbers Reference:\n0x17 (23 dec) - Block header overhead for 16-byte alignment calculation\n0xfffffff0 - Alignment mask for 16-byte boundaries\n0xf (15 dec) - Right shift amount for 32KB chunk size calculation\n0x204 (516 dec) - Size of free list structure per chunk\n0x144 (324 dec) - Base offset to free list array in allocator state\n0x3f (63 dec) - Maximum size class index (supports 64 total size classes)\n0x20 (32 dec) - Threshold between primary and secondary bitmap arrays\n0x44 (68 dec) - Offset to primary chunk bitmap array in allocator state\n0xc4 (196 dec) - Offset to secondary chunk bitmap array in allocator state\n0x80000000 - Bit mask constant for bitmap manipulation operations\n\nStructure Layout:\nBlock Header Format (at block - 4):\nOffset  Size  Field Name      Type    Description\n+0      4     nBlockSize      uint    Total block size including headers\n-4      4     nPrevBlockSize  uint    Size of previous block (for coalescing)\n\nFree List Node Format (for unallocated blocks):\nOffset  Size  Field Name   Type    Description  \n+4      4     pNext        void*   Next block in free list\n+8      4     pPrev        void*   Previous block in free list",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e4f799c77acab14c5b1bdda2181c2d46"
    },
    "Bnclient_MNE_e7313d19d2f1": {
      "addresses": {
        "LoD/1.11": "0x6FF21A79",
        "LoD/1.11b": "0x6FF21588",
        "LoD/1.12a": "0x6FF2152E",
        "LoD/1.13c": "0x6FF21374",
        "LoD/1.13d": "0x6FF21858"
      },
      "rvas": {
        "LoD/1.11": "0x1A79",
        "LoD/1.11b": "0x1588",
        "LoD/1.12a": "0x152E",
        "LoD/1.13c": "0x1374",
        "LoD/1.13d": "0x1858"
      },
      "method": "MNE",
      "index": "MNE:e7313d19d2f1b94221ec63dffd5562f1",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF022E0",
          "rva": "0x22E0",
          "confidence": 0.405,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF022C0",
          "rva": "0x22C0",
          "confidence": 0.328,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_e75ee0306c31": {
      "addresses": {
        "LoD/1.11": "0x6FF37342",
        "LoD/1.11b": "0x6FF37312",
        "LoD/1.12a": "0x6FF381C2",
        "LoD/1.13c": "0x6FF381A2",
        "LoD/1.13d": "0x6FF380E2"
      },
      "rvas": {
        "LoD/1.11": "0x17342",
        "LoD/1.11b": "0x17312",
        "LoD/1.12a": "0x181C2",
        "LoD/1.13c": "0x181A2",
        "LoD/1.13d": "0x180E2"
      },
      "name": "___InternalCxxFrameHandler",
      "signature": "undefined4 ___InternalCxxFrameHandler(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4, _s_FuncInfo * param_5, int param_6, EHRegistrationNode * param_7, uchar param_8)",
      "comment": "Library Function - Single Match\n ___InternalCxxFrameHandler\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e75ee0306c31bdd597d86ebd787537ac"
    },
    "Bnclient_MNE_e7b052927c73": {
      "addresses": {
        "LoD/1.07": "0x6FF31796",
        "LoD/1.08": "0x6FF317B6",
        "LoD/1.09": "0x6FF123D6",
        "LoD/1.09b": "0x6FF123D6",
        "LoD/1.09d": "0x6FF126C6",
        "LoD/1.10": "0x6FF12C16"
      },
      "rvas": {
        "LoD/1.07": "0x11796",
        "LoD/1.08": "0x117B6",
        "LoD/1.09": "0x123D6",
        "LoD/1.09b": "0x123D6",
        "LoD/1.09d": "0x126C6",
        "LoD/1.10": "0x12C16"
      },
      "name": "ProcessLockContextEntities",
      "signature": "int ProcessLockContextEntities(int nProcessMode)",
      "comment": "Iterates through lock context table and processes entities based on validation mode\n\nAlgorithm:\n1. Acquire global critical section (index 2) for thread-safe access\n2. Initialize loop counters and result variables to zero\n3. Iterate through all entries in global lock context table (g_ppLockContextTable)\n4. For each valid lock context entry, check if entity flags contain active bits (0x83)\n5. Acquire conditional critical section for the specific lock context\n6. Re-verify entity flags after acquiring lock (double-checked locking pattern)\n7. Process entity based on mode parameter:\n   - Mode 1 (Count Mode): Count successful validations, increment success counter\n   - Mode 0 (Fail-Fast Mode): Return error (-1) on first validation failure if bit 0x02 set\n8. Release conditional critical section for the lock context\n9. Continue to next lock context entry until all processed\n10. Release global critical section (index 2)\n11. Return appropriate result based on processing mode\n\nParameters:\nnProcessMode (int): Processing mode selector\n  - 0 = Fail-fast validation mode (returns -1 on first failure)\n  - 1 = Count mode (returns count of successful validations)\n\nReturns:\nMode 0: Returns 0 on success, -1 if any entity with flag 0x02 fails validation\nMode 1: Returns count of successfully validated entities (>= 0)\n\nSpecial Cases:\n- Empty lock context table (g_nLockContextCount <= 0): Returns 0\n- NULL lock context entries are skipped silently\n- Entities without active flags (0x83) are skipped\n- Mode 0 only processes entities with flag 0x02 set\n\nFlag Bits Reference:\n0x01 - Entity active/allocated flag\n0x02 - Entity requires validation flag (mode 0 processing)\n0x80 - Entity processing ready flag\n0x83 - Combined active flags mask (0x01 | 0x02 | 0x80)\n\nMagic Numbers Reference:\n0x83 (131) - Active entity flags mask for initial check\n0x02 (2) - Validation required flag for mode 0 processing\n2 - Global critical section index for lock context table access\n-1 - Validation failure/error return code\n\nError Handling:\n- ValidateAndProcessEntity() returns -1 on validation failure\n- Mode 0: First validation failure terminates processing with -1 result\n- Mode 1: Validation failures are ignored, only successful validations counted\n- Critical sections ensure thread-safe access to shared lock context table\n\nStructure Layout:\nLockContext structure (accessed at offset 0x0C for flags):\nOffset | Size | Field Name | Type | Description\n0x00   | ?    | data       | ?    | Context data array\n0x0C   | 4    | flags      | uint | Entity status and control flags",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e7b052927c73f8415c227814d8219b82"
    },
    "Bnclient_MNE_e83bd76a96c5": {
      "addresses": {
        "LoD/1.11": "0x6FF37788",
        "LoD/1.11b": "0x6FF37758",
        "LoD/1.12a": "0x6FF38608",
        "LoD/1.13c": "0x6FF385E8",
        "LoD/1.13d": "0x6FF38528"
      },
      "rvas": {
        "LoD/1.11": "0x17788",
        "LoD/1.11b": "0x17758",
        "LoD/1.12a": "0x18608",
        "LoD/1.13c": "0x185E8",
        "LoD/1.13d": "0x18528"
      },
      "name": "Unwind@6ff37760",
      "signature": "undefined Unwind@6ff37760(void)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e83bd76a96c575481d28f5927cfaf30f",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF05050",
          "rva": "0x5050",
          "confidence": 0.405,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF050C0",
          "rva": "0x50C0",
          "confidence": 0.328,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF04E40",
          "rva": "0x4E40",
          "confidence": 0.215,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_e83d10405144": {
      "addresses": {
        "LoD/1.07": "0x6FF2C45F",
        "LoD/1.08": "0x6FF2C2F3",
        "LoD/1.09": "0x6FF0CEF3",
        "LoD/1.09b": "0x6FF0CEF3",
        "LoD/1.09d": "0x6FF0D38F",
        "LoD/1.10": "0x6FF0D8F5",
        "LoD/1.11": "0x6FF23E2D",
        "LoD/1.11b": "0x6FF22FB6",
        "LoD/1.12a": "0x6FF22315",
        "LoD/1.13c": "0x6FF230AE",
        "LoD/1.13d": "0x6FF232F6"
      },
      "rvas": {
        "LoD/1.07": "0xC45F",
        "LoD/1.08": "0xC2F3",
        "LoD/1.09": "0xCEF3",
        "LoD/1.09b": "0xCEF3",
        "LoD/1.09d": "0xD38F",
        "LoD/1.10": "0xD8F5",
        "LoD/1.11": "0x3E2D",
        "LoD/1.11b": "0x2FB6",
        "LoD/1.12a": "0x2315",
        "LoD/1.13c": "0x30AE",
        "LoD/1.13d": "0x32F6"
      },
      "name": "ReleaseCriticalSectionByIndex",
      "signature": "void ReleaseCriticalSectionByIndex(int nCriticalSectionIndex)",
      "comment": "Releases a Windows critical section by array index from global critical section table.\n\nAlgorithm:\n1. Validate nCriticalSectionIndex parameter (implicit bounds check by caller)\n2. Index into g_ppCriticalSections array using parameter as offset\n3. Call Windows LeaveCriticalSection API on indexed critical section pointer\n4. Return to caller\n\nParameters:\nnCriticalSectionIndex (int) - Zero-based index into g_ppCriticalSections array\n\nReturns:\nvoid - No return value, function cannot fail\n\nSpecial Cases:\n- Index bounds validation must be performed by caller\n- Critical section must have been previously acquired via EnterCriticalSection\n- Undefined behavior if index exceeds array bounds or points to uninitialized critical section\n\nError Handling:\n- No error checking performed - relies on Windows API for critical section validity\n- Invalid index causes access violation at call site",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e83d104051445238b4510431aa98563d"
    },
    "Bnclient_MNE_e86a21cb50bb": {
      "addresses": {
        "LoD/1.11": "0x6FF36B3A",
        "LoD/1.11b": "0x6FF36B0A",
        "LoD/1.12a": "0x6FF379BA",
        "LoD/1.13c": "0x6FF3799A",
        "LoD/1.13d": "0x6FF378DA"
      },
      "rvas": {
        "LoD/1.11": "0x16B3A",
        "LoD/1.11b": "0x16B0A",
        "LoD/1.12a": "0x179BA",
        "LoD/1.13c": "0x1799A",
        "LoD/1.13d": "0x178DA"
      },
      "name": "TypeMatch",
      "signature": "int TypeMatch(_s_HandlerType * param_1, _s_CatchableType * param_2, _s_ThrowInfo * param_3)",
      "comment": "Library Function - Single Match\n int __cdecl TypeMatch(struct _s_HandlerType const *,struct _s_CatchableType const *,struct _s_ThrowInfo const *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e86a21cb50bb81e60f0de3031d840cd4"
    },
    "Bnclient_MNE_e8d820fe0ad4": {
      "addresses": {
        "LoD/1.08": "0x6FF2B780",
        "LoD/1.09": "0x6FF0C380",
        "LoD/1.09b": "0x6FF0C380",
        "LoD/1.09d": "0x6FF0C5B0",
        "LoD/1.10": "0x6FF0CB10"
      },
      "rvas": {
        "LoD/1.08": "0xB780",
        "LoD/1.09": "0xC380",
        "LoD/1.09b": "0xC380",
        "LoD/1.09d": "0xC5B0",
        "LoD/1.10": "0xCB10"
      },
      "name": "_strchr",
      "signature": "char * _strchr(char * _Str, int _Val)",
      "comment": "Library Function - Single Match\n _strchr\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:e8d820fe0ad4443eff596f9c063b1159"
    },
    "Bnclient_MNE_e91f70009ea5": {
      "addresses": {
        "LoD/1.07": "0x6FF31B88",
        "LoD/1.08": "0x6FF31BA8",
        "LoD/1.09": "0x6FF127C8",
        "LoD/1.09b": "0x6FF127C8",
        "LoD/1.09d": "0x6FF12AB8",
        "LoD/1.10": "0x6FF1303C"
      },
      "rvas": {
        "LoD/1.07": "0x11B88",
        "LoD/1.08": "0x11BA8",
        "LoD/1.09": "0x127C8",
        "LoD/1.09b": "0x127C8",
        "LoD/1.09d": "0x12AB8",
        "LoD/1.10": "0x1303C"
      },
      "name": "CompareMultiByteStringsLocaleSupport",
      "signature": "int CompareMultiByteStringsLocaleSupport(int nLocale, int nCmpFlags, char * lpszString1, int nCount1, char * lpszString2, int nCount2, int nCodePage)",
      "comment": "Compares two multibyte character strings with locale-specific collation support.\n\nAlgorithm:\n1. Initialize SEH (Structured Exception Handling) frame for safe stack operations\n2. Check g_nStringComparisonMode initialization status (0=uninitialized, 1=Unicode, 2=ANSI)\n3. If uninitialized, test system capabilities with CompareStringW and CompareStringA\n4. Set mode to 1 (Unicode) if CompareStringW works, 2 (ANSI) if only CompareStringA works\n5. Validate string lengths using StringLengthWithLimit for both input strings\n6. If mode=2 (ANSI only), call CompareStringA directly and return result\n7. If mode=1 (Unicode capable), use default code page if nCodePage is 0\n8. Handle empty string cases (return 2 if both empty, ordering for mixed)\n9. For single-character strings, check DBCS lead byte ranges using GetCPInfo\n10. Convert both strings to Unicode using MultiByteToWideChar with dynamic stack allocation\n11. Compare converted Unicode strings using CompareStringW with locale rules\n12. Restore SEH frame and return comparison result\n\nParameters:\nnLocale - Locale identifier for comparison rules and cultural sorting\nnCmpFlags - Comparison flags controlling case sensitivity and other options\nlpszString1 - Pointer to first multibyte string to compare\nnCount1 - Character count of first string (-1 for null-terminated)\nlpszString2 - Pointer to second multibyte string to compare  \nnCount2 - Character count of second string (-1 for null-terminated)\nnCodePage - Code page for multibyte conversion (0 = use system default)\n\nReturns:\n0 - Error occurred during comparison or conversion failed\n1 - First string is lexicographically less than second string\n2 - Strings are equal according to locale-specific rules\n3 - First string is lexicographically greater than second string",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e91f70009ea5ba58893f9b11fbf44c43"
    },
    "Bnclient_MNE_e9b79e59a5bc": {
      "addresses": {
        "LoD/1.11": "0x6FF33C10",
        "LoD/1.11b": "0x6FF2EAE0",
        "LoD/1.12a": "0x6FF2EF70",
        "LoD/1.13c": "0x6FF34FA0",
        "LoD/1.13d": "0x6FF36780"
      },
      "rvas": {
        "LoD/1.11": "0x13C10",
        "LoD/1.11b": "0xEAE0",
        "LoD/1.12a": "0xEF70",
        "LoD/1.13c": "0x14FA0",
        "LoD/1.13d": "0x16780"
      },
      "name": "DNS",
      "signature": "char * DNS(int param_1)",
      "comment": "public: char * __stdcall BNGatewayAccess::DNS(int)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e9b79e59a5bc8221fd5fa43647d8e1a6"
    },
    "Bnclient_MNE_e9b7e334c31a": {
      "addresses": {
        "LoD/1.07": "0x6FF318C0",
        "LoD/1.08": "0x6FF318E0",
        "LoD/1.09": "0x6FF12500",
        "LoD/1.09b": "0x6FF12500",
        "LoD/1.09d": "0x6FF127F0",
        "LoD/1.11": "0x6FF23EE2",
        "LoD/1.11b": "0x6FF2306B",
        "LoD/1.12a": "0x6FF223CA",
        "LoD/1.13c": "0x6FF23163",
        "LoD/1.13d": "0x6FF233AB"
      },
      "rvas": {
        "LoD/1.07": "0x118C0",
        "LoD/1.08": "0x118E0",
        "LoD/1.09": "0x12500",
        "LoD/1.09b": "0x12500",
        "LoD/1.09d": "0x127F0",
        "LoD/1.11": "0x3EE2",
        "LoD/1.11b": "0x306B",
        "LoD/1.12a": "0x23CA",
        "LoD/1.13c": "0x3163",
        "LoD/1.13d": "0x33AB"
      },
      "name": "ThreadSafeFileClose",
      "signature": "dword ThreadSafeFileClose(FILE * pFile)",
      "comment": "Thread-safe file close with critical section protection and flag management.\n\nAlgorithm:\n1. Initialize return value to 0xffffffff (failure/invalid handle code)\n2. Check if FILE._flag has 0x40 bit set (close-in-progress or error flag)\n3. If flag 0x40 is clear: perform thread-safe close operation\n   a. Acquire critical section lock for file pointer address\n   b. Call __fclose_lk to perform actual close operation\n   c. Store close result in dwResult\n   d. Release critical section lock for file pointer address\n4. If flag 0x40 is set: clear all flags to reset file state\n5. Return close operation result or 0xffffffff\n\nParameters:\npFile (FILE*): Pointer to file stream to close. Must not be NULL.\n\nReturns:\n0 on successful close, -1 (0xffffffff) on error or if close was already in progress.\nReturns 0xffffffff immediately if file has close-in-progress flag set.\n\nSpecial Cases:\nMagic number 0x40: FILE._flag bit indicating close-in-progress or error state\nMagic number 0xffffffff: Standard error return value for file operations\n\nFlag Bits:\nFILE._flag & 0x40: Close-in-progress or error state flag\n  0x40 set: File close already initiated or in error state\n  0x40 clear: File available for normal close operation",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e9b7e334c31a0ed876fb0ca3fc54ed48"
    },
    "Bnclient_MNE_ea19d8e7fec2": {
      "addresses": {
        "LoD/1.11": "0x6FF32CA0",
        "LoD/1.11b": "0x6FF2F910",
        "LoD/1.12a": "0x6FF35310",
        "LoD/1.13c": "0x6FF30D90",
        "LoD/1.13d": "0x6FF2C370"
      },
      "rvas": {
        "LoD/1.11": "0x12CA0",
        "LoD/1.11b": "0xF910",
        "LoD/1.12a": "0x15310",
        "LoD/1.13c": "0x10D90",
        "LoD/1.13d": "0xC370"
      },
      "method": "MNE",
      "index": "MNE:ea19d8e7fec28c7a678a46a5c84239d1"
    },
    "Bnclient_MNE_ea32b2bea659": {
      "addresses": {
        "LoD/1.10": "0x6FF13CC0"
      },
      "rvas": {
        "LoD/1.10": "0x13CC0"
      },
      "method": "MNE",
      "index": "MNE:ea32b2bea659c127eea399072d552154",
      "candidates": {
        "LoD/1.09d": {
          "address": "0x6FF06A40",
          "rva": "0x6A40",
          "confidence": 0.405,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_eb17d7abe573": {
      "addresses": {
        "LoD/1.07": "0x6FF2B2CD",
        "LoD/1.08": "0x6FF2B212",
        "LoD/1.09": "0x6FF0BE12",
        "LoD/1.09b": "0x6FF0BE12",
        "LoD/1.09d": "0x6FF0C14D",
        "LoD/1.10": "0x6FF0C6AD"
      },
      "rvas": {
        "LoD/1.07": "0xB2CD",
        "LoD/1.08": "0xB212",
        "LoD/1.09": "0xBE12",
        "LoD/1.09b": "0xBE12",
        "LoD/1.09d": "0xC14D",
        "LoD/1.10": "0xC6AD"
      },
      "name": "ProcessCleanupAndExit",
      "signature": "void ProcessCleanupAndExit(uint dwExitCode, int nQuickExit, int nTerminateFlag)",
      "comment": "Handles DLL/process cleanup operations with selective termination modes.\n\nAlgorithm:\n1. Call setup function FUN_6ff2b372() to initialize cleanup state\n2. Check global termination flag g_dwTerminationActiveFlag - if set to 1, terminate immediately with TerminateProcess\n3. Set global cleanup flag g_dwCleanupFlag = 1 to signal cleanup is active  \n4. Store terminate flag as byte in g_bTerminateFlagStore for later reference\n5. If nQuickExit == 0 (full cleanup mode):\n   - Process dynamic function pointer buffer from g_pbDynamicBufferEnd to g_pbDynamicBufferStart\n   - Call each non-null function pointer in reverse order (typical destructor pattern)\n   - Call static cleanup function pointer arrays from g_ppStaticCleanupArrayStart to g_ppStaticCleanupArrayEnd\n6. Always call final cleanup function pointer arrays from g_ppFinalCleanupArrayStart to g_ppFinalCleanupArrayEnd\n7. If nTerminateFlag == 0: set g_dwTerminationActiveFlag = 1 and call ExitProcess (no return)\n8. Otherwise: call FUN_6ff2b37b() final cleanup and return to caller\n\nParameters:\ndwExitCode (uint): Exit code passed to ExitProcess/TerminateProcess (0-255)\nnQuickExit (int): Cleanup mode flag - 0 = full cleanup with dynamic destructors, non-zero = skip dynamic cleanup\nnTerminateFlag (int): Termination mode - 0 = ExitProcess (no return), non-zero = return to caller\n\nReturns:\nvoid: No return value when nTerminateFlag == 0 (calls ExitProcess)\n      Returns normally when nTerminateFlag != 0 after cleanup\n\nSpecial Cases:\n- If g_dwTerminationActiveFlag already set to 1: bypasses all cleanup, calls TerminateProcess immediately\n- If g_pbDynamicBufferStart is null: skips dynamic buffer processing safely\n- If dynamic buffer traversal reaches invalid range: stops gracefully at g_pbDynamicBufferStart boundary\n- Function pointer arrays are called via CallFunctionPointerArray which handles null ranges safely\n\nMagic Numbers:\n0x1 - Cleanup active flag value stored in g_dwCleanupFlag and g_dwTerminationActiveFlag\n0x4 - Pointer size decrement for buffer traversal (32-bit function pointers)\n\nError Handling:\n- Uses TerminateProcess for immediate shutdown when termination flag pre-set\n- Uses ExitProcess for normal process termination after cleanup\n- Function pointer null checks prevent crashes during dynamic cleanup traversal\n- Buffer boundary checks prevent memory access violations during traversal",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:eb17d7abe573793d4b67d9aac794697b"
    },
    "Bnclient_MNE_eb7ebe8853ab": {
      "addresses": {
        "LoD/1.07": "0x6FF318F1",
        "LoD/1.08": "0x6FF31911",
        "LoD/1.09": "0x6FF12531",
        "LoD/1.09b": "0x6FF12531",
        "LoD/1.09d": "0x6FF12821",
        "LoD/1.11": "0x6FF2EF50",
        "LoD/1.11b": "0x6FF357E0",
        "LoD/1.12a": "0x6FF31810",
        "LoD/1.13c": "0x6FF358F0",
        "LoD/1.13d": "0x6FF35350"
      },
      "rvas": {
        "LoD/1.07": "0x118F1",
        "LoD/1.08": "0x11911",
        "LoD/1.09": "0x12531",
        "LoD/1.09b": "0x12531",
        "LoD/1.09d": "0x12821",
        "LoD/1.11": "0xEF50",
        "LoD/1.11b": "0x157E0",
        "LoD/1.12a": "0x11810",
        "LoD/1.13c": "0x158F0",
        "LoD/1.13d": "0x15350"
      },
      "name": "__fclose_lk",
      "signature": "int __fclose_lk(FILE * pFile)",
      "comment": "Standard C Runtime library function - closes a file stream with thread-safe locking.\nLibrary Function: Visual Studio 2003 Release (__fclose_lk maintains standard naming)\n\nAlgorithm:\n1. Initialize return value to -1 (error state)\n2. Check if file stream is valid by testing flags (0x83 = readable|writable|opened)\n3. If valid stream:\n   a. Flush any pending output data to underlying file\n   b. Free internal stream buffers using __freebuf\n   c. Close underlying file descriptor via FUN_6ff31a7d\n   d. If close fails, set return value to -1\n   e. If temporary filename exists, deallocate it and clear pointer\n4. Clear all file stream flags to mark as closed\n5. Return result code (0 = success, -1 = error)\n\nParameters:\npFile - Pointer to FILE structure representing the stream to close\n\nReturns:\n0 on successful closure of all resources\n-1 if any cleanup operation fails (flush, buffer free, or file descriptor close)\n\nSpecial Cases:\nIf FILE._flag & 0x83 == 0, stream is already closed - skip cleanup, only clear flags\nIf FILE._tmpfname is NULL, no temporary file to deallocate\nFunction always clears _flag to 0 regardless of cleanup success/failure\n\nMagic Numbers Reference:\n0x83 (131) - FILE flag mask for stream validity (readable|writable|opened bits)\n0x0C (12)  - Offset to FILE._flag field in FILE structure  \n0x10 (16)  - Offset to FILE._file field (underlying file descriptor)\n0x1C (28)  - Offset to FILE._tmpfname field (temporary filename pointer)\n\nError Handling:\nFlushOutputBuffer failure: Continues with cleanup, final result depends on file close\nFUN_6ff31a7d (file close) failure: Sets nResult to -1, continues with temp file cleanup\nDeallocateMemory failure: Not checked, assumes successful deallocation",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:eb7ebe8853ab4246d611f1ee5af2c48e"
    },
    "Bnclient_MNE_ec2f8cff08d7": {
      "addresses": {
        "LoD/1.11": "0x6FF262C7",
        "LoD/1.11b": "0x6FF24F3B",
        "LoD/1.12a": "0x6FF2714A",
        "LoD/1.13c": "0x6FF2612B",
        "LoD/1.13d": "0x6FF24FAB"
      },
      "rvas": {
        "LoD/1.11": "0x62C7",
        "LoD/1.11b": "0x4F3B",
        "LoD/1.12a": "0x714A",
        "LoD/1.13c": "0x612B",
        "LoD/1.13d": "0x4FAB"
      },
      "name": "___wctomb_mt",
      "signature": "int ___wctomb_mt(int param_1, LPSTR param_2, WCHAR param_3)",
      "comment": "Library Function - Single Match\n ___wctomb_mt\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:ec2f8cff08d73195854c9319296e0953"
    },
    "Bnclient_MNE_ec875c7a7ee6": {
      "addresses": {
        "LoD/1.11": "0x6FF30EE0",
        "LoD/1.11b": "0x6FF31550",
        "LoD/1.12a": "0x6FF2FFD0",
        "LoD/1.13c": "0x6FF33190",
        "LoD/1.13d": "0x6FF2F150"
      },
      "rvas": {
        "LoD/1.11": "0x10EE0",
        "LoD/1.11b": "0x11550",
        "LoD/1.12a": "0xFFD0",
        "LoD/1.13c": "0x13190",
        "LoD/1.13d": "0xF150"
      },
      "method": "MNE",
      "index": "MNE:ec875c7a7ee60978006d7a18f3b99fbf"
    },
    "Bnclient_MNE_ec98f5fe3d3a": {
      "addresses": {
        "LoD/1.12a": "0x6FF373C0",
        "LoD/1.13c": "0x6FF34930",
        "LoD/1.13d": "0x6FF34380"
      },
      "rvas": {
        "LoD/1.12a": "0x173C0",
        "LoD/1.13c": "0x14930",
        "LoD/1.13d": "0x14380"
      },
      "method": "MNE",
      "index": "MNE:ec98f5fe3d3a4daf18b47da94483c37e"
    },
    "Bnclient_MNE_ecf4fe5a7e47": {
      "addresses": {
        "LoD/1.11": "0x6FF23610",
        "LoD/1.11b": "0x6FF23D40",
        "LoD/1.12a": "0x6FF23C90",
        "LoD/1.13c": "0x6FF235A0",
        "LoD/1.13d": "0x6FF22C20"
      },
      "rvas": {
        "LoD/1.11": "0x3610",
        "LoD/1.11b": "0x3D40",
        "LoD/1.12a": "0x3C90",
        "LoD/1.13c": "0x35A0",
        "LoD/1.13d": "0x2C20"
      },
      "name": "___ascii_strnicmp",
      "signature": "int ___ascii_strnicmp(char * _Str1, char * _Str2, size_t _MaxCount)",
      "comment": "Library Function - Single Match\n ___ascii_strnicmp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:ecf4fe5a7e473ceb70f30e35ac316045"
    },
    "Bnclient_MNE_ed17ad9d511f": {
      "addresses": {
        "LoD/1.07": "0x6FF2CF3A",
        "LoD/1.08": "0x6FF2CF5A",
        "LoD/1.09": "0x6FF0DB5A",
        "LoD/1.09b": "0x6FF0DB5A",
        "LoD/1.09d": "0x6FF0DE6A",
        "LoD/1.10": "0x6FF0E3D2",
        "LoD/1.11": "0x6FF25866",
        "LoD/1.11b": "0x6FF256BA",
        "LoD/1.12a": "0x6FF24B22",
        "LoD/1.13c": "0x6FF25906",
        "LoD/1.13d": "0x6FF25C66"
      },
      "rvas": {
        "LoD/1.07": "0xCF3A",
        "LoD/1.08": "0xCF5A",
        "LoD/1.09": "0xDB5A",
        "LoD/1.09b": "0xDB5A",
        "LoD/1.09d": "0xDE6A",
        "LoD/1.10": "0xE3D2",
        "LoD/1.11": "0x5866",
        "LoD/1.11b": "0x56BA",
        "LoD/1.12a": "0x4B22",
        "LoD/1.13c": "0x5906",
        "LoD/1.13d": "0x5C66"
      },
      "name": "SaveExceptionContext",
      "signature": "void SaveExceptionContext(void)",
      "comment": "Saves current execution context state to global exception context structure.\n\nAlgorithm:\n1. Save EBX and ECX registers to stack\n2. Load base address of global exception context (0x6ff36990) into EBX\n3. Store stack parameter [EBP + 0x8] to offset 0x8 (dwStackParameter field)\n4. Store EAX register value to offset 0x4 (dwEaxRegister field) \n5. Store EBP frame pointer to offset 0xc (dwEbpRegister field)\n6. Restore EBX and ECX registers from stack\n7. Return to caller with 4-byte stack cleanup\n\nParameters:\nIMPLICIT EAX: dwEaxValue - EAX register value to save in context\nIMPLICIT EBP: Frame pointer register value to save in context\nIMPLICIT [EBP + 0x8]: dwStackParam - Stack parameter passed by caller\n\nReturns:\nvoid - Function only saves state, no return value\n\nStructure Layout:\nOffset | Size | Field Name        | Type | Description\n-------|------|-------------------|------|------------------\n0x0    | 4    | dwPadding         | uint | Reserved/padding field\n0x4    | 4    | dwEaxRegister     | uint | Saved EAX register value\n0x8    | 4    | dwStackParameter  | uint | Saved stack parameter\n0xc    | 4    | dwEbpRegister     | uint | Saved EBP frame pointer\n\nSpecial Cases:\nThis function is likely used as an exception handler registration helper,\nsaving the caller's execution state before setting up exception handling.\nThe __stdcall convention with RET 4 indicates one implicit stack parameter.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ed17ad9d511f6e330c2b6a62378d83cf"
    },
    "Bnclient_MNE_ee22dcb18299": {
      "addresses": {
        "LoD/1.07": "0x6FF2E152",
        "LoD/1.08": "0x6FF2E172",
        "LoD/1.09": "0x6FF0ED9D",
        "LoD/1.09b": "0x6FF0ED9D",
        "LoD/1.09d": "0x6FF0F082",
        "LoD/1.10": "0x6FF0F670"
      },
      "rvas": {
        "LoD/1.07": "0xE152",
        "LoD/1.08": "0xE172",
        "LoD/1.09": "0xED9D",
        "LoD/1.09b": "0xED9D",
        "LoD/1.09d": "0xF082",
        "LoD/1.10": "0xF670"
      },
      "name": "ConvertEnvironmentStringsToAnsi",
      "signature": "LPSTR ConvertEnvironmentStringsToAnsi(void)",
      "comment": "Converts environment strings from the optimal available format to ANSI format.\n\nAlgorithm:\n1. Check global environment format flag (g_dwEnvironmentStringFormat) for initialization state\n2. If uninitialized (0), attempt to get Unicode environment strings with GetEnvironmentStringsW()\n3. If Unicode available, set format flag to 1 (Unicode) and proceed to Unicode conversion\n4. If Unicode unavailable, get ANSI environment strings with GetEnvironmentStrings() and set flag to 2\n5. If already initialized with format 1, use Unicode conversion path\n6. If already initialized with format 2, use ANSI direct copy path  \n7. For Unicode conversion: iterate through wide environment block to calculate total character count\n8. Convert size from wide characters to required ANSI buffer size using WideCharToMultiByte()\n9. Allocate buffer of required size using _malloc()\n10. Convert Unicode environment strings to ANSI using WideCharToMultiByte()\n11. If conversion fails, deallocate buffer and return NULL\n12. Free Unicode environment strings with FreeEnvironmentStringsW()\n13. For ANSI direct copy: iterate through ANSI environment block to calculate total size\n14. Allocate buffer and copy environment strings using FUN_6ff2fa10()\n15. Free ANSI environment strings with FreeEnvironmentStringsA()\n16. Return allocated ANSI environment string buffer\n\nParameters:\n  None\n\nReturns:\n  LPSTR - Pointer to allocated ANSI environment string block on success\n  NULL - On failure (no environment strings, allocation failure, or conversion failure)\n\nSpecial Cases:\n  - First call determines format preference based on Unicode availability\n  - Subsequent calls use cached format preference for consistency\n  - Function handles both Unicode-to-ANSI conversion and direct ANSI copy\n  - Environment block format: series of null-terminated strings followed by additional null\n\nMagic Numbers Reference:\n  0 (0x0) - Uninitialized format flag\n  1 (0x1) - Unicode format available  \n  2 (0x2) - ANSI format only\n  \nGlobal Variables:\n  g_dwEnvironmentStringFormat - Environment string format cache (0=uninitialized, 1=Unicode, 2=ANSI)\n\nError Handling:\n  - Returns NULL if environment strings unavailable from system\n  - Returns NULL if memory allocation fails\n  - Returns NULL if Unicode to ANSI conversion fails\n  - Automatically cleans up allocated memory on conversion failure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ee22dcb18299b51eb994a57f32a5df1d"
    },
    "Bnclient_MNE_ee4facdaccbd": {
      "addresses": {
        "LoD/1.07": "0x6FF2F9E7",
        "LoD/1.08": "0x6FF2FA07",
        "LoD/1.09": "0x6FF10632",
        "LoD/1.09b": "0x6FF10632",
        "LoD/1.09d": "0x6FF10917",
        "LoD/1.10": "0x6FF10F05",
        "LoD/1.11": "0x6FF27131",
        "LoD/1.11b": "0x6FF258FB",
        "LoD/1.12a": "0x6FF24D63",
        "LoD/1.13c": "0x6FF249AE",
        "LoD/1.13d": "0x6FF26424"
      },
      "rvas": {
        "LoD/1.07": "0xF9E7",
        "LoD/1.08": "0xFA07",
        "LoD/1.09": "0x10632",
        "LoD/1.09b": "0x10632",
        "LoD/1.09d": "0x10917",
        "LoD/1.10": "0x10F05",
        "LoD/1.11": "0x7131",
        "LoD/1.11b": "0x58FB",
        "LoD/1.12a": "0x4D63",
        "LoD/1.13c": "0x49AE",
        "LoD/1.13d": "0x6424"
      },
      "name": "InvokeCallbackHandler",
      "signature": "bool InvokeCallbackHandler(uint dwParameter)",
      "comment": "Invokes registered callback handler if one is available\n\nAlgorithm:\n1. Check if global callback function pointer is not NULL\n2. If callback exists, invoke it with provided parameter\n3. Check callback return value for success/failure\n4. Return true if callback executed successfully, false otherwise\n\nParameters:\ndwParameter - uint input parameter to pass to the callback function\n\nReturns:\nbool - true if callback exists and returned non-zero (success)\nbool - false if no callback registered or callback returned zero (failure)\n\nSpecial Cases:\n- Returns false immediately if no callback handler is registered\n- Callback success is determined by non-zero return value",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ee4facdaccbd6fc5f3297fd5b85b73c2"
    },
    "Bnclient_MNE_ee9031ded8e3": {
      "addresses": {
        "LoD/1.07": "0x6FF22240",
        "LoD/1.08": "0x6FF22260",
        "LoD/1.09": "0x6FF02320",
        "LoD/1.09b": "0x6FF02320",
        "LoD/1.09d": "0x6FF022F0",
        "LoD/1.10": "0x6FF02310"
      },
      "rvas": {
        "LoD/1.07": "0x2240",
        "LoD/1.08": "0x2260",
        "LoD/1.09": "0x2320",
        "LoD/1.09b": "0x2320",
        "LoD/1.09d": "0x22F0",
        "LoD/1.10": "0x2310"
      },
      "name": "InitializeSystemBuffers",
      "signature": "uint InitializeSystemBuffers(void)",
      "comment": "Initializes system data buffers and configuration state.\n\nAlgorithm:\n1. Zero-fill system buffer A (67 uint32 values at g_adSystemBufferA)\n2. Zero-fill system buffer B (67 uint32 values at g_adSystemBufferB) \n3. Set system configuration byte to 0xFF (g_bySystemConfig = 0xFF)\n4. Clear system state variable (g_dwSystemState = 0)\n5. Call initialization subroutine FUN_6ff25a60(0)\n6. Return success status (1)\n\nParameters:\nNone\n\nReturns:\n1 - Always returns success\n\nSpecial Cases:\nBoth data buffers are exactly 67 uint32 elements (268 bytes each)\nConfiguration value 0xFF may indicate maximum/enabled state\nZero parameter passed to subroutine suggests default initialization mode\n\nMagic Numbers Reference:\n0x43 (67) - Size of each system buffer in uint32 elements  \n0xFF (255) - System configuration value, likely max/enabled state\n0x1 (1) - Success return code",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ee9031ded8e342ae4d25f0fe0f3a52b9"
    },
    "Bnclient_MNE_eef5ae1e6954": {
      "addresses": {
        "LoD/1.07": "0x6FF2C818",
        "LoD/1.08": "0x6FF2C838",
        "LoD/1.09": "0x6FF0D438",
        "LoD/1.09b": "0x6FF0D438",
        "LoD/1.09d": "0x6FF0D748",
        "LoD/1.10": "0x6FF0DCAE"
      },
      "rvas": {
        "LoD/1.07": "0xC818",
        "LoD/1.08": "0xC838",
        "LoD/1.09": "0xD438",
        "LoD/1.09b": "0xD438",
        "LoD/1.09d": "0xD748",
        "LoD/1.10": "0xDCAE"
      },
      "name": "GetAllocationSize",
      "signature": "SIZE_T GetAllocationSize(void * pAllocation)",
      "comment": "Retrieves the size of a memory allocation using the appropriate allocation strategy.\n\nAlgorithm:\n1. Initialize SEH exception frame with DAT_6ff333a0 handler and LAB_6ff2cf5c continuation\n2. Check global allocation strategy (g_dwAllocationStrategy)\n3. If strategy == 3 (Custom allocation):\n   a. Acquire critical section lock (index 9)\n   b. Call FUN_6ff2e81b() to get allocation metadata pointer\n   c. If metadata found, read size from allocation header at offset -4, subtract 9\n   d. Store result in dwSize\n   e. Release critical section via FUN_6ff2c882()\n   f. Return calculated size if allocation metadata was valid\n4. If strategy == 2 (Block allocation):\n   a. Acquire critical section lock (index 9)  \n   b. Call FUN_6ff2f576() to get block pointer with type and flags output\n   c. If block found, calculate size as first byte value shifted left 4 bits\n   d. Store result in dwSize\n   e. Release critical section via FUN_6ff2c8fd()\n   f. Return calculated size if block pointer was valid\n5. If strategy != 2 and != 3, or allocation lookup failed:\n   a. Fall back to HeapSize() API call with g_hHeapHandle\n   b. Return heap-reported allocation size\n\nParameters:\npAllocation (void*) - Pointer to the allocated memory block to query\n\nReturns:\nSIZE_T - Size of the allocation in bytes, or 0 if allocation not found\n\nSpecial Cases:\n- Strategy 3: Reads size from header at pAllocation-4, subtracts 9 bytes overhead\n- Strategy 2: Size encoded as (block[0] << 4) where block[0] is first metadata byte\n- Other strategies or failures: Uses HeapSize() as fallback mechanism\n\nMagic Numbers Reference:\n0x3 (3) - Custom allocation strategy using metadata headers\n0x2 (2) - Block allocation strategy using encoded size metadata  \n0x9 (9) - Critical section index for allocation operations\n0x9 (9) - Header overhead bytes subtracted from strategy 3 allocations\n0x4 (4) - Left shift count (multiply by 16) for strategy 2 size calculation\n\nError Handling:\n- Invalid allocation pointers return 0 via HeapSize() fallback\n- Failed metadata lookups return 0 via HeapSize() fallback\n- Critical sections are properly released via __finally handlers\n- SEH protects against access violations during header reads",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:eef5ae1e69543f2ca247fd0a568bf7f0"
    },
    "Bnclient_MNE_ef01624ba1fd": {
      "addresses": {
        "LoD/1.11": "0x6FF21180",
        "LoD/1.11b": "0x6FF21130",
        "LoD/1.12a": "0x6FF211E0",
        "LoD/1.13c": "0x6FF21180",
        "LoD/1.13d": "0x6FF21180"
      },
      "rvas": {
        "LoD/1.11": "0x1180",
        "LoD/1.11b": "0x1130",
        "LoD/1.12a": "0x11E0",
        "LoD/1.13c": "0x1180",
        "LoD/1.13d": "0x1180"
      },
      "method": "MNE",
      "index": "MNE:ef01624ba1fdf8f67386976d82d63fb9",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF0E2BF",
          "rva": "0xE2BF",
          "confidence": 0.401,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF0DD59",
          "rva": "0xDD59",
          "confidence": 0.325,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF0DA49",
          "rva": "0xDA49",
          "confidence": 0.213,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_ef5171f8f748": {
      "addresses": {
        "LoD/1.07": "0x6FF2E846",
        "LoD/1.08": "0x6FF2E866",
        "LoD/1.09": "0x6FF0F491",
        "LoD/1.09b": "0x6FF0F491",
        "LoD/1.09d": "0x6FF0F776",
        "LoD/1.10": "0x6FF0FD64"
      },
      "rvas": {
        "LoD/1.07": "0xE846",
        "LoD/1.08": "0xE866",
        "LoD/1.09": "0xF491",
        "LoD/1.09b": "0xF491",
        "LoD/1.09d": "0xF776",
        "LoD/1.10": "0xFD64"
      },
      "name": "DeallocateMemoryBlock",
      "signature": "void DeallocateMemoryBlock(MemoryPool * pMemoryPool, int nBlockAddress)",
      "comment": "Deallocates memory block and updates free list structures and allocation bitmaps.\n\nAlgorithm:\n1. Extract bitmap base address from pMemoryPool[4] and calculate pool index from block address\n2. Get free list header pointer using pool index * 0x204 + 0x144 offset calculation\n3. Read block header from (nBlockAddress - 4) to get current block size information\n4. Validate block is not already free by checking low bit of adjusted size (must be 0)\n5. If current block can be coalesced with next block:\n   a. Calculate size index from block size (>> 4) - 1, clamped to 0x3F maximum\n   b. Check if next block's prev/next pointers are equal (indicates it's in free list)\n   c. Update allocation bitmap by clearing bit and decrementing reference count\n   d. Remove next block from its free list by updating linked list pointers\n6. If current block can be coalesced with previous block:\n   a. Calculate size indices for both current and previous blocks\n   b. If size indices differ, remove previous block from its free list\n   c. Update allocation bitmap for previous block size\n   d. Merge blocks by updating size and pointers\n7. Insert merged block into appropriate free list:\n   a. Link block into free list header for calculated size index\n   b. Update allocation bitmap by setting bit and incrementing reference count\n8. Update block headers with final merged size and create footer with size\n9. Decrement free list header reference count\n10. If reference count reaches zero, deallocate entire pool:\n    a. Call VirtualFree to release 32KB memory region\n    b. Update global allocation tracking structures\n    c. Call HeapFree to release bitmap data structure\n    d. Compact allocation table by removing deallocated entry\n    e. Update global pointers and counters\n\nParameters:\npMemoryPool    - Pointer to MemoryPool structure containing bitmap and offset data\nnBlockAddress  - Memory address of block to deallocate (actual allocated address, not header)\n\nReturns:\nvoid\n\nSpecial Cases:\n- Block already marked as free (low bit set) causes early return with no action\n- Size indices are clamped to maximum value 0x3F for bitmap array bounds\n- Bitmap spans two 32-bit words: bits 0-31 and 32-63, requiring different calculations\n- Pool deallocation only occurs when reference count reaches exactly zero\n\nMagic Numbers Reference:\n0x3F (63)     - Maximum size index for allocation bitmap (64 total size classes)\n0x204 (516)   - Size of each pool's metadata structure in bytes\n0x144 (324)   - Offset to free list headers within pool structure  \n0x44 (68)     - Offset to first bitmap word (bits 0-31) from bitmap base\n0xc4 (196)    - Offset to second bitmap word (bits 32-63) from bitmap base\n0x8000        - Pool size: 32KB per memory pool allocation\n0x4000        - VirtualFree flag: MEM_DECOMMIT for releasing committed memory\n0x8000        - VirtualFree flag: MEM_RELEASE for releasing reserved memory\n0x80000000    - Bit mask base for calculating allocation bitmap bits\n\nStructure Layout:\nMemoryPool (20 bytes):\nOffset  Size  Field Name       Type    Description\n0x00    4     dwPoolFlags      uint    Pool status flags and allocation state\n0x04    4     dwSecondaryFlags uint    Secondary bitmap flags  \n0x08    4     dwPoolIndex      uint    Index of this pool in global table\n0x0C    4     dwBaseOffset     uint    Base address offset for this pool\n0x10    4     pBitmapData      void*   Pointer to allocation bitmap data structure\n\nFreeBlock (12 bytes):\nOffset  Size  Field Name    Type    Description\n0x00    4     dwBlockSize   uint    Size of this free block in bytes (low bit = free flag)\n0x04    4     pNext         void*   Pointer to next free block in same size class\n0x08    4     pPrev         void*   Pointer to previous free block in same size class",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ef5171f8f7487cff01081036951ae8fa"
    },
    "Bnclient_MNE_ef80c025e383": {
      "addresses": {
        "LoD/1.11": "0x6FF2587E",
        "LoD/1.11b": "0x6FF25065",
        "LoD/1.12a": "0x6FF26700",
        "LoD/1.13c": "0x6FF262F0",
        "LoD/1.13d": "0x6FF25C7E"
      },
      "rvas": {
        "LoD/1.11": "0x587E",
        "LoD/1.11b": "0x5065",
        "LoD/1.12a": "0x6700",
        "LoD/1.13c": "0x62F0",
        "LoD/1.13d": "0x5C7E"
      },
      "name": "_CPtoLCID",
      "signature": "undefined4 _CPtoLCID(void)",
      "comment": "Library Function - Single Match\n _CPtoLCID\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:ef80c025e3831b06764dc8da4f7409c0"
    },
    "Bnclient_MNE_efa2f79526cd": {
      "addresses": {
        "LoD/1.11": "0x6FF36C75",
        "LoD/1.11b": "0x6FF36C45",
        "LoD/1.12a": "0x6FF37AF5",
        "LoD/1.13c": "0x6FF37AD5",
        "LoD/1.13d": "0x6FF37A15"
      },
      "rvas": {
        "LoD/1.11": "0x16C75",
        "LoD/1.11b": "0x16C45",
        "LoD/1.12a": "0x17AF5",
        "LoD/1.13c": "0x17AD5",
        "LoD/1.13d": "0x17A15"
      },
      "name": "___DestructExceptionObject",
      "signature": "undefined ___DestructExceptionObject(int param_1)",
      "comment": "Library Function - Single Match\n ___DestructExceptionObject\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:efa2f79526cd6c984f92f3e2beec5d87"
    },
    "Bnclient_MNE_f1060dff4c8b": {
      "addresses": {
        "LoD/1.07": "0x6FF2B384",
        "LoD/1.08": "0x6FF2B2C9",
        "LoD/1.09": "0x6FF0BEC9",
        "LoD/1.09b": "0x6FF0BEC9",
        "LoD/1.09d": "0x6FF0C204",
        "LoD/1.10": "0x6FF0C764"
      },
      "rvas": {
        "LoD/1.07": "0xB384",
        "LoD/1.08": "0xB2C9",
        "LoD/1.09": "0xBEC9",
        "LoD/1.09b": "0xBEC9",
        "LoD/1.09d": "0xC204",
        "LoD/1.10": "0xC764"
      },
      "name": "CallFunctionPointerArray",
      "signature": "void CallFunctionPointerArray(void * * ppfnBegin, void * * ppfnEnd)",
      "comment": "Iterates through an array of function pointers and calls each non-null function.\n\nAlgorithm:\n1. Initialize loop with ppfnBegin as current pointer\n2. Check if current pointer < ppfnEnd (array boundary check)\n3. If at or beyond end, jump to exit\n4. Load function pointer from current array element  \n5. Test if function pointer is null (0x0)\n6. If null, skip to next iteration\n7. If valid, call the function pointer with no parameters\n8. Advance pointer to next array element (ppfnBegin + 1)\n9. Jump back to boundary check (step 2)\n10. Return when all function pointers processed\n\nParameters:\nppfnBegin - Starting address of function pointer array\nppfnEnd - Address immediately after last valid function pointer\n\nReturns:\nvoid - No return value, function executes until all pointers processed\n\nSpecial Cases:\n- Empty array (ppfnBegin >= ppfnEnd): Returns immediately without calling any functions\n- Null function pointers in array: Skipped safely without crashing\n- Function pointer array elements are 4 bytes each (pointer size)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f1060dff4c8b86b7cd32c42f8f136fb6"
    },
    "Bnclient_MNE_f158096e2a8f": {
      "addresses": {
        "LoD/1.11": "0x6FF36C5A",
        "LoD/1.11b": "0x6FF36C2A",
        "LoD/1.12a": "0x6FF37ADA",
        "LoD/1.13c": "0x6FF37ABA",
        "LoD/1.13d": "0x6FF379FA"
      },
      "rvas": {
        "LoD/1.11": "0x16C5A",
        "LoD/1.11b": "0x16C2A",
        "LoD/1.12a": "0x17ADA",
        "LoD/1.13c": "0x17ABA",
        "LoD/1.13d": "0x179FA"
      },
      "method": "MNE",
      "index": "MNE:f158096e2a8fe13c6f7971757535ec37",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF0CF5D",
          "rva": "0xCF5D",
          "confidence": 0.396,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_f161d272b104": {
      "addresses": {
        "LoD/1.11": "0x6FF311E0",
        "LoD/1.11b": "0x6FF31850",
        "LoD/1.12a": "0x6FF302D0",
        "LoD/1.13c": "0x6FF33490",
        "LoD/1.13d": "0x6FF2F450"
      },
      "rvas": {
        "LoD/1.11": "0x111E0",
        "LoD/1.11b": "0x11850",
        "LoD/1.12a": "0x102D0",
        "LoD/1.13c": "0x13490",
        "LoD/1.13d": "0xF450"
      },
      "method": "MNE",
      "index": "MNE:f161d272b104e72bae714ebbb85febc2",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF114F0",
          "rva": "0x114F0",
          "confidence": 0.387,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09d": {
          "address": "0x6FF10FA0",
          "rva": "0x10FA0",
          "confidence": 0.314,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        },
        "LoD/1.09b": {
          "address": "0x6FF10CB0",
          "rva": "0x10CB0",
          "confidence": 0.206,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_f16ffb8892aa": {
      "addresses": {
        "LoD/1.11": "0x6FF2BD70",
        "LoD/1.11b": "0x6FF34010",
        "LoD/1.12a": "0x6FF33B80",
        "LoD/1.13c": "0x6FF2C3A0",
        "LoD/1.13d": "0x6FF32FF0"
      },
      "rvas": {
        "LoD/1.11": "0xBD70",
        "LoD/1.11b": "0x14010",
        "LoD/1.12a": "0x13B80",
        "LoD/1.13c": "0xC3A0",
        "LoD/1.13d": "0x12FF0"
      },
      "method": "MNE",
      "index": "MNE:f16ffb8892aaeaf3dcb29928000c23e6"
    },
    "Bnclient_MNE_f1c393de2fac": {
      "addresses": {
        "LoD/1.11": "0x6FF25140",
        "LoD/1.11b": "0x6FF26A60",
        "LoD/1.12a": "0x6FF263F0",
        "LoD/1.13c": "0x6FF26AC0",
        "LoD/1.13d": "0x6FF253B0"
      },
      "rvas": {
        "LoD/1.11": "0x5140",
        "LoD/1.11b": "0x6A60",
        "LoD/1.12a": "0x63F0",
        "LoD/1.13c": "0x6AC0",
        "LoD/1.13d": "0x53B0"
      },
      "method": "MNE",
      "index": "MNE:f1c393de2fac70496494aea734de5675"
    },
    "Bnclient_MNE_f234e4dce3c4": {
      "addresses": {
        "LoD/1.11": "0x6FF310E0",
        "LoD/1.11b": "0x6FF31750",
        "LoD/1.12a": "0x6FF301D0",
        "LoD/1.13c": "0x6FF33390",
        "LoD/1.13d": "0x6FF2F350"
      },
      "rvas": {
        "LoD/1.11": "0x110E0",
        "LoD/1.11b": "0x11750",
        "LoD/1.12a": "0x101D0",
        "LoD/1.13c": "0x13390",
        "LoD/1.13d": "0xF350"
      },
      "method": "MNE",
      "index": "MNE:f234e4dce3c4517114d5b2cef35b006d"
    },
    "Bnclient_MNE_f23ef2b3a6cf": {
      "addresses": {
        "LoD/1.07": "0x6FF3183A",
        "LoD/1.08": "0x6FF3185A",
        "LoD/1.09": "0x6FF1247A",
        "LoD/1.09b": "0x6FF1247A",
        "LoD/1.09d": "0x6FF1276A",
        "LoD/1.10": "0x6FF12CBA",
        "LoD/1.11": "0x6FF2791F",
        "LoD/1.11b": "0x6FF2789F",
        "LoD/1.12a": "0x6FF27CEE",
        "LoD/1.13c": "0x6FF27C56",
        "LoD/1.13d": "0x6FF27901"
      },
      "rvas": {
        "LoD/1.07": "0x1183A",
        "LoD/1.08": "0x1185A",
        "LoD/1.09": "0x1247A",
        "LoD/1.09b": "0x1247A",
        "LoD/1.09d": "0x1276A",
        "LoD/1.10": "0x12CBA",
        "LoD/1.11": "0x791F",
        "LoD/1.11b": "0x789F",
        "LoD/1.12a": "0x7CEE",
        "LoD/1.13c": "0x7C56",
        "LoD/1.13d": "0x7901"
      },
      "name": "AcquireDynamicBufferLock",
      "signature": "void AcquireDynamicBufferLock(void)",
      "comment": "Acquires critical section 13 for thread-safe dynamic buffer operations.\n\nAlgorithm:\n1. Call FUN_6ff2c3fe with index 0xd (13) to initialize/enter critical section 13\n2. Return to caller with lock held\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Critical section index 0xd (13) is reserved for dynamic buffer synchronization\n- Must be paired with FUN_6ff2b37b() (ReleaseDynamicBufferLock) to avoid deadlock\n- If critical section not initialized, FUN_6ff2c3fe will allocate and initialize it\n- Thread will block if another thread holds this critical section\n\nMagic Numbers Reference:\n0xd (13) - Critical section index for dynamic buffer operations",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0"
    },
    "Bnclient_MNE_f31c6439952c": {
      "addresses": {
        "LoD/1.07": "0x6FF30E6E",
        "LoD/1.08": "0x6FF30E8E",
        "LoD/1.09": "0x6FF11AAE",
        "LoD/1.09b": "0x6FF11AAE",
        "LoD/1.09d": "0x6FF11D9E",
        "LoD/1.10": "0x6FF122EE"
      },
      "rvas": {
        "LoD/1.07": "0x10E6E",
        "LoD/1.08": "0x10E8E",
        "LoD/1.09": "0x11AAE",
        "LoD/1.09b": "0x11AAE",
        "LoD/1.09d": "0x11D9E",
        "LoD/1.10": "0x122EE"
      },
      "name": "GetCharacterClassFromType",
      "signature": "uint GetCharacterClassFromType(int nCharacterType)",
      "comment": "Maps character type ID to corresponding character class code.\n\nAlgorithm:\n1. Compare input character type against known character type constants\n2. Return specific character class code for Amazon (0x3a4 -> 0x411)\n3. Return specific character class code for Sorceress (0x3a8 -> 0x804)\n4. Return specific character class code for Necromancer (0x3b5 -> 0x412)\n5. Return specific character class code for Paladin (0x3b6 -> 0x404)\n6. Return 0 for unknown/invalid character types\n\nParameters:\nnCharacterType (int): Character type identifier to lookup\n  - 0x3a4 (932): Amazon character type\n  - 0x3a8 (936): Sorceress character type\n  - 0x3b5 (949): Necromancer character type\n  - 0x3b6 (950): Paladin character type\n\nReturns:\nunsigned int: Character class code for the specified type\n  - 0x411 (1041): Amazon class code\n  - 0x804 (2052): Sorceress class code\n  - 0x412 (1042): Necromancer class code\n  - 0x404 (1028): Paladin class code\n  - 0: Unknown or invalid character type\n\nMagic Numbers Reference:\n0x3a4 (932): Amazon character type constant\n0x3a8 (936): Sorceress character type constant\n0x3b5 (949): Necromancer character type constant\n0x3b6 (950): Paladin character type constant\n0x411 (1041): Amazon class code\n0x804 (2052): Sorceress class code\n0x412 (1042): Necromancer class code\n0x404 (1028): Paladin class code",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f31c6439952ca9c3e10694cce3d833df"
    },
    "Bnclient_MNE_f388330e44e4": {
      "addresses": {
        "LoD/1.11": "0x6FF25E7F",
        "LoD/1.11b": "0x6FF24A5C",
        "LoD/1.13d": "0x6FF24ACC"
      },
      "rvas": {
        "LoD/1.11": "0x5E7F",
        "LoD/1.11b": "0x4A5C",
        "LoD/1.13d": "0x4ACC"
      },
      "name": "__write_lk",
      "signature": "undefined __write_lk(uint param_1, char * param_2, uint param_3)",
      "comment": "Library Function - Single Match\n __write_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:f388330e44e46f9b9336a6a8d70bef3a"
    },
    "Bnclient_MNE_f38bb98de0ca": {
      "addresses": {
        "LoD/1.07": "0x6FF3210D",
        "LoD/1.08": "0x6FF3212D",
        "LoD/1.09": "0x6FF12D22",
        "LoD/1.09b": "0x6FF12D22",
        "LoD/1.09d": "0x6FF1303D",
        "LoD/1.10": "0x6FF135C1",
        "LoD/1.11b": "0x6FF27F22",
        "LoD/1.13c": "0x6FF27F92",
        "LoD/1.13d": "0x6FF27F92"
      },
      "rvas": {
        "LoD/1.07": "0x1210D",
        "LoD/1.08": "0x1212D",
        "LoD/1.09": "0x12D22",
        "LoD/1.09b": "0x12D22",
        "LoD/1.09d": "0x1303D",
        "LoD/1.10": "0x135C1",
        "LoD/1.11b": "0x7F22",
        "LoD/1.13c": "0x7F92",
        "LoD/1.13d": "0x7F92"
      },
      "name": "__freebuf",
      "signature": "void __freebuf(FILE * _File)",
      "comment": "Library Function - Single Match\n __freebuf\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f38bb98de0cae7e771d97b2937aba094"
    },
    "Bnclient_MNE_f69087a4d0d6": {
      "addresses": {
        "LoD/1.07": "0x6FF31A7D",
        "LoD/1.08": "0x6FF31A9D",
        "LoD/1.09": "0x6FF126BD",
        "LoD/1.09b": "0x6FF126BD",
        "LoD/1.09d": "0x6FF129AD",
        "LoD/1.10": "0x6FF12F31"
      },
      "rvas": {
        "LoD/1.07": "0x11A7D",
        "LoD/1.08": "0x11A9D",
        "LoD/1.09": "0x126BD",
        "LoD/1.09b": "0x126BD",
        "LoD/1.09d": "0x129AD",
        "LoD/1.10": "0x12F31"
      },
      "name": "ValidateAndCloseStream",
      "signature": "int ValidateAndCloseStream(int nStreamIndex)",
      "comment": "Validates a stream index and performs stream close operation with critical section protection.\n\nAlgorithm:\n1. Validate stream index against global stream count limit\n2. Calculate bucket index using bit shift (index >> 5) for 32-entry buckets  \n3. Calculate offset within bucket using bit mask (index & 0x1f)\n4. Access StreamIO descriptor using 2D array indexing with 36-byte stride\n5. Check if stream position field has active bit (0x1) set\n6. If invalid stream or inactive: set thread error code 9 (invalid parameter)\n7. If valid stream: acquire critical section lock for thread safety\n8. Call internal close operation (CloseStreamHandle)\n9. Release critical section lock\n10. Return close operation result or error code 0xffffffff\n\nParameters:\nnStreamIndex (int): Zero-based index into global stream descriptor array\n\nReturns:\nSuccess: Result value from internal close operation (typically 0)\nFailure: -1 when stream index invalid or stream inactive  \n\nSpecial Cases:\nStream index >= g_dwStreamCount triggers bounds check failure\nStream with position field bit 0 clear indicates inactive/closed stream\nThread error code 9 indicates EBADF (bad file descriptor) equivalent\n\nMagic Numbers Reference:\n0x1f (31): Bit mask for bucket offset calculation (32 entries per bucket)\n0x5: Right shift count for bucket index (divide by 32)  \n0x1: Active stream bit flag in nPosition field\n0x9: Thread error code for invalid parameter (EBADF equivalent)\n-1: Error return value indicating operation failure\n+0x4: Offset to nPosition field in StreamIO structure\n\nStructure Layout:\nStreamIO (36 bytes total):\nOffset | Size | Field Name | Type | Description\n+0x0   | 4    | ?         | ?    | Unknown field\n+0x4   | 4    | nPosition | int  | Stream position with flag bits (bit 0 = active)\n...    | ...  | ...       | ...  | Additional fields (28 bytes)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f69087a4d0d613e8eb1a99e63a6b0789"
    },
    "Bnclient_MNE_f70a35b7fba7": {
      "addresses": {
        "LoD/1.11": "0x6FF24FE9",
        "LoD/1.11b": "0x6FF2690D",
        "LoD/1.12a": "0x6FF2629E",
        "LoD/1.13c": "0x6FF26975",
        "LoD/1.13d": "0x6FF25265"
      },
      "rvas": {
        "LoD/1.11": "0x4FE9",
        "LoD/1.11b": "0x690D",
        "LoD/1.12a": "0x629E",
        "LoD/1.13c": "0x6975",
        "LoD/1.13d": "0x5265"
      },
      "name": "___free_lconv_num",
      "signature": "undefined ___free_lconv_num(undefined4 * param_1)",
      "comment": "Library Function - Single Match\n ___free_lconv_num\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:f70a35b7fba7d58d54c96ad387278a4c"
    },
    "Bnclient_MNE_f7657de81ac8": {
      "addresses": {
        "LoD/1.07": "0x6FF2D8C2",
        "LoD/1.08": "0x6FF2D8E2",
        "LoD/1.09": "0x6FF0E4E2",
        "LoD/1.09b": "0x6FF0E4E2",
        "LoD/1.09d": "0x6FF0E7F2",
        "LoD/1.10": "0x6FF0ED5A"
      },
      "rvas": {
        "LoD/1.07": "0xD8C2",
        "LoD/1.08": "0xD8E2",
        "LoD/1.09": "0xE4E2",
        "LoD/1.09b": "0xE4E2",
        "LoD/1.09d": "0xE7F2",
        "LoD/1.10": "0xED5A"
      },
      "name": "RepeatCharacterToStream",
      "signature": "void RepeatCharacterToStream(uint dwCharacter, int nCount, int * pOutputStream, int * pnErrorStatus)",
      "comment": "Writes a specified character to an output stream a given number of times.\n\nAlgorithm:\n1. Check if repeat count is positive, return immediately if zero or negative\n2. Enter loop to repeat character output nCount times\n3. Call FUN_6ff2d88d to write dwCharacter to pOutputStream \n4. Check error status after each write operation\n5. If *pnErrorStatus equals -1, terminate early with error\n6. Decrement count and continue loop if count > 0\n7. Exit when all characters written or error encountered\n\nParameters:\ndwCharacter (uint): Character code to repeat (typically ASCII value 0x20 for space, 0x30 for '0')\nnCount (int): Number of times to repeat the character \npOutputStream (int *): Pointer to output stream buffer structure\npnErrorStatus (int *): Pointer to error status flag, set to -1 on write failure\n\nReturns:\nvoid: No return value, error status communicated through pnErrorStatus\n\nSpecial Cases:\n- If nCount <= 0, function returns immediately without writing\n- Loop terminates early if write operation sets *pnErrorStatus to -1\n- Used for padding in printf formatting (spaces, zeros)\n\nError Handling:\n- Monitors error status after each character write\n- Early termination on first write failure (-1 status)\n- Calling function must check pnErrorStatus for final status",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f7657de81ac8d5d29214c35b4fa6fd17"
    },
    "Bnclient_MNE_f81cb03aaf4d": {
      "addresses": {
        "LoD/1.11": "0x6FF2A7C0",
        "LoD/1.11b": "0x6FF2A7C0",
        "LoD/1.12a": "0x6FF2ADF0",
        "LoD/1.13c": "0x6FF2ADD0",
        "LoD/1.13d": "0x6FF2ADE0"
      },
      "rvas": {
        "LoD/1.11": "0xA7C0",
        "LoD/1.11b": "0xA7C0",
        "LoD/1.12a": "0xADF0",
        "LoD/1.13c": "0xADD0",
        "LoD/1.13d": "0xADE0"
      },
      "method": "MNE",
      "index": "MNE:f81cb03aaf4d642f6fc1e4b483687712"
    },
    "Bnclient_MNE_f93a26193b15": {
      "addresses": {
        "LoD/1.07": "0x6FF2FDB0",
        "LoD/1.08": "0x6FF2FDD0",
        "LoD/1.09": "0x6FF109F0",
        "LoD/1.09b": "0x6FF109F0",
        "LoD/1.09d": "0x6FF10CE0",
        "LoD/1.10": "0x6FF0EDF0"
      },
      "rvas": {
        "LoD/1.07": "0xFDB0",
        "LoD/1.08": "0xFDD0",
        "LoD/1.09": "0x109F0",
        "LoD/1.09b": "0x109F0",
        "LoD/1.09d": "0x10CE0",
        "LoD/1.10": "0xEDF0"
      },
      "name": "CompareStrings",
      "signature": "int CompareStrings(char * lpszStr1, char * lpszStr2)",
      "comment": "High-performance string comparison function using DWORD-aligned memory access for optimal speed.\n\nAlgorithm:\n1. Check if lpszStr1 is not aligned on 4-byte boundary\n2. If unaligned, handle 1-byte alignment by comparing single byte and advancing\n3. If still unaligned, handle 2-byte alignment by comparing word and advancing  \n4. Enter main comparison loop using 4-byte DWORD reads for maximum throughput\n5. Extract each byte from DWORD using bit shifting (0, 8, 16, 24 bits)\n6. Compare corresponding bytes between strings and check for null termination\n7. Return 0 if strings are equal, or signed comparison result (-1/+1) if different\n8. Handle early termination when null character is encountered in either string\n\nParameters:\nlpszStr1 (char *): First null-terminated string to compare\nlpszStr2 (char *): Second null-terminated string to compare\n\nReturns:\n0 if strings are identical\n-1 if lpszStr1 is lexicographically less than lpszStr2\n+1 if lpszStr1 is lexicographically greater than lpszStr2\n\nSpecial Cases:\nAlgorithm uses optimized memory access patterns to compare 4 bytes simultaneously\nHandles unaligned memory addresses by processing 1-2 bytes individually first\nNull termination check occurs after each byte comparison to ensure proper string bounds\n\nMagic Numbers Reference:\n0x3 (0b11): Alignment mask to check if address is 4-byte aligned\n0x1: Single byte alignment check mask  \n0x2: Two-byte alignment check mask\n0x8: Bit shift amount for second byte extraction\n0x10: Bit shift amount for third byte extraction (16 bits)\n0x18: Bit shift amount for fourth byte extraction (24 bits)\n-2: Multiplier used in final comparison calculation\n1: Base value for comparison result calculation",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f93a26193b15127770b523718dea2fb3"
    },
    "Bnclient_MNE_f9ea1115030d": {
      "addresses": {
        "LoD/1.07": "0x6FF2A160",
        "LoD/1.08": "0x6FF2A180",
        "LoD/1.09": "0x6FF0AD80",
        "LoD/1.09b": "0x6FF0AD80",
        "LoD/1.09d": "0x6FF0AFD0",
        "LoD/1.10": "0x6FF0B810"
      },
      "rvas": {
        "LoD/1.07": "0xA160",
        "LoD/1.08": "0xA180",
        "LoD/1.09": "0xAD80",
        "LoD/1.09b": "0xAD80",
        "LoD/1.09d": "0xAFD0",
        "LoD/1.10": "0xB810"
      },
      "name": "GetAuthenticationCredentialValue",
      "signature": "dword GetAuthenticationCredentialValue(char cCredentialSelector)",
      "comment": "Selects between two authentication credential values based on character selector.\n\nAlgorithm:\n1. Load primary authentication credential value from global buffer (offset 0x4F4)\n2. Test the credential selector character for null terminator\n3. If selector is null (0x00), load secondary credential value (offset 0x4F8) \n4. Return the selected credential value\n\nParameters:\ncCredentialSelector - Character used to select credential type:\n                     0x00 (null) = Use secondary credential\n                     Any other value = Use primary credential  \n\nReturns:\nAuthentication credential value as dword:\n- Primary credential (g_dwAuthCredentialPrimary) for non-null selector\n- Secondary credential (g_dwAuthCredentialSecondary) for null selector\n\nSpecial Cases:\nOnly two credential values supported; selector is binary choice (null vs non-null)\nNo validation performed on credential values before returning\n\nMagic Numbers Reference:\n0x6ff39be4 - Address of g_dwAuthCredentialPrimary (buffer offset 0x4F4)\n0x6ff39be8 - Address of g_dwAuthCredentialSecondary (buffer offset 0x4F8)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f9ea1115030daa45b1fe796fa7fd9869",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF21CF0",
          "rva": "0x1CF0",
          "confidence": 0.283,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.11b": {
          "address": "0x6FF21469",
          "rva": "0x1469",
          "confidence": 0.283,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.12a": {
          "address": "0x6FF2140F",
          "rva": "0x140F",
          "confidence": 0.283,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF21555",
          "rva": "0x1555",
          "confidence": 0.283,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_MNE_fa8972b50a91": {
      "addresses": {
        "LoD/1.11": "0x6FF216A0",
        "LoD/1.11b": "0x6FF21236",
        "LoD/1.12a": "0x6FF21A66",
        "LoD/1.13c": "0x6FF2159A",
        "LoD/1.13d": "0x6FF2129A"
      },
      "rvas": {
        "LoD/1.11": "0x16A0",
        "LoD/1.11b": "0x1236",
        "LoD/1.12a": "0x1A66",
        "LoD/1.13c": "0x159A",
        "LoD/1.13d": "0x129A"
      },
      "name": "_sprintf",
      "signature": "int _sprintf(char * _Dest, char * _Format, ...)",
      "comment": "Library Function - Single Match\n _sprintf\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:fa8972b50a91454e34542a6f7b824984"
    },
    "Bnclient_MNE_faa86e79d9b1": {
      "addresses": {
        "LoD/1.11": "0x6FF2613C",
        "LoD/1.11b": "0x6FF24D19",
        "LoD/1.12a": "0x6FF26FBF",
        "LoD/1.13c": "0x6FF25F11",
        "LoD/1.13d": "0x6FF24D89"
      },
      "rvas": {
        "LoD/1.11": "0x613C",
        "LoD/1.11b": "0x4D19",
        "LoD/1.12a": "0x6FBF",
        "LoD/1.13c": "0x5F11",
        "LoD/1.13d": "0x4D89"
      },
      "name": "__isatty",
      "signature": "int __isatty(int _FileHandle)",
      "comment": "Library Function - Single Match\n __isatty\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:faa86e79d9b1980bad4d322b9925b87c",
      "candidates": {
        "LoD/1.10": {
          "address": "0x6FF0CF34",
          "rva": "0xCF34",
          "confidence": 0.399,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.11"
        }
      }
    },
    "Bnclient_MNE_fab24e5d32bf": {
      "addresses": {
        "LoD/1.11": "0x6FF22DBA",
        "LoD/1.11b": "0x6FF2234B",
        "LoD/1.12a": "0x6FF23421",
        "LoD/1.13c": "0x6FF227F9",
        "LoD/1.13d": "0x6FF223C0"
      },
      "rvas": {
        "LoD/1.11": "0x2DBA",
        "LoD/1.11b": "0x234B",
        "LoD/1.12a": "0x3421",
        "LoD/1.13c": "0x27F9",
        "LoD/1.13d": "0x23C0"
      },
      "name": "write_multi_char",
      "signature": "undefined write_multi_char(undefined4 param_1, int param_2)",
      "comment": "Library Function - Single Match\n _write_multi_char\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:fab24e5d32bf792b67dd222a8e1cb96f"
    },
    "Bnclient_MNE_fadc9de96206": {
      "addresses": {
        "LoD/1.07": "0x6FF21DA0",
        "LoD/1.08": "0x6FF21DC0",
        "LoD/1.09": "0x6FF01E80",
        "LoD/1.09b": "0x6FF01E80",
        "LoD/1.09d": "0x6FF01E50"
      },
      "rvas": {
        "LoD/1.07": "0x1DA0",
        "LoD/1.08": "0x1DC0",
        "LoD/1.09": "0x1E80",
        "LoD/1.09b": "0x1E80",
        "LoD/1.09d": "0x1E50"
      },
      "name": "InitializeProcessSequence",
      "signature": "int InitializeProcessSequence(uint dwParam1, uint dwParam2, uint dwParam3, char * lpszBuffer, int nBufferSize)",
      "comment": "Initializes a multi-step process sequence with buffer operations and error handling.\n\nAlgorithm:\n1. Execute initialization call with parameter 1 shifted and value 10\n2. Process parameters 1 and 2 through secondary initialization\n3. Configure buffer with single-item flag and buffer size\n4. Execute finalization call with extraout value and value 10\n5. Check process status via status query function\n6. If process failed (non-zero): Execute error cleanup with value 10, return 1\n7. If process succeeded (zero): Execute success cleanup with value 0, return 1\n\nParameters:\n- dwParam1 (uint): Primary configuration parameter, upper bits shifted in CONCAT31\n- dwParam2 (uint): Secondary configuration parameter passed to processing\n- dwParam3 (uint): Reserved parameter, currently unused in processing\n- lpszBuffer (char *): Target buffer pointer for configuration operations\n- nBufferSize (int): Size of the buffer in bytes for boundary validation\n\nReturns:\n- int: Always returns 1 regardless of processing outcome\n- Success path: Status check passes, cleanup with 0 parameter\n- Error path: Status check fails, cleanup with 10 parameter\n\nSpecial Cases:\n- Function always returns 1, actual success/failure determined by cleanup calls\n- Magic number 10 (0xa) used consistently in initialization and error cleanup\n- Magic number 1 used as flag parameter in buffer configuration\n- CONCAT31 operations suggest bit manipulation of upper parameter bits\n\nMagic Numbers Reference:\n- 0xa (10 decimal): Standard cleanup/initialization parameter\n- 0x1 (1 decimal): Single-item processing flag for buffer operations",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:fadc9de9620623c31db1c093b660c79b"
    },
    "Bnclient_MNE_fc29d055fc26": {
      "addresses": {
        "LoD/1.11": "0x6FF2B830",
        "LoD/1.11b": "0x6FF33A50",
        "LoD/1.12a": "0x6FF33720",
        "LoD/1.13c": "0x6FF2BE60",
        "LoD/1.13d": "0x6FF32B40"
      },
      "rvas": {
        "LoD/1.11": "0xB830",
        "LoD/1.11b": "0x13A50",
        "LoD/1.12a": "0x13720",
        "LoD/1.13c": "0xBE60",
        "LoD/1.13d": "0x12B40"
      },
      "method": "MNE",
      "index": "MNE:fc29d055fc26a97137c279b8dbce4b1e"
    },
    "Bnclient_MNE_fc8a902d2e36": {
      "addresses": {
        "LoD/1.07": "0x6FF27430",
        "LoD/1.08": "0x6FF27450",
        "LoD/1.09": "0x6FF08060",
        "LoD/1.09b": "0x6FF08060",
        "LoD/1.09d": "0x6FF082C0",
        "LoD/1.10": "0x6FF08CA0",
        "LoD/1.11": "0x6FF36CBA",
        "LoD/1.11b": "0x6FF36C8A",
        "LoD/1.12a": "0x6FF37B3A",
        "LoD/1.13c": "0x6FF37B1A",
        "LoD/1.13d": "0x6FF37A5A"
      },
      "rvas": {
        "LoD/1.07": "0x7430",
        "LoD/1.08": "0x7450",
        "LoD/1.09": "0x8060",
        "LoD/1.09b": "0x8060",
        "LoD/1.09d": "0x82C0",
        "LoD/1.10": "0x8CA0",
        "LoD/1.11": "0x16CBA",
        "LoD/1.11b": "0x16C8A",
        "LoD/1.12a": "0x17B3A",
        "LoD/1.13c": "0x17B1A",
        "LoD/1.13d": "0x17A5A"
      },
      "name": "ValidateAssertion",
      "signature": "int ValidateAssertion(int nCondition)",
      "comment": "Validates assertion condition and reports debug information on failure\n\nAlgorithm:\n1. Check if condition parameter is zero (assertion failed)\n2. If condition is zero, return 0 (failure)\n3. If condition is non-zero, call Storm.dll debug reporting function\n4. Pass condition value, source file path, line number 0x158 (344), and flags 0\n5. Return 1 (success) indicating assertion passed\n\nParameters:\n- nCondition: int - Assertion condition to validate (0 = failed, non-zero = passed)\n\nReturns:\n- int: 0 if assertion failed (condition was 0), 1 if assertion passed\n\nSpecial Cases:\n- Zero condition triggers early return without calling debug reporter\n- Source file path points to CACHE.CPP at line 344 (0x158)\n- Debug reporter (Ordinal_403) likely logs assertion failure details\n\nMagic Numbers Reference:\n- 0x158 (344): Line number in CACHE.CPP source file\n- 0x6ff36214: Address of debug source file path string\n- 0: Flags parameter passed to debug reporter",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:fc8a902d2e36e029ea7bd281e3fc44d4"
    },
    "Bnclient_MNE_fd78a1cdcfba": {
      "addresses": {
        "LoD/1.11": "0x6FF275D6",
        "LoD/1.11b": "0x6FF27556",
        "LoD/1.12a": "0x6FF279A5",
        "LoD/1.13c": "0x6FF2790D",
        "LoD/1.13d": "0x6FF275B8"
      },
      "rvas": {
        "LoD/1.11": "0x75D6",
        "LoD/1.11b": "0x7556",
        "LoD/1.12a": "0x79A5",
        "LoD/1.13c": "0x790D",
        "LoD/1.13d": "0x75B8"
      },
      "name": "__lock_fhandle",
      "signature": "int __lock_fhandle(int _Filehandle)",
      "comment": "Library Function - Single Match\n __lock_fhandle\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:fd78a1cdcfba52796c1191ac28710e53"
    },
    "Bnclient_MNE_fd871b6e0749": {
      "addresses": {
        "LoD/1.07": "0x6FF26A90",
        "LoD/1.08": "0x6FF26AB0",
        "LoD/1.09": "0x6FF07020",
        "LoD/1.09b": "0x6FF07020",
        "LoD/1.09d": "0x6FF07290",
        "LoD/1.10": "0x6FF07A00"
      },
      "rvas": {
        "LoD/1.07": "0x6A90",
        "LoD/1.08": "0x6AB0",
        "LoD/1.09": "0x7020",
        "LoD/1.09b": "0x7020",
        "LoD/1.09d": "0x7290",
        "LoD/1.10": "0x7A00"
      },
      "name": "InitializeMessageHandler0x1c",
      "signature": "void InitializeMessageHandler0x1c(uint * pHandlerStorage)",
      "comment": "Initializes packet handling infrastructure for message ID 0x1C (28 decimal).\n\nAlgorithm:\n1. Retrieve packet handler function pointer for message ID 0x1C using GetPacketHandler\n2. Store the handler function pointer in the provided storage location\n3. Trigger notification value lookup for the same message ID using LookupNotificationValue\n4. Return to caller (no return value)\n\nParameters:\npHandlerStorage (uint *) - Pointer to storage location for packet handler function pointer\n\nReturns:\nvoid - No return value; function performs initialization and returns\n\nSpecial Cases:\nMessage ID 0x1C is hardcoded and corresponds to a specific packet type in the protocol\nHandler storage location must be valid memory address or undefined behavior occurs\n\nMagic Numbers Reference:\n0x1C (28 decimal) - Packet message type identifier for this handler initialization",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:fd871b6e07493bea8d39bd80e2a2fb26"
    },
    "Bnclient_MNE_fdad073544ac": {
      "addresses": {
        "LoD/1.09d": "0x6FF01050",
        "LoD/1.10": "0x6FF01070",
        "LoD/1.11": "0x6FF3772F",
        "LoD/1.11b": "0x6FF376FF",
        "LoD/1.12a": "0x6FF385AF",
        "LoD/1.13c": "0x6FF3858F",
        "LoD/1.13d": "0x6FF384CF"
      },
      "rvas": {
        "LoD/1.09d": "0x1050",
        "LoD/1.10": "0x1070",
        "LoD/1.11": "0x1772F",
        "LoD/1.11b": "0x176FF",
        "LoD/1.12a": "0x185AF",
        "LoD/1.13c": "0x1858F",
        "LoD/1.13d": "0x184CF"
      },
      "name": "Ordinal_10227",
      "signature": "undefined Ordinal_10227(void)",
      "name_source": "LoD/1.09d",
      "method": "MNE",
      "index": "MNE:fdad073544ac1586678f808b3470f76a",
      "candidates": {
        "LoD/1.09b": {
          "address": "0x6FF022F0",
          "rva": "0x22F0",
          "confidence": 0.365,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.09d"
        },
        "LoD/1.09": {
          "address": "0x6FF022F0",
          "rva": "0x22F0",
          "confidence": 0.295,
          "method": "structural",
          "direction": "reverse",
          "source": "LoD/1.09d"
        }
      }
    },
    "Bnclient_MNE_fdd552c17b8c": {
      "addresses": {
        "LoD/1.11": "0x6FF26C0C",
        "LoD/1.11b": "0x6FF2613D",
        "LoD/1.12a": "0x6FF255A5",
        "LoD/1.13c": "0x6FF251F0",
        "LoD/1.13d": "0x6FF26C66"
      },
      "rvas": {
        "LoD/1.11": "0x6C0C",
        "LoD/1.11b": "0x613D",
        "LoD/1.12a": "0x55A5",
        "LoD/1.13c": "0x51F0",
        "LoD/1.13d": "0x6C66"
      },
      "name": "___sbh_alloc_block",
      "signature": "int * ___sbh_alloc_block(uint * param_1)",
      "comment": "Library Function - Single Match\n ___sbh_alloc_block\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:fdd552c17b8cb0117d531882b003b7d1"
    },
    "Bnclient_MNE_fe7518f9cbca": {
      "addresses": {
        "LoD/1.11": "0x6FF24C9F",
        "LoD/1.11b": "0x6FF26CB8",
        "LoD/1.12a": "0x6FF25F54",
        "LoD/1.13c": "0x6FF26D18",
        "LoD/1.13d": "0x6FF25948"
      },
      "rvas": {
        "LoD/1.11": "0x4C9F",
        "LoD/1.11b": "0x6CB8",
        "LoD/1.12a": "0x5F54",
        "LoD/1.13c": "0x6D18",
        "LoD/1.13d": "0x5948"
      },
      "name": "___crtGetStringTypeA",
      "signature": "BOOL ___crtGetStringTypeA(_locale_t _Plocinfo, DWORD _DWInfoType, LPCSTR _LpSrcStr, int _CchSrc, LPWORD _LpCharType, int _Code_page, BOOL _BError)",
      "comment": "Library Function - Single Match\n ___crtGetStringTypeA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:fe7518f9cbcae43d3194d5d079593073"
    },
    "Bnclient_MNE_ff64648b3e6e": {
      "addresses": {
        "LoD/1.07": "0x6FF2EB6F",
        "LoD/1.08": "0x6FF2EB8F",
        "LoD/1.09": "0x6FF0F7BA",
        "LoD/1.09b": "0x6FF0F7BA",
        "LoD/1.09d": "0x6FF0FA9F",
        "LoD/1.10": "0x6FF1008D"
      },
      "rvas": {
        "LoD/1.07": "0xEB6F",
        "LoD/1.08": "0xEB8F",
        "LoD/1.09": "0xF7BA",
        "LoD/1.09b": "0xF7BA",
        "LoD/1.09d": "0xFA9F",
        "LoD/1.10": "0x1008D"
      },
      "name": "AllocateMemoryBlock",
      "signature": "void * AllocateMemoryBlock(int nRequestedSize)",
      "comment": "Allocate memory block using bitmap-based allocation with hierarchical fallback strategy.\n\nAlgorithm:\n1. Calculate aligned block size (16-byte aligned with 23-byte header overhead)\n2. Convert aligned size to bit index for bitmap allocation tracking\n3. Generate dual bitmap masks (high/low 32-bit pairs for 64-bit bitmap coverage)\n4. Search secondary allocation table first for available blocks using bitmap masks\n5. If secondary table exhausted, scan primary allocation table with same bitmap logic\n6. Implement cascading fallback strategy for allocation pressure:\n   - First: Search existing allocated blocks for sufficient free space\n   - Second: Search backup descriptor tables for emergency allocation\n   - Third: Call external allocation expander (FUN_6ff2ee78) to grow heap\n7. Initialize block metadata system using dual-linked free list management\n8. Update bitmap allocation tracking with bit manipulation for efficient allocation state\n9. Handle block splitting when allocated block exceeds requested size:\n   - Update linked list pointers to maintain free list integrity\n   - Recalculate bitmap indices and update bit reference counting\n   - Set appropriate bitmap bits for both allocation tracking levels\n10. Configure allocated block headers with size metadata and boundary markers\n11. Update global allocation counters and active allocation tracking state\n12. Return pointer to usable memory area (past block headers and metadata)\n\nParameters:\nnRequestedSize - Size in bytes of memory block to allocate (before alignment and headers)\n\nReturns:\nvoid * - Pointer to allocated memory block, NULL if allocation fails\nSuccess: Valid memory pointer with 16-byte alignment guarantee\nFailure: NULL returned when heap exhausted or allocation system error\n\nSpecial Cases:\nBlock Size Calculation: Adds 0x17 (23) byte overhead then aligns to 16-byte boundary\nBitmap Indexing: Divides aligned size by 16 to determine bitmap bit position\nDual Bitmap System: Uses paired 32-bit masks to handle allocation tracking up to 64 size classes\nAllocation Pressure Handling: Multiple fallback strategies prevent allocation failure under memory pressure\nGlobal State Updates: Manages g_dwActiveAllocationCount and allocation table pointers\nReference Counting: Maintains bit reference counts to track allocation density per size class\n\nMagic Numbers Reference:\n0x17 (23) - Block header overhead added to requested size before alignment\n0xfffffff0 - 16-byte alignment mask for memory block boundaries  \n0x20 (32) - Bitmap word size boundary for high/low mask selection\n0x81 (129) - Block metadata stride in allocation descriptor arrays (129 DWORDs per block = 516 bytes)\n0x51 (81) - Offset to free list head array within allocation block metadata\n0x31 (49) - Offset to high bitmap word within allocation tracking structure  \n0x11 (17) - Offset to low bitmap word within allocation tracking structure\n0x3f (63) - Maximum bit index clamp to prevent bitmap overflow conditions\n0x80000000 - High bit mask used for bitmap manipulation operations\n\nError Handling:\nAllocation Table Exhaustion: Returns NULL when no allocation descriptors available\nExternal Allocator Failure: Returns NULL if FUN_6ff2ee78 cannot expand heap space\nBlock Initialization Error: Returns NULL if FUN_6ff2ef29 fails to initialize block metadata\nInvalid Size Request: Handles edge cases through alignment and size validation logic\n\nState Machine:\nState 1: Request Processing \u2192 Calculate aligned size and bitmap indices \u2192 State 2\nState 2: Secondary Table Search \u2192 Scan with bitmap masks \u2192 State 3 (found) or State 4 (not found)  \nState 3: Block Found \u2192 Skip to State 7 (allocation finalization)\nState 4: Primary Table Search \u2192 Full table scan with bitmap logic \u2192 State 5 (found) or State 6 (fallback)\nState 5: Primary Block Found \u2192 Skip to State 7 (allocation finalization) \nState 6: Fallback Strategy \u2192 Emergency allocation attempts \u2192 State 7 (success) or Error (failure)\nState 7: Block Finalization \u2192 Update metadata, split if needed, configure headers \u2192 Success Return\n\nStructure Layout:\nMemoryAllocation structure (20 bytes):\nOffset  Size  Field Name     Type    Description\n0x00    4     dwReserved1    uint    Low 32-bit allocation bitmap \n0x04    4     dwReserved2    uint    High 32-bit allocation bitmap\n0x08    4     dwReserved3    uint    Block availability status flags\n0x0C    4     (padding)      uint    Structure alignment padding\n0x10    4     pBlockInfo     void*   Pointer to detailed block metadata\n\nBlock Metadata Array Structure (516 bytes per block):\nOffset       Size    Description\n0x00-0x10    17*4    Block status and reference counting arrays\n0x44-0xC4    33*4    Low bitmap allocation tracking (32 size classes + control)\n0xC4-0x144   33*4    High bitmap allocation tracking (32 size classes + control) \n0x144+       varies  Free list head pointers (2 pointers per size class)\n\nFlag Bits:\nBlock availability status (dwReserved3):\n0x00000000 - Block available for allocation attempts\n0x00000001 - Block currently in use or reserved for allocation\nOther bits reserved for future allocation strategy extensions",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ff64648b3e6e32bc28a5e4bc8d984c1e"
    },
    "Bnclient_MNE_ff70d7fac254": {
      "addresses": {
        "LoD/1.07": "0x6FF304B3",
        "LoD/1.08": "0x6FF304D3",
        "LoD/1.09": "0x6FF110F3",
        "LoD/1.09b": "0x6FF110F3",
        "LoD/1.09d": "0x6FF113E3",
        "LoD/1.11": "0x6FF21B7D",
        "LoD/1.11b": "0x6FF212F6",
        "LoD/1.12a": "0x6FF2129C",
        "LoD/1.13c": "0x6FF213E2",
        "LoD/1.13d": "0x6FF2155E"
      },
      "rvas": {
        "LoD/1.07": "0x104B3",
        "LoD/1.08": "0x104D3",
        "LoD/1.09": "0x110F3",
        "LoD/1.09b": "0x110F3",
        "LoD/1.09d": "0x113E3",
        "LoD/1.11": "0x1B7D",
        "LoD/1.11b": "0x12F6",
        "LoD/1.12a": "0x129C",
        "LoD/1.13c": "0x13E2",
        "LoD/1.13d": "0x155E"
      },
      "name": "AcquireCriticalSectionForAddress",
      "signature": "void AcquireCriticalSectionForAddress(uint dwAddress)",
      "comment": "Acquires a critical section for memory protection based on address range.\n\nAlgorithm:\n1. Validate address parameter against defined memory range (0x6ff38ba0 to 0x6ff38e00)\n2. If address within range: Calculate indexed critical section\n   a. Subtract base address (0x6ff38ba0) to get relative offset\n   b. Divide by 32 (SAR 0x5) to get block index\n   c. Add offset 0x1c to get critical section index\n   d. Call AcquireCriticalSectionByIndex with calculated index\n3. If address outside range: Use direct critical section approach\n   a. Add 0x20 offset to address for critical section structure\n   b. Call EnterCriticalSection with calculated address\n\nParameters:\ndwAddress - uint: Memory address requiring critical section protection\n\nReturns:\nvoid - Function does not return a value\n\nSpecial Cases:\n- Range boundary: 0x6ff38ba0 to 0x6ff38e00 (exclusive end)\n- Block size: 32 bytes per indexed critical section\n- Direct offset: +0x20 for non-indexed critical sections\n\nMagic Numbers Reference:\n0x6ff38ba0 - Start of indexed critical section memory range\n0x6ff38e00 - End of indexed critical section memory range (exclusive)\n0x5 - Right shift by 5 (divide by 32) for block indexing\n0x1c - Base index offset (28) for critical section array\n0x20 - Offset to critical section structure for direct addressing",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ff70d7fac2548b5958f726d1eeb33c1c"
    },
    "Bnclient_STR_019d4ab11b5c": {
      "addresses": {
        "LoD/1.11": "0x6FF33ED0",
        "LoD/1.11b": "0x6FF2EDA0",
        "LoD/1.12a": "0x6FF2F230",
        "LoD/1.13c": "0x6FF35260",
        "LoD/1.13d": "0x6FF36B60"
      },
      "rvas": {
        "LoD/1.11": "0x13ED0",
        "LoD/1.11b": "0xEDA0",
        "LoD/1.12a": "0xF230",
        "LoD/1.13c": "0x15260",
        "LoD/1.13d": "0x16B60"
      },
      "name": "UpdateGatewaysFromIni",
      "signature": "void UpdateGatewaysFromIni(char * param_1)",
      "comment": "public: void __stdcall BNGatewayAccess::UpdateGatewaysFromIni(char *)",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:019d4ab11b5cd3b22e288ad3280ccc69"
    },
    "Bnclient_STR_1c3f1a95ce5e": {
      "addresses": {
        "LoD/1.07": "0x6FF25000",
        "LoD/1.08": "0x6FF25020",
        "LoD/1.09": "0x6FF05980",
        "LoD/1.09b": "0x6FF05980",
        "LoD/1.09d": "0x6FF05BF0",
        "LoD/1.10": "0x6FF05B60"
      },
      "rvas": {
        "LoD/1.07": "0x5000",
        "LoD/1.08": "0x5020",
        "LoD/1.09": "0x5980",
        "LoD/1.09b": "0x5980",
        "LoD/1.09d": "0x5BF0",
        "LoD/1.10": "0x5B60"
      },
      "name": "FindSection",
      "signature": "char * FindSection(BNGatewayAccess * this, char * lpszFileContent, char * lpszSectionName)",
      "comment": "Searches for a named section within INI-style file content and returns pointer to section body.\n\nAlgorithm:\n1. Calculate string length of lpszFileContent using REPNE SCASB instruction\n2. Calculate string length of lpszSectionName using REPNE SCASB instruction  \n3. Iterate through lpszFileContent character by character looking for section headers\n4. Skip characters until finding '[' (section start marker) or end of string\n5. If end of file reached without finding '[', call error handler and exit\n6. Call FUN_6ff2b820 to perform string comparison between section name and target\n7. If section name doesn't match, advance past closing ']' and continue searching\n8. If section name matches, calculate pointer to section body content\n9. Skip over any trailing whitespace, carriage returns, and line feeds\n10. Return pointer to start of section body content\n\nParameters:\nthis - BNGatewayAccess object instance (implicit)\nlpszFileContent - Pointer to null-terminated INI file content string  \nlpszSectionName - Pointer to null-terminated section name to search for\n\nReturns:\nchar * - Pointer to start of section body content after section header\nNULL - Section not found in file content or invalid input\n\nSpecial Cases:\nSection header format must be [SectionName] with square brackets\nFunction handles CRLF and LF line endings (0x0D, 0x0A)\nMissing closing bracket triggers assertion failure and program termination\nEmpty section names or content may return unexpected results\n\nMagic Numbers Reference:\n0x5B - ASCII '[' character marking section header start\n0x0D - Carriage return character  \n0x0A - Line feed character\n0xFFFFFFFF - Initial counter value for REPNE SCASB length calculation\n0x205 - Line number constant passed to error handler",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:1c3f1a95ce5e00e170f95fa80cfbefdb"
    },
    "Bnclient_STR_1cf0c0b44cb7": {
      "addresses": {
        "LoD/1.11": "0x6FF29FA0",
        "LoD/1.11b": "0x6FF29FA0",
        "LoD/1.12a": "0x6FF2A5D0",
        "LoD/1.13c": "0x6FF2A5B0",
        "LoD/1.13d": "0x6FF2A5C0"
      },
      "rvas": {
        "LoD/1.11": "0x9FA0",
        "LoD/1.11b": "0x9FA0",
        "LoD/1.12a": "0xA5D0",
        "LoD/1.13c": "0xA5B0",
        "LoD/1.13d": "0xA5C0"
      },
      "method": "STR",
      "index": "STR:1cf0c0b44cb786f4704b8d5164c9e5f1"
    },
    "Bnclient_STR_1d436b74681e": {
      "addresses": {
        "LoD/1.07": "0x6FF310F0",
        "LoD/1.08": "0x6FF31110",
        "LoD/1.09": "0x6FF11D30",
        "LoD/1.09b": "0x6FF11D30",
        "LoD/1.09d": "0x6FF12020",
        "LoD/1.10": "0x6FF12570",
        "LoD/1.11": "0x6FF27395",
        "LoD/1.11b": "0x6FF2739D",
        "LoD/1.12a": "0x6FF27426",
        "LoD/1.13c": "0x6FF27415",
        "LoD/1.13d": "0x6FF273FF"
      },
      "rvas": {
        "LoD/1.07": "0x110F0",
        "LoD/1.08": "0x11110",
        "LoD/1.09": "0x11D30",
        "LoD/1.09b": "0x11D30",
        "LoD/1.09d": "0x12020",
        "LoD/1.10": "0x12570",
        "LoD/1.11": "0x7395",
        "LoD/1.11b": "0x739D",
        "LoD/1.12a": "0x7426",
        "LoD/1.13c": "0x7415",
        "LoD/1.13d": "0x73FF"
      },
      "name": "DisplayMessageBoxWithParent",
      "signature": "int DisplayMessageBoxWithParent(char * lpszText, char * lpszCaption, int nType)",
      "comment": "Displays a message box with proper window parent handling and dynamic API loading.\n\nAlgorithm:\n1. Check if MessageBoxA function pointer is already loaded\n2. If not loaded, dynamically load user32.dll using LoadLibraryA\n3. Get function addresses for MessageBoxA, GetActiveWindow, GetLastActivePopup\n4. If function loading fails, return 0\n5. Get active window handle using GetActiveWindow\n6. If active window exists, get last active popup using GetLastActivePopup\n7. Call MessageBoxA with proper parent window and provided parameters\n8. Return MessageBoxA result (user button selection)\n\nParameters:\nlpszText    - Pointer to null-terminated string containing message text\nlpszCaption - Pointer to null-terminated string containing dialog title\nnType       - MessageBox type flags (MB_OK, MB_YESNO, etc.)\n\nReturns:\nMessageBoxA return value indicating user selection (IDOK, IDCANCEL, etc.)\nReturns 0 if dynamic loading fails\n\nSpecial Cases:\n- Dynamic loading prevents static dependency on user32.dll\n- Parent window handling ensures proper Z-order and focus\n- Function pointers cached in globals for performance\n\nMagic Numbers Reference:\n0x6ff33830 - \"user32.dll\" string address\n0x6ff33824 - \"MessageBoxA\" string address  \n0x6ff33814 - \"GetActiveWindow\" string address\n0x6ff33800 - \"GetLastActivePopup\" string address",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:1d436b74681e11a9bd214b6331c37f94"
    },
    "Bnclient_STR_304d598e6d0a": {
      "addresses": {
        "LoD/1.11": "0x6FF22A3D",
        "LoD/1.11b": "0x6FF22DC0",
        "LoD/1.12a": "0x6FF23161",
        "LoD/1.13c": "0x6FF2343C",
        "LoD/1.13d": "0x6FF2306D"
      },
      "rvas": {
        "LoD/1.11": "0x2A3D",
        "LoD/1.11b": "0x2DC0",
        "LoD/1.12a": "0x3161",
        "LoD/1.13c": "0x343C",
        "LoD/1.13d": "0x306D"
      },
      "name": "__mtinit",
      "signature": "int __mtinit(void)",
      "comment": "Library Function - Single Match\n __mtinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:304d598e6d0a621c9e3544e6fb22e61e"
    },
    "Bnclient_STR_331b50f891fc": {
      "addresses": {
        "LoD/1.09": "0x6FF14F10",
        "LoD/1.09b": "0x6FF14F10",
        "LoD/1.09d": "0x6FF15230",
        "LoD/1.10": "0x6FF157D0",
        "LoD/1.11": "0x6FF29880",
        "LoD/1.11b": "0x6FF29880",
        "LoD/1.12a": "0x6FF29EB0",
        "LoD/1.13c": "0x6FF29E90",
        "LoD/1.13d": "0x6FF29EA0"
      },
      "rvas": {
        "LoD/1.09": "0x14F10",
        "LoD/1.09b": "0x14F10",
        "LoD/1.09d": "0x15230",
        "LoD/1.10": "0x157D0",
        "LoD/1.11": "0x9880",
        "LoD/1.11b": "0x9880",
        "LoD/1.12a": "0x9EB0",
        "LoD/1.13c": "0x9E90",
        "LoD/1.13d": "0x9EA0"
      },
      "method": "STR",
      "index": "STR:331b50f891fcddff1bb380d250f8033b"
    },
    "Bnclient_STR_34afb5d5219e": {
      "addresses": {
        "LoD/1.11": "0x6FF34240",
        "LoD/1.11b": "0x6FF2F110",
        "LoD/1.12a": "0x6FF2F5A0",
        "LoD/1.13c": "0x6FF355D0",
        "LoD/1.13d": "0x6FF369D0"
      },
      "rvas": {
        "LoD/1.11": "0x14240",
        "LoD/1.11b": "0xF110",
        "LoD/1.12a": "0xF5A0",
        "LoD/1.13c": "0x155D0",
        "LoD/1.13d": "0x169D0"
      },
      "name": "Load",
      "signature": "void Load(void)",
      "comment": "public: void __stdcall BNGatewayAccess::Load(void)",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:34afb5d5219e1be2308d0f77a0541bb9"
    },
    "Bnclient_STR_387b004e286a": {
      "addresses": {
        "LoD/1.07": "0x6FF264B0",
        "LoD/1.08": "0x6FF264D0",
        "LoD/1.10": "0x6FF073F0"
      },
      "rvas": {
        "LoD/1.07": "0x64B0",
        "LoD/1.08": "0x64D0",
        "LoD/1.10": "0x73F0"
      },
      "name": "StoreRealmListData",
      "signature": "void StoreRealmListData(byte * pbSourceData, uint dwDataSize)",
      "comment": "Stores realm list data in the global buffer, replacing any existing data.\n\nAlgorithm:\n1. Check if global realm buffer exists and free it with cleanup logging\n2. Clear the buffer status flags in global string buffer (offsets 0x168-0x16b)\n3. Allocate new buffer using Ordinal_10042 with size 0x162 and store pointer\n4. Log realm storage operation start message\n5. Copy source data to allocated buffer using optimized memory operations\n6. Perform 4-byte aligned copy using REP MOVSD for bulk transfer\n7. Copy remaining 1-3 bytes using REP MOVSB for unaligned remainder\n\nParameters:\npbSourceData (byte *): Pointer to source realm data to be stored\ndwDataSize (uint): Size of source data in bytes\n\nReturns:\nvoid: No return value, operation always succeeds\n\nMagic Numbers Reference:\n0x168-0x16b (360-363): Global buffer status flags in g_abGlobalStringBuffer\n0x193 (403): Error code parameter for cleanup logging\n0x162 (354): Buffer size parameter for allocation\n0x360 (864): Offset to buffer pointer in g_abGlobalStringBuffer\n\nError Handling:\nFunction performs defensive cleanup but has no error return path\nAllocation failure in Ordinal_10042 would cause crash (no bounds checking)\nUses optimized string operations that assume valid source pointer",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:387b004e286adc1b338c859c5673919e"
    },
    "Bnclient_STR_3a86254cd520": {
      "addresses": {
        "LoD/1.07": "0x6FF29570",
        "LoD/1.08": "0x6FF29590",
        "LoD/1.09": "0x6FF0A1A0",
        "LoD/1.09b": "0x6FF0A1A0",
        "LoD/1.09d": "0x6FF0A400",
        "LoD/1.10": "0x6FF0AC60",
        "LoD/1.11": "0x6FF344C0",
        "LoD/1.11b": "0x6FF311F0",
        "LoD/1.12a": "0x6FF2F820",
        "LoD/1.13c": "0x6FF37480",
        "LoD/1.13d": "0x6FF34CE0"
      },
      "rvas": {
        "LoD/1.07": "0x9570",
        "LoD/1.08": "0x9590",
        "LoD/1.09": "0xA1A0",
        "LoD/1.09b": "0xA1A0",
        "LoD/1.09d": "0xA400",
        "LoD/1.10": "0xAC60",
        "LoD/1.11": "0x144C0",
        "LoD/1.11b": "0x111F0",
        "LoD/1.12a": "0xF820",
        "LoD/1.13c": "0x17480",
        "LoD/1.13d": "0x14CE0"
      },
      "name": "ControlBnetLoggingState",
      "signature": "int ControlBnetLoggingState(int nState, int nFlags)",
      "comment": "Controls the Battle.net logging subsystem initialization and finalization state.\n\nAlgorithm:\n1. Enter critical section to ensure thread-safe access to logging globals\n2. Check nState parameter to determine operation mode\n3. If nState == 1: Initialize logging subsystem\n   a. Call Ordinal_541 to initialize logging state with global buffer\n   b. Call Ordinal_542 to setup log file (\"BnetLog_txt\") with callback function\n   c. Set return value to 1 (success)\n4. If nState == 2: Finalize logging subsystem  \n   a. Call Ordinal_550 to finalize logging with global buffer and flags\n   b. Set return value to 0 (finalized)\n5. If nState is any other value: No operation, set return value to 0\n6. Leave critical section and return result\n\nParameters:\nnState (int): Logging operation mode\n  - 1: Initialize logging subsystem\n  - 2: Finalize/shutdown logging subsystem  \n  - Other values: No operation\ndwFlags (int): Configuration flags passed to finalization ordinal (used only when nState == 2)\n\nReturns:\nint: Operation result\n  - 1: Logging successfully initialized (nState == 1)\n  - 0: Logging finalized, no operation performed, or error condition\n\nSpecial Cases:\nCritical section at g_abGlobalStringBuffer + 0x1c8 ensures thread-safe access to logging state.\nGlobal buffer g_abGlobalStringBuffer._480_4_ contains logging context data.\nString constant \"BnetLog_txt\" (0x6ff363fc) specifies the log file identifier.\nCallback function at 0x6ff39bd0 handles log message processing.\n\nMagic Numbers Reference:\n0x1c8 (456 decimal): Offset to critical section in global buffer\n0x6ff39bd0: Address of logging callback function\n0x6ff363fc: Address of \"BnetLog_txt\" string constant",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:3a86254cd52043d317bd9043704a7e82"
    },
    "Bnclient_STR_46690a701e0b": {
      "addresses": {
        "LoD/1.07": "0x6FF21060",
        "LoD/1.08": "0x6FF21080",
        "LoD/1.09": "0x6FF01080",
        "LoD/1.09b": "0x6FF01080",
        "LoD/1.09d": "0x6FF01060",
        "LoD/1.10": "0x6FF01080",
        "LoD/1.11": "0x6FF2DEF0",
        "LoD/1.11b": "0x6FF2BE90",
        "LoD/1.12a": "0x6FF2E310",
        "LoD/1.13c": "0x6FF2F430",
        "LoD/1.13d": "0x6FF2D900"
      },
      "rvas": {
        "LoD/1.07": "0x1060",
        "LoD/1.08": "0x1080",
        "LoD/1.09": "0x1080",
        "LoD/1.09b": "0x1080",
        "LoD/1.09d": "0x1060",
        "LoD/1.10": "0x1080",
        "LoD/1.11": "0xDEF0",
        "LoD/1.11b": "0xBE90",
        "LoD/1.12a": "0xE310",
        "LoD/1.13c": "0xF430",
        "LoD/1.13d": "0xD900"
      },
      "name": "FindAndConnectToGameServer",
      "signature": "DWORD FindAndConnectToGameServer(void)",
      "comment": "Discovers and establishes connection to the fastest available game server\n\nAlgorithm:\n1. Initialize server connection structures and clear connection arrays\n2. Set initial connection state (g_dwConnectionPhase = 2)\n3. Begin server discovery loop scanning for available servers\n4. For each discovered server, create socket connection with 2-second timeout\n5. Build arrays of socket descriptors for select() monitoring\n6. Use select() with 1-second timeout to monitor socket readiness\n7. Handle socket errors by closing failed connections\n8. Handle socket readiness by establishing primary connection\n9. Close all remaining secondary connections once primary is selected\n10. If no servers found, return failure (0)\n11. Establish Battle.net protocol handshake on selected connection\n12. Perform version checking and CD-key validation\n13. Complete authentication sequence and set final connection state\n\nParameters:\nNone (void function)\nIMPLICIT: pbServerListBuffer - Pointer to server list data passed via stack\n\nReturns:\n1 - Successfully connected to game server and completed authentication\n0 - Failed to find servers, connection error, or authentication failure\n\nSpecial Cases:\n- Maximum 32 concurrent server connection attempts (0x20 limit)\n- 60-second overall timeout for server discovery (0x3C counter)\n- 2000ms minimum interval between server scan attempts  \n- Socket descriptor arrays limited to 64 entries (0x40 limit)\n- Connection phase progression: 2\u21923\u21924\u21925 for status tracking\n\nMagic Numbers Reference:\n0x840 (2112) - Stack buffer initialization size in DWORDs\n0x108 (264) - ServerConnection structure size in bytes\n0x100 (256) - Offset to connection handle within ServerConnection\n0x20 (32) - Maximum concurrent connection attempts\n0x3C (60) - Maximum timeout iterations (seconds)\n0x40 (64) - Maximum socket descriptors in fd_set arrays\n0x7D0 (2000) - Minimum milliseconds between server scans\n0x1D (29) - Protocol message ID for handshake\n0x42 (66) - Protocol message ID for authentication\n\nStructure Layout:\nServerConnection (264 bytes total):\nOffset | Size | Field Name    | Type     | Description\n0x000  | 256  | szHostname    | char[256]| Server hostname string\n0x100  | 4    | dwHandle      | DWORD    | Socket connection handle  \n0x104  | 4    | dwReserved    | DWORD    | Reserved/padding\n\nError Handling:\n- select() timeout increments retry counter, exits after 60 attempts\n- Socket errors (select() == -1) logged via WSAGetLastError()  \n- Connection failures close socket and remove from tracking arrays\n- Authentication failures return 0 and close active connection\n- No servers found displays \"no servers found\" message and returns 0",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:46690a701e0b2c8da6416fe1003b68ff"
    },
    "Bnclient_STR_4e7a4d17d1e5": {
      "addresses": {
        "LoD/1.07": "0x6FF237B0",
        "LoD/1.08": "0x6FF237D0",
        "LoD/1.09": "0x6FF04120",
        "LoD/1.09b": "0x6FF04120",
        "LoD/1.09d": "0x6FF044D0",
        "LoD/1.10": "0x6FF04480"
      },
      "rvas": {
        "LoD/1.07": "0x37B0",
        "LoD/1.08": "0x37D0",
        "LoD/1.09": "0x4120",
        "LoD/1.09b": "0x4120",
        "LoD/1.09d": "0x44D0",
        "LoD/1.10": "0x4480"
      },
      "name": "ValidateClientRevision",
      "signature": "int ValidateClientRevision(undefined4 * pdwVersionOut, undefined4 * pdwCheckSumOut, undefined1 * pbHashOut)",
      "comment": "Validates client revision using external checksum verification module.\n\nAlgorithm:\n1. Initialize output parameters to zero if non-null\n2. Store parameter pointers in local variables \n3. Initialize filename buffer for revision DLL (256 bytes)\n4. Wait for packet handler readiness with 20-second timeout\n5. Open version resource file using Ordinal_266\n6. Get version count using Ordinal_251, validate range (1-4)\n7. Copy version filename from global packet handler string\n8. Strip file extension if present using FindCharacterInString\n9. Append \".dll\" suffix to create revision DLL filename\n10. Load revision DLL resource using Ordinal_268\n11. Map resource to memory using Ordinal_265\n12. Initialize memory buffer using Ordinal_401 with source path\n13. Read revision data using Ordinal_269/Ordinal_10107/Ordinal_10111\n14. Clean up resource mapping using Ordinal_403\n15. Load revision DLL using LoadLibraryA\n16. Get CheckRevision function address using GetProcAddress\n17. Initialize path buffers for current module, bnclient.dll, d2client.dll\n18. Get current executable path using GetModuleFileNameA\n19. Copy paths and append respective DLL names\n20. Call CheckRevision function with file paths and output buffers\n21. Free loaded revision DLL using FreeLibrary\n22. Clean up resources and delete temporary files\n23. Return validation result (0=failure, non-zero=success)\n\nParameters:\npdwVersionOut    - Output pointer for version value (can be null)\npdwCheckSumOut   - Output pointer for checksum value (can be null) \npbHashOut        - Output buffer pointer for hash data (can be null)\n\nReturns:\n0   - Validation failed (timeout, file error, or checksum mismatch)\n1   - Timeout waiting for packet handler readiness (20 seconds)\n>1  - Successful validation result from CheckRevision function\n\nSpecial Cases:\nTimeout after 20000ms if packet handler not ready\nVersion count validation: must be 1-4, else fallback string processing\nMissing CheckRevision export: silently continues without validation\nNull parameter handling: safely skips output assignment\nResource mapping failure: continues with cleanup, skips validation\n\nMagic Numbers Reference:\n0xb3 (179)     - Packet handler index for version string access\n0x40 (64)      - Buffer initialization loop count (256 bytes total)\n0x2e (46)      - ASCII period '.' for file extension detection\n0x5c (92)      - ASCII backslash '\\' for path parsing\n0x342 (834)    - Memory allocation parameter for Ordinal_401\n0x35c (860)    - Memory cleanup parameter for Ordinal_403\n0x104 (260)    - MAX_PATH buffer size for GetModuleFileNameA\n0x7fffffff     - String copy length limit (strcpy-like operations)\n20000          - Timeout threshold in milliseconds\n10             - Sleep interval in milliseconds during wait loop\n\nError Handling:\nOrdinal_266 failure: Log error using Ordinal_10029 and return 0\nResource mapping failure: Clean up resources and continue processing\nLoadLibraryA failure: Skip validation, clean up resources, continue\nGetProcAddress failure: Continue without calling CheckRevision function\nAll file operations protected with null checks and proper cleanup\nStack variables cleared with STOSD.REP before filename operations\nTemporary files deleted on exit regardless of success/failure status",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:4e7a4d17d1e5c126ef3a5da2cf607ae8"
    },
    "Bnclient_STR_6756dd2b03e1": {
      "addresses": {
        "LoD/1.10": "0x6FF07FF0"
      },
      "rvas": {
        "LoD/1.10": "0x7FF0"
      },
      "method": "STR",
      "index": "STR:6756dd2b03e117a2f62e8010cf0fcfad"
    },
    "Bnclient_STR_6829c7e2ecf5": {
      "addresses": {
        "LoD/1.11": "0x6FF271B2",
        "LoD/1.11b": "0x6FF27255",
        "LoD/1.12a": "0x6FF272DB",
        "LoD/1.13c": "0x6FF272CA",
        "LoD/1.13d": "0x6FF26FC8"
      },
      "rvas": {
        "LoD/1.11": "0x71B2",
        "LoD/1.11b": "0x7255",
        "LoD/1.12a": "0x72DB",
        "LoD/1.13c": "0x72CA",
        "LoD/1.13d": "0x6FC8"
      },
      "name": "___security_error_handler",
      "signature": "undefined ___security_error_handler(int param_1)",
      "comment": "Library Function - Single Match\n ___security_error_handler\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:6829c7e2ecf5617d1af04a2d6d84fcdc"
    },
    "Bnclient_STR_693ad94f1797": {
      "addresses": {
        "LoD/1.07": "0x6FF24A30",
        "LoD/1.08": "0x6FF24A50",
        "LoD/1.09": "0x6FF053B0",
        "LoD/1.09b": "0x6FF053B0",
        "LoD/1.09d": "0x6FF05620",
        "LoD/1.10": "0x6FF05580",
        "LoD/1.11": "0x6FF33CA0",
        "LoD/1.11b": "0x6FF2EB70",
        "LoD/1.12a": "0x6FF2F000",
        "LoD/1.13c": "0x6FF35030",
        "LoD/1.13d": "0x6FF367A0"
      },
      "rvas": {
        "LoD/1.07": "0x4A30",
        "LoD/1.08": "0x4A50",
        "LoD/1.09": "0x53B0",
        "LoD/1.09b": "0x53B0",
        "LoD/1.09d": "0x5620",
        "LoD/1.10": "0x5580",
        "LoD/1.11": "0x13CA0",
        "LoD/1.11b": "0xEB70",
        "LoD/1.12a": "0xF000",
        "LoD/1.13c": "0x15030",
        "LoD/1.13d": "0x167A0"
      },
      "name": "Unload",
      "signature": "void Unload(void)",
      "comment": "Properly cleanup Battle.net Gateway Access configuration and release allocated resources.\n\nAlgorithm:\n1. Validate that gateway state and buffer pointers are initialized (non-null)\n2. Record gateway list selection string to log file via FUN_6ff295e0\n3. Calculate buffer position for region index digits using Ordinal_506 for length\n4. Convert region index to two-digit decimal representation (tens and units)\n5. Write decimal digits to buffer at calculated position with ASCII conversion\n6. Select appropriate gateway configuration string based on override mode flag\n7. Validate buffer integrity by checking null termination at end positions\n8. Write final gateway configuration to Configuration file via Ordinal_424\n9. Free primary buffer using Ordinal_403 with debug source location 0xb8\n10. Clear primary buffer pointer and end pointer to prevent reuse\n11. Free secondary buffer using Ordinal_403 with debug source location 0xbe\n12. Clear secondary buffer pointer to prevent reuse\n\nParameters:\nIMPLICIT this (BNGatewayAccess*): Gateway access object containing buffers and configuration state\n\nReturns:\nvoid: No return value, cleanup operation always succeeds\n\nSpecial Cases:\nIf buffer validation fails (non-null terminators), triggers fatal error via Ordinal_10023 and FUN_6ff2b29c with exit code 0xffffffff\n\nMagic Numbers Reference:\n0x66666667: Magic constant for fast division by 10 using multiply-shift optimization\n0x4: Offset to gateway state pointer in BNGatewayAccess structure\n0xc: Offset to region index value in BNGatewayAccess structure  \n0x10: Offset to primary buffer pointer in BNGatewayAccess structure\n0x14: Offset to buffer end pointer in BNGatewayAccess structure\n0x1c: Offset to override mode flag in BNGatewayAccess structure\n0x20: Offset to secondary buffer pointer in BNGatewayAccess structure\n0x82: Configuration file operation code for gateway string write\n0xab: Debug error code for buffer validation failure\n0xb8: Debug source location for primary buffer deallocation\n0xbe: Debug source location for secondary buffer deallocation\n\nStructure Layout:\nOffset | Size | Field Name        | Type           | Description\n0x00   | 4    | reserved_0        | uint           | Reserved field\n0x04   | 4    | pState           | void*          | Gateway state pointer\n0x08   | 4    | reserved_8        | uint           | Reserved field  \n0x0c   | 4    | nRegionIndex      | uint           | Battle.net region index\n0x10   | 4    | pBuffer          | char*          | Primary gateway buffer pointer\n0x14   | 4    | pEndBuffer       | char*          | End of primary buffer pointer\n0x18   | 4    | reserved_18       | uint           | Reserved field\n0x1c   | 4    | fOverrideMode    | uint           | Override mode flag (0=default, 1=override)\n0x20   | 4    | pSecondaryBuffer | char*          | Secondary buffer pointer",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:693ad94f179724a1ecd9cfe7a5e143be"
    },
    "Bnclient_STR_6e19490b0e99": {
      "addresses": {
        "LoD/1.08": "0x6FF21050",
        "LoD/1.09": "0x6FF01050",
        "LoD/1.09b": "0x6FF01050",
        "LoD/1.11": "0x6FF26327",
        "LoD/1.11b": "0x6FF24F9B",
        "LoD/1.12a": "0x6FF271AA",
        "LoD/1.13c": "0x6FF2618B",
        "LoD/1.13d": "0x6FF2500B"
      },
      "rvas": {
        "LoD/1.08": "0x1050",
        "LoD/1.09": "0x1050",
        "LoD/1.09b": "0x1050",
        "LoD/1.11": "0x6327",
        "LoD/1.11b": "0x4F9B",
        "LoD/1.12a": "0x71AA",
        "LoD/1.13c": "0x618B",
        "LoD/1.13d": "0x500B"
      },
      "name": "_wctomb",
      "signature": "int _wctomb(char * _MbCh, wchar_t _WCh)",
      "comment": "Library Function - Single Match\n _wctomb\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:6e19490b0e99a8478ca305b26acbc661"
    },
    "Bnclient_STR_777a86ecbe45": {
      "addresses": {
        "LoD/1.11": "0x6FF35430",
        "LoD/1.11b": "0x6FF2DB60",
        "LoD/1.12a": "0x6FF2D1C0",
        "LoD/1.13c": "0x6FF2E2E0",
        "LoD/1.13d": "0x6FF31970"
      },
      "rvas": {
        "LoD/1.11": "0x15430",
        "LoD/1.11b": "0xDB60",
        "LoD/1.12a": "0xD1C0",
        "LoD/1.13c": "0xE2E0",
        "LoD/1.13d": "0x11970"
      },
      "method": "STR",
      "index": "STR:777a86ecbe457446ad27ebc42af51707"
    },
    "Bnclient_STR_7bd3c0df1341": {
      "addresses": {
        "LoD/1.07": "0x6FF26000",
        "LoD/1.08": "0x6FF26020"
      },
      "rvas": {
        "LoD/1.07": "0x6000",
        "LoD/1.08": "0x6020"
      },
      "name": "ReadConfigurationAndSendAuth",
      "signature": "uint ReadConfigurationAndSendAuth(void)",
      "comment": "Reads authentication configuration values and sends network authentication packet.\n\nAlgorithm:\n1. Read \"Registration_Version\" configuration value from \"Configuration\" section into 4-byte buffer\n2. Read \"Registration_Authority\" configuration value from \"Configuration\" section into 4-byte buffer  \n3. Read \"Client_ID\" configuration value from \"Configuration\" section into 4-byte buffer\n4. Read \"Client_Token\" configuration value from \"Configuration\" section into 4-byte buffer\n5. Initialize packet flags to zero (bPacketFlag1 = 0, bPacketFlag2 = 0)\n6. Send network authentication packet with validation using collected configuration data\n7. Return success status (1)\n\nParameters:\n   None - Function takes no parameters\n\nReturns:\n   uint - Always returns 1 (success/completion status)\n\nSpecial Cases:\n   - Configuration reading errors are not explicitly handled in this function\n   - Network packet send failures are not explicitly handled in this function\n   - All configuration values are read as 4-byte binary data regardless of actual content\n\nMagic Numbers:\n   0x2 - Configuration value type parameter for Ordinal_423 calls\n   0x1 - Success return value indicating authentication packet sent",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:7bd3c0df134144137ddf075f5de710df",
      "candidates": {
        "LoD/1.09": {
          "address": "0x6FF13450",
          "rva": "0x13450",
          "confidence": 0.355,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.08"
        },
        "LoD/1.09b": {
          "address": "0x6FF13450",
          "rva": "0x13450",
          "confidence": 0.355,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.08"
        }
      }
    },
    "Bnclient_STR_819a2fd32709": {
      "addresses": {
        "LoD/1.07": "0x6FF2E537",
        "LoD/1.08": "0x6FF2E557",
        "LoD/1.09": "0x6FF0F182",
        "LoD/1.09b": "0x6FF0F182",
        "LoD/1.09d": "0x6FF0F467",
        "LoD/1.10": "0x6FF0FA55",
        "LoD/1.11": "0x6FF2479D",
        "LoD/1.11b": "0x6FF2478D",
        "LoD/1.12a": "0x6FF247FD",
        "LoD/1.13c": "0x6FF247FD",
        "LoD/1.13d": "0x6FF247FD"
      },
      "rvas": {
        "LoD/1.07": "0xE537",
        "LoD/1.08": "0xE557",
        "LoD/1.09": "0xF182",
        "LoD/1.09b": "0xF182",
        "LoD/1.09d": "0xF467",
        "LoD/1.10": "0xFA55",
        "LoD/1.11": "0x479D",
        "LoD/1.11b": "0x478D",
        "LoD/1.12a": "0x47FD",
        "LoD/1.13c": "0x47FD",
        "LoD/1.13d": "0x47FD"
      },
      "name": "DisplayRuntimeError",
      "signature": "void DisplayRuntimeError(uint dwErrorCode)",
      "comment": "Displays runtime error messages using either console or GUI output\n\nAlgorithm:\n1. Search error table at DAT_6ff36ae0 for matching error code\n2. Calculate table index and verify error code match\n3. Check global exit flags to determine output method\n4. If exit flags set (g_dwExitFlag1==1 OR g_dwExitFlag2==1 while g_dwExitFlag1==0):\n   - Write error message directly to stdout using WriteFile\n5. If GUI mode and error code is not 0xFC (assert error):\n   - Get current module filename with GetModuleFileNameA\n   - If filename retrieval fails, use \"<program name unknown>\"\n   - Truncate filename to 60 chars if too long, append \"...\"\n   - Build complete error message with \"Runtime Error!\n\nProgram: \" prefix\n   - Append module name, newline, and error-specific message\n   - Display message box using Microsoft Visual C++ Runtime Library title\n\nParameters:\ndwErrorCode - Error code to look up in runtime error table\n\nReturns:\nvoid - Function does not return value\n\nSpecial Cases:\n- Error code 0xFC bypasses GUI display (assertion error special case)  \n- Module name truncation occurs at 60+ characters\n- Console mode bypasses all GUI formatting\n- Invalid error codes result in no action\n\nStructure Layout:\nErrorTableEntry (8 bytes):\nOffset Size Field         Type     Description\n0x00   4    dwErrorCode   uint     Runtime error identifier\n0x04   4    lpszMessage   char *   Pointer to error message string\n\nMagic Numbers Reference:\n0xFC     - Special assertion error code that bypasses GUI display\n0x104    - Buffer size (260 bytes) for module filename  \n0x3C     - Maximum filename length (60 chars) before truncation\n0x12010  - MessageBox flags: MB_ICONHAND | MB_SYSTEMMODAL\n0x6ff36ae0 - Base address of runtime error lookup table\n0x6ff36b70 - End address of runtime error lookup table\n\nGlobal Variables:\ng_dwExitFlag1 (0x6ff39eac) - Primary exit flag for console output mode\ng_dwExitFlag2 (0x6ff39eb0) - Secondary exit flag for alternate console mode",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:819a2fd327090a03519f87cf5b9aee0d"
    },
    "Bnclient_STR_8315eedfd35b": {
      "addresses": {
        "LoD/1.07": "0x6FF2E2B1",
        "LoD/1.08": "0x6FF2E2D1",
        "LoD/1.09": "0x6FF0EEFC",
        "LoD/1.09b": "0x6FF0EEFC",
        "LoD/1.09d": "0x6FF0F1E1",
        "LoD/1.10": "0x6FF0F7CF"
      },
      "rvas": {
        "LoD/1.07": "0xE2B1",
        "LoD/1.08": "0xE2D1",
        "LoD/1.09": "0xEEFC",
        "LoD/1.09b": "0xEEFC",
        "LoD/1.09d": "0xF1E1",
        "LoD/1.10": "0xF7CF"
      },
      "name": "DetermineHeapCompatibilityMode",
      "signature": "int DetermineHeapCompatibilityMode(void)",
      "comment": "Determines heap compatibility mode based on OS version and environment configuration\n\nAlgorithm:\n1. Call StackProbe() to validate stack space\n2. Initialize version info structure (dwVersionInfoSize = 0x94)\n3. Call GetVersionExA() to retrieve OS version information\n4. Check if OS is Windows NT 5.0+ (dwMajorVersion == 2 AND dwMinorVersion >= 5)\n5. If modern OS: return compatibility mode 1 (standard heap)\n6. If legacy OS: retrieve __MSVCRT_HEAP_SELECT environment variable\n7. Convert environment variable value to uppercase using case conversion loop\n8. Compare against \"__GLOBAL_HEAP_SELECTED\" string (0x16 bytes)\n9. If exact match: use environment buffer as search source\n10. If no match: get module filename via GetModuleFileNameA()\n11. Convert module filename to uppercase using case conversion loop  \n12. Search for module name within environment variable value using _strstr()\n13. If found: locate comma delimiter using FindCharacterInString()\n14. Parse comma-delimited value by null-terminating at semicolon (0x3b)\n15. Invoke network handler with parsed value and parameters (0x0, 0xa)\n16. Return network handler result code (1, 2, or 3)\n17. If parsing fails: call GetPEMachineType() as fallback detection\n18. Calculate final result: 3 - (bZero < 6) where bZero comes from PE analysis\n\nParameters:\nNone\n\nReturns:\n1 - Standard heap mode (modern OS or network handler success)\n2 - Alternative heap mode (network handler alternate result)\n3 - Legacy compatibility mode (network handler legacy result or PE fallback)\n\nSpecial Cases:\n- GetVersionExA() failure: falls through to environment variable processing\n- Environment variable \"__MSVCRT_HEAP_SELECT\" not found: uses PE machine type detection\n- String parsing encounters semicolon (0x3b): null-terminates for parameter isolation\n- Network handler parameter 0xa (10) indicates specific heap selection mode\n\nMagic Numbers Reference:\n0x94 (148) - Size of OSVERSIONINFOA structure\n0x1090 (4240) - Maximum environment variable buffer size  \n0x104 (260) - Maximum module filename buffer size (MAX_PATH)\n0x16 (22) - Length of \"__GLOBAL_HEAP_SELECTED\" comparison string\n0x2c (44) - ASCII comma character for delimiter search\n0x3b (59) - ASCII semicolon character for value termination\n0xa (10) - Network handler mode parameter for heap selection\n0x20 (32) - ASCII case conversion offset (uppercase = lowercase - 32)\n0x61 (97) - ASCII 'a' lower bound for case conversion  \n0x7a (122) - ASCII 'z' upper bound for case conversion\n0x2 (2) - Expected dwMajorVersion for Windows NT\n0x5 (5) - Minimum dwMinorVersion for modern Windows (5.0+)\n\nError Handling:\n- GetVersionExA() failure: continues with legacy compatibility processing\n- Environment variable retrieval failure: uses PE machine type analysis\n- String search failure: bypasses network handler invocation\n- Network handler failure: falls back to PE machine type detection\n\nStructure Layout:\nOSVERSIONINFOA at [EBP + 0xffffff68]:\nOffset | Size | Field Name        | Type  | Description\n0x00   | 4    | dwOSVersionInfoSize | DWORD | Structure size (0x94)\n0x04   | 4    | dwMajorVersion      | DWORD | OS major version number  \n0x08   | 4    | dwMinorVersion      | DWORD | OS minor version number\n0x0C   | 4    | dwBuildNumber       | DWORD | OS build number\n0x10   | 4    | dwPlatformId        | DWORD | Platform identifier\n0x14   | 128  | szCSDVersion        | CHAR[128] | Service pack string",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:8315eedfd35b963ffd4ae4799f93ce60"
    },
    "Bnclient_STR_836f1a5fae39": {
      "addresses": {
        "LoD/1.07": "0x6FF296B0",
        "LoD/1.08": "0x6FF296D0",
        "LoD/1.09": "0x6FF0A2E0",
        "LoD/1.09b": "0x6FF0A2E0",
        "LoD/1.09d": "0x6FF0A530",
        "LoD/1.10": "0x6FF0AD90"
      },
      "rvas": {
        "LoD/1.07": "0x96B0",
        "LoD/1.08": "0x96D0",
        "LoD/1.09": "0xA2E0",
        "LoD/1.09b": "0xA2E0",
        "LoD/1.09d": "0xA530",
        "LoD/1.10": "0xAD90"
      },
      "name": "DecryptDataBlocks",
      "signature": "int DecryptDataBlocks(int * pDataBuffer, uint dwDataSize, int nKeyLength)",
      "comment": "Decrypts data blocks using D2 proprietary block cipher algorithm\n\nAlgorithm:\n1. Validate input parameters (null buffer check, zero key length check)\n2. Initialize decryption context with key length\n3. Return 0 if data size less than 9 bytes (minimum block size)\n4. Calculate working size by subtracting 8-byte header\n5. Verify data size is aligned to 64-byte boundaries (0x3f mask)\n6. Process data in 64-byte blocks using block cipher:\n   a. Copy 64 bytes from input to working buffer\n   b. Generate round key using key derivation function\n   c. Apply cipher transformation based on block count modulo 8\n   d. Perform byte-wise XOR with modular key indexing (mod 0x14)\n   e. Apply additional hash transformation every 16 blocks\n   f. Clear temporary variables and copy result back to input\n7. Validate final block integrity using checksum\n8. Extract padding size from block trailer\n9. Calculate and return actual decrypted data length\n\nParameters:\npDataBuffer - Pointer to input/output data buffer (modified in-place)\nnDataSize - Total size of encrypted data including headers\nnKeyLength - Length of decryption key for context initialization\n\nReturns:\n0 - Decryption failed (invalid data, checksum mismatch, or parameter error)\nNon-zero - Actual decrypted data length (data size minus header minus padding)\n\nMagic Numbers Reference:\n0x90 - Error code for null buffer parameter\n0x91 - Error code for zero key length\n0x3f - Block alignment mask (63 bytes)\n0x40 - Block size (64 bytes)\n0x48 - Header plus minimum padding offset\n0x14 - Key indexing modulo (20 bytes)\n0x80000000 - Loop termination check (signed integer wrap)\n\nError Handling:\n- Null buffer triggers assertion with error code 0x90\n- Zero key length triggers assertion with error code 0x91\n- Data size under 9 bytes returns 0\n- Misaligned data size returns 0\n- Checksum validation failure returns 0",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:836f1a5fae39fce83a9bf7efadeb90e9"
    },
    "Bnclient_STR_88411ff6f1fb": {
      "addresses": {
        "LoD/1.11": "0x6FF2DB60",
        "LoD/1.11b": "0x6FF2BB00",
        "LoD/1.12a": "0x6FF2DF80",
        "LoD/1.13c": "0x6FF2F0A0"
      },
      "rvas": {
        "LoD/1.11": "0xDB60",
        "LoD/1.11b": "0xBB00",
        "LoD/1.12a": "0xDF80",
        "LoD/1.13c": "0xF0A0"
      },
      "method": "STR",
      "index": "STR:88411ff6f1fb3ed12824bc239d67c35f"
    },
    "Bnclient_STR_91948caf7151": {
      "addresses": {
        "LoD/1.07": "0x6FF25170",
        "LoD/1.08": "0x6FF25190",
        "LoD/1.09": "0x6FF05AF0",
        "LoD/1.09b": "0x6FF05AF0",
        "LoD/1.09d": "0x6FF05D60",
        "LoD/1.10": "0x6FF05CD0"
      },
      "rvas": {
        "LoD/1.07": "0x5170",
        "LoD/1.08": "0x5190",
        "LoD/1.09": "0x5AF0",
        "LoD/1.09b": "0x5AF0",
        "LoD/1.09d": "0x5D60",
        "LoD/1.10": "0x5CD0"
      },
      "name": "UpdateGatewaysFromIni",
      "signature": "void UpdateGatewaysFromIni(char * lpszConfigPath)",
      "comment": "Updates Battle.net gateway configuration from INI file containing server list and gateway entries.\n\nAlgorithm:\n1. Calculate length of config path parameter using strlen-style loop\n2. Find \"Server List Version\" section in config data, abort if missing  \n3. Search for version marker string in section data to locate version number\n4. Parse version number from section data using base-10 conversion\n5. Compare version against current stored version, exit early if not newer\n6. Initialize timezone context: get system timezone if no gateway data exists, otherwise use existing gateway timezone\n7. Clear gateway state flags and set processing flag in BNGatewayAccess structure\n8. Allocate double-length buffer for gateway data assembly\n9. Copy base path template and append \"00\" version suffix to buffer\n10. Find \"Server_Gateways\" section for gateway enumeration\n11. For each gateway entry in config: parse gateway name, find corresponding IP section, extract IP and port data\n12. Validate final buffer has proper null termination (two consecutive nulls)\n13. Store new gateway buffer and length in BNGatewayAccess structure\n14. Select closest timezone-appropriate gateway and reload gateway system\n\nParameters:\nlpszConfigPath (char *): Path to INI configuration file containing gateway definitions\nIMPLICIT this (BNGatewayAccess *): Gateway manager object in ECX register\n\nReturns:\nvoid: No return value, but updates gateway configuration state\n\nSpecial Cases:\nMagic Numbers Reference:\n0x236 - Error code for missing Server List Version section\n0x23b - Error code for missing version data in section  \n0x256 - Memory allocation line number for gateway buffer\n0x2a5 - Error code for buffer overflow during gateway assembly\n0x2a7 - Error code for invalid buffer termination\n0x18 - Offset to version field in BNGatewayAccess structure (4-byte)\n0x10 - Offset to gateway buffer pointer (4-byte)  \n0x14 - Offset to buffer length field (4-byte)\n0xc - Offset to gateway count field (4-byte)\n0x8 - Offset to max gateway field (4-byte)\n0x4 - Offset to flags field (4-byte) \n0x1c - Offset to secondary flags field (4-byte)\n1 - Processing active flag value\n0x30 - ASCII '0' character for version suffix\n0x5d - ASCII ']' character marking section end\n0xd - ASCII carriage return character  \n0xa - ASCII line feed character\n0x3ff - Language ID mask (1023) for primary language\n9 - English language code  \n0xfc00 - Sublanguage mask for secondary language\n0xc00 - US English sublanguage code\n0x1e0 - Default timezone bias (480 minutes = -8 hours PST)\n0x3c - Conversion factor (60 seconds per minute)\n\nError Handling:\nMissing Server List Version section triggers fatal error 0x236\nMissing version data in section triggers fatal error 0x23b  \nBuffer overflow during assembly triggers fatal error 0x2a5\nInvalid buffer termination triggers fatal error 0x2a7\nAll errors call Ordinal_10023 for logging then FUN_6ff2b29c(-1) for termination\n\nFlag Bits:\n0x4+0 - Processing active flag (set to 1 during update)\n0x1c+0 - Secondary processing flag (cleared to 0 before processing)\n\nStructure Layout:\nBNGatewayAccess Offsets:\n0x4 - Processing flags (4 bytes) \n0x8 - Max gateway count (4 bytes)\n0xc - Current gateway count (4 bytes)  \n0x10 - Gateway buffer pointer (4 bytes)\n0x14 - Buffer length (4 bytes)\n0x18 - Version number (4 bytes)\n0x1c - Secondary flags (4 bytes)",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:91948caf7151a578f03059bd18a3760d"
    },
    "Bnclient_STR_920689ad3799": {
      "addresses": {
        "LoD/1.07": "0x6FF27CF0",
        "LoD/1.08": "0x6FF27D10",
        "LoD/1.09": "0x6FF08920",
        "LoD/1.09b": "0x6FF08920",
        "LoD/1.09d": "0x6FF08B80",
        "LoD/1.10": "0x6FF09500",
        "LoD/1.11": "0x6FF31DA0",
        "LoD/1.11b": "0x6FF32410",
        "LoD/1.12a": "0x6FF30E90",
        "LoD/1.13c": "0x6FF34050",
        "LoD/1.13d": "0x6FF30010"
      },
      "rvas": {
        "LoD/1.07": "0x7CF0",
        "LoD/1.08": "0x7D10",
        "LoD/1.09": "0x8920",
        "LoD/1.09b": "0x8920",
        "LoD/1.09d": "0x8B80",
        "LoD/1.10": "0x9500",
        "LoD/1.11": "0x11DA0",
        "LoD/1.11b": "0x12410",
        "LoD/1.12a": "0x10E90",
        "LoD/1.13c": "0x14050",
        "LoD/1.13d": "0x10010"
      },
      "name": "ValidateAndReadCacheEntry",
      "signature": "int ValidateAndReadCacheEntry(byte * pbFileName, uint dwOutData, int * pnAllocatedBuffer, LPDWORD pdwDataSize)",
      "comment": "Validates cache entry integrity and reads cached file data from BnCache.dat\n\nAlgorithm:\n1. Initialize output parameters to zero for safe error handling\n2. Validate all input parameters are non-NULL\n3. Check global cache system is initialized (g_abGlobalStringBuffer._440_4_)\n4. Enter critical section for thread-safe cache access\n5. Compute filename hash using iterative character processing with XOR and multiplication\n6. Calculate secondary hashes using ComputeStringHashWithContext for hash table lookup\n7. Search cache hash table using open addressing with linear probing\n8. If cache entry not found, exit with failure (cache miss)\n9. Validate cache entry timestamp against current system time\n10. Handle cache entry based on compression flags (0xc0000000 mask)\n11. For compressed entries: read header, validate CRC32, decompress data\n12. For uncompressed entries: read data directly and validate CRC32\n13. Compare computed CRC32 against stored value for integrity verification\n14. On corruption: trigger cache rebuilding and entry invalidation loop\n15. On success: allocate buffer, read file data, return buffer pointer and size\n16. On error: cleanup allocated resources and cache file deletion\n17. Exit critical section and return success (1) or failure (0)\n\nParameters:\npbFileName (const byte *): Target filename for cache lookup\nppOutData (undefined4 **): Output pointer for cache metadata (may be NULL)\npnAllocatedBuffer (int *): Output pointer to allocated data buffer\npdwDataSize (LPDWORD): Output size of read data in bytes\n\nReturns:\n1: Cache entry successfully validated and data read\n0: Cache miss, corruption detected, or validation failure\n\nSpecial Cases:\nFile timestamp validation prevents stale cache usage after file modifications\nCache rebuilding triggered on any corruption detection (codes 1-4)\nEntry invalidation marks slots as 0xfffffffe for reuse\nMemory allocation errors trigger fatal error handlers (Ordinal_10023, FUN_6ff2b29c)\n\nMagic Numbers Reference:\n0x7fed7fed: Initial hash seed for filename processing\n-0x11111112 (0xeeeeeeee): Secondary hash accumulator seed  \n0x21 (33): Hash multiplier constant for character folding\n0x144 (324): Cache header size for CRC32 validation\n0xc0000000: Compression flag mask for entry type detection\n0xffffffff: Empty hash slot marker in cache table\n0xfffffffe: Invalidated entry marker for cleanup\n0x1000001: Maximum allowed cache entry size validation\n0x5c (92): Backslash character code for path processing\n\nError Handling:\nnErrorCode 1-7: File I/O errors (read failures, size mismatches)\nnCorruptionCode 1-4: Integrity failures (CRC mismatches, header corruption)\nCache file deletion and reinitialization on persistent corruption\nResource cleanup ensures no memory leaks on error paths\n\nCRC32 Implementation:\nUses g_adwCrc32LookupTable for polynomial 0xEDB88320 (IEEE 802.3)\nProcesses data byte-by-byte with XOR and shift operations\nInitial value 0xffffffff, final result bitwise inverted (~)\nValidates both header (324 bytes) and payload data integrity",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:920689ad3799d2580e3b092c17b80586"
    },
    "Bnclient_STR_98a90bc414b3": {
      "addresses": {
        "LoD/1.12a": "0x6FF35C30",
        "LoD/1.13c": "0x6FF31780",
        "LoD/1.13d": "0x6FF2CCE0"
      },
      "rvas": {
        "LoD/1.12a": "0x15C30",
        "LoD/1.13c": "0x11780",
        "LoD/1.13d": "0xCCE0"
      },
      "method": "STR",
      "index": "STR:98a90bc414b338826eb1311699b2b5ab"
    },
    "Bnclient_STR_9cf5b89b3eb4": {
      "addresses": {
        "LoD/1.07": "0x6FF29970",
        "LoD/1.08": "0x6FF29990",
        "LoD/1.09": "0x6FF0A5A0",
        "LoD/1.09b": "0x6FF0A5A0",
        "LoD/1.09d": "0x6FF0A7F0",
        "LoD/1.10": "0x6FF0B050",
        "LoD/1.11": "0x6FF2F8F0",
        "LoD/1.11b": "0x6FF36180",
        "LoD/1.12a": "0x6FF321D0",
        "LoD/1.13c": "0x6FF362B0",
        "LoD/1.13d": "0x6FF35D10"
      },
      "rvas": {
        "LoD/1.07": "0x9970",
        "LoD/1.08": "0x9990",
        "LoD/1.09": "0xA5A0",
        "LoD/1.09b": "0xA5A0",
        "LoD/1.09d": "0xA7F0",
        "LoD/1.10": "0xB050",
        "LoD/1.11": "0xF8F0",
        "LoD/1.11b": "0x16180",
        "LoD/1.12a": "0x121D0",
        "LoD/1.13c": "0x162B0",
        "LoD/1.13d": "0x15D10"
      },
      "name": "GenerateAuthenticationCredentials",
      "signature": "void GenerateAuthenticationCredentials(void)",
      "comment": "Generates encrypted authentication credentials for CD key and user account validation.\n\nAlgorithm:\n1. Check if global string buffers are already populated and terminate if so\n2. Format initial credential string using template parameters\n3. Clear global buffer flags and prepare for encryption  \n4. Call Ordinal_279 to request credential data with formatted string\n5. If credential data received, generate 19-character random key using seeded random numbers\n6. Decrypt credential data using DecryptDataBlocks with random key\n7. Validate decrypted data length and null-terminate if valid\n8. Process character permutation using scrambled template data:\n   - Copy template data from global credential template to local buffer\n   - Initialize permutation table with hardcoded byte sequences  \n   - Apply character permutation using table indices to rearrange credential data\n9. Store processed credentials in global buffer and repeat process for second credential type\n10. If GetGlobalStateValue indicates special mode, process third credential type with extended template\n11. Clear local buffers and return\n\nParameters:\nNone\n\nReturns:\nvoid - Updates global g_abGlobalStringBuffer with encrypted credential data\n\nSpecial Cases:\n- Early termination if g_abGlobalStringBuffer._504_4_ or g_abGlobalStringBuffer._512_4_ already set\n- Uses hardcoded permutation tables for character scrambling\n- Generates exactly 19 random characters for encryption key (0x13 = 19)\n- Maximum decrypted data length limited to 128 bytes (0x80 = 128)\n- Three different credential templates used based on context\n\nMagic Numbers Reference:\n0x212 (530) - Error code for credential assertion\n0x150b (5387) - Random seed value for credential generation\n0x13 (19) - Random key length in characters\n0x80 (128) - Maximum credential data length limit\n0x6ff39bec - Hash table address for first credential type  \n0x6ff39be0 - Hash table address for second credential type\n0x6ff39bdc - Hash table address for third credential type\n\nError Handling:\n- FUN_6ff2b29c terminates process if credentials already exist\n- Ordinal_280 frees allocated memory on decryption failure\n- Zero-fills credential buffers if decryption fails or data invalid\n- All encryption operations validated before buffer updates",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:9cf5b89b3eb4e1c534c272c9e84b18bb"
    },
    "Bnclient_STR_a3bfc416695d": {
      "addresses": {
        "LoD/1.07": "0x6FF25AC0",
        "LoD/1.08": "0x6FF25AE0",
        "LoD/1.09": "0x6FF06440",
        "LoD/1.09b": "0x6FF06440",
        "LoD/1.09d": "0x6FF066B0",
        "LoD/1.10": "0x6FF06610"
      },
      "rvas": {
        "LoD/1.07": "0x5AC0",
        "LoD/1.08": "0x5AE0",
        "LoD/1.09": "0x6440",
        "LoD/1.09b": "0x6440",
        "LoD/1.09d": "0x66B0",
        "LoD/1.10": "0x6610"
      },
      "name": "GetGlobalContextValues",
      "signature": "ULONG GetGlobalContextValues(ValuePair * pOutputValues)",
      "comment": "Thread-safely retrieve and copy two global context values to output structure.\n\nAlgorithm:\n1. Validate pOutputValues parameter is not null, exit with error if null\n2. Acquire critical section lock on global buffer synchronization object  \n3. Copy two consecutive ULONG values from global buffer to output structure\n4. Clear 4 bytes at end of global buffer (reset operation flags)\n5. Release critical section lock\n6. Return success status (1)\n\nParameters:\npOutputValues - ValuePair * - Pointer to output structure receiving the two context values\n                              Structure contains dwValue1 and dwValue2 fields (8 bytes total)\n\nReturns:\n1 - Success, context values copied successfully \nFunction does not return on null parameter (calls exit handler)\n\nSpecial Cases:\nNull parameter triggers assertion failure and process termination via FUN_6ff2b29c\nCritical section ensures thread-safe access to global context storage\nBuffer reset operation (zeroing bytes 0x14c-0x14f) clears status flags\n\nMagic Numbers Reference:\n0x130 - Offset to critical section object in global buffer\n0x328 - Offset to second context value (dwValue2) in global buffer  \n0x332 - Offset to first context value (dwValue1) in global buffer\n0x14c-0x14f - Status flag bytes cleared after value retrieval\n0xd6 - Error line number for assertion failure\n0xffffffff - Exit code for process termination\n\nStructure Layout:\nValuePair structure (8 bytes):\nOffset | Size | Field Name | Type  | Description\n-------|------|------------|-------|----------------------------------\n0x00   | 4    | dwValue1   | ULONG | First global context value\n0x04   | 4    | dwValue2   | ULONG | Second global context value",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:a3bfc416695df49da2b2b674038696f4",
      "candidates": {
        "LoD/1.11": {
          "address": "0x6FF2AFE0",
          "rva": "0xAFE0",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.12a": {
          "address": "0x6FF32F40",
          "rva": "0x12F40",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        },
        "LoD/1.13c": {
          "address": "0x6FF2B5F0",
          "rva": "0xB5F0",
          "confidence": 0.295,
          "method": "structural",
          "direction": "forward",
          "source": "LoD/1.10"
        }
      }
    },
    "Bnclient_STR_a5bbf7efb063": {
      "addresses": {
        "LoD/1.11": "0x6FF34B00",
        "LoD/1.11b": "0x6FF2CBA0",
        "LoD/1.12a": "0x6FF2C200",
        "LoD/1.13c": "0x6FF2D320",
        "LoD/1.13d": "0x6FF31090"
      },
      "rvas": {
        "LoD/1.11": "0x14B00",
        "LoD/1.11b": "0xCBA0",
        "LoD/1.12a": "0xC200",
        "LoD/1.13c": "0xD320",
        "LoD/1.13d": "0x11090"
      },
      "method": "STR",
      "index": "STR:a5bbf7efb0638d0c2252aec0ffbee74a"
    },
    "Bnclient_STR_abcfa6d8132b": {
      "addresses": {
        "LoD/1.07": "0x6FF23BE0",
        "LoD/1.08": "0x6FF23C00",
        "LoD/1.09": "0x6FF04560",
        "LoD/1.09b": "0x6FF04560",
        "LoD/1.09d": "0x6FF047E0",
        "LoD/1.10": "0x6FF04780",
        "LoD/1.11": "0x6FF34DF0",
        "LoD/1.11b": "0x6FF2CE90",
        "LoD/1.12a": "0x6FF2C4F0",
        "LoD/1.13c": "0x6FF2D610",
        "LoD/1.13d": "0x6FF31330"
      },
      "rvas": {
        "LoD/1.07": "0x3BE0",
        "LoD/1.08": "0x3C00",
        "LoD/1.09": "0x4560",
        "LoD/1.09b": "0x4560",
        "LoD/1.09d": "0x47E0",
        "LoD/1.10": "0x4780",
        "LoD/1.11": "0x14DF0",
        "LoD/1.11b": "0xCE90",
        "LoD/1.12a": "0xC4F0",
        "LoD/1.13c": "0xD610",
        "LoD/1.13d": "0x11330"
      },
      "name": "ProcessBatchFileCommands",
      "signature": "uint ProcessBatchFileCommands(uint * pnStatusOut)",
      "comment": "Processes a batch file line-by-line, parsing commands and executing them sequentially.\n\nAlgorithm:\n1. Validate status output pointer parameter (pdwStatusOut)\n2. Initialize module filename buffer and get current executable path\n3. Find directory separator and null-terminate directory path\n4. Open batch file for reading using file I/O operations\n5. Parse each line from batch file data:\n   a. Read line into buffer, stopping at CR/LF or buffer limit\n   b. Skip whitespace and parse command type\n   c. Process command based on type:\n      - \"delete\": Remove specified file using DeleteFileA\n      - \"extract\": Extract file data and optionally save to disk\n      - \"execute\": Build command line and add to execution queue\n6. Build final command line by concatenating all \"execute\" commands\n7. Add default game executable if no commands specified\n8. Execute all commands sequentially using CreateProcessA\n9. Wait for each process to complete before launching next\n10. Set appropriate status code and return success/failure\n\nParameters:\npdwStatusOut (uint *): Pointer to receive operation status code\nIMPLICIT pnStatusOut (ECX): Status output pointer passed via ECX register\n\nReturns:\n1 (0x1): All commands processed successfully\n0 (0x0): Error occurred during processing or execution failed\n\nSpecial Cases:\nIf pdwStatusOut is NULL, calls error handler and terminates\nIf batch file cannot be opened or read, sets status to 0 and returns 0\nIf no commands found in batch file, sets status to 2 and returns 1\nIf process creation fails, sets status to 0xFFFFFFFF and returns 0\nEmpty command lines are skipped during execution\n\nMagic Numbers Reference:\n0x104 (260): MAX_PATH buffer size for module filename\n0x44 (68): Size of STARTUPINFOA structure\n0x20 (32): CREATE_NO_WINDOW process creation flag\n0x7 (7): Length of \"delete\" command string\n0x8 (8): Length of \"extract\" and \"execute\" command strings\n0xFF (255): Maximum line buffer size for command parsing\n0x40 (64): Buffer initialization loop count (256 bytes / 4)\n0x3F (63): Buffer initialization loop count (252 bytes / 4)\n0xFFFFFFFF: Error status code for failed operations\n0x2: Status code indicating successful completion with no commands\n\nError Handling:\nFile I/O errors result in immediate cleanup and return 0\nProcess creation failures set error status and return 0\nMemory allocation failures trigger error handler termination\nInvalid command formats are silently skipped\nNull pointer validation prevents crashes on invalid parameters\n\nBuffer Management:\nUses multiple stack buffers for file paths, command lines, and data\nModule path buffer: 0x104 bytes at stack offset 0x34\nBatch file buffer: 0x3FF bytes at stack offset 0x818  \nCommand line buffer: 0x3FF bytes at stack offset 0xC18\nLine parsing buffer: 0xFF bytes at stack offset 0x17C\nTemporary buffers: 0x103 bytes each for path manipulation",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:abcfa6d8132b6d30e796c310bbaaa7d1"
    },
    "Bnclient_STR_adbd2e7032fe": {
      "addresses": {
        "LoD/1.07": "0x6FF24DC0",
        "LoD/1.08": "0x6FF24DE0",
        "LoD/1.09": "0x6FF05740",
        "LoD/1.09b": "0x6FF05740",
        "LoD/1.09d": "0x6FF059B0",
        "LoD/1.10": "0x6FF05920"
      },
      "rvas": {
        "LoD/1.07": "0x4DC0",
        "LoD/1.08": "0x4DE0",
        "LoD/1.09": "0x5740",
        "LoD/1.09b": "0x5740",
        "LoD/1.09d": "0x59B0",
        "LoD/1.10": "0x5920"
      },
      "name": "GetGatewayList",
      "signature": "void GetGatewayList(BNGatewayAccess * this, char * lpszConfigKey)",
      "comment": "Retrieves and parses Battle.net gateway configuration list from INI configuration.\n\nAlgorithm:\n1. Validate existing buffer state - exit with fatal error if buffer already allocated\n2. Initialize temporary buffer pointer to null for configuration data\n3. Call Ordinal_421 to query configuration size for the specified key\n4. Validate configuration exists and size query succeeded  \n5. Store buffer end pointer and allocate memory buffer via Ordinal_401\n6. Call Ordinal_421 again to read actual configuration data into allocated buffer\n7. Handle allocation failure by freeing buffer and resetting pointers to null\n8. Initialize reserved counter field to zero for gateway count tracking\n9. Parse gateway list using FUN_6ff2bb3d with newline delimiter (0xa)\n10. Store parsed gateway count in reserved_18 field\n11. Reset count to zero if parse operation failed (buffer pointer unchanged)\n\nParameters:\nthis - BNGatewayAccess instance containing buffer pointers and gateway count\nlpszConfigKey - Configuration key name for gateway list section (e.g. \"regionList\")\n\nReturns:\nvoid - Function modifies object state directly through member variables\n\nSpecial Cases:\nFatal error (no return) if pBuffer already allocated - prevents memory leaks\nConfiguration missing or empty - leaves object in clean null state\nParse failure - resets gateway count to zero but preserves allocated buffer\n\nMagic Numbers Reference:\n0x82 - Configuration query flags for INI file operations\n0x138 - Error code line number for buffer already allocated assertion  \n0x148 - Error code line number for memory allocation operation\n0x150 - Error code line number for memory deallocation operation\n0xa - ASCII newline character used as gateway entry delimiter\n\nError Handling:\nBuffer allocation failure - automatic cleanup via Ordinal_403 and pointer reset\nParse failure detection - gateway count reset prevents invalid iteration\nFatal assertions - immediate termination via FUN_6ff2b29c(-1) for contract violations\n\nStructure Layout:\nBNGatewayAccess object accessed fields:\nOffset  Size  Field Name    Type     Description\n+0x10   4     pBuffer       char*    Start of allocated gateway data buffer  \n+0x14   4     pEndBuffer    char*    End boundary of allocated buffer\n+0x18   4     reserved_18   uint     Number of parsed gateway entries",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:adbd2e7032febe9f90c19211a566ff78"
    },
    "Bnclient_STR_b10883b0775b": {
      "addresses": {
        "LoD/1.07": "0x6FF27450",
        "LoD/1.08": "0x6FF27470",
        "LoD/1.09": "0x6FF08080",
        "LoD/1.09b": "0x6FF08080",
        "LoD/1.09d": "0x6FF082E0",
        "LoD/1.10": "0x6FF08CC0",
        "LoD/1.11": "0x6FF3124D",
        "LoD/1.11b": "0x6FF318BD",
        "LoD/1.12a": "0x6FF3033D",
        "LoD/1.13c": "0x6FF334FD",
        "LoD/1.13d": "0x6FF2F4BD"
      },
      "rvas": {
        "LoD/1.07": "0x7450",
        "LoD/1.08": "0x7470",
        "LoD/1.09": "0x8080",
        "LoD/1.09b": "0x8080",
        "LoD/1.09d": "0x82E0",
        "LoD/1.10": "0x8CC0",
        "LoD/1.11": "0x1124D",
        "LoD/1.11b": "0x118BD",
        "LoD/1.12a": "0x1033D",
        "LoD/1.13c": "0x134FD",
        "LoD/1.13d": "0xF4BD"
      },
      "name": "InitializeCacheManager",
      "signature": "int InitializeCacheManager(void)",
      "comment": "Initialize and manage the Battle.net cache file system for Diablo II\n\nAlgorithm:\n1. Enter critical section to protect global cache state\n2. Clean up existing cache resources if already initialized\n3. Get executable module path and construct cache file path\n4. Append \"\\\\bncache.dat\" suffix to module directory path\n5. Attempt to open cache file for reading with exclusive access\n6. If file doesn't exist, jump to cache creation/initialization sequence\n7. Allocate 0x1400 bytes for encryption lookup tables and fill with pseudorandom sequence\n8. Allocate 0x2C bytes for cache header structure\n9. Read file size and validate it's within acceptable bounds (0 < size <= 0xA00000)\n10. Read 0x2C byte header and validate magic signature (0x1A334E42 for valid, 0x1A324E42 for old format)\n11. Calculate CRC-32 checksum of header excluding checksum field\n12. Verify header checksum matches calculated value\n13. Validate header fields are non-zero (hash table offset/size, block table offset/size)\n14. Calculate required hash table size (minimum 0x400 entries, 0x10 bytes each)\n15. Allocate memory for hash table and read from file at specified offset\n16. Calculate CRC-32 checksum of hash table data\n17. Verify hash table checksum matches header value\n18. Generate hash key from hardcoded string \"hash_table\" using encryption tables\n19. Decrypt hash table using generated key and custom algorithm\n20. Calculate required block table size (minimum 0x400 entries, 0x10 bytes each)\n21. Allocate memory for block table and read from file at specified offset\n22. Calculate CRC-32 checksum of block table data\n23. Verify block table checksum matches header value\n24. Generate hash key from hardcoded string \"block_table\" using encryption tables\n25. Decrypt block table using generated key and custom algorithm\n26. Mark cache as successfully initialized in global state\n27. Exit critical section and return success\n\nError Handling:\n- If any validation fails, clean up allocated resources and attempt cache recreation\n- Cache creation involves: deleting old file, creating new file, initializing headers\n- Initialize hash table with 0xFFFFFFFF entries, block table with allocated memory\n- Set magic signature 0x1A334E42, calculate offsets and sizes\n- All memory allocation failures result in fatal error with exit code -1\n\nParameters:\nNone\n\nReturns:\n1 on successful cache initialization or creation\n0 on critical failure (file access error after cleanup attempts)\n\nSpecial Cases:\n- Old cache format (0x1A324E42) triggers immediate recreation\n- File size outside bounds (0, 0xA00000] triggers recreation  \n- Any checksum mismatch triggers recreation with warning\n- Memory allocation uses custom heap allocator (Ordinal_401/403)\n- Critical section protects against concurrent cache access\n\nMagic Numbers:\n0x1A334E42 (459967042) - Valid cache file magic signature\n0x1A324E42 (459901506) - Obsolete cache file magic signature requiring rebuild\n0xA00000 (10485760) - Maximum allowed cache file size (10MB)\n0x400 (1024) - Minimum hash/block table entry count\n0x10 (16) - Size of each hash/block table entry\n0x2C (44) - Size of cache header structure\n0x1400 (5120) - Size of encryption lookup tables\n0x4000 (16384) - Default allocation size for hash/block tables\n\nCRC-32 Algorithm:\n- Uses lookup table at 0x6ff35e14 with standard polynomial\n- Initial value 0xFFFFFFFF, result inverted after processing\n- Processes data byte-by-byte: crc = (crc >> 8) ^ table[(crc & 0xFF) ^ byte]\n\nStructure Layout:\nCache Header (44 bytes at file offset 0):\nOffset Size Field Name    Type    Description\n0x00   4    dwMagic       uint    File format magic number\n0x04   4    dwHeaderSize  uint    Size of header (0x2C)\n0x08   4    dwMaxSize     uint    Maximum allocated size\n0x0C   4    dwReserved    uint    Reserved field\n0x10   4    dwHashOffset  uint    File offset to hash table\n0x14   4    dwBlockOffset uint    File offset to block table\n0x18   4    dwHashCount   uint    Number of hash table entries\n0x1C   4    dwBlockCount  uint    Number of block table entries  \n0x20   4    dwHashCrc     uint    CRC-32 of hash table data\n0x24   4    dwBlockCrc    uint    CRC-32 of block table data\n0x28   4    dwHeaderCrc   uint    CRC-32 of header (excluding this field)",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:b10883b0775b8a7b6b8785defd3454d5"
    },
    "Bnclient_STR_b30fdbac17cb": {
      "addresses": {
        "LoD/1.07": "0x6FF247B0",
        "LoD/1.08": "0x6FF247D0",
        "LoD/1.09": "0x6FF05130",
        "LoD/1.09b": "0x6FF05130",
        "LoD/1.09d": "0x6FF053B0",
        "LoD/1.10": "0x6FF05320",
        "LoD/1.11": "0x6FF33DA0",
        "LoD/1.11b": "0x6FF2EC70",
        "LoD/1.12a": "0x6FF2F100",
        "LoD/1.13c": "0x6FF35130",
        "LoD/1.13d": "0x6FF368A0"
      },
      "rvas": {
        "LoD/1.07": "0x47B0",
        "LoD/1.08": "0x47D0",
        "LoD/1.09": "0x5130",
        "LoD/1.09b": "0x5130",
        "LoD/1.09d": "0x53B0",
        "LoD/1.10": "0x5320",
        "LoD/1.11": "0x13DA0",
        "LoD/1.11b": "0xEC70",
        "LoD/1.12a": "0xF100",
        "LoD/1.13c": "0x15130",
        "LoD/1.13d": "0x168A0"
      },
      "name": "PickClosestZone",
      "signature": "void PickClosestZone(BNGatewayAccess * this, int nTargetTime)",
      "comment": "Finds the gateway server closest to a specified target time by analyzing timezone offsets.\n\nAlgorithm:\n1. Initialize logging and output debug message about target time search\n2. Initialize minimum distance to 1380 (0x564) and set starting zone index to 1\n3. Loop through all available gateway zones with multiplier starting at 3\n4. For each zone, validate gateway buffer bounds and navigate to zone data\n5. Call string length function (Ordinal_506) to advance buffer pointer\n6. Calculate timezone offset using FUN_6ff2b921 with parameter 0xa (10)\n7. Compute absolute time difference: abs((offset * 60) - targetTime)\n8. Update closest zone if current distance is smaller than minimum\n9. Increment zone index and multiplier by 3 for next iteration\n10. Navigate to the selected closest gateway using calculated index\n11. Perform final timezone calculation for selected gateway\n12. Output debug message with selected gateway information\n13. Set gateway index in structure offset 0xc (max 99, clamped to 0x63)\n14. Set status flag in structure offset 4 to indicate selection complete\n\nParameters:\nthis - BNGatewayAccess structure pointer containing gateway data\nnTargetTime - Target time value to find closest timezone match\n\nReturns:\nvoid - Updates gateway index and status in BNGatewayAccess structure\n\nSpecial Cases:\nSelected zone index clamped to maximum value 99 (0x63) if exceeded\n\nMagic Numbers Reference:\n0x564 (1380) - Initial maximum distance threshold for zone comparison\n0x3c (60) - Conversion factor from minutes to seconds for time calculations\n0xa (10) - Parameter passed to timezone calculation function FUN_6ff2b921\n0x63 (99) - Maximum allowed gateway zone index value\n\nStructure Layout:\nOffset | Size | Field Name           | Type | Description\n0x04   | 4    | dwStatusFlags        | uint | Gateway selection status (1=selected)\n0x08   | 4    | nGatewayCount        | int  | Number of available gateways\n0x0c   | 4    | nSelectedGatewayIndex| int  | Index of selected gateway (0-99)\n0x10   | 4    | pGatewayBuffer       | ptr  | Pointer to gateway string data buffer\n0x14   | 4    | nBufferSize          | int  | Size limit of gateway buffer data",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:b30fdbac17cba3dc936a0a6deae65420"
    },
    "Bnclient_STR_b7a52aed3655": {
      "addresses": {
        "LoD/1.07": "0x6FF2D14C",
        "LoD/1.08": "0x6FF2D16C",
        "LoD/1.09": "0x6FF0DD6C",
        "LoD/1.09b": "0x6FF0DD6C",
        "LoD/1.09d": "0x6FF0E07C",
        "LoD/1.10": "0x6FF0E5E4",
        "LoD/1.11": "0x6FF22E15",
        "LoD/1.11b": "0x6FF223A6",
        "LoD/1.12a": "0x6FF2347C",
        "LoD/1.13c": "0x6FF22854",
        "LoD/1.13d": "0x6FF2241B"
      },
      "rvas": {
        "LoD/1.07": "0xD14C",
        "LoD/1.08": "0xD16C",
        "LoD/1.09": "0xDD6C",
        "LoD/1.09b": "0xDD6C",
        "LoD/1.09d": "0xE07C",
        "LoD/1.10": "0xE5E4",
        "LoD/1.11": "0x2E15",
        "LoD/1.11b": "0x23A6",
        "LoD/1.12a": "0x347C",
        "LoD/1.13c": "0x2854",
        "LoD/1.13d": "0x241B"
      },
      "name": "FormatStringProcessor",
      "signature": "int FormatStringProcessor(int * pOutputHandler, byte * pbFormatString, uint * ppnArgsPtr)",
      "comment": "FormatStringProcessor - processes printf-style format strings with variable arguments\n\nAlgorithm:\n1. Initialize state variables: dwFlags=0, nStateIndex=0, nCharCount=0\n2. Begin character-by-character processing loop of format string\n3. For each character, determine processing state using lookup table at 0x6ff333e0\n4. Execute state machine transitions based on current state (0-7):\n   - State 0: Output literal characters, handle character attributes\n   - State 1: Initialize format specifier parsing, reset all flags\n   - State 2: Parse format flags: space(0x02), hash(0x80), plus(0x01), minus(0x04), zero(0x08)\n   - State 3: Parse field width (decimal digits or asterisk for va_arg)\n   - State 4: Encountered decimal point, prepare for precision parsing\n   - State 5: Parse precision (decimal digits or asterisk for va_arg)  \n   - State 6: Parse length modifiers: I64(0x8000), h(0x20), l(0x10), w(0x800)\n   - State 7: Process conversion specifiers and generate output\n5. For conversion specifiers: handle integer(d,i,u,o,x,X), float(e,E,f,g,G), character(c,C), string(s,S), pointer(p), written count(n)\n6. Apply formatting: field width padding, precision truncation, sign prefixes, case conversion\n7. Convert wide characters to multibyte when needed using FUN_6ff30505\n8. Output formatted result through pOutputHandler callback\n9. Continue until null terminator reached\n10. Return total character count\n\nParameters:\n  pOutputHandler (int *) - callback function pointer for character output\n  pbFormatString (byte *) - printf-style format string to process\n  ppnArgsPtr (uint *) - pointer to variable arguments list array\n\nReturns:\n  int - total number of characters processed and output, or negative on error\n\nSpecial Cases:\n  - Field width of -1 indicates unlimited width (0x7fffffff)\n  - Precision of -1 disables precision limiting\n  - Zero flag (0x08) is ignored when left-align flag (0x04) is set\n  - Hash flag (0x80) adds prefixes: \"0\" for octal, \"0x\"/\"0X\" for hex\n  - I64 modifier (0x8000) enables 64-bit integer processing\n\nMagic Numbers Reference:\n  0x6ff333e0 - character classification table for format parsing\n  0x6ff33400 - state transition table (8 bytes per character class)  \n  0x20/0x78 - valid format character range (space to 'x')\n  0x7fffffff - unlimited field width sentinel value\n  0x30 - ASCII '0', base for digit conversion\n  0x39 - ASCII '9', upper limit for digit checking\n  0x2a - ASCII '*', indicates va_arg width/precision\n  0x2d - ASCII '-', negative sign character\n\nError Handling:\n  - Invalid format characters fall through to literal output\n  - Null string arguments replaced with default \"(null)\" string\n  - Negative field widths converted to left-align with positive width\n  - Buffer overflow protection through character count tracking",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:b7a52aed3655c7d65807498f610c8ff8"
    },
    "Bnclient_STR_cde503e814e1": {
      "addresses": {
        "LoD/1.07": "0x6FF22BD0",
        "LoD/1.08": "0x6FF22BF0",
        "LoD/1.09": "0x6FF03550",
        "LoD/1.09b": "0x6FF03550",
        "LoD/1.09d": "0x6FF03560",
        "LoD/1.10": "0x6FF035B0"
      },
      "rvas": {
        "LoD/1.07": "0x2BD0",
        "LoD/1.08": "0x2BF0",
        "LoD/1.09": "0x3550",
        "LoD/1.09b": "0x3550",
        "LoD/1.09d": "0x3560",
        "LoD/1.10": "0x35B0"
      },
      "name": "ProcessBattleNetGatewayOperation",
      "signature": "void ProcessBattleNetGatewayOperation(void * this, uint dwParam1, uint dwParam2, uint dwParam3, byte * pbDataBuffer, char * lpszTextBuffer, uint * pdwAdditionalData, uint dwDataSize)",
      "comment": "ProcessBattleNetGatewayOperation - Handles various Battle.net gateway communication operations\n\nAlgorithm:\n1. Switch on operation type specified in 'this' parameter (message type)\n2. For COPY_TO_PACKET_HANDLERS (0x80000001):\n   - Calculate string length of input data buffer\n   - Copy data buffer contents to global packet handler buffer at offset 0xb3\n   - Use optimized DWORD and byte copying for efficiency\n3. For PROCESS_GATEWAY_LIST (0x80000002):\n   - Enter critical section to protect gateway list access\n   - Iterate through global gateway list starting at offset 0xf5\n   - Compare each gateway entry with input data buffer using FUN_6ff2b5f0\n   - If match not found and more entries exist, log operation and exit\n   - If all entries processed, clear gateway list flags and exit\n   - Always release critical section before return\n4. For LOG_OPERATION (0x80000003):\n   - Copy input parameters to local storage for logging\n   - Validate and allocate buffers for data, text, and additional data if provided\n   - Copy all non-null input buffers to allocated local storage\n   - Call logging subsystem with formatted message buffer\n   - Log operation type 3 with parameter block (24 bytes)\n5. For UPDATE_GATEWAYS (0x80000004):\n   - Calculate length of parameter buffer using Ordinal_506\n   - Allocate temporary buffer via Ordinal_401 with project path\n   - Copy parameter data to temporary buffer via Ordinal_501\n   - Update gateways from INI file via BNGatewayAccess::UpdateGatewaysFromIni\n   - Release temporary buffer via Ordinal_403\n   - Unload gateway access module via BNGatewayAccess::Unload\n\nParameters:\nthis - Operation type ID cast as void pointer (0x80000001-0x80000004)\ndwParam1 - First operation parameter (usage varies by operation type)\ndwParam2 - Second operation parameter (usage varies by operation type) \ndwParam3 - Third operation parameter (usage varies by operation type)\npbDataBuffer - Pointer to binary data buffer for copy operations\nlpszTextBuffer - Pointer to text buffer for gateway list processing\npdwAdditionalData - Pointer to additional data buffer for logging/updates\ndwDataSize - Size in bytes of additional data buffer\n\nReturns:\nvoid - No return value, operations complete via side effects\n\nSpecial Cases:\n- Operation 0x80000003 (LOG_OPERATION) performs parameter copying and logging\n- Null buffer pointers are handled gracefully by skipping allocation and copy\n- Empty strings (length 1) are treated as null for buffer operations\n- Critical section protection ensures thread-safe gateway list access\n- Memory allocation uses Ordinal_10042 with specific size codes (0x100, 0x109, 0x112)\n\nMagic Numbers Reference:\n0x80000001 - COPY_TO_PACKET_HANDLERS operation code\n0x80000002 - PROCESS_GATEWAY_LIST operation code  \n0x80000003 - LOG_OPERATION operation code\n0x80000004 - UPDATE_GATEWAYS operation code\n0xb3 - Packet handler buffer offset (179 * 4 = 716 bytes)\n0xad - Critical section offset (173 * 4 = 692 bytes)\n0xf5 - Gateway list offset (245 * 4 = 980 bytes)\n0x100 - Memory allocation size code for data buffer (256 bytes)\n0x109 - Memory allocation size code for text buffer (265 bytes)\n0x112 - Memory allocation size code for additional data buffer (274 bytes)\n0x150 - Ordinal_401 size parameter (336 bytes)\n0x156 - Ordinal_403 size parameter (342 bytes)\n\nError Handling:\n- Invalid operation types fall through to default case (no-op return)\n- Null pointer checks prevent crashes on invalid buffer parameters\n- Critical section ensures gateway list consistency under concurrent access\n- Memory allocation failures handled by subsequent null pointer checks",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:cde503e814e11cd8212d64ad2654e732"
    },
    "Bnclient_STR_d49da70a5db4": {
      "addresses": {
        "LoD/1.10": "0x6FF083D0",
        "LoD/1.11": "0x6FF2FEE0",
        "LoD/1.11b": "0x6FF32990",
        "LoD/1.12a": "0x6FF35EC0",
        "LoD/1.13c": "0x6FF31960",
        "LoD/1.13d": "0x6FF2E150"
      },
      "rvas": {
        "LoD/1.10": "0x83D0",
        "LoD/1.11": "0xFEE0",
        "LoD/1.11b": "0x12990",
        "LoD/1.12a": "0x15EC0",
        "LoD/1.13c": "0x11960",
        "LoD/1.13d": "0xE150"
      },
      "method": "STR",
      "index": "STR:d49da70a5db4ffd4daaa6480d0f1b634"
    },
    "Bnclient_STR_d937d0c590ae": {
      "addresses": {
        "LoD/1.07": "0x6FF24500",
        "LoD/1.08": "0x6FF24520",
        "LoD/1.09": "0x6FF04E80",
        "LoD/1.09b": "0x6FF04E80",
        "LoD/1.09d": "0x6FF05100",
        "LoD/1.10": "0x6FF05090"
      },
      "rvas": {
        "LoD/1.07": "0x4500",
        "LoD/1.08": "0x4520",
        "LoD/1.09": "0x4E80",
        "LoD/1.09b": "0x4E80",
        "LoD/1.09d": "0x5100",
        "LoD/1.10": "0x5090"
      },
      "name": "Load",
      "signature": "void Load(void)",
      "comment": "Loads Battle.net gateway configuration data from embedded resources and configures the gateway access structure.\n\nAlgorithm:\n1. Validate gateway structure is not already loaded (check offset +0x10 != 0)\n2. Initialize all gateway structure fields to zero (offsets +0x8 through +0x18)\n3. Load primary realm data from \"Data\\Global\\Realms.bin\" using Ordinal_279\n4. Handle load failure by logging error and terminating with FUN_6ff2b29c(-1)\n5. Load gateway list from registry \"Override Battle.net gateways\" using GetGatewayList\n6. If no override gateways found, load from \"Diablo II Battle.net gateways\" registry key\n7. Set override flag (+0x1c) to 1 if override gateways were loaded\n8. Validate gateway count >= 1000, if not handle obsolete gateway cleanup\n9. Log obsolete gateway warning and call Unload() then Ordinal_428 for cleanup\n10. Load default gateway configuration from \"DATA\\GLOBAL\\gateways.txt\"\n11. Handle gateways.txt load failure by logging error and terminating\n12. If gateways.txt has data, call UpdateGatewaysFromIni for processing\n13. Validate final gateway count >= 1000 or terminate with regionListVersion error\n14. Parse gateway entries to calculate total count by iterating through null-terminated strings\n15. Verify entry count is divisible by 3 (entries per gateway), error if not\n16. Calculate final gateway count as (entry_count - 1) / 3 and store in structure +0x8\n17. Parse and validate gateway index from first entry using FUN_6ff2bb3d with base 10\n18. Store parsed gateway index in structure +0xc and initialize +0x4 to 0\n19. If gateway index invalid or out of bounds, perform auto-selection algorithm\n20. Auto-select by getting system timezone using GetTimeZoneInformation\n21. Check for English (Australia) locale using GetUserDefaultLangID\n22. Adjust timezone bias to 0x1e0 (480 minutes) for English Australia locale\n23. Call PickClosestZone with timezone bias to select optimal gateway\n\nParameters:\nIMPLICIT this: BNGatewayAccess* in [ESP+4] - Gateway access structure to initialize\n\nReturns:\nvoid - No return value, function terminates process on critical errors\n\nSpecial Cases:\n- Function exits early if gateway structure already loaded (+0x10 != 0)\n- Terminates process with exit code -1 on resource load failures\n- English Australia locale (LANGID 0xC09) gets special timezone bias 0x1e0\n- Gateway count validation requires minimum 1000 entries for security\n- Entry count must be divisible by 3 (format: name, address, ping per gateway)\n\nMagic Numbers Reference:\n0x10, 0x8, 0xc, 0x20, 0x14, 0x18, 0x1c, 0x4 - BNGatewayAccess structure offsets\n0x3e8 (1000) - Minimum required gateway count for validation\n0x17a (378) - Error line number for realms.bin load failure  \n0x1b8 (440) - Error line number for gateways.txt load failure\n0x4d (77) - Error line number for gateway count validation failure\n0x5e (94) - Error line number for gateway entry count validation failure\n0x1e0 (480) - Timezone bias in minutes for English Australia\n0x3ff (1023) - Language ID primary mask for locale detection\n0xfc00 (64512) - Language ID sublanguage mask for locale detection\n0x9 - English primary language identifier\n0xc00 (3072) - Australia sublanguage identifier\n3 - Entries per gateway (name, address, ping)\n\nError Handling:\n- Resource load failures logged via Ordinal_10023 then FUN_6ff2b29c(-1) termination\n- Invalid gateway counts trigger regionListVersion error and termination\n- Malformed entry counts trigger entry validation error and termination\n- All critical errors result in process termination rather than graceful handling\n\nStructure Layout:\nBNGatewayAccess structure accessed offsets:\n+0x00: Gateway state byte (initialized to 0)\n+0x04: Current gateway selection index (set to 0 during init)\n+0x08: Total gateway count (calculated from parsed entries)\n+0x0c: Selected gateway index (parsed from configuration)\n+0x10: Load state flag (checked for != 0 to prevent double-load)\n+0x14: Gateway entry data length (total bytes of gateway string data)\n+0x18: Gateway version/count field (validated against 1000 minimum)\n+0x1c: Override flag (set to 1 if override gateways loaded)\n+0x20: Gateway entry data buffer pointer (allocated by GetGatewayList)",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:d937d0c590ae16757bdbb85c94a87552"
    },
    "Bnclient_STR_d9c2f28e97cc": {
      "addresses": {
        "LoD/1.07": "0x6FF21990"
      },
      "rvas": {
        "LoD/1.07": "0x1990"
      },
      "name": "InitializeGatewayConnection",
      "signature": "DWORD InitializeGatewayConnection(void)",
      "comment": "Initialize Battle.net Gateway Connection for Game Server Discovery\n\nAlgorithm:\n1. Acquire exclusive execution lock using InterlockedIncrement on reference counter\n2. If already running (ref count > 1), decrement and exit with failure\n3. Initialize gateway data buffer and load BNGatewayAccess configuration\n4. Perform DNS lookup to resolve gateway server address\n5. Query gateway using Ordinal_422 for initial connection handshake\n6. If query succeeds, copy response to gateway data buffer\n7. Set connection phase to active and clear status flag\n8. Validate network connectivity using Ordinal_10001\n9. Create worker thread for asynchronous connection handling\n10. Wait for worker thread completion or abort signal\n11. Check connection success flag and cleanup on failure\n12. If successful, establish game server connection\n13. Handle final cleanup and set appropriate error states\n14. Return connection status (success/failure)\n\nParameters:\nNone\n\nReturns:\nTRUE (1) - Gateway connection established and game server located successfully\nFALSE (0) - Connection failed due to network error, timeout, or server unavailable\n\nSpecial Cases:\n- Early exit if function already executing (thread safety)\n- Timeout handling during worker thread execution\n- Graceful abort on user cancellation\n- Error recovery with proper cleanup sequence\n\nMagic Numbers Reference:\n0x100 (256) - Network buffer size for gateway responses\n0x1 - Connection phase active state\n0x2 - Connection operation type identifier\n0x4 - Gateway initialization flag\n0x8 - Process error state identifier\n0xfffffffc (-4) - Connection cleanup/reset flag\n10 - Thread sleep interval in milliseconds\n\nError Handling:\n- Network timeout: Sets error state 8 and returns FALSE\n- DNS resolution failure: Uses fallback buffer and continues\n- Worker thread failure: Aborts connection and cleans up\n- Server unavailable: Sets error state and returns FALSE\n\nStructure Layout:\nDnsContainer (24 bytes):\nOffset | Size | Field Name | Type | Description\n-------|------|------------|------|------------\n0x00   | 4    | dwFlags    | uint | DNS query flags and status\n0x04   | 4    | pBuffer    | char* | Pointer to DNS response buffer\n0x08   | 4    | dwSize     | uint | Buffer size for DNS response\n0x0C   | 12   | Reserved   | byte[12] | Reserved space for future use\n\nGlobal Variables:\ng_abGlobalStringBuffer - Global string buffer for network operations\ng_dwConnectionPhase - Current connection phase (0=idle, 1=active)\ng_pbThreadBuffer - Pointer to thread communication buffer\ng_dwThreadBufferFlags - Thread buffer control flags\ng_dwAbortConnection - Connection abort signal flag\ng_pActiveServerConnection - Pointer to established server connection",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:d9c2f28e97cc0411479a1702cd819f34"
    },
    "Bnclient_STR_de19d421cc0c": {
      "addresses": {
        "LoD/1.07": "0x6FF262E0",
        "LoD/1.08": "0x6FF26300"
      },
      "rvas": {
        "LoD/1.07": "0x62E0",
        "LoD/1.08": "0x6300"
      },
      "name": "ProcessClientValidationAndSync",
      "signature": "uint ProcessClientValidationAndSync(uint dwSlotIndex)",
      "comment": "Validates client credentials and synchronizes network state with game server\n\nAlgorithm:\n1. Clear slot index entry table and initialize network buffer at 0x6ff39514\n2. Get global state value and clear packet handler state for slot 6  \n3. Send network packet with validation data using 16-byte buffer\n4. If packet send successful, enter validation loop:\n   - Check if packet handler 179 is registered\n   - If not registered, lookup notification value for slot 7\n   - If no notification, check network error state\n   - On network error, return 0 (failure)\n   - Sleep 10ms and retry until handler registered or notification received\n5. Clear packet handler state after successful registration\n6. Lookup notification value for slot 7 again\n7. If no notification value found:\n   - Initialize 255-byte path buffer from g_lpszDefaultDestPath\n   - Zero-fill buffer starting at local_ff (0x3f iterations = 252 bytes)\n   - Call ValidateClientRevision with version/checksum output buffers\n   - If validation fails, set global process ID to 1 and return 0\n   - Process packet synchronization with buffer at 0x6ff39b70 and type 2\n   - Initialize packet data structure (0x45 * 4 = 276 bytes):\n     * [0]: Magic value 0x49583836 (\"IX86\")\n     * [1]: State-dependent value (0x44324456 + conditional 0x13fa offset)\n     * [2]: Protocol version 7\n     * [3]: Client version from ValidateClientRevision\n     * [4]: Revision checksum from ValidateClientRevision\n   - Call Ordinal_501 to format path buffer (256-byte limit)\n   - Call Ordinal_10029 with format string and packet data for transmission\n   - Calculate string length of formatted output and send as network packet\n   - Wait for slot activation using slot 7\n8. Return 0 (success)\n\nParameters:\ndwSlotIndex (uint): Client slot index for validation context\n\nReturns:\n0: Always returns 0 regardless of success/failure state\n\nSpecial Cases:\n- Function always returns 0 even on validation failures\n- Network errors during polling cause immediate return\n- Failed client revision validation sets global process ID before exit\n- Buffer clearing uses STOSD instruction pattern (4-byte aligned)\n- String length calculation uses SCASB.REPNE for null terminator search\n- CONCAT31 operations extract byte values from register contexts\n\nMagic Numbers Reference:\n0x6ff39514: Network buffer base address\n0x6ff39b70: Packet synchronization buffer address  \n0x49583836: Client architecture identifier (\"IX86\" as little-endian DWORD)\n0x44324456: Base protocol identifier\n0x13fa: Conditional offset added based on global state\n0x7: Protocol version number\n0xa (10): Sleep interval in milliseconds during polling loop\n0x3f (63): Buffer clear loop iterations (252 bytes total)\n0x45 (69): Packet structure clear iterations (276 bytes total) \n0x100 (256): Maximum path buffer size for Ordinal_501\n\nError Handling:\n- Network error state check returns function immediately with 0\n- Client revision validation failure triggers global process ID assignment\n- Packet send failures bypass validation loop entirely\n- No error propagation from internal buffer operations\n- Silent failures return success value (0)",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:de19d421cc0cf60025d5a12959ebb1cf"
    },
    "Bnclient_STR_e375fc905014": {
      "addresses": {
        "LoD/1.10": "0x6FF06700",
        "LoD/1.11": "0x6FF24760",
        "LoD/1.11b": "0x6FF24750",
        "LoD/1.12a": "0x6FF247C0",
        "LoD/1.13c": "0x6FF247C0",
        "LoD/1.13d": "0x6FF247C0"
      },
      "rvas": {
        "LoD/1.10": "0x6700",
        "LoD/1.11": "0x4760",
        "LoD/1.11b": "0x4750",
        "LoD/1.12a": "0x47C0",
        "LoD/1.13c": "0x47C0",
        "LoD/1.13d": "0x47C0"
      },
      "name": "__chkstk",
      "signature": "undefined __chkstk(void)",
      "comment": "Library Function - Single Match\n __chkstk\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:e375fc905014c23e48a4730922234300"
    },
    "Bnclient_STR_eed37e5586cf": {
      "addresses": {
        "LoD/1.09b": "0x6FF01650",
        "LoD/1.09d": "0x6FF01630"
      },
      "rvas": {
        "LoD/1.09b": "0x1650",
        "LoD/1.09d": "0x1630"
      },
      "method": "STR",
      "index": "STR:eed37e5586cfe49f937a838bc5c8e31f"
    },
    "Bnclient_STR_f01efdc17c15": {
      "addresses": {
        "LoD/1.11": "0x6FF30C30",
        "LoD/1.11b": "0x6FF312A0",
        "LoD/1.12a": "0x6FF2FD20",
        "LoD/1.13c": "0x6FF32EE0",
        "LoD/1.13d": "0x6FF2EEA0"
      },
      "rvas": {
        "LoD/1.11": "0x10C30",
        "LoD/1.11b": "0x112A0",
        "LoD/1.12a": "0xFD20",
        "LoD/1.13c": "0x12EE0",
        "LoD/1.13d": "0xEEA0"
      },
      "method": "STR",
      "index": "STR:f01efdc17c15540c477f1a7e8ccf113d"
    }
  }
};

if (typeof FUNCTION_DATA === 'undefined') FUNCTION_DATA = {};
FUNCTION_DATA['Bnclient.dll'] = FUNCTIONS_Bnclient_dll;
